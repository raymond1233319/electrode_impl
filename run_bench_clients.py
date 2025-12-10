#!/usr/bin/env python3
import argparse
import concurrent.futures
import pathlib
import re
import statistics
import subprocess
import sys
import time
from typing import Callable, Optional

import matplotlib.pyplot as plt

MARKERS = ["o", "^", "s", "D", "v", "P", "X"]

THROUGHPUT_RE = re.compile(r"Completed (\d+) requests in (\d+)\.(\d+) seconds")
MEDIAN_RE = re.compile(r"Median latency is (\d+) ns")
PERCENTILE_RE = re.compile(r"(\d+)[a-z]{2} percentile latency is (\d+) ns")


def parse_output(output: str) -> dict:
    metrics = {"throughput": None, "latency_ns": {}, "completed_requests": None, "duration_seconds": None}
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        match = THROUGHPUT_RE.search(line)
        if match:
            total = int(match.group(1))
            seconds = int(match.group(2)) + int(match.group(3)) / 1_000_000
            if seconds == 0:
                raise ValueError("Benchmark runtime reported zero seconds")
            metrics["throughput"] = total / seconds
            metrics["completed_requests"] = total
            metrics["duration_seconds"] = seconds
            continue
        match = MEDIAN_RE.search(line)
        if match:
            metrics["latency_ns"]["median"] = int(match.group(1))
            continue
        match = PERCENTILE_RE.search(line)
        if match:
            percentile = match.group(1)
            metrics["latency_ns"][percentile] = int(match.group(2))
            continue
    if metrics["throughput"] is None:
        raise ValueError("Failed to parse throughput from benchmark output")
    if metrics["completed_requests"] is None or metrics["duration_seconds"] is None:
        raise ValueError("Failed to capture benchmark request count or duration")
    if "median" not in metrics["latency_ns"]:
        raise ValueError("Failed to parse median latency from benchmark output")
    return metrics


def run_benchmark_instance(repo_root: pathlib.Path, requests: int, mode: str, config_path: pathlib.Path) -> dict:
    binary = repo_root / "bench" / "client"
    if not binary.exists():
        raise FileNotFoundError(f"Missing benchmark binary: {binary}")
    cmd = [
        str(binary),
        "-c",
        str(config_path),
        "-m",
        mode,
        "-n",
        str(requests),
    ]
    start = time.perf_counter()
    result = subprocess.run(cmd, cwd=repo_root, text=True, capture_output=True)
    elapsed = time.perf_counter() - start
    if result.returncode != 0:
        merged = (result.stdout or "") + (result.stderr or "")
        raise RuntimeError(f"Benchmark failed:\n{merged}")
    merged = (result.stdout or "") + (result.stderr or "")
    metrics = parse_output(merged)
    metrics["raw_output"] = merged
    metrics["elapsed"] = elapsed
    metrics["requested"] = requests
    return metrics


def run_parallel_benchmark(
    repo_root: pathlib.Path,
    parallelism: int,
    requests: int,
    mode: str,
    config_path: pathlib.Path,
    execution_mode: str = "concurrent",
) -> dict:
    if parallelism <= 0:
        raise ValueError("Parallelism must be a positive integer")
    if execution_mode not in {"concurrent", "sequential"}:
        raise ValueError("execution_mode must be 'concurrent' or 'sequential'")
    if requests < parallelism:
        raise ValueError("Number of requests must be at least the parallelism level")

    base_requests, remainder = divmod(requests, parallelism)
    worker_requests = [base_requests + (1 if idx < remainder else 0) for idx in range(parallelism)]
    if any(req <= 0 for req in worker_requests):
        raise ValueError("Each worker must be assigned at least one request")

    metrics_list: list[dict] = []

    start = time.perf_counter()
    if execution_mode == "concurrent":
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallelism) as executor:
            futures = [
                executor.submit(run_benchmark_instance, repo_root, worker_requests[idx], mode, config_path)
                for idx in range(parallelism)
            ]
            for future in concurrent.futures.as_completed(futures):
                metrics_list.append(future.result())
    else:
        for per_worker_requests in worker_requests:
            metrics_list.append(run_benchmark_instance(repo_root, per_worker_requests, mode, config_path))
    elapsed = time.perf_counter() - start

    completed_requests = sum(m.get("completed_requests", 0) for m in metrics_list)
    requested_requests = sum(m.get("requested", 0) for m in metrics_list)
    if requested_requests != requests:
        raise RuntimeError(
            f"Benchmark dispatch mismatch: expected {requests} total requests but assigned {requested_requests}"
        )

    if completed_requests != requests:
        raise RuntimeError(
            f"Benchmark completed {completed_requests} requests but expected {requests}"
        )

    throughput = completed_requests / elapsed if elapsed > 0 else float("inf")

    latencies_us = [m["latency_ns"]["median"] / 1_000 for m in metrics_list]
    if not latencies_us:
        raise RuntimeError("No latency samples gathered from benchmark runs")
    median_latency_us = statistics.median(latencies_us)

    return {
        "throughput": throughput,
        "median_latency_us": median_latency_us,
        "elapsed": elapsed,
        "metrics": metrics_list,
        "total_requests": completed_requests,
    }


def run_stable_parallel_benchmark(
    repo_root: pathlib.Path,
    parallelism: int,
    requests: int,
    mode: str,
    config_path: pathlib.Path,
    threshold: float,
    max_trials: int,
    log: Callable[..., None],
    execution_mode: str,
) -> dict:
    if max_trials <= 0:
        raise ValueError("Maximum stability trials must be positive")
    if threshold <= 0:
        raise ValueError("Stability threshold must be a positive fraction")

    attempts: list[dict] = []
    last_throughput: Optional[float] = None
    last_diff: Optional[float] = None
    stabilized = False

    for attempt in range(1, max_trials + 1):
        result = run_parallel_benchmark(
            repo_root,
            parallelism,
            requests,
            mode,
            config_path,
            execution_mode=execution_mode,
        )
        attempts.append(result)
        throughput = result["throughput"]
        latency_us = result["median_latency_us"]
        log(
            f"parallel={parallelism} attempt={attempt}: throughput={throughput:.2f} req/s, median latency={latency_us/1000:.3f} ms ({latency_us:.1f} µs)\n",
            record=True,
        )

        if last_throughput is not None:
            if last_throughput == 0:
                diff = float("inf") if throughput != 0 else 0.0
            else:
                diff = abs(throughput - last_throughput) / last_throughput
            log(
                f"parallel={parallelism} attempt={attempt}: throughput diff from previous={diff*100:.2f}%\n"
            )
            last_diff = diff
            if diff <= threshold:
                stabilized = True
                break
        last_throughput = throughput

    final_throughput = attempts[-1]["throughput"] if attempts else 0.0
    final_latency_us = attempts[-1]["median_latency_us"] if attempts else 0.0

    log(
        f"parallel={parallelism} attempt={len(attempts)}: throughput={final_throughput:.2f} req/s, median latency={final_latency_us/1000:.3f} ms ({final_latency_us:.1f} µs)\n"
    )

    if stabilized and last_diff is not None:
        log(
            f"parallel={parallelism}: stabilized with throughput diff {last_diff*100:.2f}% (threshold {threshold*100:.2f}%)\n"
        )
    elif not stabilized and len(attempts) > 1 and last_diff is not None:
        log(
            f"parallel={parallelism}: max attempts reached with last throughput diff {last_diff*100:.2f}% (> {threshold*100:.2f}%)\n"
        )

    return {
        "throughput": final_throughput,
        "median_latency_us": final_latency_us,
        "attempts": attempts,
        "stabilized": stabilized,
    }


def plot_results(series: list[dict], output_path: pathlib.Path) -> None:
    if not series:
        raise ValueError("No data series provided for plotting")

    fig, ax = plt.subplots(figsize=(5.5, 3.5))

    for idx, entry in enumerate(series):
        marker = entry.get("marker") or MARKERS[idx % len(MARKERS)]
        points = sorted(zip(entry["throughputs"], entry["latencies_us"]))
        if not points:
            continue
        xs, ys = zip(*points)
        ax.plot(
            xs,
            ys,
            marker=marker,
            linestyle="-",
            linewidth=1.5,
            markersize=6,
            label=entry["label"],
        )

    ax.set_xlabel("Throughput (req/s)")
    ax.set_ylabel("Median latency (µs)")
    ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.7)
    ax.legend(loc="upper left", frameon=False)

    fig.tight_layout()
    fig.savefig(output_path, dpi=200)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run bench/client for varying client counts and plot throughput/latency")
    parser.add_argument("--clients", metavar="N", type=int, nargs="+", help="Client counts to benchmark (mutually exclusive with --auto)")
    parser.add_argument("--auto", action="store_true", help="Automatically increment clients until latency increases drastically")
    parser.add_argument("--start", type=int, default=1, help="Starting number of clients for auto mode (default: 1)")
    parser.add_argument("--increment", type=int, default=1, help="Client increment step for auto mode (default: 1)")
    parser.add_argument("--max-clients", type=int, default=100, help="Maximum number of clients for auto mode (default: 100)")
    parser.add_argument("--latency-threshold", type=float, default=3, help="Latency increase multiplier to stop at")
    parser.add_argument("--stability-threshold", type=float, default=0.1, help="Relative throughput change threshold to stop repeating a client count (default: 0.1 = 10%)")
    parser.add_argument("--stability-max-trials", type=int, default=5, help="Maximum attempts per client count to reach throughput stability (default: 5)")
    parser.add_argument(
        "--attempt-execution",
        choices=["sequential", "concurrent"],
        default="concurrent",
        help="How to launch benchmark attempts for each client count (sequential avoids overlapping runs; default: concurrent)",
    )
    parser.add_argument("--label", default=None, help="Legend label to use for this run (default derived from mode)")
    parser.add_argument("--requests", type=int, default=10000, help="Number of requests per benchmark run")
    parser.add_argument("--mode", default="vr", help="Replication mode to pass to -m (default: vr)")
    parser.add_argument("--config", default="config.txt", help="Configuration file path relative to repository root")
    parser.add_argument("--output", default="bench_results.png", help="Output figure path relative to repository root")
    parser.add_argument("--text-output", default="bench_results.txt", help="Text results path relative to repository root")
    args = parser.parse_args()

    if args.auto and args.clients:
        parser.error("--auto and --clients are mutually exclusive")
    if not args.auto and not args.clients:
        args.clients = [1, 2, 4, 8]  # default
    if args.auto:
        if args.start <= 0:
            parser.error("Starting client count must be positive")
        if args.increment <= 0:
            parser.error("Client increment must be positive")
        if args.latency_threshold <= 1.0:
            parser.error("Latency threshold must be greater than 1.0")
    elif any(n <= 0 for n in args.clients):
        parser.error("Client counts must be positive integers")
    if args.requests <= 0:
        parser.error("Number of requests must be positive")
    if args.stability_threshold <= 0:
        parser.error("Stability threshold must be positive")
    if args.stability_max_trials <= 0:
        parser.error("Stability max trials must be positive")

    repo_root = pathlib.Path(__file__).resolve().parent
    config_path = (repo_root / args.config).resolve()
    if not config_path.exists():
        parser.error(f"Configuration file not found: {config_path}")

    file_lines: list[str] = []

    def log(message: str, *, record: bool = False) -> None:
        sys.stdout.write(message)
        if record:
            file_lines.append(message)

    def run_script(script: str) -> None:
        script_path = repo_root / script
        if not script_path.exists():
            raise FileNotFoundError(f"Required script not found: {script_path}")
        log(f"Running {script}...\n")
        result = subprocess.run(["bash", str(script_path)], cwd=repo_root)
        if result.returncode != 0:
            raise RuntimeError(f"{script} failed with exit code {result.returncode}")
        log(f"Finished {script}\n")

    log(f"Attempt execution mode: {args.attempt_execution}\n")

    run_script("stop.sh")
    run_script("deploy.sh")

    concurrency_levels = []
    throughputs = []
    latencies_us = []

    if args.auto:
        # Auto-increment mode
        count = args.start
        baseline_latency_us = None
        log(f"Auto mode: starting at {count} clients, incrementing by {args.increment}, stopping when latency exceeds {args.latency_threshold}x baseline\n")
        
        while count <= args.max_clients:
            result = run_stable_parallel_benchmark(
                repo_root,
                count,
                args.requests,
                args.mode,
                config_path,
                args.stability_threshold,
                args.stability_max_trials,
                log,
                args.attempt_execution,
            )
            concurrency_levels.append(count)
            throughputs.append(result["throughput"])
            latency_us = result["median_latency_us"]
            latencies_us.append(latency_us)
            if baseline_latency_us is None:
                baseline_latency_us = latency_us
                log(f"Baseline latency set to {baseline_latency_us/1000:.3f} ms ({baseline_latency_us:.1f} µs)\n")
            else:
                ratio = latency_us / baseline_latency_us
                if ratio >= args.latency_threshold:
                    log(
                        "Stopping: latency increased to "
                        f"{ratio:.2f}x baseline ({latency_us/1000:.3f} ms vs "
                        f"{baseline_latency_us/1000:.3f} ms)\n"
                    )
                    break
            
            count += args.increment
        
        if count > args.max_clients:
            log(f"Reached maximum client count of {args.max_clients}\n")
    else:
        # Manual mode with specified client counts
        for count in args.clients:
            result = run_stable_parallel_benchmark(
                repo_root,
                count,
                args.requests,
                args.mode,
                config_path,
                args.stability_threshold,
                args.stability_max_trials,
                log,
                args.attempt_execution,
            )
            concurrency_levels.append(count)
            throughputs.append(result["throughput"])
            latency_us = result["median_latency_us"]
            latencies_us.append(latency_us)

    output_path = repo_root / args.output
    if not concurrency_levels:
        raise RuntimeError("No benchmark data collected; ensure at least one run completes before plotting")

    label = args.label or f"{args.mode} (median)"
    series = [{"label": label, "throughputs": throughputs, "latencies_us": latencies_us}]

    plot_results(series, output_path)
    log(f"Saved plot to {output_path}\n")

    text_output_path = repo_root / args.text_output
    text_output_path.parent.mkdir(parents=True, exist_ok=True)
    text_output_path.write_text("".join(file_lines))
    log(f"Wrote text results to {text_output_path}\n")


if __name__ == "__main__":
    main()
