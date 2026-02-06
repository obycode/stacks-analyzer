import queue
import subprocess
import threading
import time
from typing import Optional


def file_reader_worker(
    *,
    source_name: str,
    path: str,
    out_queue: "queue.Queue[tuple]",
    stop_event: threading.Event,
    from_beginning: bool,
    run_once: bool,
    poll_interval_seconds: float,
) -> None:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        if not from_beginning and not run_once:
            handle.seek(0, 2)

        while not stop_event.is_set():
            line = handle.readline()
            if line:
                out_queue.put((source_name, line))
                continue

            if run_once:
                break

            time.sleep(poll_interval_seconds)

    out_queue.put((source_name, None))


def journal_reader_worker(
    *,
    source_name: str,
    unit: str,
    out_queue: "queue.Queue[tuple]",
    stop_event: threading.Event,
    prefetch_minutes: int = 30,
) -> None:
    prefetch_cmd = [
        "journalctl",
        "-u",
        unit,
        "--since",
        f"{prefetch_minutes} minutes ago",
        "--output=short",
        "--no-pager",
    ]
    follow_cmd = [
        "journalctl",
        "-f",
        "-u",
        unit,
        "-n",
        "0",
        "--since",
        "now",
        "--output=short",
        "--no-pager",
    ]
    prefetch_proc = subprocess.Popen(
        prefetch_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    try:
        out_queue.put((source_name, "__meta__prefetch_start__"))
        if prefetch_proc.stdout:
            for line in prefetch_proc.stdout:
                if stop_event.is_set():
                    break
                if line:
                    out_queue.put((source_name, line))
    finally:
        if prefetch_proc.poll() is None:
            prefetch_proc.terminate()
            try:
                prefetch_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                prefetch_proc.kill()
        out_queue.put((source_name, "__meta__prefetch_end__"))

    process = subprocess.Popen(
        follow_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    try:
        while not stop_event.is_set():
            line = process.stdout.readline() if process.stdout else ""
            if not line:
                if process.poll() is not None:
                    break
                time.sleep(0.1)
                continue
            out_queue.put((source_name, line))
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
        out_queue.put((source_name, None))


def spawn_source_threads(
    *,
    mode: str,
    node_log_path: Optional[str],
    signer_log_path: Optional[str],
    node_journal_unit: str,
    signer_journal_unit: str,
    out_queue: "queue.Queue[tuple]",
    stop_event: threading.Event,
    from_beginning: bool,
    run_once: bool,
    poll_interval_seconds: float,
) -> int:
    started = 0

    if mode == "files":
        if node_log_path:
            thread = threading.Thread(
                target=file_reader_worker,
                kwargs={
                    "source_name": "node",
                    "path": node_log_path,
                    "out_queue": out_queue,
                    "stop_event": stop_event,
                    "from_beginning": from_beginning,
                    "run_once": run_once,
                    "poll_interval_seconds": poll_interval_seconds,
                },
                daemon=True,
            )
            thread.start()
            started += 1
        if signer_log_path:
            thread = threading.Thread(
                target=file_reader_worker,
                kwargs={
                    "source_name": "signer",
                    "path": signer_log_path,
                    "out_queue": out_queue,
                    "stop_event": stop_event,
                    "from_beginning": from_beginning,
                    "run_once": run_once,
                    "poll_interval_seconds": poll_interval_seconds,
                },
                daemon=True,
            )
            thread.start()
            started += 1

    elif mode == "journalctl":
        node_thread = threading.Thread(
            target=journal_reader_worker,
            kwargs={
                "source_name": "node",
                "unit": node_journal_unit,
                "out_queue": out_queue,
                "stop_event": stop_event,
            },
            daemon=True,
        )
        signer_thread = threading.Thread(
            target=journal_reader_worker,
            kwargs={
                "source_name": "signer",
                "unit": signer_journal_unit,
                "out_queue": out_queue,
                "stop_event": stop_event,
            },
            daemon=True,
        )
        node_thread.start()
        signer_thread.start()
        started += 2

    else:
        raise ValueError("Unsupported mode: %s" % mode)

    return started
