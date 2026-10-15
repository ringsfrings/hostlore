"""Gunicorn hooks. Drop a dead worker's live-gauge samples from the shared metrics dir."""


def child_exit(server, worker):
    from prometheus_client import multiprocess
    multiprocess.mark_process_dead(worker.pid)
