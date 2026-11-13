"""
Small, dependency-free worker-pool used by the log/pcap parsers.

Parser.NetworkParser fans the per-protocol pcap parsing out across a handful of
worker threads:

    pool = ThreadManagement.ThreadPool(maxworkers)
    for f in files:
        pool.add_task(self._thread_func, f)
    pool.wait_completion()

The pool owns a fixed set of daemon workers that pull (func, args, kwargs)
tuples off a queue, run them, and mark them done. wait_completion() blocks
until every queued task has finished.
"""

import threading
from queue import Queue


class Worker(threading.Thread):
    """Consumes tasks from the shared queue until the pool is torn down."""

    def __init__(self, tasks):
        super().__init__()
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            item = self.tasks.get()
            if item is None:
                # Sentinel: time to shut the worker down.
                self.tasks.task_done()
                break
            func, args, kwargs = item
            try:
                func(*args, **kwargs)
            except Exception as e:
                # A single bad pcap/log file should not take the pool down;
                # surface it and keep processing the rest.
                print("[ThreadPool] task raised: %s" % e)
            finally:
                self.tasks.task_done()


class ThreadPool:
    """Fixed-size pool of worker threads."""

    def __init__(self, num_threads):
        self.tasks = Queue()
        self._num_threads = max(1, int(num_threads))
        self._workers = [Worker(self.tasks) for _ in range(self._num_threads)]

    def add_task(self, func, *args, **kwargs):
        """Queue a callable to be run by the next free worker."""
        self.tasks.put((func, args, kwargs))

    def wait_completion(self):
        """Block until every queued task has finished."""
        self.tasks.join()

    def close(self):
        """Stop all workers (optional; workers are daemons otherwise)."""
        for _ in self._workers:
            self.tasks.put(None)
        for w in self._workers:
            w.join()
