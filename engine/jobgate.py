"""Job gate (Phase 2) — priority queue + concurrency limits for scan jobs.

A worker thread is still created per job (as before), but before it
actually runs it must acquire a slot from this gate:
- at most GLOBAL_LIMIT jobs run concurrently,
- at most USER_LIMIT per user,
- jobs with a smaller priority value (high=0) go first among waiters,
  FIFO within the same priority.
A job cancelled while waiting never acquires a slot.
"""
import heapq
import itertools
import threading


class JobGate:
    def __init__(self, global_limit=3, user_limit=2):
        self.global_limit = global_limit
        self.user_limit = user_limit
        self._cond = threading.Condition()
        self._active = 0
        self._user_active = {}
        self._waiting = []            # heap of (priority, seq)
        self._seq = itertools.count()

    def acquire(self, priority=1, user="", cancelled=None):
        """True if a slot was acquired; False if cancelled while waiting."""
        seq = next(self._seq)
        entry = (priority, seq)
        with self._cond:
            heapq.heappush(self._waiting, entry)
            while True:
                if cancelled is not None and cancelled():
                    try:
                        self._waiting.remove(entry)
                        heapq.heapify(self._waiting)
                    except ValueError:
                        pass
                    self._cond.notify_all()
                    return False
                head = bool(self._waiting) and self._waiting[0] == entry
                if (head and self._active < self.global_limit
                        and self._user_active.get(user, 0) < self.user_limit):
                    heapq.heappop(self._waiting)
                    self._active += 1
                    self._user_active[user] = \
                        self._user_active.get(user, 0) + 1
                    return True
                self._cond.wait(timeout=0.25)

    def release(self, user=""):
        with self._cond:
            self._active = max(0, self._active - 1)
            if user in self._user_active:
                self._user_active[user] = max(0, self._user_active[user] - 1)
            self._cond.notify_all()

    def snapshot(self):
        with self._cond:
            return {"active": self._active, "waiting": len(self._waiting),
                    "global_limit": self.global_limit,
                    "user_limit": self.user_limit}
