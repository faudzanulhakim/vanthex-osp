"""Job gate Fase 2 — antrean prioritas + batas konkurensi untuk job scan.

Thread worker tetap dibuat per job (seperti sebelumnya), tetapi sebelum
benar-benar jalan ia harus memperoleh slot dari gate ini:
- maks GLOBAL_LIMIT job berjalan bersamaan,
- maks USER_LIMIT per user,
- job berprioritas lebih kecil (high=0) didahulukan di antara yang menunggu,
  FIFO di dalam prioritas yang sama.
Job yang dibatalkan saat menunggu tidak pernah memperoleh slot.
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
        """True bila slot diperoleh; False bila dibatalkan saat menunggu."""
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
