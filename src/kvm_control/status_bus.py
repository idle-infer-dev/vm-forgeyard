from __future__ import annotations

import queue
import threading
from collections import deque
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class StatusSubscription:
    subscriber_id: int
    replay: list[dict[str, Any]]
    queue: queue.Queue[dict[str, Any] | None]


class StatusEventBus:
    def __init__(self, replay_limit: int = 256, subscriber_queue_size: int = 64):
        self.replay_limit = replay_limit
        self.subscriber_queue_size = subscriber_queue_size
        self._events: deque[dict[str, Any]] = deque(maxlen=replay_limit)
        self._subscribers: dict[int, queue.Queue[dict[str, Any] | None]] = {}
        self._lock = threading.RLock()
        self._next_subscriber_id = 1

    def publish(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._events.append(dict(event))
            stale_subscribers: list[int] = []
            for subscriber_id, subscriber_queue in self._subscribers.items():
                if not self._enqueue(subscriber_queue, event):
                    stale_subscribers.append(subscriber_id)
            for subscriber_id in stale_subscribers:
                self._subscribers.pop(subscriber_id, None)

    def subscribe(self, after_id: int | None = None) -> StatusSubscription:
        with self._lock:
            subscriber_id = self._next_subscriber_id
            self._next_subscriber_id += 1
            subscriber_queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=self.subscriber_queue_size)
            self._subscribers[subscriber_id] = subscriber_queue
            replay = [
                dict(event)
                for event in self._events
                if after_id is None or int(event.get("id", 0)) > after_id
            ]
            return StatusSubscription(subscriber_id=subscriber_id, replay=replay, queue=subscriber_queue)

    def unsubscribe(self, subscriber_id: int) -> None:
        with self._lock:
            subscriber_queue = self._subscribers.pop(subscriber_id, None)
            if subscriber_queue is None:
                return
            self._enqueue_termination(subscriber_queue)

    def _enqueue(self, subscriber_queue: queue.Queue[dict[str, Any] | None], event: dict[str, Any]) -> bool:
        try:
            subscriber_queue.put_nowait(dict(event))
            return True
        except queue.Full:
            try:
                subscriber_queue.get_nowait()
            except queue.Empty:
                return False
            try:
                subscriber_queue.put_nowait(dict(event))
                return True
            except queue.Full:
                return False

    def _enqueue_termination(self, subscriber_queue: queue.Queue[dict[str, Any] | None]) -> None:
        try:
            subscriber_queue.put_nowait(None)
        except queue.Full:
            try:
                subscriber_queue.get_nowait()
            except queue.Empty:
                return
            try:
                subscriber_queue.put_nowait(None)
            except queue.Full:
                return
