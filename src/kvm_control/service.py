from __future__ import annotations

import os
from dataclasses import dataclass

from .config import AppConfig, load_config
from .db import Registry
from .executor import ExecutorClient
from .monitor import RunMonitor
from .status_bus import StatusEventBus


@dataclass(slots=True)
class Services:
    config: AppConfig
    registry: Registry
    executor: ExecutorClient
    monitor: RunMonitor
    status_bus: StatusEventBus


def build_services(config_path: str | None = None, *, start_monitor: bool = True) -> Services:
    config = load_config(config_path or os.environ.get("KVM_CONTROL_CONFIG"))
    status_bus = StatusEventBus()
    registry = Registry(config, status_bus=status_bus)
    executor = ExecutorClient(config, registry)
    monitor = RunMonitor(registry, executor, interval_s=1.0)
    services = Services(
        config=config,
        registry=registry,
        executor=executor,
        monitor=monitor,
        status_bus=status_bus,
    )
    if start_monitor:
        services.monitor.start()
    return services
