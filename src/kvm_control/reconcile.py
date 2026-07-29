from __future__ import annotations

import argparse

from .service import build_services


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config")
    args = parser.parse_args()

    services = build_services(args.config)
    tracked_vm_ids = [vm["vm_id"] for vm in services.registry.list_vms()]
    services.executor.run("reconcile-runtime", {"tracked_vm_ids": tracked_vm_ids})
    services.executor.run("cleanup-after-boot", {"tracked_vm_ids": tracked_vm_ids})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

