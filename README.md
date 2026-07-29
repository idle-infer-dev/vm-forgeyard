# vm-forgeyard

`vm-forgeyard` is a host-local KVM control plane for test and development
virtual machines.

It provides:

- `control-api`: VM lifecycle, capacity, operation, IP reservation, image, run,
  and namespace disk endpoints
- `lock-api`: FIFO lock queue by namespace/resource
- `mcp-api`: HTTP MCP adapter for agents that need to request VMs and inspect
  state
- `root-vm-exec`: a narrow request-file executor for qcow2, libvirt lifecycle,
  guest bootstrap, runtime inspection, and cleanup actions
- SQLite-backed control-plane state
- dry-run modes for API and executor workflow verification

## Status

This repository is the public code mirror. Private deployment inventory, local
hostnames, credentials, and site-specific automation are intentionally excluded.

## Install

```bash
python -m pip install -e .
```

Start the APIs with a host-specific config:

```bash
python -m kvm_control --config ./config.example.yaml control-api
python -m kvm_control --config ./config.example.yaml lock-api
python -m kvm_control --config ./config.example.yaml mcp-api
```

Use [config.example.yaml](./config.example.yaml) as a starting point. For real
VM lifecycle operations, point the storage paths at durable host storage, set
auth credentials, and run the executor through an appropriately constrained
privilege boundary.

## Auth

If `auth.admin_token` or `auth.admin_token_hash` is set, the control and lock
APIs require bearer-token authentication by default. The admin token can create
persistent dev or repository tokens through:

```text
POST /v1/admin/auth/tokens
```

Repository tokens use `git.<repo>` usernames and inherit that effective
namespace. The reserved `dev` token accepts caller-provided namespaces and
normalizes unprefixed names to `dev.<name>`.

`auth.mode: open` exists only as a rollout bridge. Requests without credentials
run as anonymous admin, while provided credentials are still validated.

## Development Checks

Run the unit test suite:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Run dry-run smoke checks:

```bash
PYTHONPATH=src python scripts/sandbox_api_smoke.py
PYTHONPATH=src python scripts/check_api_dry_run.py
PYTHONPATH=src python scripts/check_browser_mobile_layer2_dry_run.py
```

Check an MCP endpoint:

```bash
PYTHONPATH=src python scripts/check_mcp_agent_workflow.py --url http://127.0.0.1:8002/mcp
```

## Public Scope

The initial public repository contains the application code, unit tests, dry-run
checks, static status UI assets, and an example configuration.

Deployment automation is intentionally not included yet. Ansible roles should be
published only after their defaults and examples are generalized enough to be
useful outside one infrastructure environment.

## License

vm-forgeyard is licensed under the GNU General Public License version 2.0.
See [LICENSE](./LICENSE).
