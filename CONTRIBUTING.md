# Contributing

vm-forgeyard is a host-local KVM control plane. Contributions should keep the
public repository portable: no private deployment inventory, credentials,
internal hostnames, internal network addresses, or site-specific automation.

## Development Checks

Before opening a pull request, run:

```bash
PYTHONPATH=src python -m unittest discover -s tests
PYTHONPATH=src python scripts/check_contracts.py
PYTHONPATH=src python scripts/sandbox_api_smoke.py
PYTHONPATH=src python scripts/check_public_hygiene.py
```

Run the narrower dry-run scripts when the change touches API workflows,
browser-facing status assets, or MCP behavior:

```bash
PYTHONPATH=src python scripts/check_api_dry_run.py
PYTHONPATH=src python scripts/check_browser_mobile_layer2_dry_run.py
PYTHONPATH=src python scripts/check_mcp_agent_workflow.py --url http://127.0.0.1:8002/mcp
```

## Bug Reports

For behavior reports, include:

- observed behavior
- expected behavior
- exact command, HTTP path, or MCP tool used
- relevant response bodies with secrets removed
- whether `scripts/draft_contract_report.py` classified the issue as a bug,
  feature request, documentation gap, or policy rejection

The MCP contract resources under `kvm-control://contracts/*` describe the
implemented workflow boundary. Reports for behavior outside those implemented
contracts are useful feature requests, not regressions.

## Pull Requests

Keep pull requests focused. Include tests for behavior changes, update MCP
schema/resource text when agent-visible workflows change, and run the public
hygiene check before publishing.
