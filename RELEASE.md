# Release Checklist

Use this checklist before publishing a public vm-forgeyard release.

1. Confirm the public tree contains only portable code, tests, dry-run checks,
   example configuration, public documentation, and static assets.
2. Run the unit suite:

   ```bash
   PYTHONPATH=src python -m unittest discover -s tests
   ```

3. Run contract and smoke checks:

   ```bash
   PYTHONPATH=src python scripts/check_contracts.py
   PYTHONPATH=src python scripts/sandbox_api_smoke.py
   ```

4. Run public hygiene checks:

   ```bash
   PYTHONPATH=src python scripts/check_public_hygiene.py
   ```

5. Review `git status --short` and `git diff --check`.
6. Confirm no private deployment files, generated state, caches, tokens, local
   hostnames, internal IP addresses, or developer paths are staged.
7. Update version metadata and release notes when cutting a tagged release.
8. Commit, push, and tag from the public repository.
9. Verify the pushed tag or branch on GitHub.
10. Record any known limitations that affect installation, auth, MCP workflow
    contracts, or VM lifecycle behavior.
