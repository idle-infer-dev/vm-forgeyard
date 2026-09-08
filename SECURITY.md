# Security Policy

## Supported Versions

The public repository tracks the current development line. Security fixes should
target `main` unless a maintained release branch exists.

## Reporting a Vulnerability

Use GitHub private vulnerability reporting for this repository when available.
If private reporting is not available, open a GitHub issue with a minimal
description and request a private coordination path before sharing exploit
details.

Do not include bearer tokens, repository self-registration keys, private
hostnames, internal IP addresses, SSH keys, or production configuration in a
public report. Revoke any token or key that may have been exposed.

Useful reports include:

- affected commit or version
- affected API path, MCP tool, or executor action
- authentication mode and role involved
- expected security boundary
- observed bypass, denial, disclosure, or privilege escalation
- safe reproduction steps using dummy secrets and non-production paths

## Security Boundaries

vm-forgeyard controls host-local VM lifecycle operations and delegates privileged
host actions to a narrow executor. Deployments are responsible for configuring
authentication, source-address ACLs, firewall policy, service isolation, and the
executor privilege boundary for their own hosts.
