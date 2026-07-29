# Roadmap

This roadmap is intentionally short for the first public import. It lists the
next capabilities that would make vm-forgeyard more useful outside its original
deployment environment.

## Self-Hosted Staging Tests

Enable vm-forgeyard to run staging tests for itself using nested virtualization.
The goal is an automated self-test workflow that provisions test VMs through
vm-forgeyard, exercises control-plane and executor behavior end to end, and
catches regressions before deployment.
