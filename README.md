# HomeSOC

Home Network Monitoring, Documentation & Security Operations Lab.

A Raspberry Pi–based lab that performs continuous network discovery,
asset inventory, host monitoring, centralized log collection, and
rule-based alert triage for a small home network — with full operator
documentation and runbooks.

## Status

🚧 In active development. See `docs/` for the project plan and roadmap.

## Hardware

- Raspberry Pi 3 Model B v1.2 (Raspberry Pi OS)
- GL.iNet Flint 2 router
- Home LAN: 192.168.8.0/24

## Project structure

Each top-level folder has a single responsibility: discovery
(`scanners/`), log collection (`collectors/`), detection (`alerts/`),
presentation (`dashboard/`), schema (`db/`), automation (`scripts/`,
`systemd/`), documentation (`docs/`), evidence captures (`evidence/`),
and tests (`tests/`).

## Scope & disclaimer

This project operates only on the author's own home network. It is a
learning lab modeled on small-MSP and SOC analyst workflows, not a
production security platform.
