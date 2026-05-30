# RB-001 — Unknown Device Detected

| Field | Value |
|---|---|
| ID | RB-001 |
| Severity | Low / informational |
| Triggers when | `discovery.py` reports a new MAC, or `assets.is_known = 0` |
| Last updated | 2026-05-30 |
| Author | Brandon Harrison |

## Trigger

A `discovery.py` scan ends with a "NEW asset(s) detected" line. The job
of this runbook is to figure out what the device is and decide whether
it should be on the network.

## Why this matters

A device I haven't reviewed is a device I can't trust. The asset
inventory is the foundation for every other detection in HomeSOC, so
new MACs get reviewed before anything else.

## Procedure

1. Open the Flint 2 admin UI at http://192.168.8.1 and look for the
   MAC in the client list to find the hostname.
2. If the hostname doesn't help, look up the MAC vendor (online or via
   `curl https://api.macvendors.com/<MAC>`).
3. Based on what I find, apply the right Decision rule below.
4. Update `docs/asset-register.md` and run a SQL `UPDATE` on the
   `assets` table to match. Commit both together.

## Decision rules

- **Known and mine** (my own device, or one I want on the network) →
  set `is_known = 1`, fill in owner, device type, and notes.
- **Known but not wanted** (roommate's device, guest device that
  shouldn't be persistent) → block the MAC in the Flint admin UI;
  leave `is_known = 0` and note the decision.
- **Still unknown after investigation** → leave `is_known = 0`, write
  what I tried in the notes, and re-check on the next scan.

## Escalation

If three or more unidentified MACs appear within a short window, treat
as a possible Wi-Fi compromise:

1. Change the Wi-Fi password on the Flint 2 (forces all clients to
   re-authenticate).
2. Re-baseline the asset inventory once my own devices reconnect.

## Change log

| Date | Change |
|---|---|
| 2026-05-30 | Initial runbook. |

