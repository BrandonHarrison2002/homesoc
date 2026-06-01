# HomeSOC Asset Register

List of devices that have been authorized on the network.
SQLite asset inventory (`db/homesoc.db`) reads all the devices 
on the network.

**Network:** 192.168.8.0/24
**Gateway:** 192.168.8.1 (GL.iNet Flint 2)
**Monitoring host:** 192.168.8.165 (Raspberry Pi, hostname `pi-monitor`)

---

## Authorized devices

| MAC | IP (most recent) | Owner | Device type | Notes |
|---|---|---|---|---|
| b8:27:eb:f0:9d:06 | 192.168.8.165 | HomeSOC Raspberry Pi | server | Monitoring host running HomeSOC. Static via DHCP reservation. |
| 94:83:c4:ca:93:ca | 192.168.8.1 | Flint 2 router | router | controls my internet |
| bc:fc:e7:75:e4:bb | 192.168.8.119 | HACKER-MAN-2 | desktop | main working pc |
| 94:e7:0b:03:f8:86 | 192.168.8.191 | shaddy-GE66-Raider-10SFS | laptop | backup computer |
| 02:08:60:1d:09:1f | 192.168.8.171 | iPhone | phone | using MAC randomization. |
| b2:e3:fb:d1:4c:c8 | 192.168.8.223 | Brandon | phone | Spare phone using MAC randomization. Identified via RB-001 investigation 2026-05-30. |
| 5c:e7:53:xx:xx:xx (x7) | various .130–.220 | Brandon | iot | 7 smart bulbs same brand. |
| 36:cf:bc:cb:16:29 | 192.168.8.220 | Brandon | phone | iPhone with MAC randomization. Identified by household context. |
---

## Review process

When a new device appears in the asset inventory with `is_known=0`:

1. Identify the device using vendor lookup, the Flint 2 client list, and physical inspection (power-cycle test if needed).
2. Update this register with owner, device type, and notes.
3. Apply the corresponding `UPDATE` to the database (see `docs/runbooks/RB-001-unknown-device.md` — TODO).
4. Commit both changes together so the doc and the DB stay in sync.

---

## Change log

| Date | Change |
|---|---|
| 2026-05-30 | Initial asset register created |
| 2026-05-30 | RB-001 invocation: triaged unknown device 
| 2026-06-01 | RB-001 batch invocation: identified and approved 7 smart bulbs (5c:e7:53 series) and 1 iPhone (36:cf:bc randomized MAC). All set is_known=1.|
