# RB-003 — SSH Brute-Force Response

## When this runbook applies

Use this runbook when `ssh_bruteforce_watcher` creates an alert ticket because one source IP had too many failed SSH login attempts.

Current threshold:

```text
5 failed SSH attempts within 10 minutes
```

This usually means something on the network is repeatedly trying to log in over SSH.

## Background

My HomeSOC Pi uses key-only SSH. Password authentication was disabled in F1, so a normal password brute-force attempt should not actually be able to log in.

That does not mean I should ignore the alert though. Failed SSH attempts can still show scanning, bad configuration, or a device on the network acting weird. The goal is to figure out whether this is something harmless, like me mistyping or testing, or something that needs attention.

## Investigate

1. Open the alert ticket in `evidence/alerts/`.

   Look for:
   - source IP
   - number of failed attempts
   - usernames tried
   - time of the attempts

2. Check if the source IP is already known in the HomeSOC asset inventory:

   ```bash
   sqlite3 db/homesoc.db "SELECT * FROM assets WHERE ip = '<SOURCE_IP>';"
   ```

   A brute-force IP may not always show up in the asset inventory, especially if it is outside the LAN or if the IP changed.

3. Check the raw SSH log evidence:

   ```bash
   sudo grep "<SOURCE_IP>" /var/log/auth.log
   ```

   This helps confirm what actually happened instead of only relying on the alert ticket.

4. Look at the usernames being tried.

   Common automated scan usernames:

   ```text
   root
   admin
   test
   user
   ubuntu
   pi
   ```

   If the usernames are generic, it is probably an automated scan or brute-force attempt.

   If the username looks like one of my real usernames, it could be me, a typo, or a device/script I configured incorrectly.

## Decide

Use the source IP and username pattern to decide what the alert means.

If the source IP is a device I recognize, this is usually low concern. It may be my own login mistake, an old script, or a device retrying with the wrong credentials. I should document what happened and resolve the alert.

If the source IP is an unknown device on my LAN, that is more concerning. I should check what the device is, whether it recently joined the network, and whether it is supposed to be there. An unknown LAN device trying SSH logins could mean a misconfigured machine or a compromised device.

If the source IP is from outside my LAN, that is a bigger issue. My SSH should not be exposed to the internet. I need to check the Flint router, port forwarding rules, firewall settings, and any VPN or remote access setup.

## Respond

Actions I can take:

1. Confirm SSH is still key-only:

   ```bash
   sudo sshd -T | grep passwordauthentication
   ```

   Expected result:

   ```text
   passwordauthentication no
   ```

2. If the source is hostile or unknown, block it at the Flint firewall.

3. If this keeps happening, consider adding `fail2ban` as a future upgrade so repeated SSH failures can be blocked automatically.

4. Document what I found in the alert ticket.

Do not just delete the alert. The point is to leave evidence showing what happened and how I handled it.

## Resolve

Update the alert ticket in `evidence/alerts/`.

Change:

```yaml
status: open
```

to:

```yaml
status: resolved
```

Add notes explaining:

- what the source IP was
- whether it was known or unknown
- what usernames were tried
- what action I took
- whether SSH was confirmed to still be key-only

Example note:

```text
Investigated SSH brute-force alert from 192.168.8.50.
The IP was not found in the asset inventory. Logs showed repeated attempts
using generic usernames like root and admin. Confirmed SSH password auth is
disabled. No successful login was found. Source IP should be monitored or
blocked if activity continues.
```
