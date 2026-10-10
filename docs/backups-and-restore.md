# Private HomeSOC backups and restore verification

## Backup contents

`scripts/backup_homesoc.py` backs up:

- `db/homesoc.db`: inventory, scan history, and sightings, using SQLite's online backup API.
- `dashboard-state/incidents.db`: cases and investigation notes, also using the online backup API.
- Markdown tickets under `evidence/alerts/`.
- Source code, templates, scripts, docs, repository service/timer files, and collector configurations selected by the script's explicit paths and file-extension allowlist.
- A manifest with UTC creation time, host, SHA-256 file hashes, and snapshot row counts.

The script snapshots the databases individually. Each database is internally consistent, including committed WAL data, but the collection is not one atomic snapshot across both databases and Markdown files. It fails if it detects an evidence/config file changing during its copy; retry after the activity settles.

Archives live in `/home/brandon/homesoc-backups/`, outside Git. The directory is mode 700 and archives are mode 600. Archives contain private device and incident information. They are compressed, not encrypted; keep Windows copies in your private account storage.

The script deliberately excludes Flask session keys, HEC tokens, TLS private keys, detector/sender checkpoints, raw system logs, `.git`, and virtual environments. This is not a full-machine or full-Splunk backup. It does not collect `/etc` changes that have not been recorded in repository configuration, Splunk indexes/settings, router configuration, or the VM disk.

Keep a separate secure recovery method for credentials and keys. A lost Flask session key can be regenerated, which invalidates existing browser sessions. HEC token/certificate recovery or replacement is required to restore forwarding. Do not put those secrets into Git.

## Schedule and retention

`homesoc-backup.timer` runs daily around 03:15 in the Pi's system timezone, with up to five minutes of randomized delay. Persistent scheduling runs a missed job after the timer becomes active again. The service runs as `brandon`, using Python's standard library only.

The latest seven successful archives are retained. Manual runs count toward that limit, so seven archives are not necessarily seven distinct days. Retention touches only regular, user-owned archives matching the script's HomeSOC timestamp naming pattern. A failed backup/verification does not remove older successful archives. Concurrent runs are rejected by a lock.

```bash
systemctl list-timers homesoc-backup.timer --no-pager
sudo journalctl -u homesoc-backup.service -n 15 --no-pager
```

## Verification

Every backup is restored into a disposable temporary directory before being published. The check rejects unsafe archive paths, links, duplicate members, and excessive archive sizes, checks SHA-256 hashes, runs SQLite integrity/foreign-key checks, and reads the expected tables and row counts. Temporary restored copies are deleted when verification finishes. Live HomeSOC data is not overwritten.

To verify a retained archive again:

```bash
python3 scripts/backup_homesoc.py --verify /home/brandon/homesoc-backups/EXACT_ARCHIVE_NAME.tar.gz
```

The hashes detect accidental corruption; the manifest is not digitally signed. Successful verification confirms the stored data can be read and checked, not that an entire replacement Pi has been rebuilt.

## Off-Pi copy

An archive on the same SD card does not protect against losing that card. In Windows PowerShell, copy the retained archives into your account's Documents folder:

```powershell
New-Item -ItemType Directory -Force "$HOME\Documents\HomeSOC-backups" | Out-Null
scp 'brandon@192.168.8.165:/home/brandon/homesoc-backups/homesoc-*.tar.gz' "$HOME\Documents\HomeSOC-backups"
Get-ChildItem "$HOME\Documents\HomeSOC-backups\*.tar.gz"
```

This is a manual copy, not automated Windows backup or Windows retention. Repeat after meaningful changes, and manage Windows retention separately. Periodically check a copied archive after transferring it back to a temporary Pi path. No files are copied automatically by this service to Windows.

## Live recovery procedure

Do not extract an archive directly over a running HomeSOC installation.

1. Verify the selected archive using `--verify`.
2. Stop the dashboard and discovery/DHCP/SSH jobs that may write the data being restored. Take a backup of the current installation first if it is readable.
3. Extract the selected archive into a separate private directory. Review its manifest and recovered files.
4. Restore only the intended databases, evidence, or configuration. Ensure restored files belong to the service user. Do not blindly overwrite detector/sender checkpoints; determine where processing should resume.
5. Install the recorded Python dependencies if rebuilding an environment. Restore/reissue credentials securely and restore installed service configuration deliberately.
6. Start services and timers, then check inventory, cases, evidence, and forwarding. A separate end-to-end rebuild exercise is still needed to validate disaster recovery fully.

The supplied tool automates the temporary restore check, not live recovery. No live restore was performed during installation.
