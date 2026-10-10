# Resolve source alerts from the dashboard

## Workflow

1. Open an incident linked to an alert.
2. Record a resolution, select **Resolved**, and click **Save changes**.
3. When its source ticket is still open, click **Resolve source alert** in the Source alert closure section.
4. Confirm **Source status: resolved**, the resolution in the source evidence, and the timeline entry.

The action uses the saved resolution, not unsaved edits in the incident form. It changes only the source header's `status: open` to `status: resolved`, preserves the existing evidence, and appends the saved resolution with the incident number and UTC closure time. Ordinary incident saving still does not modify source evidence. Already-resolved tickets are left unchanged, so repeat requests do not append duplicate notes.

Closing an open detector ticket allows future qualifying activity to generate another ticket. Approving an unknown device is a separate inventory decision: mark it known if appropriate, or a later DHCP renewal can generate another unknown-device alert. Reopening an incident does not reopen its source ticket.

## File access and failure handling

The dashboard service user must own the source file and be able to write `evidence/alerts/`. Do not grant broad permissions to fix an error. Inspect the specific ownership first. This action rejects symlinks, hard links, paths outside the alert directory, malformed or ambiguous headers, invalid UTF-8, unsupported source statuses, and files larger than 128 KiB.

Requests require the existing session form token and POST. A per-directory advisory lock serializes dashboard closure requests. A temporary file is flushed before atomic replacement so detector readers do not see a partial ticket. The original mode bits are retained. A metadata check rejects changes detected while preparing the replacement; it does not coordinate external editors or all detector operations.

The Markdown update and SQLite audit entry are separate writes. If the source was closed but the audit insert fails, the dashboard reports that specifically; review the source and record a timeline note after addressing the database issue. Ordinary source write failure does not change the saved incident or add a closure note. No inventory database, detector cursor, or Splunk setting is changed.

This adds no authentication system. Existing LAN dashboard access controls remain in effect.

## Validation

Run from the project root using the dashboard virtual environment:

```bash
.venv/bin/python -m unittest discover -s dashboard/tests -v
```

Fifteen synthetic integration tests cover the existing incident behavior and source closure, including saved-resolution use, repeated requests, GET/CSRF rejection, missing files, malformed tickets, permissions/replacement errors, escaping, and evidence preservation. Tests use temporary files and databases, not live logs or evidence.

## Documentation follow-up

After deploying and validating, replace README/older setup-guide statements that source alerts can only be resolved manually with a link to this workflow. Manual editing remains available, but is no longer required for ordinary linked incident closure.
