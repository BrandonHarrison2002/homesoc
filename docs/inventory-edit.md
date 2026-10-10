# Edit inventory from the host page

Open Devices, select a host, and use Edit inventory to update owner, device type, notes, and review status. Choose Known / approved only after identifying the MAC. Approval requires owner, device type, and the identity checkbox when changing an unreviewed device to known. Save inventory writes the changes; Cancel edits reloads the saved record without writing. Blank owner, type, and notes are allowed for unreviewed records.

This edits only four columns in the existing inventory database: owner, device_type, notes, and is_known. It does not change the MAC, IP, discovery timestamps, sightings, archive visibility, incident status, or Markdown evidence. Known devices no longer qualify as unknown devices for the existing DHCP rule. Returning to Unreviewed allows future qualifying DHCP activity to alert again. Historical open alerts require separate investigation and closure.

This is an explicit decision in the web interface, not automatic approval from an incident resolution. Updates use a POST request and the existing CSRF token. Concurrent discovery changes to other columns are preserved because the UPDATE names only the editable columns. These edits have no separate audit timeline; record identification evidence in inventory notes and the linked incident. The dashboard remains a private LAN service without user authentication.

The dashboard service user needs write access to the existing inventory database and its directory. A failed database write reports an error and keeps submitted fields. No new database or dependency is created by this feature. Existing backups include the inventory changes.
