# Stale device review

Use the Devices page's Last seen and Inventory view filters to separate recent devices from historical inventory. UNREVIEWED means the device has not been approved; it does not mean it just joined today.

For an offline device not seen for at least 30 days, open its host details, enter an archive reason, and choose Archive stale device. This removes it from the default inventory view. Select Archived only or Include archived to find it again, or use Return to active review on its details page.

Archiving is a display decision, not an identification or approval. It does not change `assets.is_known`, delete sightings or evidence, close tickets, or suppress DHCP alerts. If discovery changes its last-seen timestamp, it returns to active review automatically. A private MAC address can belong to your own device, but that alone is not evidence to approve it.

Archive state is an additive `device_archives` table in the existing private incident database. Existing HomeSOC backups include this database. Restoring visibility retains the latest reason; this is not a complete archive action history. Inventory counts include all devices, while active unreviewed excludes archived records.

POST actions use the existing session CSRF token. This feature does not add dashboard authentication. Keep the dashboard on your private network.
