-- HomeSOC database schema
-- SQLite
--
-- This database is used to keep track of devices found on my home network.
-- The main idea is:
--   assets    = devices I have seen before
--   scans     = each time the Pi runs a discovery scan
--   sightings = which devices were seen during each scan
--
-- I am using MAC addresses to identify devices because IP addresses can change.
-- The is_known field lets me mark devices as reviewed/approved after I figure
-- out what they are.

PRAGMA foreign_keys = ON;

-- Devices found on the network
CREATE TABLE IF NOT EXISTS assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac             TEXT    NOT NULL UNIQUE,
    ip              TEXT,
    hostname        TEXT,
    vendor          TEXT,
    owner           TEXT,
    device_type     TEXT,
    notes           TEXT,
    is_known        INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT    NOT NULL,
    last_seen       TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_mac       ON assets(mac);
CREATE INDEX IF NOT EXISTS idx_assets_known     ON assets(is_known);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen);

-- Each scan the Raspberry Pi runs
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT    NOT NULL,
    finished_at     TEXT,
    duration_ms     INTEGER,
    host_count      INTEGER,
    scan_type       TEXT    NOT NULL,
    source          TEXT,
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at);

-- Tracks which devices were seen during each scan
CREATE TABLE IF NOT EXISTS sightings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    asset_id        INTEGER NOT NULL,
    ip              TEXT,
    seen_at         TEXT    NOT NULL,
    FOREIGN KEY (scan_id)  REFERENCES scans(id)  ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sightings_scan_id  ON sightings(scan_id);
CREATE INDEX IF NOT EXISTS idx_sightings_asset_id ON sightings(asset_id);
CREATE INDEX IF NOT EXISTS idx_sightings_seen_at  ON sightings(seen_at);
