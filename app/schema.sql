-- Idempotent schema. Safe to re-run on every start.
CREATE TABLE IF NOT EXISTS proxies (
    id                SERIAL PRIMARY KEY,
    label             TEXT NOT NULL DEFAULT '',
    provider          TEXT NOT NULL DEFAULT 'other',
    country           TEXT NOT NULL DEFAULT 'US',
    region            TEXT NOT NULL DEFAULT '',
    protocol          TEXT NOT NULL DEFAULT 'socks5' CHECK (protocol IN ('http', 'socks5')),
    host              TEXT NOT NULL,
    port              INT  NOT NULL,
    username          TEXT NOT NULL DEFAULT '',
    password          TEXT NOT NULL DEFAULT '',
    source            TEXT NOT NULL DEFAULT 'manual',
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    status            TEXT NOT NULL DEFAULT 'unknown',
    fail_streak       INT NOT NULL DEFAULT 0,
    ok_streak         INT NOT NULL DEFAULT 0,
    http_ok           BOOLEAN,
    smtp_ok           BOOLEAN,
    last_check_at     TIMESTAMPTZ,
    last_ok_at        TIMESTAMPTZ,
    last_latency_ms   INT,
    smtp_latency_ms   INT,
    last_error        TEXT,
    exit_ip           TEXT,
    recheck           BOOLEAN NOT NULL DEFAULT FALSE,
    status_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_sync_at TIMESTAMPTZ,
    notes             TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (host, port)
);
CREATE INDEX IF NOT EXISTS proxies_status ON proxies (status) WHERE enabled;

CREATE TABLE IF NOT EXISTS checks (
    id              BIGSERIAL PRIMARY KEY,
    proxy_id        INT NOT NULL REFERENCES proxies (id) ON DELETE CASCADE,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    ok              BOOLEAN NOT NULL,
    http_ok         BOOLEAN,
    smtp_ok         BOOLEAN,
    latency_ms      INT,
    smtp_latency_ms INT,
    error           TEXT,
    exit_ip         TEXT
);
CREATE INDEX IF NOT EXISTS checks_proxy_ts ON checks (proxy_id, ts DESC);
CREATE INDEX IF NOT EXISTS checks_ts ON checks (ts);

CREATE TABLE IF NOT EXISTS reports (
    id       BIGSERIAL PRIMARY KEY,
    proxy_id INT REFERENCES proxies (id) ON DELETE CASCADE,
    ts       TIMESTAMPTZ NOT NULL DEFAULT now(),
    source   TEXT NOT NULL DEFAULT '',
    error    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS reports_proxy_ts ON reports (proxy_id, ts DESC);

CREATE TABLE IF NOT EXISTS events (
    id       BIGSERIAL PRIMARY KEY,
    ts       TIMESTAMPTZ NOT NULL DEFAULT now(),
    proxy_id INT REFERENCES proxies (id) ON DELETE SET NULL,
    kind     TEXT NOT NULL,
    message  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts DESC);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Apps: each app is assigned (at most) one proxy; a proxy serves at most one app.
CREATE TABLE IF NOT EXISTS apps (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    proxy_id    INT REFERENCES proxies (id) ON DELETE SET NULL,
    notes       TEXT NOT NULL DEFAULT '',
    assigned_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS apps_proxy_unique ON apps (proxy_id) WHERE proxy_id IS NOT NULL;

ALTER TABLE events ADD COLUMN IF NOT EXISTS app_id INT REFERENCES apps (id) ON DELETE SET NULL;

-- Lifecycle (set by people): ready = unused, active = used by a use case, suspended = burned.
-- deleted_at = removed at the provider (GCP etc.); monitoring stops, row kept as a record.
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS lifecycle TEXT NOT NULL DEFAULT 'ready';
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ;
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS last_usecase TEXT NOT NULL DEFAULT '';

-- Dashboard users. The first admin is created from ADMIN_USER / ADMIN_PASS_HASH in the env file.
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    pass_hash     TEXT NOT NULL,
    is_admin      BOOLEAN NOT NULL DEFAULT FALSE,
    pw_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE events ADD COLUMN IF NOT EXISTS actor TEXT NOT NULL DEFAULT '';

-- v3: manual-only workflow. to_delete status, when the status last changed, and which use cases
-- a proxy was suspended on (so it isn't given to the same use case again).
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS lifecycle_at TIMESTAMPTZ;
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS suspended_for TEXT NOT NULL DEFAULT '';
UPDATE proxies SET lifecycle_at = COALESCE(suspended_at, created_at) WHERE lifecycle_at IS NULL;

-- v4: "#" is a stored, editable number (matches the proxy sheet). New rows get max + 1.
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS seq INT;
UPDATE proxies SET seq = s.rn FROM (SELECT id, row_number() OVER (ORDER BY id) AS rn FROM proxies) s
 WHERE proxies.id = s.id AND proxies.seq IS NULL
   AND NOT EXISTS (SELECT 1 FROM proxies WHERE seq IS NOT NULL);
CREATE OR REPLACE FUNCTION proxies_set_seq() RETURNS trigger AS $$
BEGIN
  IF NEW.seq IS NULL THEN
    SELECT COALESCE(max(seq), 0) + 1 INTO NEW.seq FROM proxies;
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS proxies_seq ON proxies;
CREATE TRIGGER proxies_seq BEFORE INSERT ON proxies FOR EACH ROW EXECUTE FUNCTION proxies_set_seq();
UPDATE proxies SET seq = (SELECT COALESCE(max(seq), 0) FROM proxies) + id WHERE seq IS NULL;

-- v5 (1.1.0): one row per outage of a proxy (went down -> recovered). Kept forever.
CREATE TABLE IF NOT EXISTS incidents (
    id          BIGSERIAL PRIMARY KEY,
    proxy_id    INT NOT NULL REFERENCES proxies (id) ON DELETE CASCADE,
    started_at  TIMESTAMPTZ NOT NULL,
    ended_at    TIMESTAMPTZ,
    reason      TEXT NOT NULL DEFAULT 'other',
    error       TEXT NOT NULL DEFAULT '',
    last_error  TEXT NOT NULL DEFAULT '',
    usecase     TEXT NOT NULL DEFAULT '',
    lifecycle   TEXT NOT NULL DEFAULT '',
    end_note    TEXT NOT NULL DEFAULT '',
    backfilled  BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS incidents_started ON incidents (started_at DESC);
CREATE INDEX IF NOT EXISTS incidents_proxy ON incidents (proxy_id, started_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS incidents_one_open ON incidents (proxy_id) WHERE ended_at IS NULL;
-- the same outage can never be recorded twice (also protects the one-time backfill)
CREATE UNIQUE INDEX IF NOT EXISTS incidents_proxy_start ON incidents (proxy_id, started_at);
CREATE INDEX IF NOT EXISTS events_kind_ts ON events (kind, ts DESC);
CREATE INDEX IF NOT EXISTS events_proxy_ts ON events (proxy_id, ts DESC);
-- checks taken during a "mass failure" round (our own network / the check target was down) — excluded from flaky stats
ALTER TABLE checks ADD COLUMN IF NOT EXISTS mass BOOLEAN NOT NULL DEFAULT FALSE;
