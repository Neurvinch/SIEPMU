-- SIEPMU-SX data ring schema. Mission content is never stored in plaintext:
-- message bodies are MLS / Double Ratchet ciphertext produced on clients, and
-- file chunks are client-side ciphertext additionally sealed at rest under a
-- per-file DEK wrapped by an HSM-resident KEK.

CREATE TABLE units (
    code        TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    parent_code TEXT REFERENCES units(code)
);

CREATE TABLE users (
    id                UUID PRIMARY KEY,
    service_number    TEXT NOT NULL UNIQUE,
    full_name         TEXT NOT NULL,
    rank              TEXT NOT NULL,
    unit_code         TEXT NOT NULL REFERENCES units(code),
    clearance         SMALLINT NOT NULL CHECK (clearance BETWEEN 0 AND 4),
    compartments      TEXT[] NOT NULL DEFAULT '{}',
    roles             TEXT[] NOT NULL DEFAULT '{member}',
    status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','suspended')),
    enroll_code_hash  BYTEA,
    enroll_expires_at TIMESTAMPTZ,
    webauthn_handle   BYTEA NOT NULL UNIQUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    suspended_reason  TEXT
);

CREATE TABLE webauthn_credentials (
    id              BYTEA PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_json JSONB NOT NULL,
    aaguid          BYTEA,
    attestation_fmt TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);

CREATE TABLE devices (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    jkt          TEXT NOT NULL UNIQUE,
    public_jwk   JSONB NOT NULL,
    cert_der     BYTEA,
    cert_serial  TEXT,
    label        TEXT NOT NULL,
    user_agent   TEXT NOT NULL,
    managed      BOOLEAN NOT NULL DEFAULT false,
    approved_by  UUID REFERENCES users(id),
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','revoked')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ
);
CREATE INDEX devices_user ON devices(user_id);

CREATE TABLE sessions (
    id                 UUID PRIMARY KEY,
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id          UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    auth_method        TEXT NOT NULL,
    mfa_strength       SMALLINT NOT NULL,
    refresh_hash       BYTEA NOT NULL,
    ip                 TEXT NOT NULL,
    lat                DOUBLE PRECISION,
    lon                DOUBLE PRECISION,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    revoked_reason     TEXT,
    breakglass_id      UUID
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE breakglass_requests (
    id           UUID PRIMARY KEY,
    requester_id UUID NOT NULL REFERENCES users(id),
    reason       TEXT NOT NULL,
    grant_clearance SMALLINT NOT NULL,
    grant_compartments TEXT[] NOT NULL DEFAULT '{}',
    approvals    UUID[] NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','expired','rejected','reviewed')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    review_note  TEXT,
    reviewed_by  UUID REFERENCES users(id)
);

CREATE TABLE channels (
    id             UUID PRIMARY KEY,
    name           TEXT NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('group','direct','legacy')),
    classification SMALLINT NOT NULL CHECK (classification BETWEEN 0 AND 4),
    compartments   TEXT[] NOT NULL DEFAULT '{}',
    unit_code      TEXT NOT NULL REFERENCES units(code),
    created_by     UUID NOT NULL REFERENCES users(id),
    epoch          BIGINT NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE channel_members (
    channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner','member')),
    added_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (channel_id, user_id)
);

-- Public MLS KeyPackages (RFC 9420 §10). One is consumed per group join.
CREATE TABLE key_packages (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    cipher_suite INT NOT NULL,
    body        BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at TIMESTAMPTZ
);
CREATE INDEX key_packages_free ON key_packages(user_id) WHERE consumed_at IS NULL;

-- MLS delivery service log. Handshake messages are totally ordered per group
-- by seq; at most one commit is accepted per epoch.
CREATE TABLE mls_messages (
    channel_id   UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    seq          BIGINT NOT NULL,
    sender_id    UUID NOT NULL REFERENCES users(id),
    epoch        BIGINT NOT NULL,
    content_type TEXT NOT NULL CHECK (content_type IN ('application','commit','welcome','proposal')),
    recipient_id UUID REFERENCES users(id),
    body         BYTEA NOT NULL,
    body_hash    BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (channel_id, seq)
);
CREATE UNIQUE INDEX mls_one_commit_per_epoch ON mls_messages(channel_id, epoch) WHERE content_type = 'commit';
CREATE INDEX mls_welcome_recipient ON mls_messages(recipient_id) WHERE content_type = 'welcome';

-- Double Ratchet prekey bundles (X-Wing hybrid KEM prekeys signed by the
-- device's ML-DSA-65 identity key).
CREATE TABLE dr_identities (
    user_id        UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    device_id      UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    identity_sig_pub BYTEA NOT NULL,
    signed_prekey  BYTEA NOT NULL,
    signed_prekey_id INT NOT NULL,
    signed_prekey_sig BYTEA NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE dr_one_time_prekeys (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    prekey_id  INT NOT NULL,
    public_key BYTEA NOT NULL,
    consumed_at TIMESTAMPTZ,
    PRIMARY KEY (user_id, prekey_id)
);
CREATE TABLE dr_messages (
    id           BIGSERIAL PRIMARY KEY,
    channel_id   UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    sender_id    UUID NOT NULL REFERENCES users(id),
    recipient_id UUID NOT NULL REFERENCES users(id),
    envelope     BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ
);
CREATE INDEX dr_messages_recipient ON dr_messages(recipient_id, id);

CREATE TABLE files (
    id               UUID PRIMARY KEY,
    owner_id         UUID NOT NULL REFERENCES users(id),
    channel_id       UUID REFERENCES channels(id) ON DELETE SET NULL,
    classification   SMALLINT NOT NULL,
    compartments     TEXT[] NOT NULL DEFAULT '{}',
    chunk_size       INT NOT NULL,
    chunk_count      INT NOT NULL,
    total_size       BIGINT NOT NULL,
    chunk_hashes     BYTEA[] NOT NULL,   -- BLAKE3 of each client ciphertext chunk
    manifest_hash    BYTEA NOT NULL,     -- BLAKE3 over the ordered chunk hashes
    kek_id           TEXT NOT NULL,
    wrapped_dek      BYTEA,              -- NULL after cryptographic erasure
    status           TEXT NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading','complete','erased')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    erased_at        TIMESTAMPTZ,
    erased_by        UUID REFERENCES users(id)
);

-- Signed append-only audit log (RFC 6962 Merkle tree).
CREATE TABLE audit_leaves (
    idx        BIGINT PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL,
    entry      JSONB NOT NULL,
    entry_raw  BYTEA NOT NULL,
    leaf_hash  BYTEA NOT NULL
);
CREATE TABLE audit_nodes (
    level INT NOT NULL,
    idx   BIGINT NOT NULL,
    hash  BYTEA NOT NULL,
    PRIMARY KEY (level, idx)
);
CREATE TABLE audit_tree_heads (
    size        BIGINT PRIMARY KEY,
    root_hash   BYTEA NOT NULL,
    ts          TIMESTAMPTZ NOT NULL,
    signature   BYTEA NOT NULL
);

-- Monitoring fabric.
CREATE TABLE sec_events (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL,
    source     TEXT NOT NULL,
    kind       TEXT NOT NULL,
    severity   SMALLINT NOT NULL,
    user_id    UUID,
    ip         TEXT,
    attack_ids TEXT[] NOT NULL DEFAULT '{}',
    summary    TEXT NOT NULL,
    data       JSONB NOT NULL
);
CREATE INDEX sec_events_ts ON sec_events(ts DESC);
CREATE INDEX sec_events_user ON sec_events(user_id, ts DESC);

CREATE TABLE incidents (
    id           UUID PRIMARY KEY,
    rule_id      TEXT NOT NULL,
    title        TEXT NOT NULL,
    attack_ids   TEXT[] NOT NULL,
    severity     SMALLINT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','contained','resolved','false_positive')),
    user_id      UUID REFERENCES users(id),
    ip           TEXT,
    unit_code    TEXT,
    event_ids    BIGINT[] NOT NULL,
    actions      JSONB NOT NULL DEFAULT '[]',
    assignee_id  UUID REFERENCES users(id),
    notes        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    dedup_key    TEXT NOT NULL
);
CREATE INDEX incidents_open ON incidents(status, created_at DESC);
CREATE UNIQUE INDEX incidents_dedup_open ON incidents(dedup_key) WHERE status = 'open';

CREATE TABLE blocked_ips (
    ip         TEXT PRIMARY KEY,
    reason     TEXT NOT NULL,
    incident_id UUID REFERENCES incidents(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE ueba_baselines (
    user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    feature   TEXT NOT NULL,
    mean      DOUBLE PRECISION NOT NULL,
    m2        DOUBLE PRECISION NOT NULL,   -- Welford running variance accumulator
    n         BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, feature)
);

CREATE TABLE notifications (
    id         BIGSERIAL PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    body       TEXT NOT NULL,
    ref_id     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at    TIMESTAMPTZ
);

-- RED/BLACK cross-domain guard release workflow.
CREATE TABLE guard_releases (
    id            UUID PRIMARY KEY,
    direction     TEXT NOT NULL CHECK (direction IN ('black_to_red','red_to_black')),
    filename      TEXT NOT NULL,
    classification SMALLINT NOT NULL,
    content_type  TEXT NOT NULL,
    size          BIGINT NOT NULL,
    sha384        BYTEA NOT NULL,
    sealed_body   BYTEA NOT NULL,   -- AES-256-GCM under a KMS-wrapped DEK
    wrapped_dek   BYTEA NOT NULL,
    kek_id        TEXT NOT NULL,
    justification TEXT NOT NULL,
    submitted_by  UUID NOT NULL REFERENCES users(id),
    approvals     UUID[] NOT NULL DEFAULT '{}',
    rejected_by   UUID REFERENCES users(id),
    filter_report JSONB NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','blocked','approved','transferred','rejected')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    transferred_at TIMESTAMPTZ
);

-- Legacy bridge ingestion (dedup of store-and-forward retransmissions).
CREATE TABLE bridge_messages (
    id          TEXT PRIMARY KEY,
    adapter     TEXT NOT NULL,
    channel_id  UUID REFERENCES channels(id),
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    verdict     TEXT NOT NULL
);

CREATE TABLE service_keys (
    name        TEXT PRIMARY KEY,
    algorithm   TEXT NOT NULL,
    public_key  BYTEA NOT NULL,
    sealed_seed BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
