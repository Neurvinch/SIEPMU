-- Legacy integration bridge. Legacy links (AFNET/AREN message switches, HF
-- radio, satellite) cannot carry end-to-end encryption, so traffic in
-- 'legacy' channels is sealed at rest by the HSM instead of by MLS.
CREATE TABLE bridges (
    name       TEXT PRIMARY KEY,           -- SPIFFE path is bridge/<name>
    public_key BYTEA NOT NULL,             -- composite ML-DSA-65+Ed25519
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ
);

CREATE TABLE bridge_routes (
    bridge     TEXT NOT NULL REFERENCES bridges(name) ON DELETE CASCADE,
    adapter    TEXT NOT NULL,              -- ax25 | acp127 | sbd
    address    TEXT NOT NULL,              -- callsign, routing indicator or IMEI
    channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    PRIMARY KEY (bridge, adapter, address)
);

-- Grow-only set of legacy messages; id is the content address of the signed
-- envelope so replays and store-and-forward retransmissions merge idempotently.
CREATE TABLE legacy_messages (
    id          TEXT PRIMARY KEY,
    channel_id  UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    direction   TEXT NOT NULL CHECK (direction IN ('inbound','outbound')),
    bridge      TEXT NOT NULL,
    adapter     TEXT NOT NULL,
    hlc         BIGINT NOT NULL,           -- hybrid logical clock of the origin
    origin      TEXT NOT NULL,
    destination TEXT NOT NULL,
    precedence  TEXT NOT NULL,
    classification SMALLINT NOT NULL,
    sealed_body BYTEA NOT NULL,
    sender_id   UUID REFERENCES users(id),
    status      TEXT NOT NULL DEFAULT 'delivered' CHECK (status IN ('delivered','queued','sent')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at     TIMESTAMPTZ
);
CREATE INDEX legacy_messages_channel ON legacy_messages(channel_id, hlc, id);
CREATE INDEX legacy_outbound_queue ON legacy_messages(bridge, adapter, created_at) WHERE status='queued';
