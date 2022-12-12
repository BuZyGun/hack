CREATE TABLE certs (
    id SERIAL PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    tls_version TEXT NOT NULL,
    pubkey_bit_size INTEGER NOT NULL,
    self_signed BOOLEAN NOT NULL,
    cipher TEXT NOT NULL,
    issuer TEXT NOT NULL,
    v_start BIGINT NOT NULL,
    v_end BIGINT NOT NULL,
    v_length BIGINT NOT NULL
);

CREATE TABLE hosts (
    id SERIAL PRIMARY KEY,
    host CIDR NOT NULL,
    port INTEGER NOT NULL,
    cert_id INTEGER NOT NULL,
    CONSTRAINT fk_cert FOREIGN KEY(cert_id) REFERENCES certs(id) ON DELETE CASCADE,
    UNIQUE(host, port)
);