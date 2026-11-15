# Protocols and identity binding

This page lists the wire formats a miner speaks. `deployment.v4` is the only
assignment ticket and receipt version; earlier versions are not accepted by
any Go or Python decoder.

Messages that embed a ticket or receipt (`deploy`, `deploy-response`,
`status-response`, `bridge-assign`) are `subnet-synapse.v3`; the other
messages (capabilities, status and deactivate requests, registration, chain
state) stay `subnet-synapse.v2`; the endpoint-incarnation-bound health
observation is the message-scoped `subnet-synapse.v3`; service-key
attestations are `service-binding.v2`. Unknown fields are rejected by both
the Pydantic and Go bridge decoders.

## Bittensor v11 transport

Bittensor v11 no longer ships the legacy Axon/Dendrite/Synapse networking
classes. The semantic Synapses are strict Pydantic JSON contracts over pinned
HTTPS in live mode:

- `CapabilitiesSynapse`: challenge-bearing miner capabilities and hotkey-signed Go service-key binding
- `DeploySynapseV3`: current block, authenticated validator identity/binding, and one exact Go-signed `deployment.v4` ticket
- `StatusSynapse`: endpoint-incarnation status owned by the assigning validator
- `DeactivateSynapse`: idempotent endpoint cleanup owned by the assigning validator

A miner receives `deployment.v4` work only when its capability feature list
advertises `organic-oci-v1`, which the Go agent reports only when its verified
OCI runtime is configured.

Remote requests use the SDK's `bittensor.http_auth` btauth/1 signatures. The
signed material binds the sender hotkey, receiver hotkey, nonce/timestamp,
HTTP method, path, and exact body. Miners additionally require a uniquely
registered metagraph hotkey, validator permit, configured minimum TAO stake,
and rate/priority admission. The metagraph `active` bit is not a
serving-authentication gate. HTTP is available only when both sides
explicitly select the local/mock policy; live startup never silently
downgrades.

Retries obtain a fresh btauth nonce while preserving the semantic
request/ticket identity. Redirects and environment proxies are disabled. The
Go agent returns a cached signed ready result only for the same durable
endpoint incarnation; a different assignment nonce cannot reuse it.

### TLS identity

The signed endpoint enrollment supplies only a numeric IP and port. The miner
serves a self-issued, non-CA leaf certificate (`CA:FALSE`) whose IP SAN is the
enrolled public IP (`scripts/manage-miner-tls.sh issue`). Validators pin that
exact leaf: the hotkey-signed capability response must contain the lowercase
SHA-256 fingerprint of the leaf the connection presented, and every later
deploy, status, deactivate and runtime request verifies the same pin before
writing a body. No public CA is required. Certificate DER is never logged;
private-key material never leaves the miner. After a certificate rotation,
validators re-pin on the next capability handshake.

## Hotkey-signed service binding

A capability response signs canonical JSON with the Bittensor hotkey. The binding includes:

- role (`miner`), network, netuid, hotkey, and current UID when known;
- the persistent Go Ed25519 service public key;
- transport identity: `https` plus the canonical 64-lowercase-hex SHA-256
  leaf fingerprint;
- monotonic generation and block validity window;
- the validator's unpredictable capability challenge; and
- the hotkey signature.

The binding does not make the Go key a Bittensor key. It proves that the
registered hotkey authorizes that specific local Go service key for this
subnet and block window. Accepted bindings are persisted; a generation
rollback or a same-generation change of service key, transport or certificate
is rejected, so keep the service key file persistent.

For miner capabilities, let `R` be the authenticated request's `chain_block`
and `M` and `T` be the block and tempo of the miner's metagraph snapshot.
Requests outside `M - 2 <= R <= M + 2` are refused. The miner signs a validity
start of `min(M, R)`, generation `M + 1`, and expiry `M + max(2*T, 12)`.
Fresh challenges at the same miner snapshot change neither generation nor
expiry.

Registrations forwarded to the Go control plane are `miner-registration.v2`,
or `miner-registration.v3` (adding the handshake's normalized capability
`features`). Capability-gated work (for example `organic-static-v1`) needs the
feature in the capability response.

## Bound assignment ticket

The validator Go service signs JSON with the `signature` field blank. The
ticket contains the deployment fields plus `subnet`:

- network and netuid;
- validator and miner hotkeys;
- miner UID when the metagraph provides it;
- normalized assignment-time HTTPS axon, transport, and exact accepted leaf pin;
- chain issuance block, derived epoch, and block expiry;
- validator Go service public key; and
- miner Go service public key learned in the hotkey-signed handshake.

It also binds deployment ID, replacement generation, artifact digest, manifest
key, destination miner, route, unpredictable assignment nonce, OCI workload,
`small-v1` resources, app health fields, and wall-clock issue/expiry.

The miner axon checks the btauth caller and current metagraph, UID,
network/netuid, epoch derivation, block window, and that the ticket pin equals
the certificate it is currently serving. The Go agent then verifies the
validator's Ed25519 ticket signature, exact authenticated caller/miner
identity, exact UID presence/value, current block, validator service key, its
own miner service key, HTTPS axon, and configured pin before downloading
anything. Network-facing paths reject every non-`deployment.v4` ticket,
missing pins, and pin downgrades.

Go emits RFC3339Nano timestamps. Python preserves signed ticket and receipt
timestamps as strings: coercing them to Python `datetime` would truncate
nanoseconds and invalidate an otherwise correct Go signature.

### Route domains

A route host is `<route_label>.ms.computer`, and the route label must be an
unreserved generated site label `<slug>-<l><dddd>` (one lowercase letter, four
digits). A ticket or receipt whose route host is not its deployment ID's host
is refused (`route_host_mismatch`, `receipt_identity_invalid`);
`organic.ValidRouteHost` and `organic_contracts.valid_route_host` are the
shared rule.

## Receipt

Receipts bind deployment, generation, assignment nonce, miner, replica ID,
endpoint ID, image digest, manifest key, route host, lifecycle
stage/timestamps, and the exact `subnet` value copied from the ticket. The
miner Go service signs them with its bound service key. Every field must match
the ticket it answers; runtime/container IDs never cross this boundary.
Lifecycle timestamps are diagnostic.

## Miner replay and recovery

The miner agent durably binds each assignment nonce and endpoint incarnation to
the exact signed ticket and receipt. A replay with different signed identity
fails closed. After a miner-agent restart, retained local runtime mappings are
recovered or cleaned before readiness.

## Organic edge transport

The edge forwards ordinary app traffic: methods `GET, HEAD, POST, PUT, PATCH,
DELETE, OPTIONS` (others `405`), byte-exact escaped path and raw query
(printable ASCII, else `400`), request bodies fully buffered up to 1 MiB
(`413`), and responses capped at 16 MiB of encoded bytes (`502`).
Content-Encoding is end to end: no hop adds `Accept-Encoding` or decodes a
response. Every client `X-Ms-*`, `CF-*`, `X-Trusted-*`, `Forwarded` and
`X-Forwarded-*` header is dropped; the app receives exactly one
`X-Forwarded-For`, `X-Forwarded-Host` and `X-Forwarded-Proto`,
`Host: <route_host>` (from the signed ticket at the miner), and every other
end-to-end header. App responses keep status, cookies, redirects and
encodings; app-supplied `X-Ms-*` headers are removed. There is no automatic
retry of a failed upstream request.

Every request to a network-bound replica carries `X-Ms-Edge-Authorization`
(`edge-runtime-request.v1`, signed by the validator Go service key). The miner
agent verifies it against the addressed endpoint's retained ticket, rejects a
reused nonce inside the freshness window, and answers `401` without contacting
the container on any failure. The Python axon forwards the header verbatim and
refuses a request without exactly one such header before reading its body.
The Go agent routes the runtime prefix outside `ServeMux`, whose path
cleaning would redirect `//` or `/./` instead of forwarding them. Every other
`X-Ms-*` request header is stripped before the app is contacted; see
[miner-oci-runtime.md](miner-oci-runtime.md#runtime-ingress).

## Loopback bridge contract

The Python↔Go bridge uses headers:

```text
X-Ms-Bridge-Version: 1
X-Ms-Bridge-Timestamp: <Unix nanoseconds>
X-Ms-Bridge-Nonce: <random value>
X-Ms-Bridge-Signature: HMAC-SHA256(...)
```

The signature covers `ms-bridge/1`, timestamp, nonce, uppercase method,
escaped path plus query, and SHA-256 body digest. Default freshness is 10
seconds with two seconds of future skew. Bodies and responses are capped at
one MiB. Errors use a stable envelope:

```json
{"error":{"code":"identity_mismatch","message":"...","retryable":false}}
```

Secrets must be at least 32 bytes, come from external file/env configuration,
and differ per host.

## Artifact layout

```text
v1/blobs/sha256/<layer digest>
v1/manifests/<image digest>.json
```

Fetch requires the manifest key to be the canonical key for the signed image
digest. It rejects unknown/trailing/non-canonical manifest JSON, unsupported
schema/media types, malformed digests, and invalid layer counts before pulling
layers. The manifest identity and every downloaded layer are rehashed, and
every layer length must equal its signed manifest size. Any mismatch fails the
assignment closed before runtime creation. Miners read artifacts through the
signed pull gateway (`--artifact-backend pull`) and need no delete or write
permission.
