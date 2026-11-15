# Copyright (c) 2026 Ms. Computer. All rights reserved.
# SPDX-License-Identifier: LicenseRef-MsComputer-Miner
"""Public miner and validator wire contracts.

This module owns the artifact manifest, deployment.v4 ticket and receipt,
subnet-synapse.v3 envelopes, the edge-to-miner signed request, and verifier
documents. Customer API, scheduler and edge backend models are private.

Every string is printable ASCII. Documents are rendered as canonical JSON
(sorted keys, ``,``/``:`` separators, ASCII escaping, no NaN) and carry one
trailing newline on disk. Timestamps are canonical Go RFC3339Nano UTC strings
(``Z`` suffix, no trailing fractional zeros) so that Go ``time.Time`` values
round-trip byte for byte. The Go mirror lives in ``pkg/organic``,
``pkg/protocol`` (``deployment.v4``) and ``pkg/artifact``
(manifest v2); shared fixtures in ``contracts/`` pin both.

This module has no clock, network, file, process, environment, wallet or
randomness capability. Ed25519 helpers only verify caller-supplied bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Annotated, Final, Literal, Self

from pydantic import AfterValidator, BaseModel, Field, StringConstraints, model_validator

from mscomputer_subnet.contract_codec import (
    StrictFrozenModel,
    canonical_json,
    digest,
    model_document,
    parse_model,
    revalidate,
    verify_model_digest,
)
from mscomputer_subnet.protocol import ServiceKeyBinding as ServiceKeyBinding
from mscomputer_subnet.protocol import SubnetBinding, _rfc3339nano_instant

SCHEMA_PREFIX: Final = "ms.computer/mscomputer-subnet/"
PLATFORM: Final = "linux/amd64"
RUNTIME_PROFILE: Final = "small-v1"
WORKLOAD_KIND: Final = "oci-image-v1"
TICKET_VERSION: Final = "deployment.v4"
SYNAPSE_VERSION: Final = "subnet-synapse.v3"
SCORING_DISPOSITION: Final = "organic_v1"
CAPABILITY_FEATURE: Final = "organic-oci-v1"
REPLICAS: Final = 3
HEALTH_FAILURE_LIMIT: Final = 2

OCI_MANIFEST_MEDIA_TYPE: Final = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE: Final = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_TAR: Final = "application/vnd.oci.image.layer.v1.tar"
OCI_LAYER_TAR_GZIP: Final = "application/vnd.oci.image.layer.v1.tar+gzip"
ARTIFACT_MANIFEST_MEDIA_TYPE: Final = "application/vnd.mscomputer.manifest.v2+json"
MAX_ARTIFACT_MANIFEST_BYTES: Final = 1 << 20
MAX_UNCOMPRESSED_BYTES: Final = 1 << 30
MAX_LAYERS: Final = 127
MAX_INT: Final = (1 << 63) - 1

#: ``small-v1`` resource vocabulary; a ticket's ``resources`` must equal it.
SMALL_V1_RESOURCES: Final = {
    "cpu_millis": 1_000,
    "memory_mb": 1_024,
    "disk_mb": 2_048,
    "pids": 256,
    "tmpfs_mb": 64,
}

EDGE_RUNTIME_REQUEST_DOMAIN: Final = (
    b"ms.computer/mscomputer-subnet/edge-runtime-request/v1/ed25519"
)

EDGE_AUTHORIZATION_HEADER: Final = "X-Ms-Edge-Authorization"
# The edge's signed pull of a miner's response-receipt batches
# (pkg/organic.ReceiptPullAuthorizationHeader); the agent verifies it.
RECEIPT_PULL_AUTHORIZATION_HEADER: Final = "X-Ms-Receipt-Pull-Authorization"
# The edge request id (32 hex: the edge-runtime-request nonce, the response
# receipt leaf's edge_request_id) the edge returns on the client leg of an
# authorized check (pkg/organic.EdgeRequestIDHeader). Never sent to a miner.
EDGE_REQUEST_ID_HEADER: Final = "X-Ms-Edge-Request-Id"
AGENT_ENDPOINT_UNAVAILABLE_HEADER: Final = "X-Ms-Agent-Endpoint-State"
AGENT_ENDPOINT_UNAVAILABLE_VALUE: Final = "unavailable-v1"
EDGE_REQUEST_FRESHNESS_NANOS: Final = 10_000_000_000
EDGE_REQUEST_FUTURE_SKEW_NANOS: Final = 2_000_000_000
RESERVED_ROUTE_PREFIXES: Final = ("syn-", "readiness-probe", "xn--")
#: ``<slug>-<l><dddd>``: the only labels a tenant domain admits.
_PUBLIC_SITE_LABEL: Final = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*-[a-z][0-9]{4}")


# --------------------------------------------------------------------------
# Vocabulary (contract section 4)
# --------------------------------------------------------------------------

Printable = Annotated[str, StringConstraints(pattern=r"^[\x20-\x7e]*$")]
Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
Hex32 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
Hex64 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
HexSignature = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$")]
Hotkey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9]{1,128}$")]
Count = Annotated[int, Field(ge=0, le=MAX_INT)]
PositiveCount = Annotated[int, Field(ge=1, le=MAX_INT)]
Port = Annotated[int, Field(ge=1, le=65_535)]
UID = Annotated[int, Field(ge=0, le=65_535)]
EndpointID = Annotated[str, StringConstraints(min_length=3, max_length=320)]
_DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DNSLabel = Annotated[str, StringConstraints(max_length=63, pattern=rf"^{_DNS_LABEL}$")]
Hostname = Annotated[
    str, StringConstraints(max_length=253, pattern=rf"^{_DNS_LABEL}(?:\.{_DNS_LABEL})+$")
]


def _unreserved_label(value: str) -> str:
    if value.startswith(RESERVED_ROUTE_PREFIXES):
        raise ValueError("route_label_reserved")
    return value


#: ``requested_name`` and ``route_label`` (= subnet ``deployment_id``).
RouteLabel = Annotated[DNSLabel, AfterValidator(_unreserved_label)]


def _go_utc_timestamp(value: str) -> str:
    if not value.endswith("Z"):
        raise ValueError("timestamp_not_utc")
    _rfc3339nano_instant(value)
    return value


#: Canonical Go RFC3339Nano UTC timestamp, e.g. ``2026-09-26T00:14:06.120418Z``.
Timestamp = Annotated[
    str,
    StringConstraints(
        pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$"
    ),
    AfterValidator(_go_utc_timestamp),
]

# Health path: absolute, not ``//``-prefixed, no ``?``/``#``/space/control bytes.
HealthPath = Annotated[
    str,
    StringConstraints(
        max_length=1_024,
        pattern=r"^/(?:[\x21\x22\x24-\x2e\x30-\x3e\x40-\x7e][\x21\x22\x24-\x3e\x40-\x7e]*)?$",
    ),
]
ResponseMarker = Annotated[str, StringConstraints(pattern=r"^[\x20-\x7e]{1,256}$")]
ManifestKey = Annotated[str, StringConstraints(pattern=r"^v1/manifests/[0-9a-f]{64}\.json$")]


#: Customer-facing API error codes named by the contract. The wire type stays
#: open UPPER_SNAKE so that D8 quota codes can be added without a version bump.

Attribution = Literal["application", "miner", "edge", "unknown"]
#: Replica codes that count toward the two-distinct-miner application rule.
ReceiptErrorCode = Literal[
    "artifact_fetch_failed",
    "artifact_verify_failed",
    "image_load_failed",
    "image_identity_mismatch",
    "container_create_failed",
    "container_exited",
    "health_timeout",
    "health_unexpected_status",
    "health_marker_missing",
    "resource_exhausted",
    "deactivated",
    "internal",
]
RECEIPT_ERROR_ATTRIBUTION: Final[dict[str, str]] = {
    "artifact_fetch_failed": "miner",
    "artifact_verify_failed": "miner",
    "image_load_failed": "miner",
    "image_identity_mismatch": "miner",
    "container_create_failed": "miner",
    "container_exited": "application",
    "health_timeout": "application",
    "health_unexpected_status": "application",
    "health_marker_missing": "application",
    "resource_exhausted": "miner",
    "deactivated": "none",
    "internal": "miner",
}


def manifest_key(artifact_digest: str) -> str:
    return f"v1/manifests/{artifact_digest.removeprefix('sha256:')}.json"


#: Common public suffixes of more than one label (mirrors Go
#: ``multiLabelPublicSuffixes``). A tenant domain may not be one of them (nor
#: any single label), and ``registrable_domain`` keeps one more label beneath.
#: It mirrors the infra list less one tunnel-provider suffix the public
#: boundary guard forbids.
MULTI_LABEL_PUBLIC_SUFFIXES: Final = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
        "com.au", "net.au", "org.au", "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp",
        "com.br", "com.cn", "com.hk", "com.sg", "com.tw", "com.mx", "com.tr",
        "co.in", "co.kr", "co.za", "co.il", "com.ar", "com.pl", "com.ua",
        "github.io", "gitlab.io", "pages.dev", "workers.dev", "herokuapp.com",
        "netlify.app", "vercel.app", "web.app", "firebaseapp.com", "appspot.com",
        "cloudfront.net", "azurewebsites.net", "blogspot.com",
    }
)  # fmt: skip
_HOSTNAME: Final = re.compile(rf"{_DNS_LABEL}(?:\.{_DNS_LABEL})+")


#: The retired legacy edge domain; it admits nothing.
RETIRED_ROUTE_DOMAIN: Final = "on.ms.computer"


def validate_tenant_domain(domain: object) -> str:
    """Return the configured tenant site domain (the DNS suffix under which
    generated ``<label>.<domain>`` hosts serve user content) or raise
    ``ValueError``: a lowercase hostname of at least two labels, no wildcard,
    not a public suffix by itself. There is no default; empty fails.
    """

    if not isinstance(domain, str) or domain == "":
        raise ValueError("tenant_domain_not_configured")
    if "*" in domain:
        raise ValueError("tenant_domain_wildcard")
    if len(domain) > 253 or _HOSTNAME.fullmatch(domain) is None:
        raise ValueError("tenant_domain_invalid")
    if domain in MULTI_LABEL_PUBLIC_SUFFIXES:
        raise ValueError("tenant_domain_public_suffix")
    if domain == RETIRED_ROUTE_DOMAIN or domain.endswith("." + RETIRED_ROUTE_DOMAIN):
        raise ValueError("tenant_domain_retired")
    return domain


#: A configured tenant site domain (``validate_tenant_domain``).
TenantDomain = Annotated[str, AfterValidator(validate_tenant_domain)]


def registrable_domain(host: str) -> str:
    """The registrable domain (public suffix plus one label) of a valid
    hostname, per the suffixes ``validate_tenant_domain`` knows."""

    labels = host.split(".")
    keep = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_PUBLIC_SUFFIXES else 2
    return host if len(labels) <= keep else ".".join(labels[-keep:])


def _valid_tenant_domain(domain: str) -> bool:
    try:
        validate_tenant_domain(domain)
    except ValueError:
        return False
    return True


def valid_route_host(route_label: str, host: str) -> bool:
    """Whether ``host`` is ``route_label``'s host in some valid tenant domain
    and ``route_label`` is an unreserved generated ``<slug>-<l><dddd>`` label
    of at most 63 characters. Signed protocol objects carry the host; points
    with configuration bind it to the one tenant domain (``valid_route_host_in``).
    """

    label, dot, domain = host.partition(".")
    if not dot or label != route_label or not _valid_tenant_domain(domain):
        return False
    return (
        len(route_label) <= 63
        and not route_label.startswith(RESERVED_ROUTE_PREFIXES)
        and _PUBLIC_SITE_LABEL.fullmatch(route_label) is not None
    )


def valid_route_host_in(domain: str, route_label: str, host: str) -> bool:
    """Whether ``host`` is ``route_label``'s host in the tenant ``domain``."""

    return host.partition(".")[2] == domain and valid_route_host(route_label, host)


def route_host(domain: str, route_label: str) -> str:
    host = f"{route_label}.{validate_tenant_domain(domain)}"
    if not valid_route_host_in(domain, route_label, host):
        raise ValueError("route_host_invalid")
    return host


def format_timestamp(value: datetime) -> str:
    """Render an aware datetime in the canonical Go RFC3339Nano UTC form."""

    if value.tzinfo is None:
        raise ValueError("timestamp_not_aware")
    value = value.astimezone(UTC)
    rendered = value.strftime("%Y-%m-%dT%H:%M:%S")
    if value.microsecond:
        rendered += "." + f"{value.microsecond:06d}".rstrip("0")
    return rendered + "Z"


def document_bytes(model: BaseModel) -> bytes:
    """Canonical wire/file bytes: canonical JSON plus one trailing newline."""

    return canonical_json(model_document(model)) + b"\n"


def parse_document[ModelT: BaseModel](rendered: bytes, model_type: type[ModelT]) -> ModelT:
    """Parse one strict JSON body; duplicate keys, NaN and non-ASCII are refused.

    HTTP bodies need not be canonical bytes. Content-addressed documents use
    :func:`parse_canonical_document`, which also requires the exact bytes.
    """

    return parse_model(rendered, model_type, lambda _model: rendered)


def parse_canonical_document[ModelT: BaseModel](
    rendered: bytes, model_type: type[ModelT]
) -> ModelT:
    """Parse exact canonical bytes (canonical JSON plus one trailing newline)."""

    return parse_model(rendered, model_type, document_bytes)


# --------------------------------------------------------------------------
# Shared sub-documents
# --------------------------------------------------------------------------


class HealthPredicate(StrictFrozenModel):
    """Customer health predicate (submission, runtime request)."""

    method: Literal["GET", "HEAD"]
    path: HealthPath
    expected_statuses: list[Annotated[int, Field(ge=100, le=599)]] = Field(
        min_length=1, max_length=8
    )
    response_marker: ResponseMarker | None
    successes_required: int = Field(ge=1, le=5)
    interval_millis: int = Field(ge=500, le=10_000)
    probe_timeout_millis: int = Field(ge=1_000, le=10_000)
    startup_timeout_millis: int = Field(ge=5_000, le=120_000)


class TicketHealth(HealthPredicate):
    """``deployment.v4`` health: the customer predicate plus the fixed threshold."""

    failure_threshold: Literal[2]


# --------------------------------------------------------------------------
# Artifact manifest v2
# --------------------------------------------------------------------------


class OCIManifestDescriptor(StrictFrozenModel):
    digest: Digest
    size: PositiveCount
    media_type: Literal["application/vnd.oci.image.manifest.v1+json"]


class OCIConfigDescriptor(StrictFrozenModel):
    digest: Digest
    size: PositiveCount
    media_type: Literal["application/vnd.oci.image.config.v1+json"]


class ArtifactLayer(StrictFrozenModel):
    diff_id: Digest
    digest: Digest
    media_type: Literal[
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
    ]
    size: PositiveCount
    uncompressed_size: PositiveCount

    @model_validator(mode="after")
    def uncompressed_identity(self) -> Self:
        if self.media_type == OCI_LAYER_TAR and (
            self.diff_id != self.digest or self.uncompressed_size != self.size
        ):
            raise ValueError("tar_layer_identity_invalid")
        return self


class ArtifactPlatform(StrictFrozenModel):
    architecture: Literal["amd64"]
    os: Literal["linux"]


class ArtifactManifest(StrictFrozenModel):
    """Content-addressed R2 manifest; ``artifact_digest`` is sha256 of its exact bytes."""

    contract_schema: Literal["ms.computer/mscomputer-subnet/artifact-manifest"] = Field(
        alias="schema"
    )
    schema_version: Literal[2]
    workload_type: Literal["oci-image-v1"]
    platform: ArtifactPlatform
    oci_manifest: OCIManifestDescriptor
    config: OCIConfigDescriptor
    layers: list[ArtifactLayer] = Field(min_length=1, max_length=MAX_LAYERS)
    uncompressed_bytes: int = Field(ge=1, le=MAX_UNCOMPRESSED_BYTES)

    @model_validator(mode="after")
    def totals(self) -> Self:
        if self.uncompressed_bytes != sum(layer.uncompressed_size for layer in self.layers):
            raise ValueError("uncompressed_bytes_mismatch")
        return self


def artifact_manifest_bytes(manifest: ArtifactManifest) -> bytes:
    rendered = document_bytes(manifest)
    if len(rendered) > MAX_ARTIFACT_MANIFEST_BYTES:
        raise ValueError("artifact_manifest_too_large")
    return rendered


def artifact_digest(rendered: bytes) -> str:
    return "sha256:" + hashlib.sha256(rendered).hexdigest()


def parse_artifact_manifest(
    rendered: bytes, expected_digest: str | None = None
) -> ArtifactManifest:
    """Parse exact manifest bytes and optionally bind them to ``artifact_digest``."""

    if len(rendered) > MAX_ARTIFACT_MANIFEST_BYTES:
        raise ValueError("artifact_manifest_too_large")
    manifest = parse_model(rendered, ArtifactManifest, document_bytes)
    if expected_digest is not None and artifact_digest(rendered) != expected_digest:
        raise ValueError("artifact_digest_mismatch")
    return manifest


# --------------------------------------------------------------------------
# 6.6 / 6.7 deployment.v4 ticket and receipt, subnet-synapse.v3 envelopes
# --------------------------------------------------------------------------


class WorkloadEnv(StrictFrozenModel):
    HOST: Literal["0.0.0.0"]  # noqa: S104 - container bind address, fixed by the profile
    PORT: Annotated[str, StringConstraints(pattern=r"^[1-9][0-9]{0,4}$")]


class TicketWorkload(StrictFrozenModel):
    kind: Literal["oci-image-v1"]
    container_port: Port
    runtime_profile: Literal["small-v1"]
    env: WorkloadEnv

    @model_validator(mode="after")
    def port_env(self) -> Self:
        if self.env.PORT != str(self.container_port):
            raise ValueError("workload_port_env_mismatch")
        return self


class SmallV1Resources(StrictFrozenModel):
    cpu_millis: Literal[1000]
    memory_mb: Literal[1024]
    disk_mb: Literal[2048]
    pids: Literal[256]
    tmpfs_mb: Literal[64]


def _go_timestamp(value: str) -> str:
    _rfc3339nano_instant(value)
    return value


#: Signed Go RFC3339Nano timestamp; kept as the exact signed string.
GoTimestamp = Annotated[str, StringConstraints(max_length=64), AfterValidator(_go_timestamp)]


class DeploymentTicketV4(StrictFrozenModel):
    version: Literal["deployment.v4"]
    deployment_id: RouteLabel
    generation: PositiveCount
    image_digest: Digest
    manifest_key: ManifestKey
    miner_id: Hotkey
    route_host: Hostname
    assignment_nonce: Hex32
    workload: TicketWorkload
    resources: SmallV1Resources
    health: TicketHealth
    issued_at: GoTimestamp
    expires_at: GoTimestamp
    subnet: SubnetBinding
    signature: HexSignature

    @model_validator(mode="after")
    def exact_identity(self) -> Self:
        if self.manifest_key != manifest_key(self.image_digest):
            raise ValueError("manifest_key_mismatch")
        if self.miner_id != self.subnet.miner_hotkey:
            raise ValueError("miner_id_mismatch")
        if _rfc3339nano_instant(self.expires_at) <= _rfc3339nano_instant(self.issued_at):
            raise ValueError("ticket_window_invalid")
        return self


def ticket_digest(ticket: DeploymentTicketV4) -> str:
    """Digest of the complete signed ticket in canonical JSON (manifest binding)."""

    return "sha256:" + digest(model_document(ticket))


class DeploymentReceiptV4(StrictFrozenModel):
    version: Literal["deployment.v4"]
    deployment_id: RouteLabel
    generation: PositiveCount
    assignment_nonce: Hex32
    miner_id: Hotkey
    replica_id: Annotated[str, StringConstraints(min_length=3, max_length=256)]
    endpoint_id: EndpointID
    image_digest: Digest
    manifest_key: ManifestKey
    loaded_image_config_digest: Digest | None
    route_host: Hostname
    stage: Literal["accepted", "ready", "failed"]
    error_code: ReceiptErrorCode | None
    error: Annotated[str, StringConstraints(max_length=512, pattern=r"^[\x20-\x7e]*$")]
    assignment_seen: GoTimestamp
    pull_started: GoTimestamp
    pull_completed: GoTimestamp
    runtime_started: GoTimestamp
    health_passed: GoTimestamp
    subnet: SubnetBinding
    signature: HexSignature

    @model_validator(mode="after")
    def consistent_receipt(self) -> Self:
        replica = f"{self.deployment_id}-{self.miner_id}"
        endpoint = f"{replica}-g{self.generation}-{self.assignment_nonce}"
        if self.replica_id != replica or self.endpoint_id != endpoint:
            raise ValueError("receipt_identity_invalid")
        if self.miner_id != self.subnet.miner_hotkey:
            raise ValueError("miner_id_mismatch")
        if self.manifest_key != manifest_key(self.image_digest):
            raise ValueError("manifest_key_mismatch")
        if (self.stage == "failed") != (self.error_code is not None):
            raise ValueError("receipt_error_code_invalid")
        if self.stage == "ready" and (self.loaded_image_config_digest is None or self.error):
            raise ValueError("ready_receipt_incomplete")
        return self


def receipt_digest(receipt: DeploymentReceiptV4) -> str:
    """Digest of the complete signed receipt in canonical JSON (manifest v2 binding)."""

    return "sha256:" + digest(model_document(receipt))


_GO_HTML_ESCAPES: Final = {"<": "\\u003c", ">": "\\u003e", "&": "\\u0026"}


def _go_marshal(document: dict[str, object]) -> bytes:
    """Go ``encoding/json`` bytes of a struct-ordered document.

    Go marshals struct fields in declaration order without whitespace and
    escapes ``<``, ``>`` and ``&``. The v4 models declare their fields in the
    Go struct order and admit only printable ASCII, so this reproduces the
    exact bytes the Go services sign.
    """

    rendered = json.dumps(document, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    for character, escaped in _GO_HTML_ESCAPES.items():
        rendered = rendered.replace(character, escaped)
    return rendered.encode("ascii")


def _go_signed_document(model: DeploymentTicketV4 | DeploymentReceiptV4) -> dict[str, object]:
    document = model_document(model, exclude={"signature"})
    subnet = dict(document["subnet"])  # type: ignore[call-overload]
    if subnet.get("miner_uid") is None:
        # ``miner_uid`` is ``omitempty`` in the Go binding.
        subnet.pop("miner_uid", None)
    document["subnet"] = subnet
    return document


def ticket_v4_signed_bytes(ticket: DeploymentTicketV4) -> bytes:
    """The exact bytes the validator Go service key signs for one ticket."""

    return _go_marshal(_go_signed_document(ticket))


def receipt_v4_signed_bytes(receipt: DeploymentReceiptV4) -> bytes:
    """The exact bytes the miner Go service key signs for one receipt."""

    return _go_marshal(_go_signed_document(receipt))


class MinerResultV4(StrictFrozenModel):
    receipt: DeploymentReceiptV4
    endpoint_id: EndpointID

    @model_validator(mode="after")
    def endpoint_matches(self) -> Self:
        if self.endpoint_id != self.receipt.endpoint_id:
            raise ValueError("result_endpoint_mismatch")
        return self


class DeploySynapseV3(StrictFrozenModel):
    protocol: Literal["subnet-synapse.v3"]
    request_id: Annotated[str, StringConstraints(min_length=1, max_length=2_048)]
    current_block: Count
    caller_hotkey: Hotkey
    validator_binding: ServiceKeyBinding
    ticket: DeploymentTicketV4


class DeployResponseV3(StrictFrozenModel):
    protocol: Literal["subnet-synapse.v3"]
    request_id: Annotated[str, StringConstraints(min_length=1, max_length=2_048)]
    result: MinerResultV4
    idempotent: bool


class StatusResponseV3(StrictFrozenModel):
    protocol: Literal["subnet-synapse.v3"]
    request_id: Annotated[str, StringConstraints(min_length=1, max_length=2_048)]
    status: Literal["absent", "processing", "accepted", "ready", "failed", "deactivated"]
    receipt: DeploymentReceiptV4 | None

    @model_validator(mode="after")
    def receipt_matches_status(self) -> Self:
        if self.status in {"accepted", "ready", "failed"} and (
            self.receipt is None or self.receipt.stage != self.status
        ):
            raise ValueError("status_receipt_mismatch")
        if self.status in {"absent", "processing"} and self.receipt is not None:
            raise ValueError("status_receipt_mismatch")
        return self


class BridgeAssignRequestV3(StrictFrozenModel):
    protocol: Literal["subnet-synapse.v3"]
    request_id: Annotated[str, StringConstraints(min_length=1, max_length=2_048)]
    ticket: DeploymentTicketV4


# --------------------------------------------------------------------------
# 6.9 edge -> miner runtime request authentication
# --------------------------------------------------------------------------


class EdgeRuntimeRequest(StrictFrozenModel):
    """The exact object the validator Go service key signs for one edge request.

    ``path`` is the raw (escaped) application path after
    ``/runtime/<endpoint_id>``; ``query`` is the raw query without ``?``.
    """

    body_sha256: Hex64
    endpoint_id: EndpointID
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    nonce: Hex32
    path: Annotated[str, StringConstraints(max_length=8_192, pattern=r"^/[\x21-\x7e]*$")]
    query: Annotated[str, StringConstraints(max_length=8_192, pattern=r"^[\x21-\x7e]*$")]
    timestamp: Annotated[int, Field(ge=1, le=MAX_INT)]


def edge_runtime_request_message(request: EdgeRuntimeRequest) -> bytes:
    return EDGE_RUNTIME_REQUEST_DOMAIN + b"\x00" + canonical_json(model_document(request))


def edge_authorization_header_value(request: EdgeRuntimeRequest, signature_hex: str) -> str:
    return f"v1 ts={request.timestamp},nonce={request.nonce},sig={signature_hex}"


# --------------------------------------------------------------------------
# 17.2 public validator contract
# --------------------------------------------------------------------------


class OrganicHealthProbe(StrictFrozenModel):
    """Sanitized public health predicate published for hidden validator probes."""

    method: Literal["GET", "HEAD"]
    path: HealthPath
    expected_statuses: list[Annotated[int, Field(ge=100, le=599)]] = Field(
        min_length=1, max_length=8
    )
    response_marker: ResponseMarker | None


class OrganicAssignedReplica(StrictFrozenModel):
    miner_uid: UID
    miner_hotkey: Hotkey
    miner_service_public_key: Hex64
    miner_tls_certificate_sha256: Hex64
    generation: PositiveCount
    assignment_nonce: Hex32
    replica_id: Annotated[str, StringConstraints(min_length=3, max_length=256)]
    endpoint_id: EndpointID
    ticket_digest: Digest
    receipt_digest: Digest
    chain_block: Count
    expires_at_block: PositiveCount
    activated_at_epoch: Count
    expires_at_epoch: PositiveCount
    route_state: Literal["active"]

    @model_validator(mode="after")
    def windows(self) -> Self:
        if self.expires_at_block <= self.chain_block:
            raise ValueError("replica_block_window_invalid")
        if self.expires_at_epoch <= self.activated_at_epoch:
            raise ValueError("replica_activation_window_invalid")
        if self.ticket_digest == self.receipt_digest:
            raise ValueError("replica_digest_collision")
        return self


class OrganicDeploymentAssignment(StrictFrozenModel):
    deployment_id: RouteLabel
    route_host: Hostname
    artifact_digest: Digest
    health: OrganicHealthProbe
    attestation_requirement: Literal["miner_service_key_v2"]
    replicas: list[OrganicAssignedReplica] = Field(min_length=1, max_length=8)
    assignment_digest_sha256: Hex64

    @model_validator(mode="after")
    def canonical_assignment(self) -> Self:
        keys = [(item.miner_uid, item.miner_hotkey) for item in self.replicas]
        if keys != sorted(set(keys)):
            raise ValueError("assignment_replicas_not_canonical")
        for item in self.replicas:
            replica = f"{self.deployment_id}-{item.miner_hotkey}"
            endpoint = f"{replica}-g{item.generation}-{item.assignment_nonce}"
            if item.replica_id != replica or item.endpoint_id != endpoint:
                raise ValueError("assignment_replica_identity_invalid")
        verify_model_digest(self, "assignment_digest_sha256")
        return self


#: The only (network, netuid) pairs an organic manifest or score may name:
#: mainnet SN24 and one allowlisted testnet subnet. Any other pairing of the
#: two literals (finney/581, test/24) is refused.
ORGANIC_SUBNETS: Final = frozenset({("finney", 24), ("test", 581)})


class ActiveAssignmentManifestV2(StrictFrozenModel):
    """Public snapshot of active miner routes after verified cutover (no origins)."""

    contract_schema: Literal["ms.computer/mscomputer-subnet/active-assignment-manifest"] = Field(
        alias="schema"
    )
    schema_version: Literal[2]
    purpose: Literal["active_assignment_manifest_publication_v2"]
    network: Literal["finney", "test"]
    netuid: Literal[24, 581]
    central_authority_fingerprint_sha256: Hex64
    trust_policy_digest_sha256: Hex64
    finalized_height: Count
    finalized_block_hash: Hex64
    finalized_epoch: Count
    sequence: PositiveCount
    previous_manifest_digest_sha256: Hex64 | None
    issued_at_epoch: Count
    expires_at_epoch: PositiveCount
    route_host_suffix: Hostname
    probe_scheme: Literal["https"]
    probe_port: Port
    deployments: list[OrganicDeploymentAssignment] = Field(max_length=4_096)
    assignment_vector_digest_sha256: Hex64
    manifest_digest_sha256: Hex64

    @model_validator(mode="after")
    def canonical_manifest(self) -> Self:
        if (self.network, self.netuid) not in ORGANIC_SUBNETS:
            raise ValueError("organic_subnet_invalid")
        if self.expires_at_epoch <= self.issued_at_epoch:
            raise ValueError("manifest_validity_window_invalid")
        if (self.sequence == 1) != (self.previous_manifest_digest_sha256 is None):
            raise ValueError("manifest_previous_link_invalid")
        ids = [item.deployment_id for item in self.deployments]
        if ids != sorted(set(ids)):
            raise ValueError("manifest_deployments_not_canonical")
        for item in self.deployments:
            if item.route_host != f"{item.deployment_id}.{self.route_host_suffix}":
                raise ValueError("manifest_route_host_invalid")
            for replica in item.replicas:
                if replica.expires_at_block <= self.finalized_height:
                    raise ValueError("manifest_replica_block_expired")
                if replica.expires_at_epoch <= self.issued_at_epoch:
                    raise ValueError("manifest_replica_expired")
        endpoints = [r.endpoint_id for item in self.deployments for r in item.replicas]
        if len(set(endpoints)) != len(endpoints):
            raise ValueError("manifest_endpoint_duplicate")
        vector = [model_document(item) for item in self.deployments]
        if self.assignment_vector_digest_sha256 != digest(vector):
            raise ValueError("assignment_vector_digest_sha256_mismatch")
        verify_model_digest(self, "manifest_digest_sha256")
        return self


#: Workload kinds a manifest v3 deployment may declare (static-site contract §11.1).
OCI_WORKLOAD_KIND: Final = "oci-image-v1"
STATIC_WORKLOAD_KIND: Final = "static-site-v1"


def _check_assignment_replicas(
    deployment_id: str, replicas: Sequence[OrganicAssignedReplica]
) -> None:
    keys = [(item.miner_uid, item.miner_hotkey) for item in replicas]
    if keys != sorted(set(keys)):
        raise ValueError("assignment_replicas_not_canonical")
    for item in replicas:
        replica = f"{deployment_id}-{item.miner_hotkey}"
        endpoint = f"{replica}-g{item.generation}-{item.assignment_nonce}"
        if item.replica_id != replica or item.endpoint_id != endpoint:
            raise ValueError("assignment_replica_identity_invalid")


class _DeploymentAssignmentV3(StrictFrozenModel):
    """Members every manifest v3 deployment shares with a v2 deployment."""

    deployment_id: RouteLabel
    route_host: Hostname
    attestation_requirement: Literal["miner_service_key_v2"]
    replicas: list[OrganicAssignedReplica] = Field(min_length=1, max_length=8)
    assignment_digest_sha256: Hex64

    @model_validator(mode="after")
    def canonical_assignment(self) -> Self:
        _check_assignment_replicas(self.deployment_id, self.replicas)
        verify_model_digest(self, "assignment_digest_sha256")
        return self


class OciDeploymentAssignmentV3(_DeploymentAssignmentV3):
    """An ``oci-image-v1`` deployment: the v2 deployment plus null static bindings."""

    workload_kind: Literal["oci-image-v1"]
    artifact_digest: Digest
    health: OrganicHealthProbe
    site_digest: None
    release_digest: None
    server_implementation_digest: None


class StaticDeploymentAssignmentV3(_DeploymentAssignmentV3):
    """A ``static-site-v1`` deployment; probes derive from its signed site manifest.

    Every replica shares the deployment's ``site_digest``; its ``ticket_digest``
    and ``receipt_digest`` are the static ticket and receipt v1 digests.
    """

    workload_kind: Literal["static-site-v1"]
    artifact_digest: None
    health: None
    site_digest: Digest
    release_digest: Digest
    server_implementation_digest: Digest


DeploymentAssignmentV3 = Annotated[
    OciDeploymentAssignmentV3 | StaticDeploymentAssignmentV3,
    Field(discriminator="workload_kind"),
]


class ActiveAssignmentManifestV3(StrictFrozenModel):
    """Public snapshot of active OCI and static miner routes after verified cutover.

    The v2 header and publication rules with the v3 purpose and signing
    domain; every deployment names an explicit ``workload_kind`` (static-site
    contract §11.1). A v2 manifest never carries a static deployment.
    """

    contract_schema: Literal["ms.computer/mscomputer-subnet/active-assignment-manifest"] = Field(
        alias="schema"
    )
    schema_version: Literal[3]
    purpose: Literal["active_assignment_manifest_publication_v3"]
    network: Literal["finney", "test"]
    netuid: Literal[24, 581]
    central_authority_fingerprint_sha256: Hex64
    trust_policy_digest_sha256: Hex64
    finalized_height: Count
    finalized_block_hash: Hex64
    finalized_epoch: Count
    sequence: PositiveCount
    previous_manifest_digest_sha256: Hex64 | None
    issued_at_epoch: Count
    expires_at_epoch: PositiveCount
    route_host_suffix: Hostname
    probe_scheme: Literal["https"]
    probe_port: Port
    deployments: list[DeploymentAssignmentV3] = Field(max_length=4_096)
    assignment_vector_digest_sha256: Hex64
    manifest_digest_sha256: Hex64

    @model_validator(mode="after")
    def canonical_manifest(self) -> Self:
        if (self.network, self.netuid) not in {("finney", 24), ("test", 581)}:
            raise ValueError("static_subnet_invalid")
        if self.expires_at_epoch <= self.issued_at_epoch:
            raise ValueError("manifest_validity_window_invalid")
        if (self.sequence == 1) != (self.previous_manifest_digest_sha256 is None):
            raise ValueError("manifest_previous_link_invalid")
        ids = [item.deployment_id for item in self.deployments]
        if ids != sorted(set(ids)):
            raise ValueError("manifest_deployments_not_canonical")
        for item in self.deployments:
            if item.route_host != f"{item.deployment_id}.{self.route_host_suffix}":
                raise ValueError("manifest_route_host_invalid")
            for replica in item.replicas:
                if replica.expires_at_block <= self.finalized_height:
                    raise ValueError("manifest_replica_block_expired")
                if replica.expires_at_epoch <= self.issued_at_epoch:
                    raise ValueError("manifest_replica_expired")
        endpoints = [r.endpoint_id for item in self.deployments for r in item.replicas]
        if len(set(endpoints)) != len(endpoints):
            raise ValueError("manifest_endpoint_duplicate")
        vector = [model_document(item) for item in self.deployments]
        if self.assignment_vector_digest_sha256 != digest(vector):
            raise ValueError("assignment_vector_digest_sha256_mismatch")
        verify_model_digest(self, "manifest_digest_sha256")
        return self


def oci_deployment_assignment_v2(
    deployment: OciDeploymentAssignmentV3,
) -> OrganicDeploymentAssignment:
    """The v2 deployment an ``oci-image-v1`` v3 deployment corresponds to (OCI v3 = v2).

    Drops ``workload_kind`` and the null static bindings and reseals
    ``assignment_digest_sha256``. A static deployment has no v2 form.
    """

    value = revalidate(deployment, OciDeploymentAssignmentV3)
    unsigned = model_document(
        value,
        exclude={
            "workload_kind",
            "site_digest",
            "release_digest",
            "server_implementation_digest",
            "assignment_digest_sha256",
        },
    )
    return OrganicDeploymentAssignment.model_validate(
        {**unsigned, "assignment_digest_sha256": digest(unsigned)}
    )


def response_header_sha256(headers: list[tuple[str, str]]) -> str:
    """Digest of end-to-end response headers: sorted ``[lowercase name, value]`` pairs."""

    pairs = sorted(([name.lower(), value] for name, value in headers), key=lambda p: p[0])
    return hashlib.sha256(canonical_json(pairs)).hexdigest()


#: Every organic contract, keyed by its ``contracts/schemas`` file stem.
CONTRACT_MODELS: Final[dict[str, type[BaseModel]]] = {
    "artifact-manifest.v2": ArtifactManifest,
    "deployment-ticket.v4": DeploymentTicketV4,
    "deployment-receipt.v4": DeploymentReceiptV4,
    "deploy.v3": DeploySynapseV3,
    "deploy-response.v3": DeployResponseV3,
    "status-response.v3": StatusResponseV3,
    "bridge-assign.v3": BridgeAssignRequestV3,
    "edge-runtime-request.v1": EdgeRuntimeRequest,
    "active-assignment-manifest.v2": ActiveAssignmentManifestV2,
    "active-assignment-manifest.v3": ActiveAssignmentManifestV3,
}
