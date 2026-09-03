from __future__ import annotations

import ipaddress
import base64
import binascii
import hashlib
import json
import quopri
import re
import struct
from urllib.parse import unquote_to_bytes
import zlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterator

from .models import Artifact, Observation


_PCAP_MAGIC: dict[bytes, tuple[str, str]] = {
    b"\xd4\xc3\xb2\xa1": ("<", "microsecond"),
    b"\xa1\xb2\xc3\xd4": (">", "microsecond"),
    b"\x4d\x3c\xb2\xa1": ("<", "nanosecond"),
    b"\xa1\xb2\x3c\x4d": (">", "nanosecond"),
}
_DNS_TRANSACTION_PACKET_WINDOW = 4_096
_MAX_HTTP_FLOW_STATE = 4_096
_MAX_HTTP_PACKET_PROVENANCE_RANGES = 8_192
_MAX_HTTP_REQUESTS_PER_FLOW = 100
_MAX_TLS_CLIENT_HELLO_FLOWS = 4_096
_MAX_TLS_CLIENT_HELLO_BYTES = 64 * 1024
_MAX_TLS_SERVER_HELLO_FLOWS = 4_096
_MAX_TLS_SERVER_HELLO_BYTES = 64 * 1024
_MAX_TLS_CERTIFICATE_ENTRIES = 16
_MAX_TLS_CERTIFICATE_FLOWS = 4_096
_MAX_TLS_CERTIFICATE_BYTES = 64 * 1024


@dataclass(slots=True)
class _PcapStats:
    packets: int = 0
    truncated: bool = False
    protocols: Counter[str] | None = None
    endpoints: Counter[str] | None = None
    dns_queries: list[str] | None = None
    dns_txt_records: list[dict[str, str]] | None = None
    dns_txt_fragments: list[dict[str, object]] | None = None
    dns_label_fragments: list[dict[str, object]] | None = None
    dns_transactions: dict[tuple[str, str, int, int, int], int] | None = None
    dns_transaction_matches: list[dict[str, object]] | None = None
    udp_payloads: list[dict[str, object]] | None = None
    icmp_payloads: list[dict[str, object]] | None = None
    tcp_payloads: list[dict[str, object]] | None = None
    http_flows: set[tuple[str, int, str, int]] | None = None
    http_flow_state_truncated: bool = False
    http_requests_seen: list[dict[str, str]] | None = None
    tls_server_names: list[str] | None = None
    tls_client_hellos: list[dict[str, object]] | None = None
    tls_client_hello_errors: list[dict[str, object]] | None = None
    tls_server_hellos: list[dict[str, object]] | None = None
    tls_server_hello_errors: list[dict[str, object]] | None = None
    tls_certificates: list[dict[str, object]] | None = None
    tls_certificate_errors: list[dict[str, object]] | None = None
    tls_certificate_flows: dict[tuple[str, int, str, int], dict[str, object]] | None = None
    tls_client_hello_flows: dict[tuple[str, int, str, int], dict[str, object]] | None = None
    tls_server_hello_flows: dict[tuple[str, int, str, int], dict[str, object]] | None = None
    tls_client_hello_flow_state_truncated: bool = False
    tls_server_hello_flow_state_truncated: bool = False
    tls_certificate_flow_state_truncated: bool = False
    http_requests: int = 0
    http_responses: int = 0

    def __post_init__(self) -> None:
        self.protocols = Counter()
        self.endpoints = Counter()
        self.dns_queries = []
        self.dns_txt_records = []
        self.dns_txt_fragments = []
        self.dns_label_fragments = []
        self.dns_transactions = {}
        self.dns_transaction_matches = []
        self.udp_payloads = []
        self.icmp_payloads = []
        self.tcp_payloads = []
        self.http_flows = set()
        self.http_requests_seen = []
        self.tls_server_names = []
        self.tls_client_hellos = []
        self.tls_client_hello_errors = []
        self.tls_server_hellos = []
        self.tls_server_hello_errors = []
        self.tls_certificates = []
        self.tls_certificate_errors = []
        self.tls_certificate_flows = {}
        self.tls_client_hello_flows = {}
        self.tls_server_hello_flows = {}


@dataclass(frozen=True, slots=True)
class _TcpSegment:
    """The small amount of TCP metadata needed for bounded HTTP recovery."""

    source: str
    source_port: int
    destination: str
    destination_port: int
    sequence: int
    flags: int
    payload: bytes

    @property
    def flow(self) -> tuple[str, int, str, int]:
        return (self.source, self.source_port, self.destination, self.destination_port)


@dataclass(frozen=True, slots=True)
class HttpResponseObject:
    """One bounded HTTP response object recovered from a TCP flow."""

    logical_name: str
    body: bytes
    content_encoding: tuple[str, ...] = ()
    decoded_content_encoding: tuple[str, ...] = ()
    encoded_size: int = 0
    decode_error: str | None = None
    content_type: str | None = None
    content_disposition: str | None = None
    multipart_part_index: int | None = None
    source: str | None = None
    source_port: int | None = None
    destination: str | None = None
    destination_port: int | None = None
    packet_indices: tuple[int, ...] = ()
    packet_provenance_complete: bool = True
    request_method: str | None = None
    request_host: str | None = None
    request_target: str | None = None
    request_packet_indices: tuple[int, ...] = ()
    request_packet_provenance_complete: bool = True
    multipart_content_transfer_encoding: str | None = None
    decoded_multipart_content_transfer_encoding: str | None = None
    multipart_decode_error: str | None = None


@dataclass(frozen=True, slots=True)
class FtpDataObject:
    """A bounded FTP PASV/RETR data stream with control-channel provenance."""

    logical_name: str
    transfer_command: str
    body: bytes
    source: str
    source_port: int
    destination: str
    destination_port: int
    packet_indices: tuple[int, ...]
    command_packet_index: int
    endpoint_setup_packet_index: int
    packet_provenance_complete: bool
    completion_code: int | None = None
    completion_packet_index: int | None = None


@dataclass(frozen=True, slots=True)
class FtpAuthTlsTransition:
    """An exact FTP AUTH TLS/234 transition with packet provenance."""

    source: str
    source_port: int
    destination: str
    destination_port: int
    command_packet_index: int
    ready_response_packet_index: int


@dataclass(frozen=True, slots=True)
class Smb2CreateOperation:
    """A bounded SMB2 CREATE request with filename and header provenance."""

    filename: str
    message_id: int
    session_id: int
    tree_id: int
    desired_access: int
    create_disposition: int
    create_options: int
    source: str
    source_port: int
    destination: str
    destination_port: int
    packet_indices: tuple[int, ...]
    response_status: int | None = None
    persistent_file_id: int | None = None
    volatile_file_id: int | None = None
    response_packet_indices: tuple[int, ...] = ()
    share_path: str | None = None
    tree_connect_packet_indices: tuple[int, ...] = ()
    tree_connect_response_packet_indices: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class Smb2WriteObject:
    """A contiguous acknowledged SMB2 WRITE upload tied to a CREATE FileId."""

    logical_name: str
    smb_path: str
    body: bytes
    persistent_file_id: int
    volatile_file_id: int
    source: str
    source_port: int
    destination: str
    destination_port: int
    packet_indices: tuple[int, ...]
    response_packet_indices: tuple[int, ...]
    message_ids: tuple[int, ...]
    share_path: str | None = None
    close_end_of_file: int | None = None
    close_packet_indices: tuple[int, ...] = ()
    close_response_packet_indices: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class Smb2ReadObject:
    """A contiguous SMB2 READ download tied to a successful CREATE FileId."""

    logical_name: str
    smb_path: str
    body: bytes
    persistent_file_id: int
    volatile_file_id: int
    source: str
    source_port: int
    destination: str
    destination_port: int
    request_packet_indices: tuple[int, ...]
    packet_indices: tuple[int, ...]
    message_ids: tuple[int, ...]
    share_path: str | None = None
    close_end_of_file: int | None = None
    close_packet_indices: tuple[int, ...] = ()
    close_response_packet_indices: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class Smb2CloseOperation:
    """An SMB2 CLOSE request/response tied to a successful CREATE FileId."""

    filename: str
    share_path: str | None
    persistent_file_id: int
    volatile_file_id: int
    message_id: int
    session_id: int
    tree_id: int
    source: str
    source_port: int
    destination: str
    destination_port: int
    packet_indices: tuple[int, ...]
    response_status: int | None = None
    response_packet_indices: tuple[int, ...] = ()
    creation_filetime: int | None = None
    last_access_filetime: int | None = None
    last_write_filetime: int | None = None
    change_filetime: int | None = None
    allocation_size: int | None = None
    end_of_file: int | None = None
    file_attributes: int | None = None


@dataclass(frozen=True, slots=True)
class Smb2SetInfoOperation:
    """A bounded SMB2 file rename/delete-disposition request and response."""

    operation: str
    filename: str
    share_path: str | None
    persistent_file_id: int
    volatile_file_id: int
    message_id: int
    session_id: int
    tree_id: int
    source: str
    source_port: int
    destination: str
    destination_port: int
    packet_indices: tuple[int, ...]
    target_filename: str | None = None
    replace_if_exists: bool | None = None
    delete_pending: bool | None = None
    response_status: int | None = None
    response_packet_indices: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class Smb2DirectoryEntry:
    """One validated SMB2 QUERY_DIRECTORY result entry."""

    name: str
    file_index: int | None = None
    creation_filetime: int | None = None
    last_access_filetime: int | None = None
    last_write_filetime: int | None = None
    change_filetime: int | None = None
    end_of_file: int | None = None
    allocation_size: int | None = None
    file_attributes: int | None = None
    ea_size: int | None = None
    short_name: str | None = None
    file_id: int | None = None


@dataclass(frozen=True, slots=True)
class Smb2DirectoryListing:
    """A bounded SMB2 QUERY_DIRECTORY listing response."""

    logical_name: str
    directory_path: str
    share_path: str | None
    pattern: str | None
    information_class: int
    information_class_name: str
    entries: tuple[Smb2DirectoryEntry, ...]
    names: tuple[str, ...]
    body: bytes
    persistent_file_id: int
    volatile_file_id: int
    message_id: int
    source: str
    source_port: int
    destination: str
    destination_port: int
    request_packet_indices: tuple[int, ...]
    packet_indices: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Smb3TransformRecord:
    """One structurally validated SMB3 encryption or compression transform."""

    transform_type: str
    declared_original_size: int
    flags: int
    framed_size: int
    transformed_payload_size: int
    source: str
    source_port: int
    destination: str
    destination_port: int
    packet_indices: tuple[int, ...]
    session_id: int | None = None
    signature_hex: str | None = None
    nonce_hex: str | None = None
    compression_algorithm: int | None = None
    compression_algorithm_name: str | None = None
    data_offset: int | None = None


@dataclass(frozen=True, slots=True)
class Smb2NegotiateOperation:
    """A bounded SMB2 NEGOTIATE request and exact inverse response."""

    offered_dialects: tuple[int, ...]
    offered_dialect_names: tuple[str, ...]
    request_security_mode: int
    request_capabilities: int
    client_guid_hex: str
    request_context_count: int
    message_id: int
    source: str
    source_port: int
    destination: str
    destination_port: int
    packet_indices: tuple[int, ...]
    response_status: int | None = None
    selected_dialect: int | None = None
    selected_dialect_name: str | None = None
    response_security_mode: int | None = None
    response_capabilities: int | None = None
    server_guid_hex: str | None = None
    max_transact_size: int | None = None
    max_read_size: int | None = None
    max_write_size: int | None = None
    system_filetime: int | None = None
    server_start_filetime: int | None = None
    response_context_count: int | None = None
    response_packet_indices: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class SmtpDataObject:
    logical_name: str
    body: bytes
    source: str
    source_port: int
    destination: str
    destination_port: int
    packet_indices: tuple[int, ...]
    data_command_packet_index: int
    ready_response_packet_index: int
    acceptance_code: int | None = None
    acceptance_packet_index: int | None = None
    rejection_code: int | None = None
    rejection_packet_index: int | None = None
    forwarding_code: int | None = None
    forwarding_packet_index: int | None = None


@dataclass(frozen=True, slots=True)
class SmtpStarttlsTransition:
    source: str
    source_port: int
    destination: str
    destination_port: int
    command_packet_index: int
    ready_response_packet_index: int


@dataclass(frozen=True, slots=True)
class SmtpBdatObject:
    logical_name: str
    body: bytes
    source: str
    source_port: int
    destination: str
    destination_port: int
    packet_indices: tuple[int, ...]
    command_packet_indices: tuple[int, ...]
    final_response_code: int | None = None
    final_response_packet_index: int | None = None


@dataclass(frozen=True, slots=True)
class Pop3RetrObject:
    """A complete POP3 RETR multiline response with exact control provenance."""

    logical_name: str
    body: bytes
    source: str
    source_port: int
    destination: str
    destination_port: int
    packet_indices: tuple[int, ...]
    retr_command_packet_index: int
    positive_response_packet_index: int


@dataclass(frozen=True, slots=True)
class Pop3StlsTransition:
    """An exact POP3 STLS/+OK transition with packet provenance."""

    source: str
    source_port: int
    destination: str
    destination_port: int
    command_packet_index: int
    ready_response_packet_index: int


@dataclass(frozen=True, slots=True)
class ImapFetchObject:
    """A complete IMAP FETCH message literal with tagged completion evidence."""

    logical_name: str
    body: bytes
    source: str
    source_port: int
    destination: str
    destination_port: int
    packet_indices: tuple[int, ...]
    fetch_command_packet_index: int
    literal_response_packet_index: int
    completion_packet_index: int


@dataclass(frozen=True, slots=True)
class ImapStarttlsTransition:
    """An exact IMAP STARTTLS/tagged-OK transition with packet provenance."""

    tag: str
    source: str
    source_port: int
    destination: str
    destination_port: int
    command_packet_index: int
    ready_response_packet_index: int


@dataclass(slots=True)
class _TcpFlow:
    """Contiguous payload window for one unidirectional TCP flow.

    This deliberately avoids pretending to be a general TCP stack.  It keeps
    only an ordered, finite window and discards a flow when a gap cannot be
    closed within the configured bounds.  That is sufficient for ordinary
    CTF HTTP object transfers while preventing an adversarial PCAP from using
    unbounded packet/fragment state.
    """

    next_sequence: int | None = None
    start_sequence: int | None = None
    consumed_sequence: int | None = None
    data: bytearray | None = None
    pending: dict[int, tuple[bytes, int]] | None = None
    packet_ranges: list[tuple[int, int, int]] | None = None
    packet_provenance_complete: bool = True

    def __post_init__(self) -> None:
        self.data = bytearray()
        self.pending = {}
        self.packet_ranges = []


class PcapObservationEngine:
    """Bounded decoder for common Ethernet/IPv4 classic-PCAP evidence.

    This is intentionally a triage parser, not a replacement for tshark. It
    makes offline tool planning evidence-driven even where tshark is missing.
    """

    def __init__(self, *, max_packets: int = 200_000, max_bytes: int = 128 * 1024 * 1024) -> None:
        self.max_packets = max_packets
        self.max_bytes = max_bytes

    def analyze(self, artifact: Artifact, path: Path) -> list[Observation]:
        with path.open("rb") as stream:
            global_header = stream.read(24)
            if global_header.startswith(b"\x0a\x0d\x0d\x0a"):
                return self._analyze_pcapng(artifact, path)
            info = _PCAP_MAGIC.get(global_header[:4])
            if info is None or len(global_header) != 24:
                return []
            endian, timestamp_precision = info
            try:
                _, _, _, _, _, _, network = struct.unpack(endian + "IHHIIII", global_header)
            except struct.error:
                return []
            stats = _PcapStats()
            consumed = 24
            while stats.packets < self.max_packets and consumed < self.max_bytes:
                packet_header = stream.read(16)
                consumed += len(packet_header)
                if not packet_header:
                    break
                if len(packet_header) != 16:
                    stats.truncated = True
                    break
                _, _, captured_length, _ = struct.unpack(endian + "IIII", packet_header)
                if captured_length > self.max_bytes - consumed:
                    stats.truncated = True
                    break
                packet = stream.read(captured_length)
                consumed += len(packet)
                if len(packet) != captured_length:
                    stats.truncated = True
                    break
                stats.packets += 1
                if network == 1:  # LINKTYPE_ETHERNET
                    self._decode_ethernet(packet, stats)
        long_labels = [query for query in stats.dns_queries if any(len(label) >= 40 for label in query.split("."))]
        txt_reassemblies = _reassemble_dns_txt_fragments(stats.dns_txt_fragments)
        txt_reassembly_requests = [
            {"packet_indices": item["packet_indices"], "request_packet_indices": item["request_packet_indices"]}
            for item in txt_reassemblies if isinstance(item.get("request_packet_indices"), list)
        ][:100]
        label_reassemblies = _reassemble_dns_label_fragments(stats.dns_label_fragments)
        source = "pcap_triage"
        return [
            Observation(artifact.id, "pcap.format", "pcap", source),
            Observation(artifact.id, "pcap.timestamp_precision", timestamp_precision, source),
            Observation(artifact.id, "pcap.linktype", network, source),
            Observation(artifact.id, "pcap.packet_count", stats.packets, source),
            Observation(artifact.id, "pcap.scan_bytes", consumed, source),
            Observation(artifact.id, "pcap.scan_truncated", stats.truncated or stats.packets >= self.max_packets, source),
            Observation(artifact.id, "pcap.protocol_counts", dict(stats.protocols), source),
            Observation(artifact.id, "pcap.endpoints", [host for host, _ in stats.endpoints.most_common(200)], source),
            Observation(artifact.id, "pcap.dns.query_count", len(stats.dns_queries), source),
            Observation(artifact.id, "pcap.dns.queries", stats.dns_queries[:2_000], source),
            Observation(artifact.id, "pcap.dns.long_labels", bool(long_labels), source),
            Observation(artifact.id, "pcap.dns.long_label_samples", long_labels[:100], source),
            Observation(artifact.id, "pcap.dns.txt_record_count", len(stats.dns_txt_records), source),
            Observation(artifact.id, "pcap.dns.txt_records", stats.dns_txt_records[:500], source),
            Observation(artifact.id, "pcap.dns.txt_fragments", stats.dns_txt_fragments[:2_000], source),
            Observation(artifact.id, "pcap.dns.txt_reassemblies", txt_reassemblies, source, 0.85),
            Observation(artifact.id, "pcap.dns.txt_reassembly_request_packets", txt_reassembly_requests, source, 0.9),
            Observation(artifact.id, "pcap.dns.transaction_match_count", len(stats.dns_transaction_matches), source),
            Observation(artifact.id, "pcap.dns.transaction_matches", stats.dns_transaction_matches[:2_000], source),
            Observation(artifact.id, "pcap.udp.printable_payloads", stats.udp_payloads[:500], source, 0.75),
            Observation(artifact.id, "pcap.icmp.printable_payloads", stats.icmp_payloads[:500], source, 0.75),
            Observation(artifact.id, "pcap.tcp.printable_payloads", _public_packet_payloads(stats.tcp_payloads), source, 0.75),
            Observation(artifact.id, "pcap.http.flow_state_truncated", stats.http_flow_state_truncated, source, 0.9),
            Observation(artifact.id, "pcap.dns.label_fragments", stats.dns_label_fragments[:2_000], source),
            Observation(artifact.id, "pcap.dns.label_reassemblies", label_reassemblies, source, 0.8),
            Observation(artifact.id, "pcap.http.request_count", stats.http_requests, source),
            Observation(artifact.id, "pcap.http.response_count", stats.http_responses, source),
            Observation(artifact.id, "pcap.http.requests", stats.http_requests_seen[:500], source),
            Observation(artifact.id, "pcap.http.has_objects", stats.http_requests > 0 or stats.http_responses > 0, source, 0.7),
            Observation(artifact.id, "pcap.tls.server_name_count", len(stats.tls_server_names), source),
            Observation(artifact.id, "pcap.tls.server_names", stats.tls_server_names[:500], source),
            Observation(artifact.id, "pcap.tls.client_hellos", stats.tls_client_hellos[:500], source),
            Observation(artifact.id, "pcap.tls.client_hello_errors", stats.tls_client_hello_errors[:500], source, 0.8),
            Observation(artifact.id, "pcap.tls.server_hellos", stats.tls_server_hellos[:500], source),
            Observation(artifact.id, "pcap.tls.negotiations", _tls_negotiations(stats)[:500], source, 0.9),
            Observation(artifact.id, "pcap.tls.server_hello_errors", stats.tls_server_hello_errors[:500], source, 0.8),
            Observation(artifact.id, "pcap.tls.certificates", stats.tls_certificates[:500], source, 0.9),
            Observation(artifact.id, "pcap.tls.certificate_errors", stats.tls_certificate_errors[:500], source, 0.8),
            Observation(artifact.id, "pcap.tls.certificate_flow_state_truncated", stats.tls_certificate_flow_state_truncated, source, 0.9),
            Observation(artifact.id, "pcap.tls.certificate_incomplete_flows", _tls_certificate_incomplete_flows(stats)[:500], source, 0.85),
            Observation(artifact.id, "pcap.tls.client_hello_flow_state_truncated", stats.tls_client_hello_flow_state_truncated, source, 0.9),
            Observation(artifact.id, "pcap.tls.client_hello_incomplete_flows", _tls_incomplete_flows(stats)[:500], source, 0.85),
            Observation(artifact.id, "pcap.tls.server_hello_flow_state_truncated", stats.tls_server_hello_flow_state_truncated, source, 0.9),
            Observation(artifact.id, "pcap.tls.server_hello_incomplete_flows", _tls_server_incomplete_flows(stats)[:500], source, 0.85),
        ]

    def _analyze_pcapng(self, artifact: Artifact, path: Path) -> list[Observation]:
        """Bounded PCAPNG block walker for Ethernet packet triage.

        PCAPNG has per-section byte order and potentially multiple interfaces.
        This parser only consumes well-formed Section/Header, Interface, and
        Enhanced/Simple Packet blocks; unsupported blocks are skipped by their
        declared length.  tshark remains responsible for full dissection.
        """
        stats = _PcapStats()
        interfaces: list[int] = []
        consumed = 0
        blocks = 0
        truncated = False
        endian: str | None = None
        with path.open("rb") as stream:
            while consumed < self.max_bytes and stats.packets < self.max_packets:
                prefix = stream.read(8)
                consumed += len(prefix)
                if not prefix:
                    break
                if len(prefix) != 8:
                    truncated = True
                    break
                block_type_raw = prefix[:4]
                if block_type_raw == b"\x0a\x0d\x0d\x0a":
                    # The BOM lies in the first four block-body bytes, before
                    # the trailing length, and determines this new section.
                    bom = stream.read(4)
                    consumed += len(bom)
                    if bom == b"\x4d\x3c\x2b\x1a":
                        endian = "<"
                    elif bom == b"\x1a\x2b\x3c\x4d":
                        endian = ">"
                    else:
                        truncated = True
                        break
                    length = int.from_bytes(prefix[4:8], "little" if endian == "<" else "big")
                    if length < 28 or length > self.max_bytes - (consumed - 12):
                        truncated = True
                        break
                    remainder = stream.read(length - 12)
                    consumed += len(remainder)
                    if len(remainder) != length - 12 or int.from_bytes(remainder[-4:], "little" if endian == "<" else "big") != length:
                        truncated = True
                        break
                    interfaces = []
                    blocks += 1
                    continue
                if endian is None:
                    truncated = True
                    break
                length = int.from_bytes(prefix[4:8], "little" if endian == "<" else "big")
                if length < 12 or length > self.max_bytes - (consumed - 8):
                    truncated = True
                    break
                remainder = stream.read(length - 8)
                consumed += len(remainder)
                if len(remainder) != length - 8 or int.from_bytes(remainder[-4:], "little" if endian == "<" else "big") != length:
                    truncated = True
                    break
                blocks += 1
                block_type = int.from_bytes(block_type_raw, "little" if endian == "<" else "big")
                payload = remainder[:-4]
                if block_type == 1 and len(payload) >= 8:  # Interface Description Block
                    interfaces.append(int.from_bytes(payload[:2], "little" if endian == "<" else "big"))
                elif block_type == 6 and len(payload) >= 20:  # Enhanced Packet Block
                    interface_id = int.from_bytes(payload[:4], "little" if endian == "<" else "big")
                    captured = int.from_bytes(payload[12:16], "little" if endian == "<" else "big")
                    packet = payload[20:20 + captured]
                    if len(packet) != captured:
                        truncated = True
                        continue
                    stats.packets += 1
                    if interface_id < len(interfaces) and interfaces[interface_id] == 1:
                        self._decode_ethernet(packet, stats)
                elif block_type == 3 and len(payload) >= 4:  # Simple Packet Block
                    packet = payload[4:]
                    stats.packets += 1
                    if interfaces and interfaces[0] == 1:
                        self._decode_ethernet(packet, stats)
        long_labels = [query for query in stats.dns_queries if any(len(label) >= 40 for label in query.split("."))]
        txt_reassemblies = _reassemble_dns_txt_fragments(stats.dns_txt_fragments)
        txt_reassembly_requests = [
            {"packet_indices": item["packet_indices"], "request_packet_indices": item["request_packet_indices"]}
            for item in txt_reassemblies if isinstance(item.get("request_packet_indices"), list)
        ][:100]
        label_reassemblies = _reassemble_dns_label_fragments(stats.dns_label_fragments)
        source = "pcapng_triage"
        return [
            Observation(artifact.id, "pcap.format", "pcapng", source),
            Observation(artifact.id, "pcapng.block_count", blocks, source),
            Observation(artifact.id, "pcapng.interface_count", len(interfaces), source),
            Observation(artifact.id, "pcapng.linktypes", interfaces[:100], source),
            Observation(artifact.id, "pcap.packet_count", stats.packets, source),
            Observation(artifact.id, "pcap.scan_bytes", consumed, source),
            Observation(artifact.id, "pcap.scan_truncated", truncated or stats.packets >= self.max_packets, source),
            Observation(artifact.id, "pcap.protocol_counts", dict(stats.protocols), source),
            Observation(artifact.id, "pcap.endpoints", [host for host, _ in stats.endpoints.most_common(200)], source),
            Observation(artifact.id, "pcap.dns.query_count", len(stats.dns_queries), source),
            Observation(artifact.id, "pcap.dns.queries", stats.dns_queries[:2_000], source),
            Observation(artifact.id, "pcap.dns.long_labels", bool(long_labels), source),
            Observation(artifact.id, "pcap.dns.long_label_samples", long_labels[:100], source),
            Observation(artifact.id, "pcap.dns.txt_record_count", len(stats.dns_txt_records), source),
            Observation(artifact.id, "pcap.dns.txt_records", stats.dns_txt_records[:500], source),
            Observation(artifact.id, "pcap.dns.txt_fragments", stats.dns_txt_fragments[:2_000], source),
            Observation(artifact.id, "pcap.dns.txt_reassemblies", txt_reassemblies, source, 0.85),
            Observation(artifact.id, "pcap.dns.txt_reassembly_request_packets", txt_reassembly_requests, source, 0.9),
            Observation(artifact.id, "pcap.dns.transaction_match_count", len(stats.dns_transaction_matches), source),
            Observation(artifact.id, "pcap.dns.transaction_matches", stats.dns_transaction_matches[:2_000], source),
            Observation(artifact.id, "pcap.udp.printable_payloads", stats.udp_payloads[:500], source, 0.75),
            Observation(artifact.id, "pcap.icmp.printable_payloads", stats.icmp_payloads[:500], source, 0.75),
            Observation(artifact.id, "pcap.tcp.printable_payloads", _public_packet_payloads(stats.tcp_payloads), source, 0.75),
            Observation(artifact.id, "pcap.http.flow_state_truncated", stats.http_flow_state_truncated, source, 0.9),
            Observation(artifact.id, "pcap.dns.label_fragments", stats.dns_label_fragments[:2_000], source),
            Observation(artifact.id, "pcap.dns.label_reassemblies", label_reassemblies, source, 0.8),
            Observation(artifact.id, "pcap.http.request_count", stats.http_requests, source),
            Observation(artifact.id, "pcap.http.response_count", stats.http_responses, source),
            Observation(artifact.id, "pcap.http.requests", stats.http_requests_seen[:500], source),
            Observation(artifact.id, "pcap.http.has_objects", stats.http_requests > 0 or stats.http_responses > 0, source, 0.7),
            Observation(artifact.id, "pcap.tls.server_name_count", len(stats.tls_server_names), source),
            Observation(artifact.id, "pcap.tls.server_names", stats.tls_server_names[:500], source),
            Observation(artifact.id, "pcap.tls.client_hellos", stats.tls_client_hellos[:500], source),
            Observation(artifact.id, "pcap.tls.client_hello_errors", stats.tls_client_hello_errors[:500], source, 0.8),
            Observation(artifact.id, "pcap.tls.server_hellos", stats.tls_server_hellos[:500], source),
            Observation(artifact.id, "pcap.tls.negotiations", _tls_negotiations(stats)[:500], source, 0.9),
            Observation(artifact.id, "pcap.tls.server_hello_errors", stats.tls_server_hello_errors[:500], source, 0.8),
            Observation(artifact.id, "pcap.tls.certificates", stats.tls_certificates[:500], source, 0.9),
            Observation(artifact.id, "pcap.tls.certificate_errors", stats.tls_certificate_errors[:500], source, 0.8),
            Observation(artifact.id, "pcap.tls.certificate_flow_state_truncated", stats.tls_certificate_flow_state_truncated, source, 0.9),
            Observation(artifact.id, "pcap.tls.certificate_incomplete_flows", _tls_certificate_incomplete_flows(stats)[:500], source, 0.85),
            Observation(artifact.id, "pcap.tls.client_hello_flow_state_truncated", stats.tls_client_hello_flow_state_truncated, source, 0.9),
            Observation(artifact.id, "pcap.tls.client_hello_incomplete_flows", _tls_incomplete_flows(stats)[:500], source, 0.85),
            Observation(artifact.id, "pcap.tls.server_hello_flow_state_truncated", stats.tls_server_hello_flow_state_truncated, source, 0.9),
            Observation(artifact.id, "pcap.tls.server_hello_incomplete_flows", _tls_server_incomplete_flows(stats)[:500], source, 0.85),
        ]

    def _decode_ethernet(self, packet: bytes, stats: _PcapStats) -> None:
        if len(packet) < 14:
            return
        ethertype = int.from_bytes(packet[12:14], "big")
        offset = 14
        while ethertype in {0x8100, 0x88A8} and len(packet) >= offset + 4:
            ethertype = int.from_bytes(packet[offset + 2:offset + 4], "big")
            offset += 4
        if ethertype == 0x0800:
            self._decode_ipv4(packet[offset:], stats)
        elif ethertype == 0x86DD:
            self._decode_ipv6(packet[offset:], stats)

    def _decode_ipv4(self, data: bytes, stats: _PcapStats) -> None:
        if len(data) < 20 or data[0] >> 4 != 4:
            return
        header_length = (data[0] & 0x0F) * 4
        total_length = int.from_bytes(data[2:4], "big")
        if header_length < 20 or len(data) < header_length:
            return
        payload = data[header_length:min(len(data), total_length or len(data))]
        source, destination = str(ipaddress.IPv4Address(data[12:16])), str(ipaddress.IPv4Address(data[16:20]))
        stats.endpoints[source] += 1
        stats.endpoints[destination] += 1
        self._decode_ip_transport(payload, data[9], source, destination, stats)

    def _decode_ipv6(self, data: bytes, stats: _PcapStats) -> None:
        """Decode bounded IPv6 transport headers needed for DNS/HTTP triage.

        Extension-header traversal is limited to eight headers and validates
        every declared length.  Fragmented payloads with a non-zero fragment
        offset are not reassembled here; tshark remains the deep dissector.
        """
        if len(data) < 40 or data[0] >> 4 != 6:
            return
        declared_length = int.from_bytes(data[4:6], "big")
        end = min(len(data), 40 + declared_length)
        if end < 40:
            return
        source = str(ipaddress.IPv6Address(data[8:24]))
        destination = str(ipaddress.IPv6Address(data[24:40]))
        stats.protocols["ipv6"] += 1
        stats.endpoints[source] += 1
        stats.endpoints[destination] += 1
        next_header = data[6]
        offset = 40
        for _ in range(8):
            if next_header in {0, 43, 60}:  # Hop-by-Hop, Routing, Destination Options
                if offset + 2 > end:
                    return
                following = data[offset]
                header_length = (data[offset + 1] + 1) * 8
                if header_length < 8 or offset + header_length > end:
                    return
                stats.protocols["ipv6_extension"] += 1
                next_header = following
                offset += header_length
                continue
            if next_header == 44:  # Fragment: only offset-zero payload is useful without reassembly.
                if offset + 8 > end:
                    return
                following = data[offset]
                fragment_bits = int.from_bytes(data[offset + 2:offset + 4], "big")
                if (fragment_bits >> 3) != 0:
                    stats.protocols["ipv6_fragmented"] += 1
                    return
                stats.protocols["ipv6_extension"] += 1
                next_header = following
                offset += 8
                continue
            if next_header == 51:  # Authentication Header length is in 32-bit words minus two.
                if offset + 2 > end:
                    return
                following = data[offset]
                header_length = (data[offset + 1] + 2) * 4
                if header_length < 8 or offset + header_length > end:
                    return
                stats.protocols["ipv6_extension"] += 1
                next_header = following
                offset += header_length
                continue
            if next_header == 50:  # ESP is encrypted/authenticated; no ports can be trusted.
                stats.protocols["esp"] += 1
                return
            break
        self._decode_ip_transport(data[offset:end], next_header, source, destination, stats)

    def _decode_ip_transport(
        self, payload: bytes, protocol: int, source: str, destination: str, stats: _PcapStats
    ) -> None:
        if protocol == 17:
            stats.protocols["udp"] += 1
            self._decode_udp(payload, source, destination, stats)
        elif protocol == 6:
            stats.protocols["tcp"] += 1
            self._decode_tcp(payload, source, destination, stats)
        elif protocol == 1:
            stats.protocols["icmp"] += 1
            self._decode_icmp(payload, source, destination, "icmp", stats)
        elif protocol == 58:
            stats.protocols["icmpv6"] += 1
            self._decode_icmp(payload, source, destination, "icmpv6", stats)

    def _decode_icmp(self, data: bytes, source: str, destination: str, protocol: str, stats: _PcapStats) -> None:
        if len(data) < 8 or len(stats.icmp_payloads) >= 500:
            return
        payload = data[8:]
        preview = payload[:2_000]
        if len(preview) >= 8 and all(32 <= byte <= 126 or byte in {9, 10, 13} for byte in preview):
            stats.icmp_payloads.append({"packet_index": stats.packets, "protocol": protocol, "source": source, "destination": destination, "type": data[0], "code": data[1], "length": len(payload), "text": preview.decode("utf-8", errors="replace")})

    def _decode_udp(self, data: bytes, source: str, destination: str, stats: _PcapStats) -> None:
        if len(data) < 8:
            return
        source_port, destination_port = struct.unpack("!HH", data[:4])
        payload = data[8:]
        if source_port == 53 or destination_port == 53:
            stats.protocols["dns"] += 1
            transaction_id = int.from_bytes(payload[:2], "big") if len(payload) >= 2 else None
            is_response = len(payload) >= 3 and bool(payload[2] & 0x80)
            request_packet_index = None
            if transaction_id is not None and not is_response and len(stats.dns_transactions) < 4_000:
                stats.dns_transactions[(source, destination, source_port, destination_port, transaction_id)] = stats.packets
            elif transaction_id is not None and is_response:
                transaction_key = (destination, source, destination_port, source_port, transaction_id)
                request_packet_index = stats.dns_transactions.pop(transaction_key, None)
                if request_packet_index is not None and stats.packets - request_packet_index > _DNS_TRANSACTION_PACKET_WINDOW:
                    request_packet_index = None
                if request_packet_index is not None and len(stats.dns_transaction_matches) < 2_000:
                    stats.dns_transaction_matches.append({"transaction_id": transaction_id, "request_packet_index": request_packet_index, "response_packet_index": stats.packets, "client": destination, "server": source})
            query = _dns_query_name(payload)
            if query:
                stats.dns_queries.append(query)
                labels = query.split(".")
                if len(labels) >= 2 and len(stats.dns_label_fragments) < 2_000:
                    stats.dns_label_fragments.append({"text": labels[0], "suffix": ".".join(labels[1:]), "packet_index": stats.packets, "source": source, "destination": destination})
            if len(stats.dns_txt_records) < 2_000:
                records = _dns_txt_records(payload)[: 2_000 - len(stats.dns_txt_records)]
                stats.dns_txt_records.extend(records)
                for record in records:
                    if len(stats.dns_txt_fragments) >= 2_000:
                        break
                    stats.dns_txt_fragments.append({
                        "text": record["text"], "packet_index": stats.packets,
                        "source": source, "destination": destination,
                        "transaction_id": transaction_id, "request_packet_index": request_packet_index,
                    })
        elif len(stats.udp_payloads) < 500:
            preview = payload[:2_000]
            if len(preview) >= 8 and all(32 <= byte <= 126 or byte in {9, 10, 13} for byte in preview):
                stats.udp_payloads.append({"packet_index": stats.packets, "source": source, "destination": destination, "source_port": source_port, "destination_port": destination_port, "length": len(payload), "text": preview.decode("utf-8", errors="replace")})

    def _decode_tcp(self, data: bytes, source: str, destination: str, stats: _PcapStats) -> None:
        if len(data) < 20:
            return
        source_port, destination_port = struct.unpack("!HH", data[:4])
        header_length = (data[12] >> 4) * 4
        if header_length < 20 or len(data) < header_length:
            return
        payload = data[header_length:]
        flow = (source, source_port, destination, destination_port)
        is_http_payload = payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"PATCH ", b"HTTP/"))
        if source_port in {80, 8080, 8000} or destination_port in {80, 8080, 8000}:
            if payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"PATCH ")):
                stats.protocols["http"] += 1
                stats.http_requests += 1
                request = _http_request(payload)
                if request:
                    stats.http_requests_seen.append(request)
            elif payload.startswith(b"HTTP/"):
                stats.protocols["http"] += 1
                stats.http_responses += 1
            if is_http_payload:
                if flow in stats.http_flows or len(stats.http_flows) < _MAX_HTTP_FLOW_STATE:
                    stats.http_flows.add(flow)
                else:
                    stats.http_flow_state_truncated = True
                stats.tcp_payloads[:] = [item for item in stats.tcp_payloads if item.get("_flow") != flow]
        if source_port in {443, 8443, 9443} or destination_port in {443, 8443, 9443}:
            stats.protocols["tls"] += 1
            sequence = struct.unpack("!I", data[4:8])[0]
            hello, packet_indices, waiting_for_continuation = _tls_client_hello_from_tcp_segment(
                flow, sequence, payload, stats
            )
            if hello:
                if hello.get("server_name"):
                    stats.tls_server_names.append(str(hello["server_name"]))
                if len(stats.tls_client_hellos) < 500:
                    stats.tls_client_hellos.append({
                        **hello, "packet_index": stats.packets, "source": source, "destination": destination,
                        "source_port": source_port, "destination_port": destination_port,
                        "packet_indices": packet_indices,
                    })
            elif not waiting_for_continuation and payload.startswith(b"\x16") and len(payload) >= 6 and payload[5] == 0x01 and len(stats.tls_client_hello_errors) < 500:
                stats.tls_client_hello_errors.append({
                    "packet_index": stats.packets, "source": source, "destination": destination,
                    "source_port": source_port, "destination_port": destination_port,
                    "error": "TLS ClientHello record or extension bounds did not validate",
                })
            server_hello, server_packet_indices, server_waiting_for_continuation, server_error_reported = _tls_server_hello_from_tcp_segment(
                flow, sequence, payload, stats
            )
            if server_hello and len(stats.tls_server_hellos) < 500:
                stats.tls_server_hellos.append({
                    **server_hello, "packet_index": stats.packets, "source": source, "destination": destination,
                    "source_port": source_port, "destination_port": destination_port,
                    "packet_indices": server_packet_indices,
                })
            elif not server_waiting_for_continuation and not server_error_reported and payload.startswith(b"\x16") and len(payload) >= 6 and payload[5] == 0x02 and len(stats.tls_server_hello_errors) < 500:
                expected_length = 5 + int.from_bytes(payload[3:5], "big")
                stats.tls_server_hello_errors.append({
                    "packet_index": stats.packets, "source": source, "destination": destination,
                    "source_port": source_port, "destination_port": destination_port,
                    "packet_indices": server_packet_indices,
                    "captured_length": len(payload), "expected_length": expected_length,
                    "incomplete": len(payload) < expected_length,
                    "error": "TLS ServerHello record or extension bounds did not validate",
                })
            certificate, certificate_packet_indices, certificate_waiting_for_continuation, certificate_error_reported = _tls_certificate_from_tcp_segment(
                flow, sequence, payload, stats
            )
            if certificate and len(stats.tls_certificates) < 500:
                stats.tls_certificates.append({
                    **certificate, "packet_index": stats.packets, "packet_indices": certificate_packet_indices,
                    "source": source, "destination": destination,
                    "source_port": source_port, "destination_port": destination_port,
                })
        if len(stats.tcp_payloads) < 500 and payload and flow not in stats.http_flows and not is_http_payload and not payload.startswith(b"\x16\x03"):
            preview = payload[:2_000]
            if len(preview) >= 8 and all(32 <= byte <= 126 or byte in {9, 10, 13} for byte in preview):
                stats.tcp_payloads.append({"packet_index": stats.packets, "source": source, "destination": destination, "source_port": source_port, "destination_port": destination_port, "length": len(payload), "text": preview.decode("utf-8", errors="replace"), "_flow": flow})


def _public_packet_payloads(payloads: list[dict[str, object]] | None) -> list[dict[str, object]]:
    if not payloads:
        return []
    return [{key: value for key, value in item.items() if key != "_flow"} for item in payloads[:500]]


def _tls_incomplete_flows(stats: _PcapStats) -> list[dict[str, object]]:
    if not stats.tls_client_hello_flows:
        return []
    rows: list[dict[str, object]] = []
    for flow, state in sorted(stats.tls_client_hello_flows.items()):
        data = state.get("data")
        expected = state.get("expected_length")
        packets = state.get("packet_indices")
        if not isinstance(data, bytes) or not isinstance(expected, int) or not isinstance(packets, list):
            continue
        rows.append({
            "source": flow[0], "source_port": flow[1], "destination": flow[2], "destination_port": flow[3],
            "packet_indices": packets[:64], "captured_length": len(data), "expected_length": expected,
        })
        if len(rows) >= 500:
            break
    return rows


def _tls_server_incomplete_flows(stats: _PcapStats) -> list[dict[str, object]]:
    if not stats.tls_server_hello_flows:
        return []
    rows: list[dict[str, object]] = []
    for flow, state in sorted(stats.tls_server_hello_flows.items()):
        data = state.get("data")
        expected = state.get("expected_length")
        packets = state.get("packet_indices")
        if not isinstance(data, bytes) or not isinstance(expected, int) or not isinstance(packets, list):
            continue
        rows.append({
            "source": flow[0], "source_port": flow[1], "destination": flow[2], "destination_port": flow[3],
            "packet_indices": packets[:64], "captured_length": len(data), "expected_length": expected,
        })
        if len(rows) >= 500:
            break
    return rows


def _tls_certificate_incomplete_flows(stats: _PcapStats) -> list[dict[str, object]]:
    if not stats.tls_certificate_flows:
        return []
    rows: list[dict[str, object]] = []
    for flow, state in sorted(stats.tls_certificate_flows.items()):
        data = state.get("data")
        expected = state.get("expected_length")
        packets = state.get("packet_indices")
        if not isinstance(data, bytes) or not isinstance(expected, int) or not isinstance(packets, list):
            continue
        rows.append({
            "source": flow[0], "source_port": flow[1], "destination": flow[2], "destination_port": flow[3],
            "packet_indices": packets[:64], "captured_length": len(data), "expected_length": expected,
        })
        if len(rows) >= 500:
            break
    return rows


def _tls_negotiations(stats: _PcapStats) -> list[dict[str, object]]:
    if not stats.tls_client_hellos or not stats.tls_server_hellos:
        return []
    negotiations: list[dict[str, object]] = []
    for server in stats.tls_server_hellos:
        candidates = [
            client for client in stats.tls_client_hellos
            if client.get("source") == server.get("destination")
            and client.get("destination") == server.get("source")
            and client.get("source_port") == server.get("destination_port")
            and client.get("destination_port") == server.get("source_port")
            and isinstance(client.get("packet_index"), int) and isinstance(server.get("packet_index"), int)
            and client["packet_index"] <= server["packet_index"]
        ]
        if not candidates:
            continue
        client = candidates[-1]
        offered = client.get("alpn_protocols") if isinstance(client.get("alpn_protocols"), list) else []
        selected = server.get("selected_alpn")
        negotiations.append({
            "client_hello_packet_indices": client.get("packet_indices", [client.get("packet_index")]),
            "server_hello_packet_index": server.get("packet_index"), "server_name": client.get("server_name"),
            "offered_alpn": offered, "selected_alpn": selected,
            "selected_alpn_offered": selected in offered if isinstance(selected, str) else None,
            "cipher_suite": server.get("cipher_suite"),
        })
        if len(negotiations) >= 500:
            break
    return negotiations


def _dns_query_name(payload: bytes) -> str | None:
    if len(payload) < 13 or payload[4:6] == b"\x00\x00":
        return None
    offset = 12
    labels: list[str] = []
    for _ in range(128):
        if offset >= len(payload):
            return None
        length = payload[offset]
        offset += 1
        if length == 0:
            return ".".join(labels) if labels else None
        if length & 0xC0 or length > 63 or offset + length > len(payload):
            return None
        label = payload[offset:offset + length]
        offset += length
        labels.append(label.decode("ascii", errors="replace"))
    return None


def _dns_skip_name(payload: bytes, offset: int) -> int | None:
    """Return the byte after one DNS name, accepting compressed pointers."""
    for _ in range(128):
        if offset >= len(payload):
            return None
        length = payload[offset]
        offset += 1
        if length == 0:
            return offset
        if length & 0xC0 == 0xC0:
            return offset + 1 if offset < len(payload) else None
        if length & 0xC0 or length > 63 or offset + length > len(payload):
            return None
        offset += length
    return None


def _dns_txt_records(payload: bytes) -> list[dict[str, str]]:
    """Recover bounded plaintext TXT answers; no name-pointer dereference."""
    if len(payload) < 12 or not (payload[2] & 0x80):
        return []
    questions = int.from_bytes(payload[4:6], "big")
    answers = int.from_bytes(payload[6:8], "big")
    if questions > 100 or answers > 500:
        return []
    offset = 12
    for _ in range(questions):
        offset = _dns_skip_name(payload, offset)
        if offset is None or offset + 4 > len(payload):
            return []
        offset += 4
    results: list[dict[str, str]] = []
    for _ in range(answers):
        name_offset = _dns_skip_name(payload, offset)
        if name_offset is None or name_offset + 10 > len(payload):
            break
        record_type = int.from_bytes(payload[name_offset:name_offset + 2], "big")
        data_length = int.from_bytes(payload[name_offset + 8:name_offset + 10], "big")
        data_offset = name_offset + 10
        if data_offset + data_length > len(payload):
            break
        if record_type == 16:
            cursor, strings = data_offset, []
            end = data_offset + data_length
            while cursor < end and len(strings) < 32:
                length = payload[cursor]
                cursor += 1
                if cursor + length > end:
                    strings = []
                    break
                strings.append(payload[cursor:cursor + length].decode("utf-8", errors="replace")[:1_000])
                cursor += length
            if strings:
                results.append({"text": "".join(strings)[:4_000]})
        offset = data_offset + data_length
    return results


def _reassemble_dns_txt_fragments(fragments: list[dict[str, object]] | None) -> list[dict[str, object]]:
    """Join only adjacent, encoding-shaped TXT fragments with packet provenance."""
    if not fragments:
        return []
    groups: dict[tuple[str, str, object], list[dict[str, object]]] = {}
    for item in fragments[:2_000]:
        text, source, destination = item.get("text"), item.get("source"), item.get("destination")
        if not all(isinstance(value, str) for value in (text, source, destination)):
            continue
        if not re.fullmatch(r"[A-Za-z0-9+/_=-]{4,1024}", text):
            continue
        transaction = item.get("request_packet_index")
        if not isinstance(transaction, int):
            transaction = item.get("transaction_id")
        groups.setdefault((source, destination, transaction), []).append(item)
    results: list[dict[str, object]] = []
    for (source, destination, _transaction), items in sorted(groups.items(), key=lambda item: str(item[0])):
        deduplicated: list[dict[str, object]] = []
        for item in items:
            if deduplicated and item["text"] == deduplicated[-1]["text"]:
                continue
            deduplicated.append(item)
        for start in range(0, len(deduplicated) - 1, 64):
            chunk = deduplicated[start:start + 64]
            joined = "".join(str(item["text"]) for item in chunk)
            if len(chunk) < 2 or len(joined) > 65_536:
                continue
            decoded = ""
            try:
                padded = joined + "=" * (-len(joined) % 4)
                raw = base64.b64decode(padded, validate=True)
                decoded = raw.decode("utf-8", errors="replace")[:4_000]
            except (ValueError, UnicodeError):
                pass
            result = {
                "source": source, "destination": destination,
                "packet_indices": [int(item["packet_index"]) for item in chunk],
                "fragment_count": len(chunk), "text": joined[:65_536],
                "transform": "base64" if decoded else "identity",
                "decoded_text": decoded,
            }
            request_packets = sorted({item["request_packet_index"] for item in chunk if isinstance(item.get("request_packet_index"), int)})
            if request_packets:
                result["request_packet_indices"] = request_packets
            results.append(result)
            if len(results) >= 100:
                return results
    return results


def _reassemble_dns_label_fragments(fragments: list[dict[str, object]] | None) -> list[dict[str, object]]:
    if not fragments:
        return []
    grouped: dict[tuple[str, str, str], list[dict[str, object]]] = {}
    for item in fragments[:2_000]:
        text, source, destination, suffix = (item.get(key) for key in ("text", "source", "destination", "suffix"))
        if not all(isinstance(value, str) for value in (text, source, destination, suffix)) or not re.fullmatch(r"[A-Za-z0-9+/_=-]{4,63}", text):
            continue
        grouped.setdefault((source, destination, suffix), []).append(item)
    results: list[dict[str, object]] = []
    for (source, destination, suffix), items in sorted(grouped.items()):
        deduplicated: list[dict[str, object]] = []
        for item in items:
            if deduplicated and item["text"] == deduplicated[-1]["text"]:
                continue
            deduplicated.append(item)
        if len(deduplicated) < 2:
            continue
        joined = "".join(str(item["text"]) for item in deduplicated[:64])
        try:
            if re.fullmatch(r"[0-9a-fA-F]+", joined) and len(joined) % 2 == 0:
                raise ValueError
            decoded = base64.b64decode(joined + "=" * (-len(joined) % 4), validate=True).decode("utf-8", errors="replace")[:4_000]
            transform = "base64"
        except (ValueError, UnicodeError):
            try:
                decoded = bytes.fromhex(joined).decode("utf-8", errors="replace")[:4_000]
                transform = "hex"
            except ValueError:
                continue
        results.append({"source": source, "destination": destination, "suffix": suffix, "packet_indices": [int(item["packet_index"]) for item in deduplicated[:64]], "fragment_count": min(len(deduplicated), 64), "text": joined[:65_536], "transform": transform, "decoded_text": decoded})
        if len(results) >= 100:
            break
    return results


def _http_request(payload: bytes) -> dict[str, str] | None:
    header = payload[:32_768].decode("latin-1", errors="replace")
    lines = header.split("\r\n")
    if not lines:
        return None
    first = lines[0].split()
    if len(first) < 2 or first[0] not in {"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"}:
        return None
    result = {"method": first[0], "uri": first[1][:2_000]}
    for line in lines[1:]:
        if not line:
            break
        if line.lower().startswith("host:"):
            result["host"] = line.split(":", 1)[1].strip()[:1_000]
        elif line.lower().startswith("content-type:"):
            result["content_type"] = line.split(":", 1)[1].strip()[:500]
    return result


def _tls_client_hello_from_tcp_segment(
    flow: tuple[str, int, str, int], sequence: int, payload: bytes, stats: _PcapStats,
) -> tuple[dict[str, object] | None, list[int], bool]:
    """Reassemble only an in-order, bounded TLS ClientHello record prefix."""
    state = stats.tls_client_hello_flows.pop(flow, None)
    packet_indices = [stats.packets]
    if state is not None:
        next_sequence = state.get("next_sequence")
        buffered = state.get("data")
        previous_packets = state.get("packet_indices")
        start_sequence = state.get("start_sequence")
        if (
            isinstance(next_sequence, int) and isinstance(start_sequence, int) and isinstance(buffered, bytes)
            and isinstance(previous_packets, list) and sequence >= start_sequence and sequence + len(payload) <= next_sequence
            and buffered[sequence - start_sequence:sequence - start_sequence + len(payload)] == payload
        ):
            stats.tls_client_hello_flows[flow] = state
            return None, previous_packets, True
        if not isinstance(next_sequence, int) or sequence != next_sequence or not isinstance(buffered, bytes) or not isinstance(previous_packets, list):
            if len(stats.tls_client_hello_errors) < 500:
                stats.tls_client_hello_errors.append({
                    "packet_index": stats.packets, "source": flow[0], "destination": flow[2],
                    "source_port": flow[1], "destination_port": flow[3],
                    "packet_indices": previous_packets if isinstance(previous_packets, list) else [],
                    "captured_length": len(buffered) if isinstance(buffered, bytes) else None,
                    "expected_length": state.get("expected_length"),
                    "error": "TLS ClientHello continuation was out of order or had a TCP sequence gap",
                })
            return None, packet_indices, False
        combined = buffered + payload
        packet_indices = [*previous_packets, stats.packets]
        expected = state.get("expected_length")
        if not isinstance(expected, int) or len(combined) > expected:
            if len(stats.tls_client_hello_errors) < 500:
                stats.tls_client_hello_errors.append({
                    "packet_index": stats.packets, "source": flow[0], "destination": flow[2],
                    "source_port": flow[1], "destination_port": flow[3], "packet_indices": packet_indices,
                    "captured_length": len(combined), "expected_length": expected,
                    "error": "TLS ClientHello continuation exceeded its declared TLS record length",
                })
            return None, packet_indices, False
        hello = _tls_client_hello_metadata(combined) if len(combined) == expected else None
        if hello:
            return hello, packet_indices, False
        if len(combined) == expected:
            return None, packet_indices, False
        stats.tls_client_hello_flows[flow] = {
            "start_sequence": start_sequence, "next_sequence": sequence + len(payload), "expected_length": expected,
            "data": combined, "packet_indices": packet_indices,
        }
        return None, packet_indices, True

    hello = _tls_client_hello_metadata(payload)
    if hello:
        return hello, packet_indices, False
    if len(payload) < 9 or payload[0] != 0x16 or payload[5] != 0x01:
        return None, packet_indices, False
    expected = 5 + int.from_bytes(payload[3:5], "big")
    if expected <= len(payload) or expected > _MAX_TLS_CLIENT_HELLO_BYTES:
        return None, packet_indices, False
    if len(stats.tls_client_hello_flows) >= _MAX_TLS_CLIENT_HELLO_FLOWS:
        stats.tls_client_hello_flow_state_truncated = True
        return None, packet_indices, False
    stats.tls_client_hello_flows[flow] = {
        "start_sequence": sequence, "next_sequence": sequence + len(payload), "expected_length": expected,
        "data": payload, "packet_indices": packet_indices,
    }
    return None, packet_indices, True


def _tls_client_hello_metadata(payload: bytes) -> dict[str, object] | None:
    """Return bounded plaintext ClientHello metadata from one complete TLS record."""
    if len(payload) < 9 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    record_length = int.from_bytes(payload[3:5], "big")
    handshake_length = int.from_bytes(payload[6:9], "big")
    if record_length + 5 > len(payload) or handshake_length + 9 > len(payload):
        return None
    body = payload[9:9 + handshake_length]
    if len(body) < 35:
        return None
    offset = 34  # legacy_version + random
    session_length = body[offset]
    offset += 1 + session_length
    if offset + 2 > len(body):
        return None
    cipher_length = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2 + cipher_length
    if offset >= len(body):
        return None
    compression_length = body[offset]
    offset += 1 + compression_length
    if offset + 2 > len(body):
        return None
    extensions_length = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2
    end = min(len(body), offset + extensions_length)
    server_name: str | None = None
    alpn_protocols: list[str] = []
    while offset + 4 <= end:
        extension_type = int.from_bytes(body[offset:offset + 2], "big")
        extension_length = int.from_bytes(body[offset + 2:offset + 4], "big")
        offset += 4
        if offset + extension_length > end:
            return None
        if extension_type == 0 and extension_length >= 5:
            names = body[offset:offset + extension_length]
            list_length = int.from_bytes(names[:2], "big")
            if list_length + 2 > len(names) or names[2] != 0:
                return None
            name_length = int.from_bytes(names[3:5], "big")
            if name_length == 0 or 5 + name_length > len(names):
                return None
            server_name = names[5:5 + name_length].decode("ascii", errors="replace")[:1_000]
        elif extension_type == 16 and extension_length >= 2:
            protocols = body[offset:offset + extension_length]
            total = int.from_bytes(protocols[:2], "big")
            if total + 2 > len(protocols):
                return None
            alpn: list[str] = []
            position = 2
            end_protocols = 2 + total
            while position < end_protocols and len(alpn) < 32:
                protocol_length = protocols[position]
                position += 1
                if not protocol_length or position + protocol_length > end_protocols:
                    return None
                alpn.append(protocols[position:position + protocol_length].decode("ascii", errors="replace")[:255])
                position += protocol_length
            if position != end_protocols:
                return None
            alpn_protocols = alpn
        offset += extension_length
    if server_name is None and not alpn_protocols:
        return None
    return {
        "record_version": f"0x{int.from_bytes(payload[1:3], 'big'):04X}",
        "server_name": server_name,
        "alpn_protocols": alpn_protocols,
    }


def _tls_client_hello_sni(payload: bytes) -> str | None:
    metadata = _tls_client_hello_metadata(payload)
    server_name = metadata.get("server_name") if metadata else None
    return server_name if isinstance(server_name, str) else None


def _record_tls_server_hello_error(
    stats: _PcapStats,
    flow: tuple[str, int, str, int],
    packet_indices: list[int],
    captured_length: int | None,
    expected_length: object,
    error: str,
) -> None:
    if len(stats.tls_server_hello_errors) >= 500:
        return
    stats.tls_server_hello_errors.append({
        "packet_index": stats.packets, "source": flow[0], "destination": flow[2],
        "source_port": flow[1], "destination_port": flow[3], "packet_indices": packet_indices,
        "captured_length": captured_length, "expected_length": expected_length,
        "incomplete": False, "error": error,
    })


def _tls_server_hello_from_tcp_segment(
    flow: tuple[str, int, str, int], sequence: int, payload: bytes, stats: _PcapStats,
) -> tuple[dict[str, object] | None, list[int], bool, bool]:
    """Reassemble only an in-order, bounded TLS ServerHello record prefix."""
    state = stats.tls_server_hello_flows.pop(flow, None)
    packet_indices = [stats.packets]
    if state is not None:
        next_sequence = state.get("next_sequence")
        buffered = state.get("data")
        previous_packets = state.get("packet_indices")
        start_sequence = state.get("start_sequence")
        if (
            isinstance(next_sequence, int) and isinstance(start_sequence, int) and isinstance(buffered, bytes)
            and isinstance(previous_packets, list) and sequence >= start_sequence and sequence + len(payload) <= next_sequence
            and buffered[sequence - start_sequence:sequence - start_sequence + len(payload)] == payload
        ):
            stats.tls_server_hello_flows[flow] = state
            return None, previous_packets, True, False
        if not isinstance(next_sequence, int) or sequence != next_sequence or not isinstance(buffered, bytes) or not isinstance(previous_packets, list):
            _record_tls_server_hello_error(
                stats, flow, previous_packets if isinstance(previous_packets, list) else [],
                len(buffered) if isinstance(buffered, bytes) else None, state.get("expected_length"),
                "TLS ServerHello continuation was out of order or had a TCP sequence gap",
            )
            return None, packet_indices, False, True
        packet_indices = [*previous_packets, stats.packets]
        expected = state.get("expected_length")
        combined = buffered + payload
        if not isinstance(expected, int) or len(combined) > expected:
            _record_tls_server_hello_error(
                stats, flow, packet_indices, len(combined), expected,
                "TLS ServerHello continuation exceeded its declared TLS record length",
            )
            return None, packet_indices, False, True
        hello = _tls_server_hello_metadata(combined) if len(combined) == expected else None
        if hello:
            return hello, packet_indices, False, False
        if len(combined) == expected:
            _record_tls_server_hello_error(
                stats, flow, packet_indices, len(combined), expected,
                "TLS ServerHello record or extension bounds did not validate",
            )
            return None, packet_indices, False, True
        stats.tls_server_hello_flows[flow] = {
            "start_sequence": start_sequence, "next_sequence": sequence + len(payload), "expected_length": expected,
            "data": combined, "packet_indices": packet_indices,
        }
        return None, packet_indices, True, False

    hello = _tls_server_hello_metadata(payload)
    if hello:
        return hello, packet_indices, False, False
    if len(payload) < 9 or payload[0] != 0x16 or payload[5] != 0x02:
        return None, packet_indices, False, False
    expected = 5 + int.from_bytes(payload[3:5], "big")
    if expected <= len(payload) or expected > _MAX_TLS_SERVER_HELLO_BYTES:
        return None, packet_indices, False, False
    if len(stats.tls_server_hello_flows) >= _MAX_TLS_SERVER_HELLO_FLOWS:
        stats.tls_server_hello_flow_state_truncated = True
        return None, packet_indices, False, False
    stats.tls_server_hello_flows[flow] = {
        "start_sequence": sequence, "next_sequence": sequence + len(payload), "expected_length": expected,
        "data": payload, "packet_indices": packet_indices,
    }
    return None, packet_indices, True, False


def _tls_server_hello_metadata(payload: bytes) -> dict[str, object] | None:
    """Return selected ALPN and fixed fields from one complete plaintext ServerHello."""
    if len(payload) < 9 or payload[0] != 0x16 or payload[5] != 0x02:
        return None
    record_length = int.from_bytes(payload[3:5], "big")
    handshake_length = int.from_bytes(payload[6:9], "big")
    if record_length + 5 > len(payload) or handshake_length + 9 > len(payload):
        return None
    body = payload[9:9 + handshake_length]
    if len(body) < 38:
        return None
    session_length = body[34]
    offset = 35 + session_length
    if offset + 5 > len(body):
        return None
    cipher_suite = f"0x{int.from_bytes(body[offset:offset + 2], 'big'):04X}"
    offset += 3
    extensions_length = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2
    if offset + extensions_length > len(body):
        return None
    selected_alpn: str | None = None
    end = offset + extensions_length
    while offset + 4 <= end:
        extension_type = int.from_bytes(body[offset:offset + 2], "big")
        extension_length = int.from_bytes(body[offset + 2:offset + 4], "big")
        offset += 4
        if offset + extension_length > end:
            return None
        if extension_type == 16:
            if extension_length < 3:
                return None
            list_length = int.from_bytes(body[offset:offset + 2], "big")
            protocol_length = body[offset + 2]
            if list_length != protocol_length + 1 or not protocol_length or protocol_length + 3 != extension_length:
                return None
            selected_alpn = body[offset + 3:offset + 3 + protocol_length].decode("ascii", errors="replace")[:255]
        offset += extension_length
    if offset != end:
        return None
    return {
        "record_version": f"0x{int.from_bytes(payload[1:3], 'big'):04X}",
        "cipher_suite": cipher_suite,
        "selected_alpn": selected_alpn,
    }


def _record_tls_certificate_error(
    stats: _PcapStats,
    flow: tuple[str, int, str, int],
    packet_indices: list[int],
    captured_length: int | None,
    expected_length: object,
    error: str,
) -> None:
    if len(stats.tls_certificate_errors) >= 500:
        return
    stats.tls_certificate_errors.append({
        "packet_index": stats.packets, "source": flow[0], "destination": flow[2],
        "source_port": flow[1], "destination_port": flow[3], "packet_indices": packet_indices,
        "captured_length": captured_length, "expected_length": expected_length,
        "incomplete": False, "error": error,
    })


def _tls_certificate_from_tcp_segment(
    flow: tuple[str, int, str, int], sequence: int, payload: bytes, stats: _PcapStats,
) -> tuple[dict[str, object] | None, list[int], bool, bool]:
    """Reassemble one in-order bounded TLS Certificate record without decryption."""
    state = stats.tls_certificate_flows.pop(flow, None)
    packet_indices = [stats.packets]
    if state is not None:
        next_sequence = state.get("next_sequence")
        buffered = state.get("data")
        previous_packets = state.get("packet_indices")
        start_sequence = state.get("start_sequence")
        if (
            isinstance(next_sequence, int) and isinstance(start_sequence, int) and isinstance(buffered, bytes)
            and isinstance(previous_packets, list) and sequence >= start_sequence and sequence + len(payload) <= next_sequence
            and buffered[sequence - start_sequence:sequence - start_sequence + len(payload)] == payload
        ):
            stats.tls_certificate_flows[flow] = state
            return None, previous_packets, True, False
        if not isinstance(next_sequence, int) or sequence != next_sequence or not isinstance(buffered, bytes) or not isinstance(previous_packets, list):
            _record_tls_certificate_error(
                stats, flow, previous_packets if isinstance(previous_packets, list) else [],
                len(buffered) if isinstance(buffered, bytes) else None, state.get("expected_length"),
                "TLS Certificate continuation was out of order or had a TCP sequence gap",
            )
            return None, packet_indices, False, True
        packet_indices = [*previous_packets, stats.packets]
        expected = state.get("expected_length")
        combined = buffered + payload
        if not isinstance(expected, int) or len(combined) > expected:
            _record_tls_certificate_error(
                stats, flow, packet_indices, len(combined), expected,
                "TLS Certificate continuation exceeded its declared TLS record length",
            )
            return None, packet_indices, False, True
        certificate, error = _tls_certificate_metadata(combined) if len(combined) == expected else (None, None)
        if certificate:
            return certificate, packet_indices, False, False
        if len(combined) == expected:
            _record_tls_certificate_error(
                stats, flow, packet_indices, len(combined), expected,
                error or "TLS Certificate record or list bounds did not validate",
            )
            return None, packet_indices, False, True
        stats.tls_certificate_flows[flow] = {
            "start_sequence": start_sequence, "next_sequence": sequence + len(payload), "expected_length": expected,
            "data": combined, "packet_indices": packet_indices,
        }
        return None, packet_indices, True, False

    if len(payload) < 9 or payload[0] != 0x16 or payload[5] != 0x0B:
        return None, packet_indices, False, False
    expected = 5 + int.from_bytes(payload[3:5], "big")
    if expected > _MAX_TLS_CERTIFICATE_BYTES:
        _record_tls_certificate_error(
            stats, flow, packet_indices, len(payload), expected,
            "TLS Certificate declared record length exceeds the 64 KiB native analysis bound",
        )
        return None, packet_indices, False, True
    if len(payload) < expected:
        if len(stats.tls_certificate_flows) >= _MAX_TLS_CERTIFICATE_FLOWS:
            stats.tls_certificate_flow_state_truncated = True
            return None, packet_indices, False, False
        stats.tls_certificate_flows[flow] = {
            "start_sequence": sequence, "next_sequence": sequence + len(payload), "expected_length": expected,
            "data": payload, "packet_indices": packet_indices,
        }
        return None, packet_indices, True, False
    certificate, error = _tls_certificate_metadata(payload[:expected])
    if certificate:
        return certificate, packet_indices, False, False
    _record_tls_certificate_error(
        stats, flow, packet_indices, expected, expected,
        error or "TLS Certificate record or list bounds did not validate",
    )
    return None, packet_indices, False, True


def _tls_certificate_metadata(payload: bytes) -> tuple[dict[str, object] | None, str | None]:
    """Inventory one complete TLS Certificate handshake without X.509 decoding.

    Only one self-contained TLS record is accepted. Certificate bytes remain
    opaque: SHA-256 fingerprints and declared lengths make the lead reviewable
    without loading a crypto stack or claiming subject/issuer semantics.
    """
    if len(payload) < 12 or payload[0] != 0x16 or payload[5] != 0x0B:
        return None, None
    record_length = int.from_bytes(payload[3:5], "big")
    handshake_length = int.from_bytes(payload[6:9], "big")
    if record_length + 5 > len(payload) or handshake_length + 4 != record_length:
        return None, "TLS Certificate record or handshake length did not validate"
    body = payload[9:9 + handshake_length]
    tls12_entries = _tls12_certificate_entries(body)
    if tls12_entries is not None:
        return _tls_certificate_inventory(payload, "tls12", tls12_entries), None
    tls13 = _tls13_certificate_entries(body)
    if tls13 is not None:
        context_length, entries = tls13
        metadata = _tls_certificate_inventory(payload, "tls13", entries)
        metadata["request_context_length"] = context_length
        return metadata, None
    return None, "TLS Certificate list bounds or DER framing did not validate"


def _tls12_certificate_entries(body: bytes) -> list[bytes] | None:
    if len(body) < 6:
        return None
    list_length = int.from_bytes(body[:3], "big")
    if list_length != len(body) - 3:
        return None
    return _tls_certificate_entries(body, 3, len(body), tls13=False)


def _tls13_certificate_entries(body: bytes) -> tuple[int, list[bytes]] | None:
    if len(body) < 7:
        return None
    context_length = body[0]
    offset = 1 + context_length
    if offset + 3 > len(body):
        return None
    list_length = int.from_bytes(body[offset:offset + 3], "big")
    offset += 3
    end = offset + list_length
    if list_length == 0 or end != len(body):
        return None
    entries = _tls_certificate_entries(body, offset, end, tls13=True)
    return (context_length, entries) if entries is not None else None


def _tls_certificate_entries(body: bytes, offset: int, end: int, *, tls13: bool) -> list[bytes] | None:
    entries: list[bytes] = []
    while offset < end:
        if len(entries) >= _MAX_TLS_CERTIFICATE_ENTRIES or offset + 3 > end:
            return None
        certificate_length = int.from_bytes(body[offset:offset + 3], "big")
        offset += 3
        if certificate_length < 2 or offset + certificate_length > end:
            return None
        certificate = body[offset:offset + certificate_length]
        if certificate[0] != 0x30:
            return None
        entries.append(certificate)
        offset += certificate_length
        if tls13:
            if offset + 2 > end:
                return None
            extension_length = int.from_bytes(body[offset:offset + 2], "big")
            offset += 2
            if offset + extension_length > end:
                return None
            offset += extension_length
    return entries if entries and offset == end else None


def _tls_certificate_inventory(payload: bytes, certificate_format: str, entries: list[bytes]) -> dict[str, object]:
    return {
        "record_version": f"0x{int.from_bytes(payload[1:3], 'big'):04X}",
        "certificate_format": certificate_format,
        "certificate_count": len(entries),
        "certificate_lengths": [len(entry) for entry in entries],
        "certificate_sha256": [hashlib.sha256(entry).hexdigest() for entry in entries],
    }


def iter_ftp_retr_objects(
    path: Path, *, max_objects: int = 32, max_body_bytes: int = 64 * 1024 * 1024,
    max_packets: int = 200_000, max_scan_bytes: int = 128 * 1024 * 1024,
) -> Iterator[FtpDataObject]:
    """Recover only PASV-correlated FTP RETR streams from Ethernet captures.

    A data flow is accepted only after a client ``RETR`` on TCP/21 and its
    exact inverse control flow emits a syntactically valid IPv4 ``227``
    response.  The advertised server address is deliberately ignored in
    favour of the observed control endpoint, preventing a control payload
    from redirecting extraction to unrelated traffic.
    """
    commands: dict[tuple[str, int, str, int], tuple[str, int, str]] = {}
    transfers: dict[tuple[str, int, str], tuple[str, int, int, str]] = {}
    active_endpoints: dict[tuple[str, int, str, int], tuple[int, int]] = {}
    active_transfers: dict[tuple[str, str, int, str], tuple[str, int, int, str]] = {}
    completions: dict[int, tuple[int, int]] = {}
    data_flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    data_transfer_meta: dict[tuple[str, int, str, int], tuple[str, int, int, str]] = {}
    control_flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    auth_tls_commands: dict[tuple[str, int, str, int], int] = {}
    encrypted_control_flows: set[tuple[str, int, str, int]] = set()
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None:
            continue
        if segment.flow in encrypted_control_flows:
            continue
        if (segment.destination_port == 21 or segment.source_port == 21) and segment.payload:
            for line, line_packet_indices in _ftp_control_lines(control_flows, segment, packet_index):
                line_packet_index = line_packet_indices[-1] if line_packet_indices else packet_index
                if segment.destination_port == 21:
                    if line.upper() == "AUTH TLS":
                        auth_tls_commands[segment.flow] = line_packet_index
                        continue
                    active = re.fullmatch(r"PORT\s+(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})", line, re.I)
                    if active:
                        values = [int(value) for value in active.groups()]
                        declared_ip = ".".join(str(value) for value in values[:4])
                        port = values[4] * 256 + values[5]
                        if all(value <= 255 for value in values) and declared_ip == segment.source and port:
                            active_endpoints[segment.flow] = (port, line_packet_index)
                    if line.upper().startswith("EPRT "):
                        value = line[5:]
                        delimiter = value[:1]
                        parts = value.split(delimiter) if delimiter else []
                        if len(parts) == 5 and parts[0] == parts[-1] == "" and parts[1] == "1":
                            try:
                                port = int(parts[3])
                            except ValueError:
                                port = 0
                            if parts[2] == segment.source and 0 < port <= 65535:
                                active_endpoints[segment.flow] = (port, line_packet_index)
                    match = re.fullmatch(r"(RETR|STOR)\s+([^\r\n]{1,255})", line, re.I)
                    listing = re.fullmatch(r"(MLSD|NLST)(?:\s+[^\r\n]{1,255})?", line, re.I)
                    if match:
                        name, command_name = match.group(2), match.group(1).upper()
                    elif listing:
                        command_name = listing.group(1).upper()
                        name = f"ftp_{command_name.lower()}_listing.txt"
                    else:
                        name = command_name = None
                    if name and command_name:
                        commands[segment.flow] = (name, line_packet_index, command_name)
                        endpoint = active_endpoints.get(segment.flow)
                        if endpoint:
                            active_transfers[(segment.destination, segment.source, endpoint[0], command_name)] = (
                                name, line_packet_index, endpoint[1], command_name,
                            )
                elif segment.source_port == 21:
                    client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
                    auth_command_index = auth_tls_commands.get(client_flow)
                    status = re.match(r"(\d{3})\b", line)
                    if auth_command_index is not None and status:
                        auth_tls_commands.pop(client_flow, None)
                        if int(status.group(1)) == 234:
                            encrypted_control_flows.add(client_flow)
                            encrypted_control_flows.add(segment.flow)
                            commands.pop(client_flow, None)
                            active_endpoints.pop(client_flow, None)
                            for key in [key for key in transfers if key[0] == segment.source and key[2] == segment.destination]:
                                transfers.pop(key, None)
                            for key in [key for key in active_transfers if key[0] == segment.source and key[1] == segment.destination]:
                                active_transfers.pop(key, None)
                            break
                        continue
                    command = commands.get(client_flow)
                    if not command:
                        continue
                    control_text = line
                    completion = re.match(r"(\d{3})\b", control_text)
                    if completion:
                        code = int(completion.group(1))
                        if code == 226 or 400 <= code <= 599:
                            completions[command[1]] = (code, line_packet_index)
                    match = re.search(r"(?:^|\r\n)227\s+[^\r\n]*\((\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})\)", control_text)
                    port: int | None = None
                    if match:
                        values = [int(value) for value in match.groups()]
                        if all(value <= 255 for value in values):
                            port = values[4] * 256 + values[5]
                    else:
                        extended = re.search(r"(?:^|\r\n)229\s+[^\r\n]*\((.)(?:\1){2}(\d{1,5})\1\)", control_text)
                        if extended:
                            candidate = int(extended.group(2))
                            if candidate <= 65535:
                                port = candidate
                    if port:
                        transfers[(segment.source, port, segment.destination)] = (command[0], command[1], line_packet_index, command[2])
        if segment.flow in encrypted_control_flows:
            continue
        active_transfer = None
        if segment.source_port == 20:
            for command_name in ("RETR", "MLSD", "NLST"):
                active_transfer = active_transfers.get((segment.source, segment.destination, segment.destination_port, command_name))
                if active_transfer:
                    break
        elif segment.destination_port == 20:
            active_transfer = active_transfers.get((segment.destination, segment.source, segment.source_port, "STOR"))
        transfer = active_transfer or transfers.get((segment.source, segment.source_port, segment.destination))
        if transfer is None or transfer[3] not in {"RETR", "MLSD", "NLST"}:
            transfer = transfers.get((segment.destination, segment.destination_port, segment.source))
            if transfer is None or transfer[3] != "STOR":
                continue
        if not segment.payload:
            continue
        flow = data_flows.setdefault(segment.flow, _TcpFlow())
        data_transfer_meta[segment.flow] = transfer
        if len(flow.data) + len(segment.payload) > max_body_bytes:
            _reset_tcp_flow(flow)
            continue
        _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, max_body_bytes)
    for flow_key, flow in sorted(data_flows.items()):
        if not flow.data or not flow.packet_provenance_complete:
            continue
        transfer = data_transfer_meta.get(flow_key)
        if transfer is None:
            continue
        name, command_packet_index, endpoint_setup_packet_index, transfer_command = transfer
        packet_indices = _flow_packet_indices(flow, flow.start_sequence, len(flow.data))
        if not packet_indices:
            continue
        yield FtpDataObject(
            logical_name=name, transfer_command=transfer_command, body=bytes(flow.data), source=flow_key[0], source_port=flow_key[1],
            destination=flow_key[2], destination_port=flow_key[3], packet_indices=packet_indices,
            command_packet_index=command_packet_index, endpoint_setup_packet_index=endpoint_setup_packet_index,
            packet_provenance_complete=True,
            completion_code=completions.get(command_packet_index, (None, None))[0],
            completion_packet_index=completions.get(command_packet_index, (None, None))[1],
        )


def iter_ftp_auth_tls_transitions(path: Path, *, max_transitions: int = 32, max_packets: int = 200_000,
                                  max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[FtpAuthTlsTransition]:
    """Yield exact TCP/21 FTP AUTH TLS/234 transitions only."""
    commands: dict[tuple[str, int, str, int], int] = {}
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    encrypted_flows: set[tuple[str, int, str, int]] = set()
    produced = 0
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload or (segment.destination_port != 21 and segment.source_port != 21):
            continue
        if segment.flow in encrypted_flows:
            continue
        for line, indices in _ftp_control_lines(flows, segment, packet_index):
            line_index = indices[-1] if indices else packet_index
            if segment.destination_port == 21:
                if line.upper() == "AUTH TLS" and (segment.flow in commands or len(commands) < 512):
                    commands[segment.flow] = line_index
                continue
            client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
            command_index = commands.get(client_flow)
            status = re.match(r"(\d{3})\b", line)
            if command_index is None or status is None:
                continue
            commands.pop(client_flow, None)
            if int(status.group(1)) != 234:
                continue
            encrypted_flows.add(client_flow)
            encrypted_flows.add(segment.flow)
            yield FtpAuthTlsTransition(
                source=client_flow[0], source_port=client_flow[1],
                destination=client_flow[2], destination_port=client_flow[3],
                command_packet_index=command_index, ready_response_packet_index=line_index,
            )
            produced += 1
            if produced >= max_transitions:
                return
            break


def iter_smb2_create_operations(path: Path, *, max_operations: int = 100, max_message_bytes: int = 1024 * 1024,
                                max_packets: int = 200_000, max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[Smb2CreateOperation]:
    """Inventory bounded SMB2 CREATE requests from Direct TCP frames.

    Only complete NetBIOS Session Service frames on TCP/445 are accepted. The
    parser validates SMB2/compound-command bounds and decodes the declared
    UTF-16LE CREATE name; it never opens a path or executes captured content.
    """
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    records: list[dict[str, object]] = []
    pending: dict[tuple[tuple[str, int, str, int], int, int, int], dict[str, object]] = {}
    tree_requests: dict[tuple[tuple[str, int, str, int], int, int], dict[str, object]] = {}
    shares: dict[tuple[tuple[str, int, str, int], int, int], dict[str, object]] = {}
    maximum_buffer = max_message_bytes * 2 + 8
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload or (segment.destination_port != 445 and segment.source_port != 445):
            continue
        flow = flows.get(segment.flow)
        if flow is None:
            if len(flows) >= 512:
                continue
            flow = _TcpFlow()
            flows[segment.flow] = flow
        _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, maximum_buffer)
        while len(flow.data) >= 4:
            if flow.data[0] != 0:
                _reset_tcp_flow(flow)
                break
            message_length = int.from_bytes(flow.data[1:4], "big")
            if message_length < 64 or message_length > max_message_bytes:
                _reset_tcp_flow(flow)
                break
            framed_length = 4 + message_length
            if len(flow.data) < framed_length:
                break
            frame_start = flow.start_sequence
            packet_indices = _flow_packet_indices(flow, frame_start, framed_length)
            frame = bytes(flow.data[4:framed_length])
            _consume_tcp_flow(flow, framed_length)
            if not packet_indices or not flow.packet_provenance_complete:
                continue
            command_offset = 0
            for _ in range(16):
                if command_offset + 64 > len(frame) or frame[command_offset:command_offset + 4] != b"\xfeSMB":
                    break
                if int.from_bytes(frame[command_offset + 4:command_offset + 6], "little") != 64:
                    break
                command = int.from_bytes(frame[command_offset + 12:command_offset + 14], "little")
                flags = int.from_bytes(frame[command_offset + 16:command_offset + 20], "little")
                next_command = int.from_bytes(frame[command_offset + 20:command_offset + 24], "little")
                message_id = int.from_bytes(frame[command_offset + 24:command_offset + 32], "little")
                tree_id = int.from_bytes(frame[command_offset + 36:command_offset + 40], "little")
                session_id = int.from_bytes(frame[command_offset + 40:command_offset + 48], "little")
                command_end = command_offset + next_command if next_command else len(frame)
                if command_end > len(frame) or command_end < command_offset + 64 or (next_command and next_command % 8):
                    break
                if command == 3 and not (flags & 0x00000001) and command_offset + 72 <= command_end and len(tree_requests) < 512:
                    request = command_offset + 64
                    if int.from_bytes(frame[request:request + 2], "little") == 9:
                        path_offset = int.from_bytes(frame[request + 4:request + 6], "little")
                        path_length = int.from_bytes(frame[request + 6:request + 8], "little")
                        path_start = command_offset + path_offset
                        path_end = path_start + path_length
                        if 0 < path_length <= 510 and path_length % 2 == 0 and path_offset >= 64 and path_end <= command_end:
                            try:
                                share_path = frame[path_start:path_end].decode("utf-16le", errors="strict")
                            except UnicodeDecodeError:
                                share_path = ""
                            if share_path and len(share_path) <= 255 and "\x00" not in share_path:
                                tree_requests[(segment.flow, message_id, session_id)] = {
                                    "share_path": share_path, "packet_indices": packet_indices,
                                }
                elif command == 3 and flags & 0x00000001:
                    client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
                    tree_request = tree_requests.pop((client_flow, message_id, session_id), None)
                    status = int.from_bytes(frame[command_offset + 8:command_offset + 12], "little")
                    response = command_offset + 64
                    if tree_request is not None and status == 0 and response + 16 <= command_end and int.from_bytes(frame[response:response + 2], "little") == 16:
                        shares[(client_flow, session_id, tree_id)] = {
                            **tree_request, "response_packet_indices": packet_indices,
                        }
                if command == 5 and not (flags & 0x00000001) and len(records) < max_operations and command_offset + 120 <= command_end:
                    request = command_offset + 64
                    if int.from_bytes(frame[request:request + 2], "little") == 57:
                        name_offset = int.from_bytes(frame[request + 44:request + 46], "little")
                        name_length = int.from_bytes(frame[request + 46:request + 48], "little")
                        name_start = command_offset + name_offset
                        name_end = name_start + name_length
                        if 0 < name_length <= 510 and name_length % 2 == 0 and name_offset >= 64 and name_end <= command_end:
                            try:
                                filename = frame[name_start:name_end].decode("utf-16le", errors="strict")
                            except UnicodeDecodeError:
                                filename = ""
                            if filename and len(filename) <= 255 and "\x00" not in filename:
                                share = shares.get((segment.flow, session_id, tree_id), {})
                                record: dict[str, object] = {
                                    "filename": filename, "message_id": message_id, "tree_id": tree_id, "session_id": session_id,
                                    "desired_access": int.from_bytes(frame[request + 24:request + 28], "little"),
                                    "create_disposition": int.from_bytes(frame[request + 36:request + 40], "little"),
                                    "create_options": int.from_bytes(frame[request + 40:request + 44], "little"),
                                    "source": segment.source, "source_port": segment.source_port,
                                    "destination": segment.destination, "destination_port": segment.destination_port,
                                    "packet_indices": packet_indices, "response_status": None,
                                    "persistent_file_id": None, "volatile_file_id": None, "response_packet_indices": (),
                                    "share_path": share.get("share_path"),
                                    "tree_connect_packet_indices": share.get("packet_indices", ()),
                                    "tree_connect_response_packet_indices": share.get("response_packet_indices", ()),
                                }
                                records.append(record)
                                pending[(segment.flow, message_id, session_id, tree_id)] = record
                elif command == 5 and flags & 0x00000001:
                    client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
                    record = pending.pop((client_flow, message_id, session_id, tree_id), None)
                    if record is not None:
                        status = int.from_bytes(frame[command_offset + 8:command_offset + 12], "little")
                        record["response_status"] = status
                        record["response_packet_indices"] = packet_indices
                        response = command_offset + 64
                        if status == 0 and response + 88 <= command_end and int.from_bytes(frame[response:response + 2], "little") == 89:
                            record["persistent_file_id"] = int.from_bytes(frame[response + 64:response + 72], "little")
                            record["volatile_file_id"] = int.from_bytes(frame[response + 72:response + 80], "little")
                if not next_command:
                    break
                command_offset = command_end
    for record in records:
        yield Smb2CreateOperation(**record)


def iter_smb2_write_objects(path: Path, *, max_objects: int = 32, max_body_bytes: int = 64 * 1024 * 1024,
                            max_message_bytes: int = 1024 * 1024, max_packets: int = 200_000,
                            max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[Smb2WriteObject]:
    """Recover contiguous acknowledged SMB2 WRITE bytes for known CREATE FileIds."""
    creates = [
        item for item in iter_smb2_create_operations(
            path, max_operations=max_objects * 4, max_message_bytes=max_message_bytes,
            max_packets=max_packets, max_scan_bytes=max_scan_bytes,
        )
        if item.response_status == 0 and item.persistent_file_id is not None and item.volatile_file_id is not None
    ]
    known: dict[tuple[tuple[str, int, str, int], int, int, int, int], Smb2CreateOperation] = {
        ((item.source, item.source_port, item.destination, item.destination_port), item.session_id, item.tree_id,
         int(item.persistent_file_id), int(item.volatile_file_id)): item
        for item in creates
    }
    if not known:
        return
    closes = {
        ((item.source, item.source_port, item.destination, item.destination_port), item.session_id, item.tree_id,
         item.persistent_file_id, item.volatile_file_id): item
        for item in iter_smb2_close_operations(
            path, max_operations=max_objects * 4, max_message_bytes=max_message_bytes,
            max_packets=max_packets, max_scan_bytes=max_scan_bytes,
        )
        if item.response_status == 0 and item.end_of_file is not None
    }
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    pending: dict[tuple[tuple[str, int, str, int], int, int, int], dict[str, object]] = {}
    chunks: dict[tuple[tuple[str, int, str, int], int, int, int, int], dict[int, dict[str, object]]] = {}
    invalid_files: set[tuple[tuple[str, int, str, int], int, int, int, int]] = set()
    maximum_buffer = max_message_bytes * 2 + 8
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload or (segment.destination_port != 445 and segment.source_port != 445):
            continue
        flow = flows.get(segment.flow)
        if flow is None:
            if len(flows) >= 512:
                continue
            flow = _TcpFlow()
            flows[segment.flow] = flow
        _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, maximum_buffer)
        while len(flow.data) >= 4:
            if flow.data[0] != 0:
                _reset_tcp_flow(flow)
                break
            message_length = int.from_bytes(flow.data[1:4], "big")
            if message_length < 64 or message_length > max_message_bytes:
                _reset_tcp_flow(flow)
                break
            framed_length = 4 + message_length
            if len(flow.data) < framed_length:
                break
            packet_indices = _flow_packet_indices(flow, flow.start_sequence, framed_length)
            frame = bytes(flow.data[4:framed_length])
            _consume_tcp_flow(flow, framed_length)
            if not packet_indices or not flow.packet_provenance_complete:
                continue
            command_offset = 0
            for _ in range(16):
                if command_offset + 64 > len(frame) or frame[command_offset:command_offset + 4] != b"\xfeSMB":
                    break
                if int.from_bytes(frame[command_offset + 4:command_offset + 6], "little") != 64:
                    break
                command = int.from_bytes(frame[command_offset + 12:command_offset + 14], "little")
                flags = int.from_bytes(frame[command_offset + 16:command_offset + 20], "little")
                next_command = int.from_bytes(frame[command_offset + 20:command_offset + 24], "little")
                message_id = int.from_bytes(frame[command_offset + 24:command_offset + 32], "little")
                tree_id = int.from_bytes(frame[command_offset + 36:command_offset + 40], "little")
                session_id = int.from_bytes(frame[command_offset + 40:command_offset + 48], "little")
                command_end = command_offset + next_command if next_command else len(frame)
                if command_end > len(frame) or command_end < command_offset + 64 or (next_command and next_command % 8):
                    break
                if command == 9 and not (flags & 1) and command_offset + 112 <= command_end and len(pending) < max_objects * 256:
                    request = command_offset + 64
                    if int.from_bytes(frame[request:request + 2], "little") == 49:
                        data_offset = int.from_bytes(frame[request + 2:request + 4], "little")
                        length = int.from_bytes(frame[request + 4:request + 8], "little")
                        file_offset = int.from_bytes(frame[request + 8:request + 16], "little")
                        persistent = int.from_bytes(frame[request + 16:request + 24], "little")
                        volatile = int.from_bytes(frame[request + 24:request + 32], "little")
                        data_start = command_offset + data_offset
                        data_end = data_start + length
                        file_key = (segment.flow, session_id, tree_id, persistent, volatile)
                        if file_key in known and 0 < length <= max_body_bytes and data_offset >= 64 and data_end <= command_end:
                            pending[(segment.flow, message_id, session_id, tree_id)] = {
                                "file_key": file_key, "offset": file_offset, "body": frame[data_start:data_end],
                                "packet_indices": packet_indices, "message_id": message_id,
                            }
                elif command == 9 and flags & 1:
                    client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
                    write = pending.pop((client_flow, message_id, session_id, tree_id), None)
                    response = command_offset + 64
                    status = int.from_bytes(frame[command_offset + 8:command_offset + 12], "little")
                    if write is not None and status == 0 and response + 16 <= command_end and int.from_bytes(frame[response:response + 2], "little") == 17:
                        count = int.from_bytes(frame[response + 4:response + 8], "little")
                        body = bytes(write["body"])
                        if count == len(body):
                            file_key = write["file_key"]
                            file_chunks = chunks.setdefault(file_key, {})
                            offset = int(write["offset"])
                            existing = file_chunks.get(offset)
                            accepted = {**write, "response_packet_indices": packet_indices}
                            if existing is None:
                                if len(file_chunks) < 256:
                                    file_chunks[offset] = accepted
                                else:
                                    invalid_files.add(file_key)
                            elif existing["body"] != body:
                                invalid_files.add(file_key)
                if not next_command:
                    break
                command_offset = command_end
    produced = 0
    for file_key, by_offset in chunks.items():
        if file_key in invalid_files or not by_offset or produced >= max_objects:
            continue
        expected = 0
        body = bytearray()
        packet_set: set[int] = set()
        response_packet_set: set[int] = set()
        message_ids: list[int] = []
        valid = True
        for offset, chunk in sorted(by_offset.items()):
            payload = bytes(chunk["body"])
            if offset != expected or len(body) + len(payload) > max_body_bytes:
                valid = False
                break
            body.extend(payload)
            expected += len(payload)
            packet_set.update(chunk["packet_indices"])
            response_packet_set.update(chunk["response_packet_indices"])
            message_ids.append(int(chunk["message_id"]))
        if not valid or not body:
            continue
        create = known[file_key]
        close = closes.get(file_key)
        if close is not None and len(body) != close.end_of_file:
            continue
        basename = PurePosixPath(create.filename.replace("\\", "/")).name or f"smb2_write_{produced:04d}.bin"
        yield Smb2WriteObject(
            logical_name=basename, smb_path=create.filename, body=bytes(body),
            persistent_file_id=int(create.persistent_file_id), volatile_file_id=int(create.volatile_file_id),
            source=create.source, source_port=create.source_port, destination=create.destination, destination_port=create.destination_port,
            packet_indices=tuple(sorted(packet_set)), response_packet_indices=tuple(sorted(response_packet_set)),
            message_ids=tuple(message_ids), share_path=create.share_path,
            close_end_of_file=close.end_of_file if close is not None else None,
            close_packet_indices=close.packet_indices if close is not None else (),
            close_response_packet_indices=close.response_packet_indices if close is not None else (),
        )
        produced += 1


def iter_smb2_read_objects(path: Path, *, max_objects: int = 32, max_body_bytes: int = 64 * 1024 * 1024,
                           max_message_bytes: int = 1024 * 1024, max_packets: int = 200_000,
                           max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[Smb2ReadObject]:
    """Recover contiguous SMB2 READ response bytes for known CREATE FileIds."""
    creates = [
        item for item in iter_smb2_create_operations(
            path, max_operations=max_objects * 4, max_message_bytes=max_message_bytes,
            max_packets=max_packets, max_scan_bytes=max_scan_bytes,
        )
        if item.response_status == 0 and item.persistent_file_id is not None and item.volatile_file_id is not None
    ]
    known: dict[tuple[tuple[str, int, str, int], int, int, int, int], Smb2CreateOperation] = {
        ((item.source, item.source_port, item.destination, item.destination_port), item.session_id, item.tree_id,
         int(item.persistent_file_id), int(item.volatile_file_id)): item
        for item in creates
    }
    if not known:
        return
    closes = {
        ((item.source, item.source_port, item.destination, item.destination_port), item.session_id, item.tree_id,
         item.persistent_file_id, item.volatile_file_id): item
        for item in iter_smb2_close_operations(
            path, max_operations=max_objects * 4, max_message_bytes=max_message_bytes,
            max_packets=max_packets, max_scan_bytes=max_scan_bytes,
        )
        if item.response_status == 0 and item.end_of_file is not None
    }
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    pending: dict[tuple[tuple[str, int, str, int], int, int, int], dict[str, object]] = {}
    chunks: dict[tuple[tuple[str, int, str, int], int, int, int, int], dict[int, dict[str, object]]] = {}
    invalid_files: set[tuple[tuple[str, int, str, int], int, int, int, int]] = set()
    maximum_buffer = max_message_bytes * 2 + 8
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload or (segment.destination_port != 445 and segment.source_port != 445):
            continue
        flow = flows.get(segment.flow)
        if flow is None:
            if len(flows) >= 512:
                continue
            flow = _TcpFlow()
            flows[segment.flow] = flow
        _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, maximum_buffer)
        while len(flow.data) >= 4:
            if flow.data[0] != 0:
                _reset_tcp_flow(flow)
                break
            message_length = int.from_bytes(flow.data[1:4], "big")
            if message_length < 64 or message_length > max_message_bytes:
                _reset_tcp_flow(flow)
                break
            framed_length = 4 + message_length
            if len(flow.data) < framed_length:
                break
            packet_indices = _flow_packet_indices(flow, flow.start_sequence, framed_length)
            frame = bytes(flow.data[4:framed_length])
            _consume_tcp_flow(flow, framed_length)
            if not packet_indices or not flow.packet_provenance_complete:
                continue
            command_offset = 0
            for _ in range(16):
                if command_offset + 64 > len(frame) or frame[command_offset:command_offset + 4] != b"\xfeSMB":
                    break
                if int.from_bytes(frame[command_offset + 4:command_offset + 6], "little") != 64:
                    break
                command = int.from_bytes(frame[command_offset + 12:command_offset + 14], "little")
                flags = int.from_bytes(frame[command_offset + 16:command_offset + 20], "little")
                next_command = int.from_bytes(frame[command_offset + 20:command_offset + 24], "little")
                message_id = int.from_bytes(frame[command_offset + 24:command_offset + 32], "little")
                tree_id = int.from_bytes(frame[command_offset + 36:command_offset + 40], "little")
                session_id = int.from_bytes(frame[command_offset + 40:command_offset + 48], "little")
                command_end = command_offset + next_command if next_command else len(frame)
                if command_end > len(frame) or command_end < command_offset + 64 or (next_command and next_command % 8):
                    break
                if command == 8 and not (flags & 1) and command_offset + 112 <= command_end and len(pending) < max_objects * 256:
                    request = command_offset + 64
                    if int.from_bytes(frame[request:request + 2], "little") == 49:
                        requested_length = int.from_bytes(frame[request + 4:request + 8], "little")
                        file_offset = int.from_bytes(frame[request + 8:request + 16], "little")
                        persistent = int.from_bytes(frame[request + 16:request + 24], "little")
                        volatile = int.from_bytes(frame[request + 24:request + 32], "little")
                        file_key = (segment.flow, session_id, tree_id, persistent, volatile)
                        if file_key in known and 0 < requested_length <= max_body_bytes:
                            pending[(segment.flow, message_id, session_id, tree_id)] = {
                                "file_key": file_key, "offset": file_offset, "requested_length": requested_length,
                                "request_packet_indices": packet_indices, "message_id": message_id,
                            }
                elif command == 8 and flags & 1:
                    client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
                    read = pending.pop((client_flow, message_id, session_id, tree_id), None)
                    response = command_offset + 64
                    status = int.from_bytes(frame[command_offset + 8:command_offset + 12], "little")
                    if read is not None and status == 0 and response + 16 <= command_end and int.from_bytes(frame[response:response + 2], "little") == 17:
                        data_offset = frame[response + 2]
                        data_length = int.from_bytes(frame[response + 4:response + 8], "little")
                        data_start = command_offset + data_offset
                        data_end = data_start + data_length
                        if 0 < data_length <= int(read["requested_length"]) and data_offset >= 64 and data_end <= command_end:
                            file_key = read["file_key"]
                            file_chunks = chunks.setdefault(file_key, {})
                            offset = int(read["offset"])
                            accepted = {
                                **read, "body": frame[data_start:data_end], "packet_indices": packet_indices,
                            }
                            existing = file_chunks.get(offset)
                            if existing is None:
                                if len(file_chunks) < 256:
                                    file_chunks[offset] = accepted
                                else:
                                    invalid_files.add(file_key)
                            elif existing["body"] != accepted["body"]:
                                invalid_files.add(file_key)
                if not next_command:
                    break
                command_offset = command_end
    produced = 0
    for file_key, by_offset in chunks.items():
        if file_key in invalid_files or not by_offset or produced >= max_objects:
            continue
        expected = 0
        body = bytearray()
        request_packet_set: set[int] = set()
        packet_set: set[int] = set()
        message_ids: list[int] = []
        valid = True
        for offset, chunk in sorted(by_offset.items()):
            payload = bytes(chunk["body"])
            if offset != expected or len(body) + len(payload) > max_body_bytes:
                valid = False
                break
            body.extend(payload)
            expected += len(payload)
            request_packet_set.update(chunk["request_packet_indices"])
            packet_set.update(chunk["packet_indices"])
            message_ids.append(int(chunk["message_id"]))
        if not valid or not body:
            continue
        create = known[file_key]
        close = closes.get(file_key)
        if close is not None and len(body) != close.end_of_file:
            continue
        basename = PurePosixPath(create.filename.replace("\\", "/")).name or f"smb2_read_{produced:04d}.bin"
        yield Smb2ReadObject(
            logical_name=basename, smb_path=create.filename, body=bytes(body),
            persistent_file_id=int(create.persistent_file_id), volatile_file_id=int(create.volatile_file_id),
            source=create.destination, source_port=create.destination_port,
            destination=create.source, destination_port=create.source_port,
            request_packet_indices=tuple(sorted(request_packet_set)), packet_indices=tuple(sorted(packet_set)),
            message_ids=tuple(message_ids), share_path=create.share_path,
            close_end_of_file=close.end_of_file if close is not None else None,
            close_packet_indices=close.packet_indices if close is not None else (),
            close_response_packet_indices=close.response_packet_indices if close is not None else (),
        )
        produced += 1


def iter_smb2_close_operations(path: Path, *, max_operations: int = 100, max_message_bytes: int = 1024 * 1024,
                               max_packets: int = 200_000, max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[Smb2CloseOperation]:
    """Correlate bounded SMB2 CLOSE requests/responses to known CREATE FileIds."""
    creates = [
        item for item in iter_smb2_create_operations(
            path, max_operations=max_operations, max_message_bytes=max_message_bytes,
            max_packets=max_packets, max_scan_bytes=max_scan_bytes,
        )
        if item.response_status == 0 and item.persistent_file_id is not None and item.volatile_file_id is not None
    ]
    known = {
        ((item.source, item.source_port, item.destination, item.destination_port), item.session_id, item.tree_id,
         int(item.persistent_file_id), int(item.volatile_file_id)): item
        for item in creates
    }
    if not known:
        return
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    pending: dict[tuple[tuple[str, int, str, int], int, int, int], dict[str, object]] = {}
    records: list[dict[str, object]] = []
    maximum_buffer = max_message_bytes * 2 + 8
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload or (segment.destination_port != 445 and segment.source_port != 445):
            continue
        flow = flows.get(segment.flow)
        if flow is None:
            if len(flows) >= 512:
                continue
            flow = _TcpFlow()
            flows[segment.flow] = flow
        _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, maximum_buffer)
        while len(flow.data) >= 4:
            if flow.data[0] != 0:
                _reset_tcp_flow(flow)
                break
            message_length = int.from_bytes(flow.data[1:4], "big")
            if message_length < 64 or message_length > max_message_bytes:
                _reset_tcp_flow(flow)
                break
            framed_length = 4 + message_length
            if len(flow.data) < framed_length:
                break
            packet_indices = _flow_packet_indices(flow, flow.start_sequence, framed_length)
            frame = bytes(flow.data[4:framed_length])
            _consume_tcp_flow(flow, framed_length)
            if not packet_indices or not flow.packet_provenance_complete:
                continue
            command_offset = 0
            for _ in range(16):
                if command_offset + 64 > len(frame) or frame[command_offset:command_offset + 4] != b"\xfeSMB":
                    break
                if int.from_bytes(frame[command_offset + 4:command_offset + 6], "little") != 64:
                    break
                command = int.from_bytes(frame[command_offset + 12:command_offset + 14], "little")
                flags = int.from_bytes(frame[command_offset + 16:command_offset + 20], "little")
                next_command = int.from_bytes(frame[command_offset + 20:command_offset + 24], "little")
                message_id = int.from_bytes(frame[command_offset + 24:command_offset + 32], "little")
                tree_id = int.from_bytes(frame[command_offset + 36:command_offset + 40], "little")
                session_id = int.from_bytes(frame[command_offset + 40:command_offset + 48], "little")
                command_end = command_offset + next_command if next_command else len(frame)
                if command_end > len(frame) or command_end < command_offset + 64 or (next_command and next_command % 8):
                    break
                if command == 6 and not (flags & 1) and command_offset + 88 <= command_end and len(records) < max_operations:
                    request = command_offset + 64
                    if int.from_bytes(frame[request:request + 2], "little") == 24:
                        persistent = int.from_bytes(frame[request + 8:request + 16], "little")
                        volatile = int.from_bytes(frame[request + 16:request + 24], "little")
                        file_key = (segment.flow, session_id, tree_id, persistent, volatile)
                        create = known.get(file_key)
                        if create is not None:
                            record: dict[str, object] = {
                                "filename": create.filename, "share_path": create.share_path,
                                "persistent_file_id": persistent, "volatile_file_id": volatile,
                                "message_id": message_id, "session_id": session_id, "tree_id": tree_id,
                                "source": segment.source, "source_port": segment.source_port,
                                "destination": segment.destination, "destination_port": segment.destination_port,
                                "packet_indices": packet_indices, "response_status": None, "response_packet_indices": (),
                                "creation_filetime": None, "last_access_filetime": None, "last_write_filetime": None,
                                "change_filetime": None, "allocation_size": None, "end_of_file": None, "file_attributes": None,
                            }
                            records.append(record)
                            pending[(segment.flow, message_id, session_id, tree_id)] = record
                elif command == 6 and flags & 1:
                    client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
                    record = pending.pop((client_flow, message_id, session_id, tree_id), None)
                    if record is not None:
                        status = int.from_bytes(frame[command_offset + 8:command_offset + 12], "little")
                        record["response_status"] = status
                        record["response_packet_indices"] = packet_indices
                        response = command_offset + 64
                        if status == 0 and response + 60 <= command_end and int.from_bytes(frame[response:response + 2], "little") == 60:
                            record["creation_filetime"] = int.from_bytes(frame[response + 8:response + 16], "little")
                            record["last_access_filetime"] = int.from_bytes(frame[response + 16:response + 24], "little")
                            record["last_write_filetime"] = int.from_bytes(frame[response + 24:response + 32], "little")
                            record["change_filetime"] = int.from_bytes(frame[response + 32:response + 40], "little")
                            record["allocation_size"] = int.from_bytes(frame[response + 40:response + 48], "little")
                            record["end_of_file"] = int.from_bytes(frame[response + 48:response + 56], "little")
                            record["file_attributes"] = int.from_bytes(frame[response + 56:response + 60], "little")
                if not next_command:
                    break
                command_offset = command_end
    for record in records:
        yield Smb2CloseOperation(**record)


def iter_smb2_set_info_operations(path: Path, *, max_operations: int = 100, max_message_bytes: int = 1024 * 1024,
                                  max_packets: int = 200_000, max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[Smb2SetInfoOperation]:
    """Correlate bounded SMB2 rename/delete-disposition requests to CREATE FileIds."""
    creates = [
        item for item in iter_smb2_create_operations(
            path, max_operations=max_operations, max_message_bytes=max_message_bytes,
            max_packets=max_packets, max_scan_bytes=max_scan_bytes,
        )
        if item.response_status == 0 and item.persistent_file_id is not None and item.volatile_file_id is not None
    ]
    known = {
        ((item.source, item.source_port, item.destination, item.destination_port), item.session_id, item.tree_id,
         int(item.persistent_file_id), int(item.volatile_file_id)): item
        for item in creates
    }
    if not known:
        return
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    pending: dict[tuple[tuple[str, int, str, int], int, int, int], dict[str, object]] = {}
    records: list[dict[str, object]] = []
    maximum_buffer = max_message_bytes * 2 + 8
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload or (segment.destination_port != 445 and segment.source_port != 445):
            continue
        flow = flows.get(segment.flow)
        if flow is None:
            if len(flows) >= 512:
                continue
            flow = _TcpFlow()
            flows[segment.flow] = flow
        _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, maximum_buffer)
        while len(flow.data) >= 4:
            if flow.data[0] != 0:
                _reset_tcp_flow(flow)
                break
            message_length = int.from_bytes(flow.data[1:4], "big")
            if message_length < 64 or message_length > max_message_bytes:
                _reset_tcp_flow(flow)
                break
            framed_length = 4 + message_length
            if len(flow.data) < framed_length:
                break
            packet_indices = _flow_packet_indices(flow, flow.start_sequence, framed_length)
            frame = bytes(flow.data[4:framed_length])
            _consume_tcp_flow(flow, framed_length)
            if not packet_indices or not flow.packet_provenance_complete:
                continue
            command_offset = 0
            for _ in range(16):
                if command_offset + 64 > len(frame) or frame[command_offset:command_offset + 4] != b"\xfeSMB":
                    break
                if int.from_bytes(frame[command_offset + 4:command_offset + 6], "little") != 64:
                    break
                command = int.from_bytes(frame[command_offset + 12:command_offset + 14], "little")
                flags = int.from_bytes(frame[command_offset + 16:command_offset + 20], "little")
                next_command = int.from_bytes(frame[command_offset + 20:command_offset + 24], "little")
                message_id = int.from_bytes(frame[command_offset + 24:command_offset + 32], "little")
                tree_id = int.from_bytes(frame[command_offset + 36:command_offset + 40], "little")
                session_id = int.from_bytes(frame[command_offset + 40:command_offset + 48], "little")
                command_end = command_offset + next_command if next_command else len(frame)
                if command_end > len(frame) or command_end < command_offset + 64 or (next_command and next_command % 8):
                    break
                if command == 17 and not (flags & 1) and command_offset + 96 <= command_end and len(records) < max_operations:
                    request = command_offset + 64
                    if int.from_bytes(frame[request:request + 2], "little") == 33 and frame[request + 2] == 1:
                        info_class = frame[request + 3]
                        buffer_length = int.from_bytes(frame[request + 4:request + 8], "little")
                        buffer_offset = int.from_bytes(frame[request + 8:request + 10], "little")
                        persistent = int.from_bytes(frame[request + 16:request + 24], "little")
                        volatile = int.from_bytes(frame[request + 24:request + 32], "little")
                        buffer_start = command_offset + buffer_offset
                        buffer_end = buffer_start + buffer_length
                        file_key = (segment.flow, session_id, tree_id, persistent, volatile)
                        create = known.get(file_key)
                        record: dict[str, object] | None = None
                        if create is not None and 0 < buffer_length <= 510 and buffer_offset >= 64 and buffer_end <= command_end:
                            if info_class == 10 and buffer_length >= 20:
                                name_length = int.from_bytes(frame[buffer_start + 16:buffer_start + 20], "little")
                                name_end = buffer_start + 20 + name_length
                                if 0 < name_length <= 490 and name_length % 2 == 0 and name_end <= buffer_end:
                                    try:
                                        target = frame[buffer_start + 20:name_end].decode("utf-16le", errors="strict")
                                    except UnicodeDecodeError:
                                        target = ""
                                    if target and len(target) <= 255 and "\x00" not in target:
                                        record = {
                                            "operation": "rename", "target_filename": target,
                                            "replace_if_exists": bool(frame[buffer_start]), "delete_pending": None,
                                        }
                            elif info_class == 13 and buffer_length == 1 and frame[buffer_start] in {0, 1}:
                                record = {
                                    "operation": "delete_disposition", "target_filename": None,
                                    "replace_if_exists": None, "delete_pending": bool(frame[buffer_start]),
                                }
                        if record is not None and create is not None:
                            record.update({
                                "filename": create.filename, "share_path": create.share_path,
                                "persistent_file_id": persistent, "volatile_file_id": volatile,
                                "message_id": message_id, "session_id": session_id, "tree_id": tree_id,
                                "source": segment.source, "source_port": segment.source_port,
                                "destination": segment.destination, "destination_port": segment.destination_port,
                                "packet_indices": packet_indices, "response_status": None,
                                "response_packet_indices": (),
                            })
                            records.append(record)
                            pending[(segment.flow, message_id, session_id, tree_id)] = record
                elif command == 17 and flags & 1:
                    client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
                    record = pending.pop((client_flow, message_id, session_id, tree_id), None)
                    if record is not None:
                        record["response_status"] = int.from_bytes(frame[command_offset + 8:command_offset + 12], "little")
                        record["response_packet_indices"] = packet_indices
                if not next_command:
                    break
                command_offset = command_end
    for record in records:
        yield Smb2SetInfoOperation(**record)


_SMB2_DIALECT_NAMES = {
    0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x02FF: "SMB 2.x wildcard",
    0x0300: "SMB 3.0", 0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1",
}


def _smb2_dialect_name(dialect: int) -> str:
    return _SMB2_DIALECT_NAMES.get(dialect, f"unknown 0x{dialect:04x}")


def iter_smb2_negotiate_operations(path: Path, *, max_operations: int = 100, max_message_bytes: int = 1024 * 1024,
                                   max_packets: int = 200_000, max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[Smb2NegotiateOperation]:
    """Correlate bounded SMB2 NEGOTIATE requests and exact inverse responses."""
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    pending: dict[tuple[tuple[str, int, str, int], int], dict[str, object]] = {}
    records: list[dict[str, object]] = []
    maximum_buffer = max_message_bytes * 2 + 8
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload or (segment.destination_port != 445 and segment.source_port != 445):
            continue
        flow = flows.get(segment.flow)
        if flow is None:
            if len(flows) >= 512:
                continue
            flow = _TcpFlow()
            flows[segment.flow] = flow
        _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, maximum_buffer)
        while len(flow.data) >= 4:
            if flow.data[0] != 0:
                _reset_tcp_flow(flow)
                break
            message_length = int.from_bytes(flow.data[1:4], "big")
            if message_length < 64 or message_length > max_message_bytes:
                _reset_tcp_flow(flow)
                break
            framed_length = 4 + message_length
            if len(flow.data) < framed_length:
                break
            provenance_complete = flow.packet_provenance_complete
            packet_indices = _flow_packet_indices(flow, flow.start_sequence, framed_length)
            frame = bytes(flow.data[4:framed_length])
            _consume_tcp_flow(flow, framed_length)
            if not provenance_complete or not packet_indices:
                continue
            command_offset = 0
            for _ in range(16):
                if command_offset + 64 > len(frame) or frame[command_offset:command_offset + 4] != b"\xfeSMB":
                    break
                if int.from_bytes(frame[command_offset + 4:command_offset + 6], "little") != 64:
                    break
                command = int.from_bytes(frame[command_offset + 12:command_offset + 14], "little")
                flags = int.from_bytes(frame[command_offset + 16:command_offset + 20], "little")
                next_command = int.from_bytes(frame[command_offset + 20:command_offset + 24], "little")
                message_id = int.from_bytes(frame[command_offset + 24:command_offset + 32], "little")
                command_end = command_offset + next_command if next_command else len(frame)
                if command_end > len(frame) or command_end < command_offset + 64 or (next_command and next_command % 8):
                    break
                if command == 0 and not (flags & 1) and len(records) < max_operations and command_offset + 100 <= command_end:
                    request = command_offset + 64
                    dialect_count = int.from_bytes(frame[request + 2:request + 4], "little")
                    security_mode = int.from_bytes(frame[request + 4:request + 6], "little")
                    dialect_end = request + 36 + dialect_count * 2
                    context_offset = int.from_bytes(frame[request + 28:request + 32], "little")
                    context_count = int.from_bytes(frame[request + 32:request + 34], "little")
                    contexts_valid = (
                        (context_count == 0 and context_offset == 0)
                        or (
                            0 < context_count <= 64 and context_offset % 8 == 0
                            and command_offset + context_offset >= dialect_end
                            and command_offset + context_offset < command_end
                        )
                    )
                    if (
                        int.from_bytes(frame[request:request + 2], "little") == 36
                        and 0 < dialect_count <= 64 and dialect_end <= command_end
                        and security_mode & ~0x0003 == 0 and contexts_valid
                    ):
                        dialects = tuple(
                            int.from_bytes(frame[offset:offset + 2], "little")
                            for offset in range(request + 36, dialect_end, 2)
                        )
                        record: dict[str, object] = {
                            "offered_dialects": dialects,
                            "offered_dialect_names": tuple(_smb2_dialect_name(item) for item in dialects),
                            "request_security_mode": security_mode,
                            "request_capabilities": int.from_bytes(frame[request + 8:request + 12], "little"),
                            "client_guid_hex": frame[request + 12:request + 28].hex(),
                            "request_context_count": context_count,
                            "message_id": message_id,
                            "source": segment.source, "source_port": segment.source_port,
                            "destination": segment.destination, "destination_port": segment.destination_port,
                            "packet_indices": packet_indices,
                            "response_status": None, "selected_dialect": None, "selected_dialect_name": None,
                            "response_security_mode": None, "response_capabilities": None,
                            "server_guid_hex": None, "max_transact_size": None, "max_read_size": None,
                            "max_write_size": None, "system_filetime": None, "server_start_filetime": None,
                            "response_context_count": None, "response_packet_indices": (),
                        }
                        records.append(record)
                        if len(pending) < max_operations * 4:
                            pending[(segment.flow, message_id)] = record
                elif command == 0 and flags & 1:
                    client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
                    record = pending.pop((client_flow, message_id), None)
                    if record is not None:
                        status = int.from_bytes(frame[command_offset + 8:command_offset + 12], "little")
                        record["response_status"] = status
                        record["response_packet_indices"] = packet_indices
                        response = command_offset + 64
                        if status == 0 and response + 64 <= command_end and int.from_bytes(frame[response:response + 2], "little") == 65:
                            response_security_mode = int.from_bytes(frame[response + 2:response + 4], "little")
                            security_offset = int.from_bytes(frame[response + 56:response + 58], "little")
                            security_length = int.from_bytes(frame[response + 58:response + 60], "little")
                            response_context_count = int.from_bytes(frame[response + 6:response + 8], "little")
                            response_context_offset = int.from_bytes(frame[response + 60:response + 64], "little")
                            security_end = command_offset + security_offset + security_length
                            security_valid = (
                                (security_length == 0 and security_offset == 0)
                                or (security_offset >= 128 and security_end <= command_end)
                            )
                            response_contexts_valid = (
                                (response_context_count == 0 and response_context_offset == 0)
                                or (
                                    0 < response_context_count <= 64 and response_context_offset % 8 == 0
                                    and command_offset + response_context_offset >= response + 64
                                    and command_offset + response_context_offset < command_end
                                )
                            )
                            if response_security_mode & ~0x0003 == 0 and security_valid and response_contexts_valid:
                                selected = int.from_bytes(frame[response + 4:response + 6], "little")
                                record.update({
                                    "selected_dialect": selected,
                                    "selected_dialect_name": _smb2_dialect_name(selected),
                                    "response_security_mode": response_security_mode,
                                    "response_capabilities": int.from_bytes(frame[response + 24:response + 28], "little"),
                                    "server_guid_hex": frame[response + 8:response + 24].hex(),
                                    "max_transact_size": int.from_bytes(frame[response + 28:response + 32], "little"),
                                    "max_read_size": int.from_bytes(frame[response + 32:response + 36], "little"),
                                    "max_write_size": int.from_bytes(frame[response + 36:response + 40], "little"),
                                    "system_filetime": int.from_bytes(frame[response + 40:response + 48], "little"),
                                    "server_start_filetime": int.from_bytes(frame[response + 48:response + 56], "little"),
                                    "response_context_count": response_context_count,
                                })
                if not next_command:
                    break
                command_offset = command_end
    for record in records:
        yield Smb2NegotiateOperation(**record)


def iter_smb3_transform_records(path: Path, *, max_records: int = 100, max_message_bytes: int = 1024 * 1024,
                                max_original_message_bytes: int = 64 * 1024 * 1024,
                                max_packets: int = 200_000, max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[Smb3TransformRecord]:
    """Inventory bounded SMB3 transform headers without decoding their payloads."""
    compression_names = {
        0: "NONE", 1: "LZNT1", 2: "LZ77", 3: "LZ77_HUFFMAN", 4: "PATTERN_V1",
    }
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    records: list[Smb3TransformRecord] = []
    maximum_buffer = max_message_bytes * 2 + 8
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        if len(records) >= max_records:
            break
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload or (segment.destination_port != 445 and segment.source_port != 445):
            continue
        flow = flows.get(segment.flow)
        if flow is None:
            if len(flows) >= 512:
                continue
            flow = _TcpFlow()
            flows[segment.flow] = flow
        _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, maximum_buffer)
        while len(flow.data) >= 4 and len(records) < max_records:
            if flow.data[0] != 0:
                _reset_tcp_flow(flow)
                break
            message_length = int.from_bytes(flow.data[1:4], "big")
            if message_length < 16 or message_length > max_message_bytes:
                _reset_tcp_flow(flow)
                break
            framed_length = 4 + message_length
            if len(flow.data) < framed_length:
                break
            provenance_complete = flow.packet_provenance_complete
            packet_indices = _flow_packet_indices(flow, flow.start_sequence, framed_length)
            frame = bytes(flow.data[4:framed_length])
            _consume_tcp_flow(flow, framed_length)
            if not provenance_complete or not packet_indices:
                continue
            if frame.startswith(b"\xfdSMB") and len(frame) > 52:
                declared_size = int.from_bytes(frame[36:40], "little")
                reserved = int.from_bytes(frame[40:42], "little")
                flags = int.from_bytes(frame[42:44], "little")
                if reserved == 0 and flags == 1 and 0 < declared_size <= max_original_message_bytes:
                    records.append(Smb3TransformRecord(
                        transform_type="encryption", declared_original_size=declared_size, flags=flags,
                        framed_size=message_length, transformed_payload_size=len(frame) - 52,
                        session_id=int.from_bytes(frame[44:52], "little"),
                        signature_hex=frame[4:20].hex(), nonce_hex=frame[20:36].hex(),
                        source=segment.source, source_port=segment.source_port,
                        destination=segment.destination, destination_port=segment.destination_port,
                        packet_indices=packet_indices,
                    ))
            elif frame.startswith(b"\xfcSMB") and len(frame) > 16:
                declared_size = int.from_bytes(frame[4:8], "little")
                algorithm = int.from_bytes(frame[8:10], "little")
                flags = int.from_bytes(frame[10:12], "little")
                data_offset = int.from_bytes(frame[12:16], "little")
                payload_size = len(frame) - 16
                ordinary_valid = flags == 0 and algorithm in {1, 2, 3, 4} and data_offset <= payload_size
                chained_valid = flags == 1 and algorithm == 0 and data_offset == 0 and payload_size >= 8
                if (ordinary_valid or chained_valid) and 0 < declared_size <= max_original_message_bytes:
                    records.append(Smb3TransformRecord(
                        transform_type="compression", declared_original_size=declared_size, flags=flags,
                        framed_size=message_length, transformed_payload_size=payload_size,
                        compression_algorithm=algorithm, compression_algorithm_name=compression_names[algorithm],
                        data_offset=data_offset, source=segment.source, source_port=segment.source_port,
                        destination=segment.destination, destination_port=segment.destination_port,
                        packet_indices=packet_indices,
                    ))
    yield from records


def _smb2_directory_entries(data: bytes, information_class: int) -> tuple[Smb2DirectoryEntry, ...] | None:
    """Validate one bounded FileNames/FileIdBoth directory-information buffer."""
    if information_class not in {12, 37} or not data:
        return None
    entries: list[Smb2DirectoryEntry] = []
    cursor = 0
    terminated = False
    minimum_entry_size = 12 if information_class == 12 else 104
    filename_offset = 12 if information_class == 12 else 104
    filename_length_offset = 8 if information_class == 12 else 60
    for _ in range(256):
        if cursor + minimum_entry_size > len(data):
            return None
        next_entry = int.from_bytes(data[cursor:cursor + 4], "little")
        entry_end = cursor + next_entry if next_entry else len(data)
        if (
            entry_end > len(data)
            or entry_end < cursor + minimum_entry_size
            or (next_entry and (next_entry < minimum_entry_size or next_entry % 8))
        ):
            return None
        name_length_start = cursor + filename_length_offset
        name_length = int.from_bytes(data[name_length_start:name_length_start + 4], "little")
        name_start = cursor + filename_offset
        name_end = name_start + name_length
        if name_length <= 0 or name_length > 510 or name_length % 2 or name_end > entry_end:
            return None
        try:
            name = data[name_start:name_end].decode("utf-16le", errors="strict")
        except UnicodeDecodeError:
            return None
        if not name or len(name) > 255 or "\x00" in name:
            return None
        if information_class == 12:
            entries.append(Smb2DirectoryEntry(
                name=name,
                file_index=int.from_bytes(data[cursor + 4:cursor + 8], "little"),
            ))
        else:
            short_name_length = data[cursor + 68]
            if short_name_length > 24 or short_name_length % 2:
                return None
            short_name: str | None = None
            if short_name_length:
                try:
                    short_name = data[cursor + 70:cursor + 70 + short_name_length].decode("utf-16le", errors="strict")
                except UnicodeDecodeError:
                    return None
                if not short_name or len(short_name) > 12 or "\x00" in short_name:
                    return None
            entries.append(Smb2DirectoryEntry(
                name=name,
                file_index=int.from_bytes(data[cursor + 4:cursor + 8], "little"),
                creation_filetime=int.from_bytes(data[cursor + 8:cursor + 16], "little"),
                last_access_filetime=int.from_bytes(data[cursor + 16:cursor + 24], "little"),
                last_write_filetime=int.from_bytes(data[cursor + 24:cursor + 32], "little"),
                change_filetime=int.from_bytes(data[cursor + 32:cursor + 40], "little"),
                end_of_file=int.from_bytes(data[cursor + 40:cursor + 48], "little"),
                allocation_size=int.from_bytes(data[cursor + 48:cursor + 56], "little"),
                file_attributes=int.from_bytes(data[cursor + 56:cursor + 60], "little"),
                ea_size=int.from_bytes(data[cursor + 64:cursor + 68], "little"),
                short_name=short_name,
                file_id=int.from_bytes(data[cursor + 96:cursor + 104], "little"),
            ))
        if not next_entry:
            terminated = True
            break
        cursor = entry_end
    if not terminated or not entries:
        return None
    return tuple(entries)


def _smb2_directory_listing_body(entries: tuple[Smb2DirectoryEntry, ...], information_class: int) -> bytes:
    if information_class == 12:
        return ("\n".join(entry.name for entry in entries) + "\n").encode("utf-8")
    lines = []
    for entry in entries:
        lines.append(json.dumps({
            "name": entry.name,
            "file_index": entry.file_index,
            "creation_filetime": entry.creation_filetime,
            "last_access_filetime": entry.last_access_filetime,
            "last_write_filetime": entry.last_write_filetime,
            "change_filetime": entry.change_filetime,
            "end_of_file": entry.end_of_file,
            "allocation_size": entry.allocation_size,
            "file_attributes": entry.file_attributes,
            "ea_size": entry.ea_size,
            "short_name": entry.short_name,
            "file_id": entry.file_id,
        }, ensure_ascii=False, separators=(",", ":")))
    return ("\n".join(lines) + "\n").encode("utf-8")


def iter_smb2_directory_listings(path: Path, *, max_listings: int = 32, max_message_bytes: int = 1024 * 1024,
                                 max_packets: int = 200_000, max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[Smb2DirectoryListing]:
    """Recover bounded SMB2 FileNames/FileIdBoth QUERY_DIRECTORY responses."""
    creates = [
        item for item in iter_smb2_create_operations(
            path, max_operations=max_listings * 4, max_message_bytes=max_message_bytes,
            max_packets=max_packets, max_scan_bytes=max_scan_bytes,
        )
        if item.response_status == 0 and item.persistent_file_id is not None and item.volatile_file_id is not None
    ]
    known = {
        ((item.source, item.source_port, item.destination, item.destination_port), item.session_id, item.tree_id,
         int(item.persistent_file_id), int(item.volatile_file_id)): item
        for item in creates
    }
    if not known:
        return
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    pending: dict[tuple[tuple[str, int, str, int], int, int, int], dict[str, object]] = {}
    records: list[Smb2DirectoryListing] = []
    maximum_buffer = max_message_bytes * 2 + 8
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload or (segment.destination_port != 445 and segment.source_port != 445):
            continue
        flow = flows.get(segment.flow)
        if flow is None:
            if len(flows) >= 512:
                continue
            flow = _TcpFlow()
            flows[segment.flow] = flow
        _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, maximum_buffer)
        while len(flow.data) >= 4:
            if flow.data[0] != 0:
                _reset_tcp_flow(flow)
                break
            message_length = int.from_bytes(flow.data[1:4], "big")
            if message_length < 64 or message_length > max_message_bytes:
                _reset_tcp_flow(flow)
                break
            framed_length = 4 + message_length
            if len(flow.data) < framed_length:
                break
            packet_indices = _flow_packet_indices(flow, flow.start_sequence, framed_length)
            frame = bytes(flow.data[4:framed_length])
            _consume_tcp_flow(flow, framed_length)
            if not packet_indices or not flow.packet_provenance_complete:
                continue
            command_offset = 0
            for _ in range(16):
                if command_offset + 64 > len(frame) or frame[command_offset:command_offset + 4] != b"\xfeSMB":
                    break
                if int.from_bytes(frame[command_offset + 4:command_offset + 6], "little") != 64:
                    break
                command = int.from_bytes(frame[command_offset + 12:command_offset + 14], "little")
                flags = int.from_bytes(frame[command_offset + 16:command_offset + 20], "little")
                next_command = int.from_bytes(frame[command_offset + 20:command_offset + 24], "little")
                message_id = int.from_bytes(frame[command_offset + 24:command_offset + 32], "little")
                tree_id = int.from_bytes(frame[command_offset + 36:command_offset + 40], "little")
                session_id = int.from_bytes(frame[command_offset + 40:command_offset + 48], "little")
                command_end = command_offset + next_command if next_command else len(frame)
                if command_end > len(frame) or command_end < command_offset + 64 or (next_command and next_command % 8):
                    break
                if command == 14 and not (flags & 1) and command_offset + 96 <= command_end and len(pending) < max_listings * 4:
                    request = command_offset + 64
                    information_class = frame[request + 2]
                    if int.from_bytes(frame[request:request + 2], "little") == 33 and information_class in {12, 37}:
                        persistent = int.from_bytes(frame[request + 8:request + 16], "little")
                        volatile = int.from_bytes(frame[request + 16:request + 24], "little")
                        file_key = (segment.flow, session_id, tree_id, persistent, volatile)
                        create = known.get(file_key)
                        pattern_offset = int.from_bytes(frame[request + 24:request + 26], "little")
                        pattern_length = int.from_bytes(frame[request + 26:request + 28], "little")
                        pattern: str | None = None
                        if pattern_length:
                            pattern_start = command_offset + pattern_offset
                            pattern_end = pattern_start + pattern_length
                            if pattern_length > 510 or pattern_length % 2 or pattern_offset < 64 or pattern_end > command_end:
                                create = None
                            else:
                                try:
                                    decoded_pattern = frame[pattern_start:pattern_end].decode("utf-16le", errors="strict")
                                except UnicodeDecodeError:
                                    decoded_pattern = ""
                                if not decoded_pattern or len(decoded_pattern) > 255 or "\x00" in decoded_pattern:
                                    create = None
                                else:
                                    pattern = decoded_pattern
                        if create is not None:
                            pending[(segment.flow, message_id, session_id, tree_id)] = {
                                "create": create, "pattern": pattern, "persistent": persistent, "volatile": volatile,
                                "information_class": information_class, "request_packet_indices": packet_indices,
                            }
                elif command == 14 and flags & 1 and len(records) < max_listings:
                    client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
                    request_record = pending.pop((client_flow, message_id, session_id, tree_id), None)
                    response = command_offset + 64
                    status = int.from_bytes(frame[command_offset + 8:command_offset + 12], "little")
                    if request_record is not None and status == 0 and response + 8 <= command_end and int.from_bytes(frame[response:response + 2], "little") == 9:
                        output_offset = int.from_bytes(frame[response + 2:response + 4], "little")
                        output_length = int.from_bytes(frame[response + 4:response + 8], "little")
                        output_start = command_offset + output_offset
                        output_end = output_start + output_length
                        if 0 < output_length <= max_message_bytes and output_offset >= 64 and output_end <= command_end:
                            information_class = int(request_record["information_class"])
                            entries = _smb2_directory_entries(frame[output_start:output_end], information_class)
                            if entries is not None:
                                create = request_record["create"]
                                body = _smb2_directory_listing_body(entries, information_class)
                                if len(body) <= max_message_bytes:
                                    directory_name = PurePosixPath(create.filename.replace("\\", "/")).name or "root"
                                    class_name = "FileNamesInformation" if information_class == 12 else "FileIdBothDirectoryInformation"
                                    suffix = "listing.txt" if information_class == 12 else "inventory.jsonl"
                                    records.append(Smb2DirectoryListing(
                                        logical_name=f"{directory_name}_smb2_directory_{suffix}",
                                        directory_path=create.filename, share_path=create.share_path,
                                        pattern=request_record["pattern"], information_class=information_class,
                                        information_class_name=class_name, entries=entries,
                                        names=tuple(entry.name for entry in entries), body=body,
                                        persistent_file_id=int(request_record["persistent"]), volatile_file_id=int(request_record["volatile"]),
                                        message_id=message_id, source=segment.source, source_port=segment.source_port,
                                        destination=segment.destination, destination_port=segment.destination_port,
                                        request_packet_indices=tuple(request_record["request_packet_indices"]), packet_indices=packet_indices,
                                    ))
                if not next_command:
                    break
                command_offset = command_end
    yield from records


def iter_smtp_data_objects(path: Path, *, max_objects: int = 32, max_body_bytes: int = 64 * 1024 * 1024,
                           max_packets: int = 200_000, max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[SmtpDataObject]:
    """Recover complete SMTP DATA bodies only after exact DATA/354 correlation."""
    data_commands: dict[tuple[str, int, str, int], int] = {}
    starttls_commands: dict[tuple[str, int, str, int], int] = {}
    encrypted_flows: set[tuple[str, int, str, int]] = set()
    ready: dict[tuple[str, int, str, int], tuple[int, int]] = {}
    bodies: dict[tuple[str, int, str, int], _TcpFlow] = {}
    control_flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    completed_messages: list[dict[str, object]] = []
    completed_by_flow: dict[tuple[str, int, str, int], list[dict[str, object]]] = {}
    produced = 0
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload:
            continue
        if segment.flow in encrypted_flows:
            continue
        setup = ready.get(segment.flow)
        if setup is None and (segment.destination_port == 25 or segment.source_port == 25):
            for line, line_indices in _smtp_control_lines(control_flows, segment, packet_index):
                line_index = line_indices[-1] if line_indices else packet_index
                if segment.destination_port == 25 and line.upper() == "DATA":
                    data_commands[segment.flow] = line_index
                elif segment.destination_port == 25 and line.upper() == "STARTTLS":
                    starttls_commands[segment.flow] = line_index
                elif segment.source_port == 25 and re.match(r"354(?:\s|$)", line):
                    client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
                    command_index = data_commands.get(client_flow)
                    if command_index is not None:
                        ready[client_flow] = (command_index, line_index)
                elif segment.source_port == 25 and re.match(r"220(?:\s|$)", line):
                    client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
                    if client_flow in starttls_commands:
                        encrypted_flows.add(client_flow)
                        encrypted_flows.add(segment.flow)
                elif segment.source_port == 25 and re.match(r"(?:250|251|252|[45]\d{2})(?:\s|$)", line):
                    client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
                    pending = completed_by_flow.get(client_flow)
                    if pending:
                        code = int(line[:3])
                        status = "acceptance" if code == 250 else "forwarding" if code in {251, 252} else "rejection"
                        pending[-1][status] = (code, line_index)
            continue
        if setup is None:
            continue
        body_flow = bodies.setdefault(segment.flow, _TcpFlow())
        if _tcp_flow_buffered_length(body_flow) + len(segment.payload) > max_body_bytes:
            del ready[segment.flow]
            bodies.pop(segment.flow, None)
            continue
        _append_tcp_segment(body_flow, segment.sequence, segment.payload, packet_index, max_body_bytes)
        marker = body_flow.data.find(b"\r\n.\r\n")
        if marker < 0:
            continue
        packet_indices = _flow_packet_indices(body_flow, body_flow.start_sequence, marker + 2)
        body = bytes(body_flow.data[:marker + 2]).replace(b"\r\n..", b"\r\n.")
        record = {
            "logical_name": f"smtp_message_{produced:04d}.eml", "body": body,
            "source": segment.source, "source_port": segment.source_port,
            "destination": segment.destination, "destination_port": segment.destination_port,
            "packet_indices": packet_indices, "data_command_packet_index": setup[0],
            "ready_response_packet_index": setup[1], "flow": segment.flow,
        }
        completed_messages.append(record)
        completed_by_flow.setdefault(segment.flow, []).append(record)
        produced += 1
        ready.pop(segment.flow, None)
        bodies.pop(segment.flow, None)
        if produced >= max_objects:
            break
    for record in completed_messages:
        acceptance = record.get("acceptance")
        code, acceptance_packet_index = acceptance if isinstance(acceptance, tuple) else (None, None)
        rejection = record.get("rejection")
        rejection_code, rejection_packet_index = rejection if isinstance(rejection, tuple) else (None, None)
        forwarding = record.get("forwarding")
        forwarding_code, forwarding_packet_index = forwarding if isinstance(forwarding, tuple) else (None, None)
        yield SmtpDataObject(
            logical_name=str(record["logical_name"]), body=bytes(record["body"]),
            source=str(record["source"]), source_port=int(record["source_port"]),
            destination=str(record["destination"]), destination_port=int(record["destination_port"]),
            packet_indices=tuple(record["packet_indices"]), data_command_packet_index=int(record["data_command_packet_index"]),
            ready_response_packet_index=int(record["ready_response_packet_index"]),
            acceptance_code=code, acceptance_packet_index=acceptance_packet_index,
            rejection_code=rejection_code, rejection_packet_index=rejection_packet_index,
            forwarding_code=forwarding_code, forwarding_packet_index=forwarding_packet_index,
        )


def iter_smtp_starttls_transitions(path: Path, *, max_packets: int = 200_000,
                                   max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[SmtpStarttlsTransition]:
    """Return exact SMTP STARTTLS/220 transitions without interpreting TLS bytes."""
    commands: dict[tuple[str, int, str, int], int] = {}
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload or (segment.destination_port != 25 and segment.source_port != 25):
            continue
        for line, indices in _smtp_control_lines(flows, segment, packet_index):
            line_index = indices[-1] if indices else packet_index
            if segment.destination_port == 25 and line.upper() == "STARTTLS":
                commands[segment.flow] = line_index
            elif segment.source_port == 25 and re.match(r"220(?:\s|$)", line):
                client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
                command_index = commands.pop(client_flow, None)
                if command_index is not None:
                    yield SmtpStarttlsTransition(client_flow[0], client_flow[1], client_flow[2], client_flow[3], command_index, line_index)


def iter_smtp_bdat_objects(path: Path, *, max_objects: int = 32, max_body_bytes: int = 64 * 1024 * 1024,
                           max_packets: int = 200_000, max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[SmtpBdatObject]:
    """Recover exact-length SMTP BDAT messages, never guessing chunk boundaries."""
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    states: dict[tuple[str, int, str, int], dict[str, object]] = {}
    completed: list[dict[str, object]] = []
    completed_by_flow: dict[tuple[str, int, str, int], list[dict[str, object]]] = {}
    control_flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload or (segment.destination_port != 25 and segment.source_port != 25):
            continue
        if segment.source_port == 25:
            for line, indices in _smtp_control_lines(control_flows, segment, packet_index):
                if not re.match(r"(?:250|251|252|[45]\d{2})(?:\s|$)", line):
                    continue
                client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
                pending = completed_by_flow.get(client_flow)
                if pending:
                    pending[-1]["final_response"] = (int(line[:3]), indices[-1] if indices else packet_index)
            continue
        flow = flows.get(segment.flow)
        if flow is None:
            if len(flows) >= 512:
                continue
            flow = _TcpFlow()
            flows[segment.flow] = flow
        _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, max_body_bytes)
        state = states.setdefault(segment.flow, {"body": bytearray(), "packet_indices": set(), "command_packet_indices": [], "remaining": None, "last": False})
        while flow.data:
            remaining = state["remaining"]
            if isinstance(remaining, int):
                if len(flow.data) < remaining:
                    start = flow.start_sequence
                    state["body"].extend(flow.data)
                    state["packet_indices"].update(_flow_packet_indices(flow, start, len(flow.data)))
                    state["remaining"] = remaining - len(flow.data)
                    _consume_tcp_flow(flow, len(flow.data))
                    break
                start = flow.start_sequence
                state["body"].extend(flow.data[:remaining])
                state["packet_indices"].update(_flow_packet_indices(flow, start, remaining))
                _consume_tcp_flow(flow, remaining)
                state["remaining"] = None
                if state["last"]:
                    record = {"flow": segment.flow, **state}
                    completed.append(record)
                    completed_by_flow.setdefault(segment.flow, []).append(record)
                    states[segment.flow] = {"body": bytearray(), "packet_indices": set(), "command_packet_indices": [], "remaining": None, "last": False}
                    state = states[segment.flow]
                    if len(completed) >= max_objects:
                        break
                continue
            end = flow.data.find(b"\r\n")
            if end < 0:
                if len(flow.data) > 8 * 1024:
                    _reset_tcp_flow(flow)
                break
            command_start = flow.start_sequence
            line = bytes(flow.data[:end]).decode("latin-1", errors="replace")
            command_indices = _flow_packet_indices(flow, command_start, end + 2)
            _consume_tcp_flow(flow, end + 2)
            match = re.fullmatch(r"BDAT\s+(\d{1,8})(?:\s+(LAST))?", line, re.I)
            if match is None:
                continue
            length = int(match.group(1))
            if length > max_body_bytes or len(state["body"]) + length > max_body_bytes:
                states.pop(segment.flow, None)
                _reset_tcp_flow(flow)
                break
            state["remaining"] = length
            state["last"] = bool(match.group(2))
            state["command_packet_indices"].append(command_indices[-1] if command_indices else packet_index)
            if length == 0:
                state["remaining"] = None
                if state["last"]:
                    record = {"flow": segment.flow, **state}
                    completed.append(record)
                    completed_by_flow.setdefault(segment.flow, []).append(record)
                    states[segment.flow] = {"body": bytearray(), "packet_indices": set(), "command_packet_indices": [], "remaining": None, "last": False}
                    state = states[segment.flow]
    for index, record in enumerate(completed[:max_objects]):
        source, source_port, destination, destination_port = record["flow"]
        final_response = record.get("final_response")
        final_response_code, final_response_packet_index = final_response if isinstance(final_response, tuple) else (None, None)
        yield SmtpBdatObject(
            logical_name=f"smtp_bdat_message_{index:04d}.eml", body=bytes(record["body"]),
            source=source, source_port=source_port, destination=destination, destination_port=destination_port,
            packet_indices=tuple(sorted(record["packet_indices"])), command_packet_indices=tuple(record["command_packet_indices"]),
            final_response_code=final_response_code, final_response_packet_index=final_response_packet_index,
        )


def iter_pop3_retr_objects(path: Path, *, max_objects: int = 32, max_body_bytes: int = 64 * 1024 * 1024,
                           max_packets: int = 200_000, max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[Pop3RetrObject]:
    """Recover bounded POP3 RETR bodies only after exact inverse ``+OK`` replies.

    POP3 uses a dot-terminated multiline response.  The parser keeps a small
    sequence-aware window per observed TCP/110 direction and never promotes a
    response without both its RETR command and final terminator.
    """
    commands: dict[tuple[str, int, str, int], list[int]] = {}
    stls_commands: dict[tuple[str, int, str, int], int] = {}
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    active: dict[tuple[str, int, str, int], tuple[int, int]] = {}
    encrypted_flows: set[tuple[str, int, str, int]] = set()
    produced = 0
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload or (segment.destination_port != 110 and segment.source_port != 110):
            continue
        if segment.flow in encrypted_flows:
            continue
        if segment.destination_port == 110:
            for line, indices in _pop3_control_lines(flows, segment, packet_index):
                if line.upper() == "STLS":
                    stls_commands[segment.flow] = indices[-1] if indices else packet_index
                elif re.fullmatch(r"RETR\s+\d{1,10}", line, re.I):
                    commands.setdefault(segment.flow, []).append(indices[-1] if indices else packet_index)
            continue
        flow = flows.get(segment.flow)
        if flow is None:
            if len(flows) >= 512:
                continue
            flow = _TcpFlow()
            flows[segment.flow] = flow
        _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, max_body_bytes + 8 * 1024)
        client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
        while flow.data and produced < max_objects:
            command = active.get(segment.flow)
            if command is None:
                line_end = flow.data.find(b"\r\n")
                if line_end < 0:
                    if len(flow.data) > 8 * 1024:
                        _reset_tcp_flow(flow)
                    break
                line_indices = _flow_packet_indices(flow, flow.start_sequence, line_end + 2)
                line = bytes(flow.data[:line_end]).decode("latin-1", errors="replace")
                _consume_tcp_flow(flow, line_end + 2)
                if client_flow in stls_commands:
                    stls_commands.pop(client_flow, None)
                    if re.match(r"\+OK(?:\s|$)", line, re.I):
                        encrypted_flows.add(client_flow)
                        encrypted_flows.add(segment.flow)
                        commands.pop(client_flow, None)
                        active.pop(segment.flow, None)
                        break
                    continue
                pending = commands.get(client_flow)
                if not pending:
                    continue
                retr_command_index = pending.pop(0)
                if not pending:
                    commands.pop(client_flow, None)
                if re.match(r"\+OK(?:\s|$)", line, re.I):
                    active[segment.flow] = (retr_command_index, line_indices[-1] if line_indices else packet_index)
                continue
            if flow.data.startswith(b".\r\n"):
                body_length = 0
                consumed = 3
            else:
                marker = flow.data.find(b"\r\n.\r\n")
                if marker < 0:
                    if len(flow.data) > max_body_bytes:
                        active.pop(segment.flow, None)
                        _reset_tcp_flow(flow)
                    break
                body_length = marker + 2
                consumed = marker + 5
            packet_indices = _flow_packet_indices(flow, flow.start_sequence, body_length)
            body = bytes(flow.data[:body_length]).replace(b"\r\n..", b"\r\n.")
            _consume_tcp_flow(flow, consumed)
            retr_command_index, positive_response_packet_index = active.pop(segment.flow)
            yield Pop3RetrObject(
                logical_name=f"pop3_retr_message_{produced:04d}.eml", body=body,
                source=segment.source, source_port=segment.source_port,
                destination=segment.destination, destination_port=segment.destination_port,
                packet_indices=packet_indices, retr_command_packet_index=retr_command_index,
                positive_response_packet_index=positive_response_packet_index,
            )
            produced += 1


def iter_pop3_stls_transitions(path: Path, *, max_transitions: int = 32, max_packets: int = 200_000,
                               max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[Pop3StlsTransition]:
    """Yield exact TCP/110 POP3 STLS/+OK transitions only."""
    commands: dict[tuple[str, int, str, int], int] = {}
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    encrypted_flows: set[tuple[str, int, str, int]] = set()
    produced = 0
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload or (segment.destination_port != 110 and segment.source_port != 110):
            continue
        if segment.flow in encrypted_flows:
            continue
        for line, indices in _pop3_control_lines(flows, segment, packet_index):
            line_index = indices[-1] if indices else packet_index
            if segment.destination_port == 110:
                if line.upper() == "STLS" and (segment.flow in commands or len(commands) < 512):
                    commands[segment.flow] = line_index
                continue
            client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
            command_index = commands.get(client_flow)
            if command_index is None or not re.match(r"[+-](?:OK|ERR)(?:\s|$)", line, re.I):
                continue
            commands.pop(client_flow, None)
            if not re.match(r"\+OK(?:\s|$)", line, re.I):
                continue
            encrypted_flows.add(client_flow)
            encrypted_flows.add(segment.flow)
            yield Pop3StlsTransition(
                source=client_flow[0], source_port=client_flow[1],
                destination=client_flow[2], destination_port=client_flow[3],
                command_packet_index=command_index, ready_response_packet_index=line_index,
            )
            produced += 1
            if produced >= max_transitions:
                return
            break


def _pop3_control_lines(
    flows: dict[tuple[str, int, str, int], _TcpFlow], segment: _TcpSegment, packet_index: int,
) -> Iterator[tuple[str, tuple[int, ...]]]:
    """Yield bounded complete POP3 command lines from one client TCP flow."""
    flow = flows.get(segment.flow)
    if flow is None:
        if len(flows) >= 512:
            return
        flow = _TcpFlow()
        flows[segment.flow] = flow
    _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, 64 * 1024)
    while flow.data:
        end = flow.data.find(b"\r\n")
        if end < 0:
            if len(flow.data) > 8 * 1024:
                _reset_tcp_flow(flow)
            return
        indices = _flow_packet_indices(flow, flow.start_sequence, end + 2)
        line = bytes(flow.data[:end]).decode("latin-1", errors="replace")
        _consume_tcp_flow(flow, end + 2)
        yield line, indices


def iter_imap_fetch_objects(path: Path, *, max_objects: int = 32, max_body_bytes: int = 64 * 1024 * 1024,
                            max_packets: int = 200_000, max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[ImapFetchObject]:
    """Recover complete IMAP BODY[]/RFC822 literals after tagged ``OK`` completion.

    This narrow offline parser accepts only a complete client ``FETCH`` for a
    full-message field, its inverse untagged FETCH literal declaration, and
    the matching tagged success line.  Other IMAP constructs are left to
    tshark instead of guessing message boundaries.
    """
    commands: dict[tuple[str, int, str, int], list[tuple[str, int]]] = {}
    starttls_commands: dict[tuple[str, int, str, int], dict[str, int]] = {}
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    active: dict[tuple[str, int, str, int], dict[str, object]] = {}
    encrypted_flows: set[tuple[str, int, str, int]] = set()
    produced = 0
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload or (segment.destination_port != 143 and segment.source_port != 143):
            continue
        if segment.flow in encrypted_flows:
            continue
        if segment.destination_port == 143:
            for line, indices in _imap_control_lines(flows, segment, packet_index):
                starttls = re.fullmatch(r"([^\s()]{1,32})\s+STARTTLS", line, re.I)
                if starttls:
                    starttls_commands.setdefault(segment.flow, {})[starttls.group(1)] = indices[-1] if indices else packet_index
                    continue
                match = re.fullmatch(r"([^\s()]{1,32})\s+FETCH\s+\d{1,10}\s+.*(?:BODY\[\]|RFC822)(?:\.PEEK)?[^\r\n]*", line, re.I)
                if match:
                    commands.setdefault(segment.flow, []).append((match.group(1), indices[-1] if indices else packet_index))
            continue
        flow = flows.get(segment.flow)
        if flow is None:
            if len(flows) >= 512:
                continue
            flow = _TcpFlow()
            flows[segment.flow] = flow
        _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, max_body_bytes + 8 * 1024)
        client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
        while flow.data and produced < max_objects:
            state = active.get(segment.flow)
            if state is not None and int(state["remaining"]) > 0:
                remaining = int(state["remaining"])
                take = min(remaining, len(flow.data))
                start = flow.start_sequence
                state["body"].extend(flow.data[:take])
                state["packet_indices"].update(_flow_packet_indices(flow, start, take))
                _consume_tcp_flow(flow, take)
                state["remaining"] = remaining - take
                if int(state["remaining"]) > 0:
                    break
                continue
            line_end = flow.data.find(b"\r\n")
            if line_end < 0:
                if len(flow.data) > 8 * 1024:
                    _reset_tcp_flow(flow)
                    active.pop(segment.flow, None)
                break
            line_indices = _flow_packet_indices(flow, flow.start_sequence, line_end + 2)
            line = bytes(flow.data[:line_end]).decode("latin-1", errors="replace")
            _consume_tcp_flow(flow, line_end + 2)
            if state is None:
                starttls = re.fullmatch(r"([^\s()]{1,32})\s+OK(?:\s|$).*", line, re.I)
                if starttls and starttls.group(1) in starttls_commands.get(client_flow, {}):
                    encrypted_flows.add(client_flow)
                    encrypted_flows.add(segment.flow)
                    active.pop(segment.flow, None)
                    commands.pop(client_flow, None)
                    continue
                pending = commands.get(client_flow)
                literal = re.fullmatch(r"\*\s+\d{1,10}\s+FETCH\s+\(.*(?:BODY\[\]|RFC822)(?:\.PEEK)?[^{}]*\{(\d{1,8})\}", line, re.I)
                if literal is None or not pending:
                    continue
                length = int(literal.group(1))
                if length > max_body_bytes:
                    continue
                tag, command_packet_index = pending.pop(0)
                if not pending:
                    commands.pop(client_flow, None)
                active[segment.flow] = {
                    "tag": tag, "command_packet_index": command_packet_index,
                    "literal_response_packet_index": line_indices[-1] if line_indices else packet_index,
                    "remaining": length, "body": bytearray(), "packet_indices": set(),
                }
                continue
            tag = str(state["tag"])
            completion = re.fullmatch(rf"{re.escape(tag)}\s+OK(?:\s|$).*", line, re.I)
            if completion is not None:
                yield ImapFetchObject(
                    logical_name=f"imap_fetch_message_{produced:04d}.eml", body=bytes(state["body"]),
                    source=segment.source, source_port=segment.source_port,
                    destination=segment.destination, destination_port=segment.destination_port,
                    packet_indices=tuple(sorted(state["packet_indices"])),
                    fetch_command_packet_index=int(state["command_packet_index"]),
                    literal_response_packet_index=int(state["literal_response_packet_index"]),
                    completion_packet_index=line_indices[-1] if line_indices else packet_index,
                )
                produced += 1
                active.pop(segment.flow, None)
            elif re.fullmatch(rf"{re.escape(tag)}\s+(?:NO|BAD)(?:\s|$).*", line, re.I):
                active.pop(segment.flow, None)


def iter_imap_starttls_transitions(path: Path, *, max_transitions: int = 32, max_packets: int = 200_000,
                                   max_scan_bytes: int = 128 * 1024 * 1024) -> Iterator[ImapStarttlsTransition]:
    """Yield exact TCP/143 IMAP STARTTLS/tagged-OK transitions only."""
    commands: dict[tuple[str, int, str, int], dict[str, int]] = {}
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    produced = 0
    for packet_index, packet in enumerate(_iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1):
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload or (segment.destination_port != 143 and segment.source_port != 143):
            continue
        for line, indices in _imap_control_lines(flows, segment, packet_index):
            line_index = indices[-1] if indices else packet_index
            if segment.destination_port == 143:
                match = re.fullmatch(r"([^\s()]{1,32})\s+STARTTLS", line, re.I)
                if match:
                    pending = commands.get(segment.flow)
                    if pending is None:
                        if len(commands) >= 512:
                            continue
                        pending = {}
                        commands[segment.flow] = pending
                    if len(pending) < 128:
                        pending[match.group(1)] = line_index
                continue
            response = re.fullmatch(r"([^\s()]{1,32})\s+OK(?:\s|$).*", line, re.I)
            if response is None:
                continue
            client_flow = (segment.destination, segment.destination_port, segment.source, segment.source_port)
            pending = commands.get(client_flow)
            command_index = pending.pop(response.group(1), None) if pending else None
            if pending == {}:
                commands.pop(client_flow, None)
            if command_index is None:
                continue
            yield ImapStarttlsTransition(
                tag=response.group(1), source=client_flow[0], source_port=client_flow[1],
                destination=client_flow[2], destination_port=client_flow[3],
                command_packet_index=command_index, ready_response_packet_index=line_index,
            )
            produced += 1
            if produced >= max_transitions:
                return


def _imap_control_lines(
    flows: dict[tuple[str, int, str, int], _TcpFlow], segment: _TcpSegment, packet_index: int,
) -> Iterator[tuple[str, tuple[int, ...]]]:
    """Yield complete bounded IMAP client command lines without literals."""
    flow = flows.get(segment.flow)
    if flow is None:
        if len(flows) >= 512:
            return
        flow = _TcpFlow()
        flows[segment.flow] = flow
    _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, 64 * 1024)
    while flow.data:
        end = flow.data.find(b"\r\n")
        if end < 0:
            if len(flow.data) > 8 * 1024:
                _reset_tcp_flow(flow)
            return
        indices = _flow_packet_indices(flow, flow.start_sequence, end + 2)
        line = bytes(flow.data[:end]).decode("latin-1", errors="replace")
        _consume_tcp_flow(flow, end + 2)
        yield line, indices


def _smtp_control_lines(
    flows: dict[tuple[str, int, str, int], _TcpFlow], segment: _TcpSegment, packet_index: int,
) -> Iterator[tuple[str, tuple[int, ...]]]:
    """Yield complete bounded SMTP control lines, never message DATA bytes."""
    flow = flows.get(segment.flow)
    if flow is None:
        if len(flows) >= 512:
            return
        flow = _TcpFlow()
        flows[segment.flow] = flow
    _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, 64 * 1024)
    while flow.data:
        end = flow.data.find(b"\r\n")
        if end < 0:
            if len(flow.data) > 8 * 1024:
                _reset_tcp_flow(flow)
            return
        line_indices = _flow_packet_indices(flow, flow.start_sequence, end + 2)
        raw = bytes(flow.data[:end])
        _consume_tcp_flow(flow, end + 2)
        yield raw.decode("latin-1", errors="replace"), line_indices


def _ftp_control_lines(
    flows: dict[tuple[str, int, str, int], _TcpFlow], segment: _TcpSegment, packet_index: int,
) -> Iterator[tuple[str, tuple[int, ...]]]:
    """Yield only complete bounded FTP control lines from one TCP direction."""
    flow = flows.get(segment.flow)
    if flow is None:
        if len(flows) >= 512:
            return
        flow = _TcpFlow()
        flows[segment.flow] = flow
    _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, 64 * 1024)
    while flow.data:
        end = flow.data.find(b"\r\n")
        if end < 0:
            if len(flow.data) > 8 * 1024:
                _reset_tcp_flow(flow)
            return
        start = flow.start_sequence
        packet_indices = _flow_packet_indices(flow, start, end + 2)
        raw = bytes(flow.data[:end])
        _consume_tcp_flow(flow, end + 2)
        yield raw.decode("latin-1", errors="replace"), packet_indices


def iter_http_response_objects(
    path: Path,
    *,
    max_objects: int = 100,
    max_body_bytes: int = 64 * 1024 * 1024,
    max_flows: int = 512,
    max_reassembly_bytes_per_flow: int = 72 * 1024 * 1024,
    max_total_reassembly_bytes: int = 256 * 1024 * 1024,
    max_packets: int = 200_000,
    max_scan_bytes: int = 128 * 1024 * 1024,
) -> Iterator[HttpResponseObject]:
    """Yield bounded HTTP response objects from Ethernet PCAP/PCAPNG traffic.

    Responses can span ordered TCP segments and may use either Content-Length
    or chunked transfer encoding.  TCP retransmissions are harmless; gaps and
    excessive flow state are safely ignored rather than guessed at.  This is a
    dependency-free fallback for environments without tshark, not a full TCP
    implementation.
    """
    produced = 0
    flows: dict[tuple[str, int, str, int], _TcpFlow] = {}
    requests_by_flow: dict[tuple[str, int, str, int], list[dict[str, object]]] = {}
    request_flow_pairing_truncated: set[tuple[str, int, str, int]] = set()
    total_buffered = 0
    for packet_index, packet in enumerate(
        _iter_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes), start=1,
    ):
        if produced >= max_objects:
            return
        if len(packet) > max_reassembly_bytes_per_flow + 128 * 1024:
            continue
        segment = _ethernet_tcp_segment(packet)
        if segment is None or not segment.payload:
            continue
        key = segment.flow
        flow = flows.get(key)
        if flow is None:
            if len(flows) >= max_flows:
                continue
            flow = _TcpFlow()
            flows[key] = flow
        before = _tcp_flow_buffered_length(flow)
        _append_tcp_segment(flow, segment.sequence, segment.payload, packet_index, max_reassembly_bytes_per_flow)
        after = _tcp_flow_buffered_length(flow)
        total_buffered += after - before
        if total_buffered > max_total_reassembly_bytes:
            # Keeping recent flows cannot be justified once the global bound
            # is hit.  Drop the largest buffered flow deterministically.
            largest_key, largest = max(
                flows.items(),
                key=lambda item: _tcp_flow_buffered_length(item[1]),
            )
            total_buffered -= _tcp_flow_buffered_length(largest)
            del flows[largest_key]
            requests_by_flow.pop(largest_key, None)
            request_flow_pairing_truncated.discard(largest_key)
            if largest_key == key:
                continue

        for request, consumed in _complete_http_requests(flow.data, max_body_bytes):
            request_start = flow.start_sequence
            request["packet_indices"] = _flow_packet_indices(flow, request_start, consumed)
            request["packet_provenance_complete"] = flow.packet_provenance_complete
            _consume_tcp_flow(flow, consumed)
            total_buffered -= consumed
            if key in request_flow_pairing_truncated:
                continue
            queue = requests_by_flow.setdefault(key, [])
            if len(queue) >= _MAX_HTTP_REQUESTS_PER_FLOW:
                queue.clear()
                request_flow_pairing_truncated.add(key)
                continue
            queue.append(request)

        _discard_non_http_prefix(flow)
        for headers, body, consumed in _complete_http_responses(flow.data, max_body_bytes):
            response_start = flow.start_sequence
            packet_indices = _flow_packet_indices(flow, response_start, consumed)
            packet_provenance_complete = flow.packet_provenance_complete
            _consume_tcp_flow(flow, consumed)
            total_buffered -= consumed
            content_encoding = tuple(
                item.strip().lower() for item in headers.get("content-encoding", "").split(",") if item.strip()
            )
            decoded_body, decoded_encodings, decode_error = _decode_http_content_encodings(
                body, content_encoding, max_body_bytes
            )
            request = _pop_inverse_http_request(requests_by_flow, request_flow_pairing_truncated, segment.flow)
            parts = _http_multipart_parts(decoded_body, headers.get("content-type", ""), max_body_bytes)
            object_headers = parts if parts is not None else [(headers, decoded_body)]
            for part_index, (part_headers, part_body) in enumerate(object_headers):
                transfer_encoding = part_headers.get("content-transfer-encoding") if parts is not None else None
                decoded_part_body, decoded_transfer_encoding, multipart_decode_error = _decode_multipart_transfer_encoding(
                    part_body, transfer_encoding, max_body_bytes
                )
                filename = _http_object_name(part_headers, produced)
                yield HttpResponseObject(
                    logical_name=filename, body=decoded_part_body, content_encoding=content_encoding,
                    decoded_content_encoding=decoded_encodings, encoded_size=len(body), decode_error=decode_error,
                    content_type=part_headers.get("content-type"),
                    content_disposition=part_headers.get("content-disposition"),
                    multipart_part_index=part_index if parts is not None else None,
                    source=segment.source,
                    source_port=segment.source_port,
                    destination=segment.destination,
                    destination_port=segment.destination_port,
                    packet_indices=packet_indices,
                    packet_provenance_complete=packet_provenance_complete,
                    request_method=str(request.get("method")) if request and request.get("method") else None,
                    request_host=str(request.get("host")) if request and request.get("host") else None,
                    request_target=str(request.get("target")) if request and request.get("target") else None,
                    request_packet_indices=tuple(request.get("packet_indices", ())) if request else (),
                    request_packet_provenance_complete=bool(request.get("packet_provenance_complete", True)) if request else True,
                    multipart_content_transfer_encoding=transfer_encoding,
                    decoded_multipart_content_transfer_encoding=decoded_transfer_encoding,
                    multipart_decode_error=multipart_decode_error,
                )
                produced += 1
                if produced >= max_objects:
                    return
        # `_complete_http_responses` may discard a non-HTTP prefix after its
        # bounded resynchronisation attempt.  Recalculate the small flow set
        # rather than allowing accounting drift to affect global limits.
        total_buffered = sum(
            _tcp_flow_buffered_length(item)
            for item in flows.values()
        )


def iter_http_response_bodies(
    path: Path,
    *,
    max_objects: int = 100,
    max_body_bytes: int = 64 * 1024 * 1024,
    max_flows: int = 512,
    max_reassembly_bytes_per_flow: int = 72 * 1024 * 1024,
    max_total_reassembly_bytes: int = 256 * 1024 * 1024,
    max_packets: int = 200_000,
    max_scan_bytes: int = 128 * 1024 * 1024,
) -> Iterator[tuple[str, bytes]]:
    """Compatibility wrapper returning only logical names and recovered bytes."""
    for response in iter_http_response_objects(
        path, max_objects=max_objects, max_body_bytes=max_body_bytes, max_flows=max_flows,
        max_reassembly_bytes_per_flow=max_reassembly_bytes_per_flow,
        max_total_reassembly_bytes=max_total_reassembly_bytes, max_packets=max_packets,
        max_scan_bytes=max_scan_bytes,
    ):
        yield response.logical_name, response.body


def _iter_ethernet_packets(path: Path, *, max_packets: int, max_scan_bytes: int) -> Iterator[bytes]:
    """Yield only Ethernet frames from well-bounded classic PCAP/PCAPNG input."""
    try:
        with path.open("rb") as stream:
            magic = stream.read(4)
    except OSError:
        return
    if magic == b"\x0a\x0d\x0d\x0a":
        yield from _iter_pcapng_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes)
    elif magic in _PCAP_MAGIC:
        yield from _iter_classic_ethernet_packets(path, max_packets=max_packets, max_scan_bytes=max_scan_bytes)


def _iter_classic_ethernet_packets(path: Path, *, max_packets: int, max_scan_bytes: int) -> Iterator[bytes]:
    with path.open("rb") as stream:
        global_header = stream.read(24)
        info = _PCAP_MAGIC.get(global_header[:4])
        if info is None or len(global_header) != 24:
            return
        endian = info[0]
        try:
            network = struct.unpack(endian + "IHHIIII", global_header)[-1]
        except struct.error:
            return
        if network != 1:
            return
        consumed = 24
        packets = 0
        while packets < max_packets and consumed < max_scan_bytes:
            record_header = stream.read(16)
            consumed += len(record_header)
            if len(record_header) != 16:
                return
            _, _, captured_length, _ = struct.unpack(endian + "IIII", record_header)
            if captured_length > max_scan_bytes - consumed:
                return
            packet = stream.read(captured_length)
            consumed += len(packet)
            if len(packet) != captured_length:
                return
            packets += 1
            yield packet


def _iter_pcapng_ethernet_packets(path: Path, *, max_packets: int, max_scan_bytes: int) -> Iterator[bytes]:
    interfaces: list[int] = []
    endian: str | None = None
    consumed = 0
    packets = 0
    with path.open("rb") as stream:
        while packets < max_packets and consumed < max_scan_bytes:
            prefix = stream.read(8)
            consumed += len(prefix)
            if len(prefix) != 8:
                return
            block_type_raw = prefix[:4]
            if block_type_raw == b"\x0a\x0d\x0d\x0a":
                bom = stream.read(4)
                consumed += len(bom)
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    return
                length = int.from_bytes(prefix[4:8], "little" if endian == "<" else "big")
                if length < 28 or length > max_scan_bytes - (consumed - 12):
                    return
                remainder = stream.read(length - 12)
                consumed += len(remainder)
                if len(remainder) != length - 12 or int.from_bytes(remainder[-4:], "little" if endian == "<" else "big") != length:
                    return
                interfaces = []
                continue
            if endian is None:
                return
            length = int.from_bytes(prefix[4:8], "little" if endian == "<" else "big")
            if length < 12 or length > max_scan_bytes - (consumed - 8):
                return
            remainder = stream.read(length - 8)
            consumed += len(remainder)
            if len(remainder) != length - 8 or int.from_bytes(remainder[-4:], "little" if endian == "<" else "big") != length:
                return
            block_type = int.from_bytes(block_type_raw, "little" if endian == "<" else "big")
            payload = remainder[:-4]
            if block_type == 1 and len(payload) >= 8:
                interfaces.append(int.from_bytes(payload[:2], "little" if endian == "<" else "big"))
            elif block_type == 6 and len(payload) >= 20:
                interface_id = int.from_bytes(payload[:4], "little" if endian == "<" else "big")
                captured = int.from_bytes(payload[12:16], "little" if endian == "<" else "big")
                packet = payload[20:20 + captured]
                if len(packet) != captured:
                    continue
                packets += 1
                if interface_id < len(interfaces) and interfaces[interface_id] == 1:
                    yield packet
            elif block_type == 3 and len(payload) >= 4:
                packets += 1
                if interfaces and interfaces[0] == 1:
                    yield payload[4:]


def _ethernet_tcp_segment(packet: bytes) -> _TcpSegment | None:
    if len(packet) < 14:
        return None
    ethertype = int.from_bytes(packet[12:14], "big")
    offset = 14
    while ethertype in {0x8100, 0x88A8} and len(packet) >= offset + 4:
        ethertype = int.from_bytes(packet[offset + 2:offset + 4], "big")
        offset += 4
    if ethertype == 0x0800:
        ip = packet[offset:]
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            return None
        ip_header = (ip[0] & 0x0F) * 4
        if ip_header < 20 or len(ip) < ip_header + 20:
            return None
        ip_length = int.from_bytes(ip[2:4], "big")
        tcp = ip[ip_header:ip_length or len(ip)]
        source = str(ipaddress.IPv4Address(ip[12:16]))
        destination = str(ipaddress.IPv4Address(ip[16:20]))
    elif ethertype == 0x86DD:
        ip = packet[offset:]
        if len(ip) < 40 or ip[0] >> 4 != 6:
            return None
        end = min(len(ip), 40 + int.from_bytes(ip[4:6], "big"))
        protocol = ip[6]
        tcp_offset = 40
        # Mirror the observation engine's bounded extension-header policy so
        # IPv6 HTTP objects follow the same no-gap/no-reassembly guarantees.
        for _ in range(8):
            if protocol in {0, 43, 60}:
                if tcp_offset + 2 > end:
                    return None
                following = ip[tcp_offset]
                extension_length = (ip[tcp_offset + 1] + 1) * 8
                if extension_length < 8 or tcp_offset + extension_length > end:
                    return None
                protocol = following
                tcp_offset += extension_length
                continue
            if protocol == 44:
                if tcp_offset + 8 > end:
                    return None
                following = ip[tcp_offset]
                # Non-first fragments need IP-layer reassembly, which this
                # intentionally bounded HTTP extractor does not attempt.
                if int.from_bytes(ip[tcp_offset + 2:tcp_offset + 4], "big") >> 3:
                    return None
                protocol = following
                tcp_offset += 8
                continue
            if protocol == 51:
                if tcp_offset + 2 > end:
                    return None
                following = ip[tcp_offset]
                extension_length = (ip[tcp_offset + 1] + 2) * 4
                if extension_length < 8 or tcp_offset + extension_length > end:
                    return None
                protocol = following
                tcp_offset += extension_length
                continue
            break
        if protocol != 6 or tcp_offset + 20 > end:
            return None
        tcp = ip[tcp_offset:end]
        source = str(ipaddress.IPv6Address(ip[8:24]))
        destination = str(ipaddress.IPv6Address(ip[24:40]))
    else:
        return None
    tcp_header = (tcp[12] >> 4) * 4
    if tcp_header < 20 or len(tcp) < tcp_header:
        return None
    source_port, destination_port = struct.unpack("!HH", tcp[:4])
    return _TcpSegment(
        source=source,
        source_port=source_port,
        destination=destination,
        destination_port=destination_port,
        sequence=int.from_bytes(tcp[4:8], "big"),
        flags=tcp[13],
        payload=tcp[tcp_header:],
    )


def _append_tcp_segment(flow: _TcpFlow, sequence: int, payload: bytes, packet_index: int, maximum: int) -> None:
    """Append a segment only when it extends a contiguous finite stream."""
    if not payload:
        return
    if flow.next_sequence is None:
        flow.next_sequence = sequence
        flow.start_sequence = sequence
    assert flow.next_sequence is not None
    assert flow.start_sequence is not None
    if sequence < flow.start_sequence:
        # Once a protocol parser consumed a prefix, an overlapping older
        # segment is necessarily a retransmission of already-consumed bytes.
        # It must not be prepended to the current window (which would replay
        # control lines or inject a prior response prefix into a body).
        if flow.consumed_sequence is not None:
            return
        # A capture can contain an out-of-order predecessor after we first saw
        # a later response segment.  Prepend only perfectly contiguous bytes;
        # arbitrary overlap/gaps remain intentionally untrusted.
        end_sequence = sequence + len(payload)
        if end_sequence <= flow.start_sequence:
            if end_sequence == flow.start_sequence and len(flow.data) + len(payload) <= maximum:
                flow.data[:0] = payload
                _record_flow_packet_range(flow, sequence, len(payload), packet_index)
                flow.start_sequence = sequence
            return
        overlap = flow.start_sequence - sequence
        prefix = payload[:overlap]
        if prefix and len(flow.data) + len(prefix) <= maximum:
            flow.data[:0] = prefix
            _record_flow_packet_range(flow, sequence, len(prefix), packet_index)
            flow.start_sequence = sequence
        return
    if sequence < flow.next_sequence:
        overlap = flow.next_sequence - sequence
        if overlap >= len(payload):
            return  # Fully retransmitted bytes.
        sequence = flow.next_sequence
        payload = payload[overlap:]
    if sequence == flow.next_sequence:
        if len(flow.data) + len(payload) > maximum:
            _reset_tcp_flow(flow)
            return
        flow.data.extend(payload)
        _record_flow_packet_range(flow, sequence, len(payload), packet_index)
        flow.next_sequence += len(payload)
        while flow.next_sequence in flow.pending:
            following, following_packet_index = flow.pending.pop(flow.next_sequence)
            if len(flow.data) + len(following) > maximum:
                _reset_tcp_flow(flow)
                return
            flow.data.extend(following)
            _record_flow_packet_range(flow, flow.next_sequence, len(following), following_packet_index)
            flow.next_sequence += len(following)
        return
    # A future segment: retain one copy until its missing predecessor arrives.
    if sequence not in flow.pending and len(flow.data) + sum(len(item[0]) for item in flow.pending.values()) + len(payload) <= maximum:
        flow.pending[sequence] = (payload, packet_index)


def _tcp_flow_buffered_length(flow: _TcpFlow) -> int:
    assert flow.data is not None and flow.pending is not None
    return len(flow.data) + sum(len(payload) for payload, _ in flow.pending.values())


def _record_flow_packet_range(flow: _TcpFlow, sequence: int, length: int, packet_index: int) -> None:
    if not flow.packet_provenance_complete or length <= 0:
        return
    assert flow.packet_ranges is not None
    if len(flow.packet_ranges) >= _MAX_HTTP_PACKET_PROVENANCE_RANGES:
        flow.packet_ranges.clear()
        flow.packet_provenance_complete = False
        return
    flow.packet_ranges.append((sequence, sequence + length, packet_index))


def _reset_tcp_flow(flow: _TcpFlow) -> None:
    assert flow.data is not None and flow.pending is not None and flow.packet_ranges is not None
    flow.data.clear()
    flow.pending.clear()
    flow.packet_ranges.clear()
    flow.next_sequence = None
    flow.start_sequence = None
    flow.consumed_sequence = None
    flow.packet_provenance_complete = False


def _consume_tcp_flow(flow: _TcpFlow, consumed: int) -> None:
    assert flow.data is not None and flow.packet_ranges is not None
    del flow.data[:consumed]
    if flow.start_sequence is None:
        return
    flow.start_sequence += consumed
    flow.consumed_sequence = flow.start_sequence
    flow.packet_ranges[:] = [item for item in flow.packet_ranges if item[1] > flow.start_sequence]


def _discard_non_http_prefix(flow: _TcpFlow) -> None:
    """Bounded HTTP resynchronisation that keeps TCP byte provenance aligned."""
    assert flow.data is not None
    if flow.data.startswith(b"HTTP/"):
        return
    marker = flow.data.find(b"HTTP/")
    if marker > 0:
        _consume_tcp_flow(flow, marker)
    elif marker < 0 and len(flow.data) > 32_768:
        _consume_tcp_flow(flow, len(flow.data) - 8)


def _flow_packet_indices(flow: _TcpFlow, start_sequence: int | None, length: int) -> tuple[int, ...]:
    if start_sequence is None or length <= 0 or not flow.packet_provenance_complete:
        return ()
    assert flow.packet_ranges is not None
    end_sequence = start_sequence + length
    return tuple(sorted({packet_index for first, last, packet_index in flow.packet_ranges if first < end_sequence and last > start_sequence}))


def _complete_http_requests(data: bytearray, maximum: int) -> Iterator[tuple[dict[str, object], int]]:
    """Return complete bounded HTTP/1.x requests without interpreting bodies.

    A request is retained only after its header and any declared body framing
    are complete.  This makes inverse-flow pairing evidence-led and avoids
    assigning a later response to a partial or guessed request.
    """
    while data:
        split = data.find(b"\r\n\r\n")
        if split < 0:
            return
        if split > 64 * 1024:
            return
        raw_header = bytes(data[:split]).decode("latin-1", errors="replace")
        lines = raw_header.split("\r\n")
        first = lines[0].split() if lines else []
        if len(first) != 3 or first[0] not in {"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS", "CONNECT"} or not first[2].startswith("HTTP/"):
            return
        target = first[1]
        if len(target) > 4_000:
            return
        headers = _http_headers(raw_header)
        body_start = split + 4
        raw_body = bytes(data[body_start:])
        if "chunked" in headers.get("transfer-encoding", "").lower():
            decoded = _decode_chunked_with_consumed(raw_body, maximum)
            if decoded is None:
                return
            _, body_consumed = decoded
        else:
            try:
                declared = int(headers.get("content-length", "0"))
            except ValueError:
                return
            if declared < 0 or declared > maximum or len(raw_body) < declared:
                return
            body_consumed = declared
        request: dict[str, object] = {"method": first[0], "target": target}
        host = headers.get("host")
        if host:
            request["host"] = host[:1_000]
        yield request, body_start + body_consumed


def _pop_inverse_http_request(
    requests_by_flow: dict[tuple[str, int, str, int], list[dict[str, object]]],
    pairing_truncated: set[tuple[str, int, str, int]],
    response_flow: tuple[str, int, str, int],
) -> dict[str, object] | None:
    request_flow = (response_flow[2], response_flow[3], response_flow[0], response_flow[1])
    if request_flow in pairing_truncated:
        return None
    queue = requests_by_flow.get(request_flow)
    if not queue:
        return None
    request = queue.pop(0)
    if not queue:
        del requests_by_flow[request_flow]
    return request


def _complete_http_responses(data: bytearray, maximum: int) -> Iterator[tuple[dict[str, str], bytes, int]]:
    """Return every complete HTTP response at the start of a reassembled flow."""
    while data:
        if not data.startswith(b"HTTP/"):
            return
        split = data.find(b"\r\n\r\n")
        if split < 0:
            if len(data) > 128 * 1024:
                data.clear()
            return
        raw_header = bytes(data[:split]).decode("latin-1", errors="replace")
        headers = _http_headers(raw_header)
        body_start = split + 4
        raw_body = bytes(data[body_start:])
        if "chunked" in headers.get("transfer-encoding", "").lower():
            decoded = _decode_chunked_with_consumed(raw_body, maximum)
            if decoded is None:
                return
            body, body_consumed = decoded
        else:
            try:
                declared = int(headers.get("content-length", ""))
            except ValueError:
                return
            if declared < 0 or declared > maximum or len(raw_body) < declared:
                return
            body, body_consumed = raw_body[:declared], declared
        yield headers, body, body_start + body_consumed


def _http_object_name(headers: dict[str, str], index: int) -> str:
    disposition = headers.get("content-disposition", "")
    continued = _continued_content_disposition_filename(disposition)
    if continued:
        return continued
    extended = re.search(r"filename\*=(?:UTF-8|utf-8)''([^;]+)", disposition)
    if extended:
        try:
            name = unquote_to_bytes(extended.group(1)).decode("utf-8")
            if name and len(name) <= 255:
                return name
        except UnicodeDecodeError:
            pass
    match = re.search(r'filename="?([^";]+)', disposition, re.I)
    if match:
        return match.group(1)
    content_type = headers.get("content-type", "").lower()
    extension = ".zip" if "zip" in content_type else ".txt" if content_type.startswith("text/") else ".bin"
    return f"http_object_{index:04d}{extension}"


def _continued_content_disposition_filename(disposition: str) -> str | None:
    """Recover only complete, bounded RFC 2231 filename continuations."""
    parts: dict[int, tuple[str, bool]] = {}
    for match in re.finditer(r'(?:^|;)\s*filename\*(\d{1,2})(\*)?\s*=\s*(?:"([^"]*)"|([^;]*))', disposition, re.I):
        number = int(match.group(1))
        if number >= 16 or number in parts:
            return None
        value = (match.group(3) if match.group(3) is not None else match.group(4)).strip()
        parts[number] = (value, bool(match.group(2)))
    if not parts or 0 not in parts or set(parts) != set(range(len(parts))):
        return None
    values = [parts[number] for number in range(len(parts))]
    if values[0][1]:
        prefix = re.fullmatch(r"(?i:utf-8)'[^']*'(.*)", values[0][0])
        if prefix is None:
            return None
        try:
            name = unquote_to_bytes(prefix.group(1) + "".join(value for value, _ in values[1:])).decode("utf-8")
        except UnicodeDecodeError:
            return None
    elif any(encoded for _, encoded in values):
        return None
    else:
        name = "".join(value for value, _ in values)
    return name if name and len(name) <= 255 else None


def _http_headers(raw_header: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in raw_header.split("\r\n")[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return headers


def _http_multipart_parts(body: bytes, content_type: str, maximum: int) -> list[tuple[dict[str, str], bytes]] | None:
    """Return fully bounded MIME response parts, never guessing a boundary."""
    match = re.search(r"(?:^|;)\s*boundary=(?:\"([^\"]+)\"|([^;\s]+))", content_type, re.I)
    if match is None:
        return None
    boundary_text = match.group(1) or match.group(2)
    if not boundary_text:
        return None
    boundary = boundary_text.encode("latin-1", errors="ignore")
    if not boundary or len(boundary) > 200:
        return None
    delimiter = b"--" + boundary
    if not body.startswith(delimiter):
        return None
    offset = 0
    parts: list[tuple[dict[str, str], bytes]] = []
    while offset < len(body):
        if not body.startswith(delimiter, offset):
            return None
        offset += len(delimiter)
        if body[offset:offset + 2] == b"--":
            return parts if parts else None
        if body[offset:offset + 2] != b"\r\n":
            return None
        offset += 2
        header_end = body.find(b"\r\n\r\n", offset)
        if header_end < 0 or header_end - offset > 64 * 1024:
            return None
        headers = _mime_part_headers(body[offset:header_end])
        data_start = header_end + 4
        next_boundary = body.find(b"\r\n" + delimiter, data_start)
        if next_boundary < 0 or next_boundary - data_start > maximum:
            return None
        parts.append((headers, body[data_start:next_boundary]))
        if len(parts) >= 32:
            return None
        offset = next_boundary + 2
    return None


def _mime_part_headers(raw_headers: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in raw_headers.decode("latin-1", errors="replace").split("\r\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return headers


def _decode_multipart_transfer_encoding(
    body: bytes, content_transfer_encoding: str | None, maximum: int,
) -> tuple[bytes, str | None, str | None]:
    """Decode only declared, bounded MIME Base64 parts without guessing.

    The encoded original remains the registered body on an unsupported or
    malformed declaration, so no evidence is lost while the error remains
    reproducible in extraction provenance.
    """
    if not content_transfer_encoding:
        return body, None, None
    encoding = content_transfer_encoding.strip().lower()
    if encoding in {"7bit", "8bit", "binary"}:
        return body, None, None
    if encoding == "quoted-printable":
        decoded = quopri.decodestring(body)
        if len(decoded) > maximum:
            return body, None, f"multipart quoted-printable output exceeds bounded decode limit of {maximum} bytes"
        return decoded, "quoted-printable", None
    if encoding != "base64":
        return body, None, f"unsupported multipart Content-Transfer-Encoding: {content_transfer_encoding}"
    compact = re.sub(rb"[\t\r\n ]", b"", body)
    if len(compact) > maximum * 2:
        return body, None, f"multipart base64 input exceeds bounded decode limit of {maximum} bytes"
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error):
        return body, None, "multipart base64 Content-Transfer-Encoding did not validate"
    if len(decoded) > maximum:
        return body, None, f"multipart base64 output exceeds bounded decode limit of {maximum} bytes"
    return decoded, "base64", None


def _decode_http_content_encodings(
    body: bytes, encodings: tuple[str, ...], maximum: int,
) -> tuple[bytes, tuple[str, ...], str | None]:
    """Decode only bounded, declared HTTP gzip/deflate content encodings.

    HTTP applies listed encodings in order, so decoding happens in reverse.
    An unsupported or malformed chain remains as its original encoded body;
    the caller can still preserve it as evidence and report the exact reason.
    """
    if not encodings:
        return body, (), None
    decoded = body
    decoded_encodings: list[str] = []
    for encoding in reversed(encodings):
        if encoding not in {"gzip", "deflate"}:
            return body, tuple(decoded_encodings), f"unsupported HTTP Content-Encoding: {encoding}"
        candidate = _bounded_http_decompress(decoded, encoding, maximum)
        if candidate is None:
            return body, tuple(decoded_encodings), f"HTTP {encoding} content decoding failed or exceeded {maximum} bytes"
        decoded = candidate
        decoded_encodings.append(encoding)
    return decoded, tuple(decoded_encodings), None


def _bounded_http_decompress(data: bytes, encoding: str, maximum: int) -> bytes | None:
    wbits_values = (16 + zlib.MAX_WBITS,) if encoding == "gzip" else (zlib.MAX_WBITS, -zlib.MAX_WBITS)
    for wbits in wbits_values:
        try:
            decoder = zlib.decompressobj(wbits)
            output = decoder.decompress(data, maximum + 1)
            if len(output) > maximum or decoder.unconsumed_tail:
                continue
            output += decoder.flush(maximum + 1 - len(output))
            if len(output) > maximum or not decoder.eof or decoder.unused_data:
                continue
            return output
        except zlib.error:
            continue
    return None


def _decode_chunked(data: bytes, maximum: int) -> bytes | None:
    decoded = _decode_chunked_with_consumed(data, maximum)
    return decoded[0] if decoded is not None else None


def _decode_chunked_with_consumed(data: bytes, maximum: int) -> tuple[bytes, int] | None:
    result = bytearray()
    offset = 0
    while True:
        end = data.find(b"\r\n", offset)
        if end < 0:
            return None
        try:
            size = int(data[offset:end].split(b";", 1)[0], 16)
        except ValueError:
            return None
        offset = end + 2
        if size == 0:
            # A response can omit trailers, but its zero-size chunk is still
            # terminated by a CRLF.  Include optional trailers when complete.
            if len(data) < offset + 2:
                return None
            if data[offset:offset + 2] == b"\r\n":
                return bytes(result), offset + 2
            trailer_end = data.find(b"\r\n\r\n", offset)
            if trailer_end < 0:
                return None
            return bytes(result), trailer_end + 4
        if size < 0 or size > maximum - len(result) or offset + size + 2 > len(data):
            return None
        result.extend(data[offset:offset + size])
        offset += size
        if data[offset:offset + 2] != b"\r\n":
            return None
        offset += 2
