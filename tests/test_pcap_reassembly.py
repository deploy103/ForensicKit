from __future__ import annotations

import struct
import base64
import gzip
import io
import json
import zipfile
import hashlib
import ipaddress
import zlib
from pathlib import Path

from forensickit.config import ForensicKitConfig
from forensickit.engine import AnalysisEngine
from forensickit.models import AnalysisMode
from forensickit.models import Artifact
from forensickit.models import Observation
from forensickit.pcap import PcapObservationEngine, _PcapStats, _reassemble_dns_txt_fragments, _tls_certificate_metadata, _tls_client_hello_metadata, _tls_server_hello_metadata, iter_ftp_auth_tls_transitions, iter_ftp_retr_objects, iter_http_response_bodies, iter_http_response_objects, iter_imap_fetch_objects, iter_imap_starttls_transitions, iter_pop3_retr_objects, iter_pop3_stls_transitions, iter_smb2_close_operations, iter_smb2_create_operations, iter_smb2_directory_listings, iter_smb2_negotiate_operations, iter_smb2_read_objects, iter_smb2_set_info_operations, iter_smb2_write_objects, iter_smb3_transform_records, iter_smtp_bdat_objects, iter_smtp_data_objects, iter_smtp_starttls_transitions


def _tcp_packet(payload: bytes, *, sequence: int, source_port: int = 80, destination_port: int = 41000, source_ip: bytes = b"\x0a\x00\x00\x01", destination_ip: bytes = b"\x0a\x00\x00\x02") -> bytes:
    ethernet = b"\x00" * 12 + b"\x08\x00"
    total_length = 20 + 20 + len(payload)
    ipv4 = bytes((0x45, 0)) + struct.pack("!H", total_length) + b"\x00\x00\x00\x00\x40\x06\x00\x00"
    ipv4 += source_ip + destination_ip
    tcp = struct.pack("!HHII", source_port, destination_port, sequence, 0) + b"\x50\x18\x00\x00\x00\x00\x00\x00"
    return ethernet + ipv4 + tcp + payload


def _pcap(packets: list[bytes]) -> bytes:
    result = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, packet in enumerate(packets):
        result.extend(struct.pack("<IIII", 1, index, len(packet), len(packet)))
        result.extend(packet)
    return bytes(result)


def _smb2_create_request(filename: str, *, message_id: int = 7, tree_id: int = 3, session_id: int = 9) -> bytes:
    encoded_name = filename.encode("utf-16le")
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (5).to_bytes(2, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    header[36:40] = tree_id.to_bytes(4, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    request = bytearray(56)
    request[:2] = (57).to_bytes(2, "little")
    request[24:28] = (0x00120089).to_bytes(4, "little")
    request[36:40] = (1).to_bytes(4, "little")
    request[40:44] = (0x00000040).to_bytes(4, "little")
    request[44:46] = (120).to_bytes(2, "little")
    request[46:48] = len(encoded_name).to_bytes(2, "little")
    smb = bytes(header + request) + encoded_name
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_create_response(*, message_id: int, tree_id: int, session_id: int, persistent_file_id: int, volatile_file_id: int) -> bytes:
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (5).to_bytes(2, "little")
    header[16:20] = (1).to_bytes(4, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    header[36:40] = tree_id.to_bytes(4, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    response = bytearray(88)
    response[:2] = (89).to_bytes(2, "little")
    response[64:72] = persistent_file_id.to_bytes(8, "little")
    response[72:80] = volatile_file_id.to_bytes(8, "little")
    smb = bytes(header + response)
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_tree_connect_request(share_path: str, *, message_id: int, session_id: int) -> bytes:
    encoded_path = share_path.encode("utf-16le")
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (3).to_bytes(2, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    request = bytearray(8)
    request[:2] = (9).to_bytes(2, "little")
    request[4:6] = (72).to_bytes(2, "little")
    request[6:8] = len(encoded_path).to_bytes(2, "little")
    smb = bytes(header + request) + encoded_path
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_tree_connect_response(*, message_id: int, tree_id: int, session_id: int) -> bytes:
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (3).to_bytes(2, "little")
    header[16:20] = (1).to_bytes(4, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    header[36:40] = tree_id.to_bytes(4, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    response = bytearray(16)
    response[:2] = (16).to_bytes(2, "little")
    smb = bytes(header + response)
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_write_request(data: bytes, *, message_id: int, tree_id: int, session_id: int, persistent_file_id: int, volatile_file_id: int, offset: int = 0) -> bytes:
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (9).to_bytes(2, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    header[36:40] = tree_id.to_bytes(4, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    request = bytearray(48)
    request[:2] = (49).to_bytes(2, "little")
    request[2:4] = (112).to_bytes(2, "little")
    request[4:8] = len(data).to_bytes(4, "little")
    request[8:16] = offset.to_bytes(8, "little")
    request[16:24] = persistent_file_id.to_bytes(8, "little")
    request[24:32] = volatile_file_id.to_bytes(8, "little")
    smb = bytes(header + request) + data
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_write_response(*, message_id: int, tree_id: int, session_id: int, count: int) -> bytes:
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (9).to_bytes(2, "little")
    header[16:20] = (1).to_bytes(4, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    header[36:40] = tree_id.to_bytes(4, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    response = bytearray(16)
    response[:2] = (17).to_bytes(2, "little")
    response[4:8] = count.to_bytes(4, "little")
    smb = bytes(header + response)
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_read_request(*, message_id: int, tree_id: int, session_id: int, persistent_file_id: int, volatile_file_id: int, length: int, offset: int = 0) -> bytes:
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (8).to_bytes(2, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    header[36:40] = tree_id.to_bytes(4, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    request = bytearray(48)
    request[:2] = (49).to_bytes(2, "little")
    request[4:8] = length.to_bytes(4, "little")
    request[8:16] = offset.to_bytes(8, "little")
    request[16:24] = persistent_file_id.to_bytes(8, "little")
    request[24:32] = volatile_file_id.to_bytes(8, "little")
    smb = bytes(header + request)
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_read_response(data: bytes, *, message_id: int, tree_id: int, session_id: int) -> bytes:
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (8).to_bytes(2, "little")
    header[16:20] = (1).to_bytes(4, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    header[36:40] = tree_id.to_bytes(4, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    response = bytearray(16)
    response[:2] = (17).to_bytes(2, "little")
    response[2] = 80
    response[4:8] = len(data).to_bytes(4, "little")
    smb = bytes(header + response) + data
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_close_request(*, message_id: int, tree_id: int, session_id: int, persistent_file_id: int, volatile_file_id: int) -> bytes:
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (6).to_bytes(2, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    header[36:40] = tree_id.to_bytes(4, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    request = bytearray(24)
    request[:2] = (24).to_bytes(2, "little")
    request[8:16] = persistent_file_id.to_bytes(8, "little")
    request[16:24] = volatile_file_id.to_bytes(8, "little")
    smb = bytes(header + request)
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_close_response(*, message_id: int, tree_id: int, session_id: int, end_of_file: int) -> bytes:
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (6).to_bytes(2, "little")
    header[16:20] = (1).to_bytes(4, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    header[36:40] = tree_id.to_bytes(4, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    response = bytearray(60)
    response[:2] = (60).to_bytes(2, "little")
    response[8:16] = (132537600000000000).to_bytes(8, "little")
    response[16:24] = (132537600100000000).to_bytes(8, "little")
    response[24:32] = (132537600200000000).to_bytes(8, "little")
    response[32:40] = (132537600300000000).to_bytes(8, "little")
    response[40:48] = end_of_file.to_bytes(8, "little")
    response[48:56] = end_of_file.to_bytes(8, "little")
    response[56:60] = (0x20).to_bytes(4, "little")
    smb = bytes(header + response)
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_set_info_request(buffer: bytes, *, info_class: int, message_id: int, tree_id: int, session_id: int, persistent_file_id: int, volatile_file_id: int) -> bytes:
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (17).to_bytes(2, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    header[36:40] = tree_id.to_bytes(4, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    request = bytearray(32)
    request[:2] = (33).to_bytes(2, "little")
    request[2] = 1
    request[3] = info_class
    request[4:8] = len(buffer).to_bytes(4, "little")
    request[8:10] = (96).to_bytes(2, "little")
    request[16:24] = persistent_file_id.to_bytes(8, "little")
    request[24:32] = volatile_file_id.to_bytes(8, "little")
    smb = bytes(header + request) + buffer
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_set_info_response(*, message_id: int, tree_id: int, session_id: int) -> bytes:
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (17).to_bytes(2, "little")
    header[16:20] = (1).to_bytes(4, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    header[36:40] = tree_id.to_bytes(4, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    smb = bytes(header) + (2).to_bytes(2, "little")
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_query_directory_request(pattern: str, *, message_id: int, tree_id: int, session_id: int, persistent_file_id: int, volatile_file_id: int, information_class: int = 12) -> bytes:
    encoded_pattern = pattern.encode("utf-16le")
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (14).to_bytes(2, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    header[36:40] = tree_id.to_bytes(4, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    request = bytearray(32)
    request[:2] = (33).to_bytes(2, "little")
    request[2] = information_class
    request[8:16] = persistent_file_id.to_bytes(8, "little")
    request[16:24] = volatile_file_id.to_bytes(8, "little")
    request[24:26] = (96).to_bytes(2, "little")
    request[26:28] = len(encoded_pattern).to_bytes(2, "little")
    request[28:32] = (64 * 1024).to_bytes(4, "little")
    smb = bytes(header + request) + encoded_pattern
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_query_directory_response(names: list[str], *, message_id: int, tree_id: int, session_id: int) -> bytes:
    listing = bytearray()
    for index, name in enumerate(names):
        encoded_name = name.encode("utf-16le")
        entry_length = 12 + len(encoded_name)
        aligned_length = (entry_length + 7) & ~7 if index + 1 < len(names) else entry_length
        entry = bytearray(aligned_length)
        entry[:4] = (aligned_length if index + 1 < len(names) else 0).to_bytes(4, "little")
        entry[4:8] = index.to_bytes(4, "little")
        entry[8:12] = len(encoded_name).to_bytes(4, "little")
        entry[12:12 + len(encoded_name)] = encoded_name
        listing.extend(entry)
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (14).to_bytes(2, "little")
    header[16:20] = (1).to_bytes(4, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    header[36:40] = tree_id.to_bytes(4, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    response = bytearray(8)
    response[:2] = (9).to_bytes(2, "little")
    response[2:4] = (72).to_bytes(2, "little")
    response[4:8] = len(listing).to_bytes(4, "little")
    smb = bytes(header + response + listing)
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_file_id_both_directory_response(entries: list[dict[str, int | str]], *, message_id: int, tree_id: int, session_id: int) -> bytes:
    listing = bytearray()
    for index, metadata in enumerate(entries):
        encoded_name = str(metadata["name"]).encode("utf-16le")
        encoded_short_name = str(metadata.get("short_name", "")).encode("utf-16le")
        entry_length = 104 + len(encoded_name)
        aligned_length = (entry_length + 7) & ~7 if index + 1 < len(entries) else entry_length
        entry = bytearray(aligned_length)
        entry[:4] = (aligned_length if index + 1 < len(entries) else 0).to_bytes(4, "little")
        entry[4:8] = int(metadata["file_index"]).to_bytes(4, "little")
        entry[8:16] = int(metadata["creation_filetime"]).to_bytes(8, "little")
        entry[16:24] = int(metadata["last_access_filetime"]).to_bytes(8, "little")
        entry[24:32] = int(metadata["last_write_filetime"]).to_bytes(8, "little")
        entry[32:40] = int(metadata["change_filetime"]).to_bytes(8, "little")
        entry[40:48] = int(metadata["end_of_file"]).to_bytes(8, "little")
        entry[48:56] = int(metadata["allocation_size"]).to_bytes(8, "little")
        entry[56:60] = int(metadata["file_attributes"]).to_bytes(4, "little")
        entry[60:64] = len(encoded_name).to_bytes(4, "little")
        entry[64:68] = int(metadata["ea_size"]).to_bytes(4, "little")
        entry[68] = len(encoded_short_name)
        entry[70:70 + len(encoded_short_name)] = encoded_short_name
        entry[96:104] = int(metadata["file_id"]).to_bytes(8, "little")
        entry[104:104 + len(encoded_name)] = encoded_name
        listing.extend(entry)
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (14).to_bytes(2, "little")
    header[16:20] = (1).to_bytes(4, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    header[36:40] = tree_id.to_bytes(4, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    response = bytearray(8)
    response[:2] = (9).to_bytes(2, "little")
    response[2:4] = (72).to_bytes(2, "little")
    response[4:8] = len(listing).to_bytes(4, "little")
    smb = bytes(header + response + listing)
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb3_encryption_transform(payload: bytes, *, original_size: int, session_id: int) -> bytes:
    header = bytearray(52)
    header[:4] = b"\xfdSMB"
    header[4:20] = bytes(range(1, 17))
    header[20:36] = bytes(range(17, 33))
    header[36:40] = original_size.to_bytes(4, "little")
    header[42:44] = (1).to_bytes(2, "little")
    header[44:52] = session_id.to_bytes(8, "little")
    smb = bytes(header) + payload
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb3_compression_transform(payload: bytes, *, original_size: int, algorithm: int, flags: int = 0, data_offset: int = 0) -> bytes:
    header = bytearray(16)
    header[:4] = b"\xfcSMB"
    header[4:8] = original_size.to_bytes(4, "little")
    header[8:10] = algorithm.to_bytes(2, "little")
    header[10:12] = flags.to_bytes(2, "little")
    header[12:16] = data_offset.to_bytes(4, "little")
    smb = bytes(header) + payload
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_negotiate_request(dialects: list[int], *, message_id: int, security_mode: int, capabilities: int) -> bytes:
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (0).to_bytes(2, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    request = bytearray(36)
    request[:2] = (36).to_bytes(2, "little")
    request[2:4] = len(dialects).to_bytes(2, "little")
    request[4:6] = security_mode.to_bytes(2, "little")
    request[8:12] = capabilities.to_bytes(4, "little")
    request[12:28] = bytes(range(16))
    smb = bytes(header + request) + b"".join(item.to_bytes(2, "little") for item in dialects)
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _smb2_negotiate_response(*, message_id: int, security_mode: int, dialect: int, capabilities: int) -> bytes:
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (0).to_bytes(2, "little")
    header[16:20] = (1).to_bytes(4, "little")
    header[24:32] = message_id.to_bytes(8, "little")
    response = bytearray(64)
    response[:2] = (65).to_bytes(2, "little")
    response[2:4] = security_mode.to_bytes(2, "little")
    response[4:6] = dialect.to_bytes(2, "little")
    response[8:24] = bytes(range(16, 32))
    response[24:28] = capabilities.to_bytes(4, "little")
    response[28:32] = (1_048_576).to_bytes(4, "little")
    response[32:36] = (2_097_152).to_bytes(4, "little")
    response[36:40] = (3_145_728).to_bytes(4, "little")
    response[40:48] = (132537600000000000).to_bytes(8, "little")
    response[48:56] = (132537500000000000).to_bytes(8, "little")
    smb = bytes(header + response)
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _ipv6_udp_dns_packet(name: str) -> bytes:
    labels = b"".join(bytes((len(label),)) + label.encode() for label in name.split(".")) + b"\x00"
    dns = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x01\x00\x01"
    udp = struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0) + dns
    ipv6 = bytes((0x60, 0, 0, 0)) + struct.pack("!HBB", len(udp), 17, 64)
    ipv6 += ipaddress.IPv6Address("2001:db8::1").packed
    ipv6 += ipaddress.IPv6Address("2001:db8::53").packed
    return b"\x00" * 12 + b"\x86\xdd" + ipv6 + udp


def _ipv6_udp_packet(payload: bytes, *, source_port: int, destination_port: int) -> bytes:
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    ipv6 = bytes((0x60, 0, 0, 0)) + struct.pack("!HBB", len(udp), 17, 64)
    ipv6 += ipaddress.IPv6Address("2001:db8::53").packed
    ipv6 += ipaddress.IPv6Address("2001:db8::1").packed
    return b"\x00" * 12 + b"\x86\xdd" + ipv6 + udp


def _ipv6_icmp_packet(payload: bytes) -> bytes:
    icmp = b"\x80\x00\x00\x00\x00\x01\x00\x01" + payload
    ipv6 = bytes((0x60, 0, 0, 0)) + struct.pack("!HBB", len(icmp), 58, 64)
    ipv6 += ipaddress.IPv6Address("2001:db8::1").packed
    ipv6 += ipaddress.IPv6Address("2001:db8::2").packed
    return b"\x00" * 12 + b"\x86\xdd" + ipv6 + icmp


def _ipv6_tcp_packet(payload: bytes, *, sequence: int) -> bytes:
    tcp = struct.pack("!HHII", 80, 41000, sequence, 0) + b"\x50\x18\x00\x00\x00\x00\x00\x00" + payload
    ipv6 = bytes((0x60, 0, 0, 0)) + struct.pack("!HBB", len(tcp), 6, 64)
    ipv6 += ipaddress.IPv6Address("2001:db8::80").packed
    ipv6 += ipaddress.IPv6Address("2001:db8::1").packed
    return b"\x00" * 12 + b"\x86\xdd" + ipv6 + tcp


def _pcapng_block(block_type: int, payload: bytes) -> bytes:
    length = 12 + len(payload)
    length += (-length) % 4
    return struct.pack("<II", block_type, length) + payload + b"\x00" * (length - 12 - len(payload)) + struct.pack("<I", length)


def _pcapng(packets: list[bytes]) -> bytes:
    section_header = _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = _pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
    enhanced = b"".join(
        _pcapng_block(6, struct.pack("<IIIII", 0, 0, index, len(packet), len(packet)) + packet)
        for index, packet in enumerate(packets)
    )
    return section_header + interface + enhanced


def _tls_client_hello(*, server_name: str, alpn: list[str]) -> bytes:
    encoded_name = server_name.encode("ascii")
    sni = b"\x00" + len(encoded_name).to_bytes(2, "big") + encoded_name
    sni_extension = b"\x00\x00" + (len(sni) + 2).to_bytes(2, "big") + len(sni).to_bytes(2, "big") + sni
    alpn_values = b"".join(bytes([len(value)]) + value.encode("ascii") for value in alpn)
    alpn_extension = b"\x00\x10" + (len(alpn_values) + 2).to_bytes(2, "big") + len(alpn_values).to_bytes(2, "big") + alpn_values
    extensions = sni_extension + alpn_extension
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + len(extensions).to_bytes(2, "big") + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def _tls_server_hello(*, selected_alpn: str) -> bytes:
    protocol = selected_alpn.encode("ascii")
    alpn_data = (len(protocol) + 1).to_bytes(2, "big") + bytes([len(protocol)]) + protocol
    extensions = b"\x00\x10" + len(alpn_data).to_bytes(2, "big") + alpn_data
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x13\x01" + b"\x00" + len(extensions).to_bytes(2, "big") + extensions
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def _tls12_certificate_record(*certificates: bytes) -> bytes:
    entries = b"".join(len(certificate).to_bytes(3, "big") + certificate for certificate in certificates)
    body = len(entries).to_bytes(3, "big") + entries
    handshake = b"\x0b" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def _tls13_certificate_record(*, request_context: bytes, certificate: bytes) -> bytes:
    entry = len(certificate).to_bytes(3, "big") + certificate + b"\x00\x00"
    body = bytes([len(request_context)]) + request_context + len(entry).to_bytes(3, "big") + entry
    handshake = b"\x0b" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def test_recovers_content_length_response_split_across_tcp_segments(tmp_path: Path) -> None:
    body = b"PK\x03\x04split-http-object"
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\n"
        b"Content-Disposition: attachment; filename=answer.zip\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode()
        + body
    )
    evidence = tmp_path / "split.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(response[:31], sequence=1000),
        _tcp_packet(response[31:78], sequence=1031),
        _tcp_packet(response[78:], sequence=1078),
    ]))

    assert list(iter_http_response_bodies(evidence)) == [("answer.zip", body)]
    response_object = next(iter_http_response_objects(evidence))
    assert (
        response_object.source, response_object.source_port,
        response_object.destination, response_object.destination_port,
        response_object.packet_indices, response_object.packet_provenance_complete,
    ) == ("10.0.0.1", 80, "10.0.0.2", 41000, (1, 2, 3), True)


def test_recovers_rfc5987_http_content_disposition_filename(tmp_path: Path) -> None:
    body = b"flag"
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename*=UTF-8''ctf%20flag.txt\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
    )
    evidence = tmp_path / "rfc5987.pcap"
    evidence.write_bytes(_pcap([_tcp_packet(response, sequence=1000)]))
    assert list(iter_http_response_bodies(evidence)) == [("ctf flag.txt", body)]


def test_recovers_complete_rfc2231_multipart_content_disposition_filename(tmp_path: Path) -> None:
    boundary = b"continued-name"
    body = (
        b"--" + boundary + b"\r\nContent-Disposition: attachment; filename=fallback.txt; "
        b"filename*0*=UTF-8''ctf%20; filename*1*=flag; filename*2*=.txt\r\n\r\nflag\r\n"
        b"--" + boundary + b"--"
    )
    response = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/mixed; boundary=continued-name\r\n" + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
    evidence = tmp_path / "rfc2231.pcap"
    evidence.write_bytes(_pcap([_tcp_packet(response, sequence=1000)]))
    assert list(iter_http_response_bodies(evidence)) == [("ctf flag.txt", b"flag")]

    invalid = body.replace(b"filename*1*=flag; ", b"filename*2*=flag; ")
    invalid_response = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/mixed; boundary=continued-name\r\n" + f"Content-Length: {len(invalid)}\r\n\r\n".encode() + invalid
    invalid_evidence = tmp_path / "rfc2231-gap.pcap"
    invalid_evidence.write_bytes(_pcap([_tcp_packet(invalid_response, sequence=1000)]))
    assert list(iter_http_response_bodies(invalid_evidence)) == [("fallback.txt", b"flag")]


def test_recovers_bounded_pasv_ftp_retr_object_with_control_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "ftp-retr.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    evidence.write_bytes(_pcap([
        _tcp_packet(b"RETR fl", sequence=1000, source_port=41000, destination_port=21, source_ip=client, destination_ip=server),
        _tcp_packet(b"ag.txt\r\n", sequence=1007, source_port=41000, destination_port=21, source_ip=client, destination_ip=server),
        _tcp_packet(b"227 Entering Passive Mode (10,0,0,1,", sequence=2000, source_port=21, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(b"195,80)\r\n", sequence=2036, source_port=21, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(b"CTF{ftp_retr_object}", sequence=3000, source_port=50000, destination_port=42000, source_ip=server, destination_ip=client),
        _tcp_packet(b"226 Transfer complete\r\n", sequence=2045, source_port=21, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    objects = list(iter_ftp_retr_objects(evidence))
    assert [(item.logical_name, item.body, item.packet_indices, item.command_packet_index, item.endpoint_setup_packet_index) for item in objects] == [
        ("flag.txt", b"CTF{ftp_retr_object}", (5,), 2, 4),
    ]
    assert (objects[0].completion_code, objects[0].completion_packet_index) == (226, 6)
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    assert [artifact.logical_name for artifact in result.artifacts] == ["ftp-retr.pcap", "flag.txt"]
    finding = next(item for item in result.findings if item.category == "pcap_ftp_retr_extraction")
    assert "retr_command_packet_index=2" in finding.supporting_evidence
    assert "data_endpoint_setup_packet_index=4" in finding.supporting_evidence
    assert "completion_code=226" in finding.supporting_evidence
    assert "completion_packet_index=6" in finding.supporting_evidence


def test_recovers_bounded_pasv_ftp_stor_object_with_control_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "ftp-stor.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    evidence.write_bytes(_pcap([
        _tcp_packet(b"STOR upload.txt\r\n", sequence=1000, source_port=41000, destination_port=21, source_ip=client, destination_ip=server),
        _tcp_packet(b"227 Entering Passive Mode (10,0,0,1,195,80)\r\n", sequence=2000, source_port=21, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(b"CTF{ftp_stor_object}", sequence=3000, source_port=42000, destination_port=50000, source_ip=client, destination_ip=server),
    ]))
    objects = list(iter_ftp_retr_objects(evidence))
    assert [(item.logical_name, item.transfer_command, item.body, item.packet_indices) for item in objects] == [
        ("upload.txt", "STOR", b"CTF{ftp_stor_object}", (3,)),
    ]


def test_recovers_bounded_epsv_ftp_retr_object_with_control_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "ftp-epsv.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    evidence.write_bytes(_pcap([
        _tcp_packet(b"RETR epsv.txt\r\n", sequence=1000, source_port=41000, destination_port=21, source_ip=client, destination_ip=server),
        _tcp_packet(b"229 Entering Extended Passive Mode (|||50000|)\r\n", sequence=2000, source_port=21, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(b"CTF{ftp_epsv_object}", sequence=3000, source_port=50000, destination_port=42000, source_ip=server, destination_ip=client),
    ]))
    objects = list(iter_ftp_retr_objects(evidence))
    assert [(item.logical_name, item.transfer_command, item.body, item.packet_indices) for item in objects] == [
        ("epsv.txt", "RETR", b"CTF{ftp_epsv_object}", (3,)),
    ]


def test_recovers_bounded_active_ftp_port_retr_object_with_control_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "ftp-port.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    evidence.write_bytes(_pcap([
        _tcp_packet(b"PORT 10,0,0,2,164,16\r\n", sequence=1000, source_port=41000, destination_port=21, source_ip=client, destination_ip=server),
        _tcp_packet(b"RETR active.txt\r\n", sequence=1022, source_port=41000, destination_port=21, source_ip=client, destination_ip=server),
        _tcp_packet(b"CTF{ftp_port_object}", sequence=3000, source_port=20, destination_port=42000, source_ip=server, destination_ip=client),
    ]))
    objects = list(iter_ftp_retr_objects(evidence))
    assert [(item.logical_name, item.transfer_command, item.body, item.packet_indices, item.command_packet_index, item.endpoint_setup_packet_index) for item in objects] == [
        ("active.txt", "RETR", b"CTF{ftp_port_object}", (3,), 2, 1),
    ]


def test_recovers_bounded_active_ftp_eprt_retr_object_with_control_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "ftp-eprt.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    command = b"EPRT |1|10.0.0.2|42000|\r\n"
    evidence.write_bytes(_pcap([
        _tcp_packet(command, sequence=1000, source_port=41000, destination_port=21, source_ip=client, destination_ip=server),
        _tcp_packet(b"RETR eprt.txt\r\n", sequence=1000 + len(command), source_port=41000, destination_port=21, source_ip=client, destination_ip=server),
        _tcp_packet(b"CTF{ftp_eprt_object}", sequence=3000, source_port=20, destination_port=42000, source_ip=server, destination_ip=client),
    ]))
    objects = list(iter_ftp_retr_objects(evidence))
    assert [(item.logical_name, item.transfer_command, item.body, item.packet_indices, item.command_packet_index, item.endpoint_setup_packet_index) for item in objects] == [
        ("eprt.txt", "RETR", b"CTF{ftp_eprt_object}", (3,), 2, 1),
    ]


def test_recovers_bounded_pasv_ftp_mlsd_listing_with_control_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "ftp-mlsd.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    listing = b"type=file;size=23; flag.txt\r\n"
    evidence.write_bytes(_pcap([
        _tcp_packet(b"MLSD\r\n", sequence=1000, source_port=41000, destination_port=21, source_ip=client, destination_ip=server),
        _tcp_packet(b"227 Entering Passive Mode (10,0,0,1,195,80)\r\n", sequence=2000, source_port=21, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(listing, sequence=3000, source_port=50000, destination_port=42000, source_ip=server, destination_ip=client),
    ]))
    objects = list(iter_ftp_retr_objects(evidence))
    assert [(item.logical_name, item.transfer_command, item.body, item.packet_indices) for item in objects] == [
        ("ftp_mlsd_listing.txt", "MLSD", listing, (3,)),
    ]


def test_recovers_bounded_active_ftp_nlst_listing_with_control_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "ftp-port-nlst.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    port = b"PORT 10,0,0,2,164,16\r\n"
    evidence.write_bytes(_pcap([
        _tcp_packet(port, sequence=1000, source_port=41000, destination_port=21, source_ip=client, destination_ip=server),
        _tcp_packet(b"NLST\r\n", sequence=1000 + len(port), source_port=41000, destination_port=21, source_ip=client, destination_ip=server),
        _tcp_packet(b"flag.txt\r\n", sequence=3000, source_port=20, destination_port=42000, source_ip=server, destination_ip=client),
    ]))
    objects = list(iter_ftp_retr_objects(evidence))
    assert [(item.logical_name, item.transfer_command, item.body, item.packet_indices) for item in objects] == [
        ("ftp_nlst_listing.txt", "NLST", b"flag.txt\r\n", (3,)),
    ]


def test_ftp_auth_tls_transition_has_provenance_and_suppresses_plaintext_recovery(tmp_path: Path) -> None:
    evidence = tmp_path / "ftp-auth-tls.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    auth = b"AUTH TLS\r\n"
    ready = b"234 AUTH TLS successful\r\n"
    retr = b"RETR should-not-recover.txt\r\n"
    passive = b"227 Entering Passive Mode (10,0,0,1,195,80)\r\n"
    evidence.write_bytes(_pcap([
        _tcp_packet(auth, sequence=1000, source_port=41000, destination_port=21, source_ip=client, destination_ip=server),
        _tcp_packet(ready, sequence=2000, source_port=21, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(retr, sequence=1000 + len(auth), source_port=41000, destination_port=21, source_ip=client, destination_ip=server),
        _tcp_packet(passive, sequence=2000 + len(ready), source_port=21, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(b"CTF{not_ftp_auth_tls}", sequence=3000, source_port=50000, destination_port=42000, source_ip=server, destination_ip=client),
    ]))
    assert list(iter_ftp_retr_objects(evidence)) == []
    transitions = list(iter_ftp_auth_tls_transitions(evidence))
    assert [(item.source, item.source_port, item.destination, item.destination_port, item.command_packet_index, item.ready_response_packet_index) for item in transitions] == [
        ("10.0.0.2", 41000, "10.0.0.1", 21, 1, 2),
    ]
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    finding = next(item for item in result.findings if item.category == "pcap_ftp_auth_tls_transition")
    assert "auth_tls_command_packet_index=1" in finding.supporting_evidence
    assert "ready_response_packet_index=2" in finding.supporting_evidence


def test_smb2_create_request_inventory_preserves_filename_ids_and_packet_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "smb2-create.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    frame = _smb2_create_request(r"evidence\flag.txt", message_id=17, tree_id=23, session_id=42)
    response = _smb2_create_response(message_id=17, tree_id=23, session_id=42, persistent_file_id=0x1111, volatile_file_id=0x2222)
    split = 77
    evidence.write_bytes(_pcap([
        _tcp_packet(frame[:split], sequence=1000, source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(frame[split:], sequence=1000 + split, source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(response, sequence=2000, source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    operation = next(iter_smb2_create_operations(evidence))
    assert (operation.filename, operation.message_id, operation.tree_id, operation.session_id, operation.packet_indices) == (
        r"evidence\flag.txt", 17, 23, 42, (1, 2),
    )
    assert (operation.desired_access, operation.create_disposition, operation.create_options) == (0x00120089, 1, 0x40)
    assert (operation.response_status, operation.persistent_file_id, operation.volatile_file_id, operation.response_packet_indices) == (0, 0x1111, 0x2222, (3,))
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    finding = next(item for item in result.findings if item.category == "pcap_smb2_create_operation")
    assert r"filename=evidence\flag.txt" in finding.supporting_evidence
    assert "message_id=17" in finding.supporting_evidence
    assert "packet_indices=1,2" in finding.supporting_evidence
    assert "response_status=0x00000000" in finding.supporting_evidence
    assert "persistent_file_id=4369" in finding.supporting_evidence
    assert "volatile_file_id=8738" in finding.supporting_evidence
    assert "response_packet_indices=3" in finding.supporting_evidence


def test_smb2_tree_connect_share_path_correlates_to_create_operation(tmp_path: Path) -> None:
    evidence = tmp_path / "smb2-tree-create.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    tree = _smb2_tree_connect_request(r"\\server\evidence", message_id=16, session_id=42)
    tree_response = _smb2_tree_connect_response(message_id=16, tree_id=23, session_id=42)
    create = _smb2_create_request(r"folder\flag.txt", message_id=17, tree_id=23, session_id=42)
    create_response = _smb2_create_response(message_id=17, tree_id=23, session_id=42, persistent_file_id=0x1111, volatile_file_id=0x2222)
    evidence.write_bytes(_pcap([
        _tcp_packet(tree, sequence=1000, source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(tree_response, sequence=2000, source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(create, sequence=1000 + len(tree), source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(create_response, sequence=2000 + len(tree_response), source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    operation = next(iter_smb2_create_operations(evidence))
    assert operation.share_path == r"\\server\evidence"
    assert operation.tree_connect_packet_indices == (1,)
    assert operation.tree_connect_response_packet_indices == (2,)
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    finding = next(item for item in result.findings if item.category == "pcap_smb2_create_operation")
    assert r"share_path=\\server\evidence" in finding.supporting_evidence
    assert "tree_connect_packet_indices=1" in finding.supporting_evidence
    assert "tree_connect_response_packet_indices=2" in finding.supporting_evidence


def test_smb2_write_recovery_requires_create_file_id_and_successful_acknowledgement(tmp_path: Path) -> None:
    evidence = tmp_path / "smb2-write.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    create = _smb2_create_request(r"uploads\flag.txt", message_id=17, tree_id=23, session_id=42)
    create_response = _smb2_create_response(message_id=17, tree_id=23, session_id=42, persistent_file_id=0x1111, volatile_file_id=0x2222)
    payload = b"CTF{smb2_write_upload}"
    write = _smb2_write_request(payload, message_id=18, tree_id=23, session_id=42, persistent_file_id=0x1111, volatile_file_id=0x2222)
    write_response = _smb2_write_response(message_id=18, tree_id=23, session_id=42, count=len(payload))
    close = _smb2_close_request(message_id=19, tree_id=23, session_id=42, persistent_file_id=0x1111, volatile_file_id=0x2222)
    close_response = _smb2_close_response(message_id=19, tree_id=23, session_id=42, end_of_file=len(payload))
    evidence.write_bytes(_pcap([
        _tcp_packet(create, sequence=1000, source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(create_response, sequence=2000, source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(write, sequence=1000 + len(create), source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(write_response, sequence=2000 + len(create_response), source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(close, sequence=1000 + len(create) + len(write), source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(close_response, sequence=2000 + len(create_response) + len(write_response), source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    uploaded = next(iter_smb2_write_objects(evidence))
    assert (uploaded.logical_name, uploaded.smb_path, uploaded.body) == ("flag.txt", r"uploads\flag.txt", payload)
    assert (uploaded.message_ids, uploaded.packet_indices, uploaded.response_packet_indices) == ((18,), (3,), (4,))
    assert (uploaded.close_end_of_file, uploaded.close_packet_indices, uploaded.close_response_packet_indices) == (len(payload), (5,), (6,))
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    assert [artifact.logical_name for artifact in result.artifacts] == ["smb2-write.pcap", "flag.txt"]
    assert any(flag.value == "CTF{smb2_write_upload}" for flag in result.flags)
    finding = next(item for item in result.findings if item.category == "pcap_smb2_write_extraction")
    assert not any(item.category == "pcap_http_extraction" for item in result.findings)
    assert "message_ids=18" in finding.supporting_evidence
    assert "packet_indices=3" in finding.supporting_evidence
    assert "response_packet_indices=4" in finding.supporting_evidence
    assert f"close_end_of_file={len(payload)}" in finding.supporting_evidence
    assert "close_size_match=True" in finding.supporting_evidence
    assert "close_packet_indices=5" in finding.supporting_evidence
    assert "close_response_packet_indices=6" in finding.supporting_evidence

    mismatch = tmp_path / "smb2-write-close-mismatch.pcap"
    mismatch_close_response = _smb2_close_response(message_id=19, tree_id=23, session_id=42, end_of_file=len(payload) + 1)
    mismatch.write_bytes(_pcap([
        _tcp_packet(create, sequence=1000, source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(create_response, sequence=2000, source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(write, sequence=1000 + len(create), source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(write_response, sequence=2000 + len(create_response), source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(close, sequence=1000 + len(create) + len(write), source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(mismatch_close_response, sequence=2000 + len(create_response) + len(write_response), source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    assert list(iter_smb2_write_objects(mismatch)) == []


def test_smb2_read_recovery_requires_create_file_id_and_exact_response_bounds(tmp_path: Path) -> None:
    evidence = tmp_path / "smb2-read.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    create = _smb2_create_request(r"downloads\flag.txt", message_id=17, tree_id=23, session_id=42)
    create_response = _smb2_create_response(message_id=17, tree_id=23, session_id=42, persistent_file_id=0x1111, volatile_file_id=0x2222)
    payload = b"CTF{smb2_read_download}"
    read = _smb2_read_request(message_id=18, tree_id=23, session_id=42, persistent_file_id=0x1111, volatile_file_id=0x2222, length=len(payload))
    read_response = _smb2_read_response(payload, message_id=18, tree_id=23, session_id=42)
    evidence.write_bytes(_pcap([
        _tcp_packet(create, sequence=1000, source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(create_response, sequence=2000, source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(read, sequence=1000 + len(create), source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(read_response, sequence=2000 + len(create_response), source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    downloaded = next(iter_smb2_read_objects(evidence))
    assert (downloaded.logical_name, downloaded.smb_path, downloaded.body) == ("flag.txt", r"downloads\flag.txt", payload)
    assert (downloaded.message_ids, downloaded.request_packet_indices, downloaded.packet_indices) == ((18,), (3,), (4,))
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    assert [artifact.logical_name for artifact in result.artifacts] == ["smb2-read.pcap", "flag.txt"]
    assert any(flag.value == "CTF{smb2_read_download}" for flag in result.flags)
    finding = next(item for item in result.findings if item.category == "pcap_smb2_read_extraction")
    assert "message_ids=18" in finding.supporting_evidence
    assert "request_packet_indices=3" in finding.supporting_evidence
    assert "packet_indices=4" in finding.supporting_evidence


def test_smb2_close_correlates_file_id_status_size_and_timestamp_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "smb2-close.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    create = _smb2_create_request(r"lifecycle\flag.txt", message_id=17, tree_id=23, session_id=42)
    create_response = _smb2_create_response(message_id=17, tree_id=23, session_id=42, persistent_file_id=0x1111, volatile_file_id=0x2222)
    close = _smb2_close_request(message_id=19, tree_id=23, session_id=42, persistent_file_id=0x1111, volatile_file_id=0x2222)
    close_response = _smb2_close_response(message_id=19, tree_id=23, session_id=42, end_of_file=23)
    evidence.write_bytes(_pcap([
        _tcp_packet(create, sequence=1000, source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(create_response, sequence=2000, source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(close, sequence=1000 + len(create), source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(close_response, sequence=2000 + len(create_response), source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    operation = next(iter_smb2_close_operations(evidence))
    assert (operation.filename, operation.message_id, operation.packet_indices, operation.response_packet_indices) == (
        r"lifecycle\flag.txt", 19, (3,), (4,),
    )
    assert (operation.response_status, operation.end_of_file, operation.allocation_size, operation.file_attributes) == (0, 23, 23, 0x20)
    assert operation.creation_filetime == 132537600000000000
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    finding = next(item for item in result.findings if item.category == "pcap_smb2_close_operation")
    assert "message_id=19" in finding.supporting_evidence
    assert "response_status=0x00000000" in finding.supporting_evidence
    assert "end_of_file=23" in finding.supporting_evidence
    assert "creation_filetime=132537600000000000" in finding.supporting_evidence


def test_smb2_set_info_rename_and_delete_disposition_retain_file_id_and_response_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "smb2-set-info.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    create = _smb2_create_request(r"staging\flag.tmp", message_id=17, tree_id=23, session_id=42)
    create_response = _smb2_create_response(message_id=17, tree_id=23, session_id=42, persistent_file_id=0x1111, volatile_file_id=0x2222)
    target = r"archive\flag.txt".encode("utf-16le")
    rename_buffer = bytearray(20)
    rename_buffer[0] = 1
    rename_buffer[16:20] = len(target).to_bytes(4, "little")
    rename = _smb2_set_info_request(bytes(rename_buffer) + target, info_class=10, message_id=18, tree_id=23, session_id=42, persistent_file_id=0x1111, volatile_file_id=0x2222)
    rename_response = _smb2_set_info_response(message_id=18, tree_id=23, session_id=42)
    delete = _smb2_set_info_request(b"\x01", info_class=13, message_id=19, tree_id=23, session_id=42, persistent_file_id=0x1111, volatile_file_id=0x2222)
    delete_response = _smb2_set_info_response(message_id=19, tree_id=23, session_id=42)
    evidence.write_bytes(_pcap([
        _tcp_packet(create, sequence=1000, source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(create_response, sequence=2000, source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(rename, sequence=1000 + len(create), source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(rename_response, sequence=2000 + len(create_response), source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(delete, sequence=1000 + len(create) + len(rename), source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(delete_response, sequence=2000 + len(create_response) + len(rename_response), source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    operations = list(iter_smb2_set_info_operations(evidence))
    assert [(item.operation, item.target_filename, item.replace_if_exists, item.delete_pending, item.response_status) for item in operations] == [
        ("rename", r"archive\flag.txt", True, None, 0),
        ("delete_disposition", None, None, True, 0),
    ]
    assert [(item.packet_indices, item.response_packet_indices) for item in operations] == [((3,), (4,)), ((5,), (6,))]
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    findings = [item for item in result.findings if item.category == "pcap_smb2_set_info_operation"]
    assert len(findings) == 2
    assert any(r"target_filename=archive\flag.txt" in item.supporting_evidence for item in findings)
    assert any("delete_pending=True" in item.supporting_evidence for item in findings)
    assert all("response_status=0x00000000" in item.supporting_evidence for item in findings)


def test_smb2_query_directory_recovers_bounded_listing_child_with_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "smb2-query-directory.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    create = _smb2_create_request("folder", message_id=17, tree_id=23, session_id=42)
    create_response = _smb2_create_response(
        message_id=17, tree_id=23, session_id=42,
        persistent_file_id=0x1111, volatile_file_id=0x2222,
    )
    query = _smb2_query_directory_request(
        "*", message_id=18, tree_id=23, session_id=42,
        persistent_file_id=0x1111, volatile_file_id=0x2222,
    )
    names = ["alpha.txt", "CTF{smb2_directory_flag}.txt"]
    response = _smb2_query_directory_response(names, message_id=18, tree_id=23, session_id=42)
    evidence.write_bytes(_pcap([
        _tcp_packet(create, sequence=1000, source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(create_response, sequence=2000, source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(query, sequence=1000 + len(create), source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(response, sequence=2000 + len(create_response), source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
    ]))

    listing = next(iter_smb2_directory_listings(evidence))
    assert (listing.logical_name, listing.directory_path, listing.pattern) == (
        "folder_smb2_directory_listing.txt", "folder", "*",
    )
    assert listing.names == tuple(names)
    assert listing.body == b"alpha.txt\nCTF{smb2_directory_flag}.txt\n"
    assert (listing.request_packet_indices, listing.packet_indices) == ((3,), (4,))

    result = AnalysisEngine(ForensicKitConfig()).analyze(
        evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False,
    )
    assert [artifact.logical_name for artifact in result.artifacts] == [
        "smb2-query-directory.pcap", "folder_smb2_directory_listing.txt",
    ]
    assert any(flag.value == "CTF{smb2_directory_flag}" for flag in result.flags)
    finding = next(item for item in result.findings if item.category == "pcap_smb2_directory_listing_extraction")
    assert "directory_path=folder" in finding.supporting_evidence
    assert "pattern=*" in finding.supporting_evidence
    assert "entry_count=2" in finding.supporting_evidence
    assert "persistent_file_id=4369" in finding.supporting_evidence
    assert "volatile_file_id=8738" in finding.supporting_evidence
    assert "message_id=18" in finding.supporting_evidence
    assert "request_packet_indices=3" in finding.supporting_evidence
    assert "packet_indices=4" in finding.supporting_evidence
    assert not any(item.category == "pcap_http_extraction" for item in result.findings)


def test_smb2_file_id_both_directory_inventory_preserves_raw_entry_metadata(tmp_path: Path) -> None:
    evidence = tmp_path / "smb2-file-id-both-directory.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    create = _smb2_create_request("evidence", message_id=17, tree_id=23, session_id=42)
    create_response = _smb2_create_response(
        message_id=17, tree_id=23, session_id=42,
        persistent_file_id=0x1111, volatile_file_id=0x2222,
    )
    query = _smb2_query_directory_request(
        "*.bin", message_id=18, tree_id=23, session_id=42,
        persistent_file_id=0x1111, volatile_file_id=0x2222, information_class=37,
    )
    entries: list[dict[str, int | str]] = [
        {
            "name": "sample.bin", "short_name": "SAMPLE~1.BIN", "file_index": 7,
            "creation_filetime": 132537600000000001, "last_access_filetime": 132537600000000002,
            "last_write_filetime": 132537600000000003, "change_filetime": 132537600000000004,
            "end_of_file": 23, "allocation_size": 4096, "file_attributes": 0x20,
            "ea_size": 0, "file_id": 0x3333,
        },
        {
            "name": "CTF{smb2_file_id_both}.bin", "short_name": "FLAG.BIN", "file_index": 8,
            "creation_filetime": 132537600000000011, "last_access_filetime": 132537600000000012,
            "last_write_filetime": 132537600000000013, "change_filetime": 132537600000000014,
            "end_of_file": 42, "allocation_size": 4096, "file_attributes": 0x21,
            "ea_size": 4, "file_id": 0x4444,
        },
    ]
    response = _smb2_file_id_both_directory_response(entries, message_id=18, tree_id=23, session_id=42)
    evidence.write_bytes(_pcap([
        _tcp_packet(create, sequence=1000, source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(create_response, sequence=2000, source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(query, sequence=1000 + len(create), source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(response, sequence=2000 + len(create_response), source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
    ]))

    listing = next(iter_smb2_directory_listings(evidence))
    assert (listing.logical_name, listing.information_class, listing.information_class_name) == (
        "evidence_smb2_directory_inventory.jsonl", 37, "FileIdBothDirectoryInformation",
    )
    assert listing.names == ("sample.bin", "CTF{smb2_file_id_both}.bin")
    assert (listing.entries[0].short_name, listing.entries[0].file_id, listing.entries[0].end_of_file) == (
        "SAMPLE~1.BIN", 0x3333, 23,
    )
    assert (listing.entries[1].creation_filetime, listing.entries[1].file_attributes, listing.entries[1].ea_size) == (
        132537600000000011, 0x21, 4,
    )
    decoded_lines = [json.loads(line) for line in listing.body.decode("utf-8").splitlines()]
    assert decoded_lines[1]["name"] == "CTF{smb2_file_id_both}.bin"
    assert decoded_lines[1]["file_id"] == 0x4444
    assert (listing.request_packet_indices, listing.packet_indices) == ((3,), (4,))

    result = AnalysisEngine(ForensicKitConfig()).analyze(
        evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False,
    )
    assert [artifact.logical_name for artifact in result.artifacts] == [
        "smb2-file-id-both-directory.pcap", "evidence_smb2_directory_inventory.jsonl",
    ]
    assert any(flag.value == "CTF{smb2_file_id_both}" for flag in result.flags)
    finding = next(item for item in result.findings if item.category == "pcap_smb2_directory_listing_extraction")
    assert "information_class=37" in finding.supporting_evidence
    assert "information_class_name=FileIdBothDirectoryInformation" in finding.supporting_evidence
    assert "entry_count=2" in finding.supporting_evidence
    assert any("file_id" in item and "end_of_file" in item for item in finding.supporting_evidence)
    assert "request_packet_indices=3" in finding.supporting_evidence
    assert "packet_indices=4" in finding.supporting_evidence


def test_smb3_transform_headers_preserve_bounded_flow_and_packet_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "smb3-transforms.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    encrypted = _smb3_encryption_transform(b"encrypted-payload", original_size=4096, session_id=0x12345678)
    compressed = _smb3_compression_transform(
        b"HEADcompressed", original_size=8192, algorithm=1, data_offset=4,
    )
    split = 31
    evidence.write_bytes(_pcap([
        _tcp_packet(encrypted[:split], sequence=2000, source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(encrypted[split:], sequence=2000 + split, source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(compressed, sequence=1000, source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
    ]))

    records = list(iter_smb3_transform_records(evidence))
    assert [item.transform_type for item in records] == ["encryption", "compression"]
    assert (records[0].declared_original_size, records[0].session_id, records[0].packet_indices) == (
        4096, 0x12345678, (1, 2),
    )
    assert records[0].signature_hex == bytes(range(1, 17)).hex()
    assert records[0].nonce_hex == bytes(range(17, 33)).hex()
    assert (records[1].declared_original_size, records[1].compression_algorithm, records[1].compression_algorithm_name) == (
        8192, 1, "LZNT1",
    )
    assert (records[1].flags, records[1].data_offset, records[1].packet_indices) == (0, 4, (3,))

    result = AnalysisEngine(ForensicKitConfig()).analyze(
        evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False,
    )
    assert [artifact.logical_name for artifact in result.artifacts] == ["smb3-transforms.pcap"]
    findings = [item for item in result.findings if item.category == "pcap_smb3_transform"]
    assert len(findings) == 2
    assert any("transform_type=encryption" in item.supporting_evidence and "session_id=305419896" in item.supporting_evidence for item in findings)
    assert any("transform_type=compression" in item.supporting_evidence and "compression_algorithm_name=LZNT1" in item.supporting_evidence for item in findings)
    assert any("packet_indices=1,2" in item.supporting_evidence for item in findings)
    assert any("packet_indices=3" in item.supporting_evidence for item in findings)


def test_smb2_negotiate_correlates_dialect_signing_capabilities_and_sizes(tmp_path: Path) -> None:
    evidence = tmp_path / "smb2-negotiate.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    request = _smb2_negotiate_request(
        [0x0202, 0x0210, 0x0300], message_id=7, security_mode=3, capabilities=0x44,
    )
    response = _smb2_negotiate_response(
        message_id=7, security_mode=3, dialect=0x0300, capabilities=0x40,
    )
    split = 73
    evidence.write_bytes(_pcap([
        _tcp_packet(request[:split], sequence=1000, source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(request[split:], sequence=1000 + split, source_port=41000, destination_port=445, source_ip=client, destination_ip=server),
        _tcp_packet(response, sequence=2000, source_port=445, destination_port=41000, source_ip=server, destination_ip=client),
    ]))

    operation = next(iter_smb2_negotiate_operations(evidence))
    assert operation.offered_dialects == (0x0202, 0x0210, 0x0300)
    assert operation.offered_dialect_names == ("SMB 2.0.2", "SMB 2.1", "SMB 3.0")
    assert (operation.request_security_mode, operation.request_capabilities, operation.client_guid_hex) == (
        3, 0x44, bytes(range(16)).hex(),
    )
    assert (operation.message_id, operation.packet_indices, operation.response_packet_indices) == (7, (1, 2), (3,))
    assert (operation.response_status, operation.selected_dialect, operation.selected_dialect_name) == (
        0, 0x0300, "SMB 3.0",
    )
    assert (operation.response_security_mode, operation.response_capabilities, operation.server_guid_hex) == (
        3, 0x40, bytes(range(16, 32)).hex(),
    )
    assert (operation.max_transact_size, operation.max_read_size, operation.max_write_size) == (
        1_048_576, 2_097_152, 3_145_728,
    )
    assert (operation.system_filetime, operation.server_start_filetime) == (
        132537600000000000, 132537500000000000,
    )

    result = AnalysisEngine(ForensicKitConfig()).analyze(
        evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False,
    )
    finding = next(item for item in result.findings if item.category == "pcap_smb2_negotiate_operation")
    assert "offered_dialects=0x0202,0x0210,0x0300" in finding.supporting_evidence
    assert "request_signing_required=True" in finding.supporting_evidence
    assert "selected_dialect=0x0300" in finding.supporting_evidence
    assert "selected_dialect_offered=True" in finding.supporting_evidence
    assert "response_signing_required=True" in finding.supporting_evidence
    assert "max_read_size=2097152" in finding.supporting_evidence
    assert "packet_indices=1,2" in finding.supporting_evidence
    assert "response_packet_indices=3" in finding.supporting_evidence


def test_recovers_bounded_smtp_data_message_with_control_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "smtp-data.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    body = b"From: analyst@example\r\nSubject: CTF\r\n\r\nCTF{smtp_message}\r\n..dot\r\n"
    ready = b"354 End data with <CR><LF>.<CR><LF>\r\n"
    evidence.write_bytes(_pcap([
        _tcp_packet(b"DA", sequence=1000, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(b"TA\r\n", sequence=1002, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(ready[:12], sequence=2000, source_port=25, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(ready[12:], sequence=2012, source_port=25, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(body[:35], sequence=1006, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(body[:35], sequence=1006, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(body[35:] + b".\r\n", sequence=1041, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(b"250 queued\r\n", sequence=2037, source_port=25, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    objects = list(iter_smtp_data_objects(evidence))
    assert [(item.logical_name, item.body, item.packet_indices, item.data_command_packet_index, item.ready_response_packet_index) for item in objects] == [
        ("smtp_message_0000.eml", body.replace(b"\r\n..", b"\r\n."), (5, 7), 2, 4),
    ]
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    assert [artifact.logical_name for artifact in result.artifacts] == ["smtp-data.pcap", "smtp_message_0000.eml"]
    finding = next(item for item in result.findings if item.category == "pcap_smtp_data_extraction")
    assert "data_command_packet_index=2" in finding.supporting_evidence
    assert "ready_response_packet_index=4" in finding.supporting_evidence
    assert "acceptance_code=250" in finding.supporting_evidence
    assert "acceptance_packet_index=8" in finding.supporting_evidence


def test_smtp_data_message_retains_exact_final_rejection_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "smtp-rejection.pcap"
    client = b"\x0a\x00\x00\x02"; server = b"\x0a\x00\x00\x01"
    message = b"Subject: rejected\r\n\r\nCTF{smtp_rejected}\r\n"
    evidence.write_bytes(_pcap([
        _tcp_packet(b"DATA\r\n", sequence=1000, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(b"354 go\r\n", sequence=2000, source_port=25, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(message + b".\r\n", sequence=1006, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(b"554 rejected\r\n", sequence=2008, source_port=25, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    message_object = next(iter_smtp_data_objects(evidence))
    assert (message_object.acceptance_code, message_object.rejection_code, message_object.rejection_packet_index) == (None, 554, 4)


def test_smtp_data_message_retains_final_forwarding_acceptance_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "smtp-forwarded.pcap"
    client = b"\x0a\x00\x00\x02"; server = b"\x0a\x00\x00\x01"
    message = b"Subject: forwarded\r\n\r\nCTF{smtp_forwarded}\r\n"
    evidence.write_bytes(_pcap([
        _tcp_packet(b"DATA\r\n", sequence=1000, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(b"354 go\r\n", sequence=2000, source_port=25, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(message + b".\r\n", sequence=1006, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(b"251 User not local; will forward\r\n", sequence=2008, source_port=25, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    message_object = next(iter_smtp_data_objects(evidence))
    assert (message_object.acceptance_code, message_object.forwarding_code, message_object.forwarding_packet_index, message_object.rejection_code) == (None, 251, 4, None)


def test_smtp_starttls_transition_has_provenance_and_suppresses_plaintext_recovery(tmp_path: Path) -> None:
    evidence = tmp_path / "smtp-starttls.pcap"
    client = b"\x0a\x00\x00\x02"; server = b"\x0a\x00\x00\x01"
    evidence.write_bytes(_pcap([
        _tcp_packet(b"STARTTLS\r\n", sequence=1000, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(b"220 Ready to start TLS\r\n", sequence=2000, source_port=25, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(b"DATA\r\n", sequence=1010, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
    ]))
    assert [(item.source, item.source_port, item.destination, item.destination_port, item.command_packet_index, item.ready_response_packet_index) for item in iter_smtp_starttls_transitions(evidence)] == [
        ("10.0.0.2", 41000, "10.0.0.1", 25, 1, 2),
    ]
    assert list(iter_smtp_data_objects(evidence)) == []


def test_recovers_bounded_smtp_bdat_chunks_with_child_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "smtp-bdat.pcap"
    client = b"\x0a\x00\x00\x02"; server = b"\x0a\x00\x00\x01"
    first = b"Subject: bdat\r\n\r\n"
    second = b"CTF{smtp_bdat}\r\n"
    first_record = f"BDAT {len(first)}\r\n".encode() + first
    second_record = f"BDAT {len(second)} LAST\r\n".encode() + second
    evidence.write_bytes(_pcap([
        _tcp_packet(first_record, sequence=1000, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(second_record, sequence=1000 + len(first_record), source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(b"250 queued\r\n", sequence=2000, source_port=25, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    assert [(item.body, item.packet_indices, item.command_packet_indices) for item in iter_smtp_bdat_objects(evidence)] == [
        (first + second, (1, 2), (1, 2)),
    ]
    assert next(iter_smtp_bdat_objects(evidence)).final_response_code == 250
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    assert [artifact.logical_name for artifact in result.artifacts] == ["smtp-bdat.pcap", "smtp_bdat_message_0000.eml"]
    assert any(flag.value == "CTF{smtp_bdat}" for flag in result.flags)
    finding = next(item for item in result.findings if item.category == "pcap_smtp_bdat_extraction")
    assert "bdat_command_packet_indices=1,2" in finding.supporting_evidence
    assert "final_response_code=250" in finding.supporting_evidence


def test_smtp_bdat_reassembly_excludes_retransmitted_split_command_and_payload(tmp_path: Path) -> None:
    evidence = tmp_path / "smtp-bdat-retransmit.pcap"
    client = b"\x0a\x00\x00\x02"; server = b"\x0a\x00\x00\x01"
    first = b"Subject: split\r\n\r\n"; second = b"CTF{smtp_bdat_split}\r\n"
    record_one = f"BDAT {len(first)}\r\n".encode() + first
    record_two = f"BDAT {len(second)} LAST\r\n".encode() + second
    split = 5
    evidence.write_bytes(_pcap([
        _tcp_packet(record_one[:split], sequence=1000, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(record_one[:split], sequence=1000, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(record_one[split:], sequence=1000 + split, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(record_two, sequence=1000 + len(record_one), source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
    ]))
    recovered = next(iter_smtp_bdat_objects(evidence))
    assert recovered.body == first + second
    assert recovered.packet_indices == (3, 4)
    assert recovered.command_packet_indices == (3, 4)


def test_smtp_bdat_without_last_is_not_promoted_as_complete_message(tmp_path: Path) -> None:
    evidence = tmp_path / "smtp-bdat-incomplete.pcap"
    client = b"\x0a\x00\x00\x02"; server = b"\x0a\x00\x00\x01"
    body = b"Subject: incomplete\r\n\r\nCTF{not_complete}\r\n"
    record = f"BDAT {len(body)}\r\n".encode() + body
    evidence.write_bytes(_pcap([_tcp_packet(record, sequence=1000, source_port=41000, destination_port=25, source_ip=client, destination_ip=server)]))
    assert list(iter_smtp_bdat_objects(evidence)) == []


def test_recovers_bounded_pop3_retr_message_with_child_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "pop3-retr.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    body = b"Subject: POP3\r\n\r\nCTF{pop3_retr}\r\n..dot\r\n"
    response = b"+OK message follows\r\n" + body + b".\r\n"
    evidence.write_bytes(_pcap([
        _tcp_packet(b"RETR 1\r\n", sequence=1000, source_port=41000, destination_port=110, source_ip=client, destination_ip=server),
        _tcp_packet(response[:23], sequence=2000, source_port=110, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(response[23:], sequence=2023, source_port=110, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    recovered = next(iter_pop3_retr_objects(evidence))
    assert (recovered.body, recovered.packet_indices, recovered.retr_command_packet_index, recovered.positive_response_packet_index) == (
        body.replace(b"\r\n..", b"\r\n."), (2, 3), 1, 2,
    )
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    assert [artifact.logical_name for artifact in result.artifacts] == ["pop3-retr.pcap", "pop3_retr_message_0000.eml"]
    assert any(flag.value == "CTF{pop3_retr}" for flag in result.flags)
    finding = next(item for item in result.findings if item.category == "pcap_pop3_retr_extraction")
    assert "retr_command_packet_index=1" in finding.supporting_evidence
    assert "positive_response_packet_index=2" in finding.supporting_evidence


def test_pop3_retr_reassembly_excludes_retransmission_and_requires_positive_response(tmp_path: Path) -> None:
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    body = b"Subject: retry\r\n\r\nCTF{pop3_retransmit}\r\n"
    response = b"+OK\r\n" + body + b".\r\n"
    evidence = tmp_path / "pop3-retransmit.pcap"
    split = 12
    evidence.write_bytes(_pcap([
        _tcp_packet(b"RETR 1\r\n", sequence=1000, source_port=41000, destination_port=110, source_ip=client, destination_ip=server),
        _tcp_packet(response[:split], sequence=2000, source_port=110, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(response[:split], sequence=2000, source_port=110, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(response[split:], sequence=2000 + split, source_port=110, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    recovered = next(iter_pop3_retr_objects(evidence))
    assert recovered.body == body
    assert recovered.packet_indices == (2, 4)

    rejected = tmp_path / "pop3-rejected.pcap"
    rejected.write_bytes(_pcap([
        _tcp_packet(b"RETR 9\r\n", sequence=1000, source_port=41000, destination_port=110, source_ip=client, destination_ip=server),
        _tcp_packet(b"-ERR no such message\r\nSubject: not-a-message\r\n\r\nCTF{not_pop3}\r\n.\r\n", sequence=2000, source_port=110, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    assert list(iter_pop3_retr_objects(rejected)) == []


def test_pop3_stls_transition_has_provenance_and_suppresses_plaintext_recovery(tmp_path: Path) -> None:
    evidence = tmp_path / "pop3-stls.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    body = b"Subject: should-not-recover\r\n\r\nCTF{not_pop3_stls}\r\n"
    response = b"+OK message follows\r\n" + body + b".\r\n"
    evidence.write_bytes(_pcap([
        _tcp_packet(b"STLS\r\n", sequence=1000, source_port=41000, destination_port=110, source_ip=client, destination_ip=server),
        _tcp_packet(b"+OK begin TLS\r\n", sequence=2000, source_port=110, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(b"RETR 1\r\n", sequence=1006, source_port=41000, destination_port=110, source_ip=client, destination_ip=server),
        _tcp_packet(response, sequence=2015, source_port=110, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    assert list(iter_pop3_retr_objects(evidence)) == []
    transitions = list(iter_pop3_stls_transitions(evidence))
    assert [(item.source, item.source_port, item.destination, item.destination_port, item.command_packet_index, item.ready_response_packet_index) for item in transitions] == [
        ("10.0.0.2", 41000, "10.0.0.1", 110, 1, 2),
    ]
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    finding = next(item for item in result.findings if item.category == "pcap_pop3_stls_transition")
    assert "stls_command_packet_index=1" in finding.supporting_evidence
    assert "ready_response_packet_index=2" in finding.supporting_evidence


def test_recursive_engine_registers_pop3_mime_attachment_with_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "pop3-mime.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    attachment = base64.b64encode(b"CTF{pop3_mime_attachment}")
    body = (
        b"Content-Type: multipart/mixed; boundary=pop3-boundary\r\n\r\n"
        b"--pop3-boundary\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
        b"--pop3-boundary\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=pop3-flag.txt\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n" + attachment + b"\r\n--pop3-boundary--\r\n"
    )
    evidence.write_bytes(_pcap([
        _tcp_packet(b"RETR 1\r\n", sequence=1000, source_port=41000, destination_port=110, source_ip=client, destination_ip=server),
        _tcp_packet(b"+OK message follows\r\n" + body + b".\r\n", sequence=2000, source_port=110, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    assert [artifact.logical_name for artifact in result.artifacts] == ["pop3-mime.pcap", "pop3_retr_message_0000.eml", "pop3-flag.txt"]
    assert any(flag.value == "CTF{pop3_mime_attachment}" for flag in result.flags)
    finding = next(item for item in result.findings if item.category == "pcap_pop3_mime_attachment_extraction")
    assert "logical_name=pop3-flag.txt" in finding.supporting_evidence
    assert "content_transfer_encoding=base64" in finding.supporting_evidence


def test_recovers_bounded_imap_fetch_message_with_child_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "imap-fetch.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    body = b"Subject: IMAP\r\n\r\nCTF{imap_fetch}\r\n"
    response = b"* 1 FETCH (BODY[] {" + str(len(body)).encode() + b"}\r\n" + body + b")\r\nA001 OK FETCH completed\r\n"
    split = len(response) - 12
    evidence.write_bytes(_pcap([
        _tcp_packet(b"A001 FETCH 1 BODY[]\r\n", sequence=1000, source_port=41000, destination_port=143, source_ip=client, destination_ip=server),
        _tcp_packet(response[:split], sequence=2000, source_port=143, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(response[split:], sequence=2000 + split, source_port=143, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    recovered = next(iter_imap_fetch_objects(evidence))
    assert (recovered.body, recovered.packet_indices, recovered.fetch_command_packet_index, recovered.literal_response_packet_index, recovered.completion_packet_index) == (
        body, (2,), 1, 2, 3,
    )
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    assert [artifact.logical_name for artifact in result.artifacts] == ["imap-fetch.pcap", "imap_fetch_message_0000.eml"]
    assert any(flag.value == "CTF{imap_fetch}" for flag in result.flags)
    finding = next(item for item in result.findings if item.category == "pcap_imap_fetch_extraction")
    assert "fetch_command_packet_index=1" in finding.supporting_evidence
    assert "completion_packet_index=3" in finding.supporting_evidence


def test_imap_starttls_tagged_ok_suppresses_plaintext_fetch_recovery(tmp_path: Path) -> None:
    evidence = tmp_path / "imap-starttls.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    body = b"Subject: should-not-recover\r\n\r\nCTF{not_imap}\r\n"
    response = b"* 1 FETCH (BODY[] {" + str(len(body)).encode() + b"}\r\n" + body + b")\r\nA002 OK done\r\n"
    evidence.write_bytes(_pcap([
        _tcp_packet(b"A001 STARTTLS\r\n", sequence=1000, source_port=41000, destination_port=143, source_ip=client, destination_ip=server),
        _tcp_packet(b"A001 OK begin TLS\r\n", sequence=2000, source_port=143, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(b"A002 FETCH 1 BODY[]\r\n", sequence=1015, source_port=41000, destination_port=143, source_ip=client, destination_ip=server),
        _tcp_packet(response, sequence=2019, source_port=143, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    assert list(iter_imap_fetch_objects(evidence)) == []
    transitions = list(iter_imap_starttls_transitions(evidence))
    assert [(item.tag, item.source, item.source_port, item.destination, item.destination_port, item.command_packet_index, item.ready_response_packet_index) for item in transitions] == [
        ("A001", "10.0.0.2", 41000, "10.0.0.1", 143, 1, 2),
    ]
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    finding = next(item for item in result.findings if item.category == "pcap_imap_starttls_transition")
    assert "tag=A001" in finding.supporting_evidence
    assert "starttls_command_packet_index=1" in finding.supporting_evidence
    assert "ready_response_packet_index=2" in finding.supporting_evidence


def test_recursive_engine_registers_imap_mime_attachment_with_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "imap-mime.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    attachment = base64.b64encode(b"CTF{imap_mime_attachment}")
    body = (
        b"Content-Type: multipart/mixed; boundary=imap-boundary\r\n\r\n"
        b"--imap-boundary\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
        b"--imap-boundary\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=imap-flag.txt\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n" + attachment + b"\r\n--imap-boundary--\r\n"
    )
    response = b"* 1 FETCH (RFC822 {" + str(len(body)).encode() + b"}\r\n" + body + b")\r\nA001 OK done\r\n"
    evidence.write_bytes(_pcap([
        _tcp_packet(b"A001 FETCH 1 RFC822\r\n", sequence=1000, source_port=41000, destination_port=143, source_ip=client, destination_ip=server),
        _tcp_packet(response, sequence=2000, source_port=143, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    assert [artifact.logical_name for artifact in result.artifacts] == ["imap-mime.pcap", "imap_fetch_message_0000.eml", "imap-flag.txt"]
    assert any(flag.value == "CTF{imap_mime_attachment}" for flag in result.flags)
    finding = next(item for item in result.findings if item.category == "pcap_imap_mime_attachment_extraction")
    assert "logical_name=imap-flag.txt" in finding.supporting_evidence
    assert "content_transfer_encoding=base64" in finding.supporting_evidence


def test_recursive_engine_registers_smtp_bdat_mime_attachment_with_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "smtp-bdat-mime.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    attachment = base64.b64encode(b"CTF{smtp_bdat_attachment}")
    message = (
        b"Content-Type: multipart/mixed; boundary=bdat-boundary\r\n\r\n"
        b"--bdat-boundary\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
        b"--bdat-boundary\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=bdat-flag.txt\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n" + attachment + b"\r\n--bdat-boundary--\r\n"
    )
    record = f"BDAT {len(message)} LAST\r\n".encode() + message
    evidence.write_bytes(_pcap([
        _tcp_packet(record, sequence=1000, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(b"250 queued\r\n", sequence=2000, source_port=25, destination_port=41000, source_ip=server, destination_ip=client),
    ]))
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    assert [artifact.logical_name for artifact in result.artifacts] == ["smtp-bdat-mime.pcap", "smtp_bdat_message_0000.eml", "bdat-flag.txt"]
    assert any(flag.value == "CTF{smtp_bdat_attachment}" for flag in result.flags)
    finding = next(item for item in result.findings if item.category == "pcap_smtp_mime_attachment_extraction")
    assert "logical_name=bdat-flag.txt" in finding.supporting_evidence
    assert "content_transfer_encoding=base64" in finding.supporting_evidence


def test_recursive_engine_registers_smtp_mime_attachment_with_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "smtp-mime.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    attachment = base64.b64encode(b"CTF{smtp_mime_attachment}")
    message = (
        b"Content-Type: multipart/mixed; boundary=mail-boundary\r\n\r\n"
        b"--mail-boundary\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
        b"--mail-boundary\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename*=UTF-8''ctf%20flag.txt\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n" + attachment + b"\r\n--mail-boundary--\r\n"
    )
    evidence.write_bytes(_pcap([
        _tcp_packet(b"DATA\r\n", sequence=1000, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(b"354 go\r\n", sequence=2000, source_port=25, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(message + b".\r\n", sequence=1006, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
    ]))
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    assert [artifact.logical_name for artifact in result.artifacts] == ["smtp-mime.pcap", "smtp_message_0000.eml", "ctf flag.txt"]
    assert any(flag.value == "CTF{smtp_mime_attachment}" for flag in result.flags)
    finding = next(item for item in result.findings if item.category == "pcap_smtp_mime_attachment_extraction")
    assert "logical_name=ctf flag.txt" in finding.supporting_evidence
    assert "content_transfer_encoding=base64" in finding.supporting_evidence


def test_recursive_engine_registers_nested_smtp_message_attachment(tmp_path: Path) -> None:
    evidence = tmp_path / "smtp-nested.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    message = (
        b"Content-Type: multipart/mixed; boundary=outer\r\n\r\n"
        b"--outer\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename=forwarded.eml\r\n\r\n"
        b"From: sender@example\r\nSubject: nested\r\n\r\nCTF{smtp_nested_message}\r\n"
        b"--outer--\r\n"
    )
    evidence.write_bytes(_pcap([
        _tcp_packet(b"DATA\r\n", sequence=1000, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(b"354 go\r\n", sequence=2000, source_port=25, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(message + b".\r\n", sequence=1006, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
    ]))
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    assert [artifact.logical_name for artifact in result.artifacts] == ["smtp-nested.pcap", "smtp_message_0000.eml", "forwarded.eml"]
    assert any(flag.value == "CTF{smtp_nested_message}" for flag in result.flags)


def test_recursive_engine_registers_smtp_inline_content_id_object(tmp_path: Path) -> None:
    evidence = tmp_path / "smtp-inline.pcap"
    client = b"\x0a\x00\x00\x02"
    server = b"\x0a\x00\x00\x01"
    encoded = base64.b64encode(b"CTF{smtp_inline_content_id}")
    message = (
        b"Content-Type: multipart/related; boundary=inline\r\n\r\n"
        b"--inline\r\nContent-Type: text/html\r\n\r\n<img src=\"cid:flag\">\r\n"
        b"--inline\r\nContent-Type: application/octet-stream\r\nContent-Disposition: inline; filename=inline.bin\r\n"
        b"Content-ID: <flag>\r\nContent-Transfer-Encoding: base64\r\n\r\n" + encoded + b"\r\n--inline--\r\n"
    )
    evidence.write_bytes(_pcap([
        _tcp_packet(b"DATA\r\n", sequence=1000, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(b"354 go\r\n", sequence=2000, source_port=25, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(message + b".\r\n", sequence=1006, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
    ]))
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    assert [artifact.logical_name for artifact in result.artifacts] == ["smtp-inline.pcap", "smtp_message_0000.eml", "inline.bin"]
    assert any(flag.value == "CTF{smtp_inline_content_id}" for flag in result.flags)
    finding = next(item for item in result.findings if item.category == "pcap_smtp_mime_attachment_extraction")
    assert "content_disposition=inline" in finding.supporting_evidence
    assert "content_id=<flag>" in finding.supporting_evidence


def test_smtp_multipart_alternative_flag_has_mime_specific_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "smtp-alternative.pcap"
    client = b"\x0a\x00\x00\x02"; server = b"\x0a\x00\x00\x01"
    message = b"Content-Type: multipart/alternative; boundary=alt\r\n\r\n--alt\r\nContent-Type: text/plain\r\n\r\nCTF{smtp_alternative}\r\n--alt\r\nContent-Type: text/html\r\n\r\n<b>CTF{smtp_alternative}</b>\r\n--alt--\r\n"
    evidence.write_bytes(_pcap([
        _tcp_packet(b"DATA\r\n", sequence=1000, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
        _tcp_packet(b"354 go\r\n", sequence=2000, source_port=25, destination_port=41000, source_ip=server, destination_ip=client),
        _tcp_packet(message + b".\r\n", sequence=1006, source_port=41000, destination_port=25, source_ip=client, destination_ip=server),
    ]))
    result = AnalysisEngine(ForensicKitConfig()).analyze(evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False)
    candidates = [item for item in result.flags if item.value == "CTF{smtp_alternative}" and item.source == "smtp_multipart_alternative_flag_hunter"]
    assert len(candidates) == 1


def test_tls_client_hello_sni_alpn_and_packet_provenance_are_bounded(tmp_path: Path) -> None:
    hello = _tls_client_hello(server_name="ctf.example", alpn=["h2", "http/1.1"])
    assert _tls_client_hello_metadata(hello) == {
        "record_version": "0x0301", "server_name": "ctf.example", "alpn_protocols": ["h2", "http/1.1"],
    }
    evidence = tmp_path / "tls.pcap"
    evidence.write_bytes(_pcap([_tcp_packet(hello, sequence=100, source_port=44444, destination_port=443)]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.server_names"] == ["ctf.example"]
    assert values["pcap.tls.client_hellos"] == [{
        "record_version": "0x0301", "server_name": "ctf.example", "alpn_protocols": ["h2", "http/1.1"],
        "packet_index": 1, "packet_indices": [1], "source": "10.0.0.1", "destination": "10.0.0.2", "source_port": 44444, "destination_port": 443,
    }]


def test_tls_server_hello_selected_alpn_and_packet_provenance_are_bounded(tmp_path: Path) -> None:
    hello = _tls_server_hello(selected_alpn="h2")
    assert _tls_server_hello_metadata(hello) == {
        "record_version": "0x0303", "cipher_suite": "0x1301", "selected_alpn": "h2",
    }
    evidence = tmp_path / "tls-server.pcap"
    evidence.write_bytes(_pcap([_tcp_packet(hello, sequence=100, source_port=443, destination_port=44444)]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-server", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.server_hellos"] == [{
        "record_version": "0x0303", "cipher_suite": "0x1301", "selected_alpn": "h2",
        "packet_index": 1, "packet_indices": [1], "source": "10.0.0.1", "destination": "10.0.0.2", "source_port": 443, "destination_port": 44444,
    }]


def test_tls_certificate_chain_inventory_has_fingerprints_and_packet_provenance(tmp_path: Path) -> None:
    leaf = b"\x30\x03one"
    issuer = b"\x30\x03two"
    record = _tls12_certificate_record(leaf, issuer)
    assert _tls_certificate_metadata(record) == ({
        "record_version": "0x0303", "certificate_format": "tls12", "certificate_count": 2,
        "certificate_lengths": [len(leaf), len(issuer)],
        "certificate_sha256": [hashlib.sha256(leaf).hexdigest(), hashlib.sha256(issuer).hexdigest()],
    }, None)
    evidence = tmp_path / "tls-certificate.pcap"
    evidence.write_bytes(_pcap([_tcp_packet(record, sequence=100, source_port=443, destination_port=44444)]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-certificate", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.certificate_errors"] == []
    assert values["pcap.tls.certificates"] == [{
        "record_version": "0x0303", "certificate_format": "tls12", "certificate_count": 2,
        "certificate_lengths": [len(leaf), len(issuer)],
        "certificate_sha256": [hashlib.sha256(leaf).hexdigest(), hashlib.sha256(issuer).hexdigest()],
        "packet_index": 1, "packet_indices": [1], "source": "10.0.0.1", "destination": "10.0.0.2",
        "source_port": 443, "destination_port": 44444,
    }]


def test_tls13_certificate_inventory_preserves_request_context_length() -> None:
    certificate = b"\x30\x03tls"
    record = _tls13_certificate_record(request_context=b"ctx", certificate=certificate)
    assert _tls_certificate_metadata(record) == ({
        "record_version": "0x0303", "certificate_format": "tls13", "certificate_count": 1,
        "certificate_lengths": [len(certificate)], "certificate_sha256": [hashlib.sha256(certificate).hexdigest()],
        "request_context_length": 3,
    }, None)


def test_tls_certificate_malformed_list_is_a_bounded_structural_error(tmp_path: Path) -> None:
    malformed = b"\x16\x03\x03\x00\x0a\x0b\x00\x00\x06\x00\x00\x03\x00\x00\x02"
    assert _tls_certificate_metadata(malformed) == (None, "TLS Certificate list bounds or DER framing did not validate")
    evidence = tmp_path / "tls-certificate-malformed.pcap"
    evidence.write_bytes(_pcap([_tcp_packet(malformed, sequence=100, source_port=443, destination_port=44444)]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-certificate-error", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.certificates"] == []
    assert values["pcap.tls.certificate_errors"][0]["packet_index"] == 1
    assert values["pcap.tls.certificate_errors"][0]["error"] == "TLS Certificate list bounds or DER framing did not validate"


def test_tls_certificate_continuation_reassembles_and_ignores_exact_retransmission(tmp_path: Path) -> None:
    record = _tls12_certificate_record(b"\x30\x03one", b"\x30\x03two")
    first_split = 13
    second_split = 22
    evidence = tmp_path / "tls-certificate-retransmit.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(record[:first_split], sequence=100, source_port=443, destination_port=44444),
        _tcp_packet(record[first_split:second_split], sequence=100 + first_split, source_port=443, destination_port=44444),
        _tcp_packet(record[first_split:second_split], sequence=100 + first_split, source_port=443, destination_port=44444),
        _tcp_packet(record[second_split:], sequence=100 + second_split, source_port=443, destination_port=44444),
    ]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-certificate-retransmit", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.certificate_errors"] == []
    assert values["pcap.tls.certificate_incomplete_flows"] == []
    assert values["pcap.tls.certificates"][0]["packet_indices"] == [1, 2, 4]
    assert values["pcap.tls.certificates"][0]["certificate_count"] == 2


def test_tls_certificate_incomplete_flow_retains_declared_length_provenance(tmp_path: Path) -> None:
    record = _tls12_certificate_record(b"\x30\x03one")
    evidence = tmp_path / "tls-certificate-incomplete.pcap"
    evidence.write_bytes(_pcap([_tcp_packet(record[:13], sequence=100, source_port=443, destination_port=44444)]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-certificate-incomplete", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.certificate_errors"] == []
    assert values["pcap.tls.certificate_incomplete_flows"] == [{
        "source": "10.0.0.1", "source_port": 443, "destination": "10.0.0.2", "destination_port": 44444,
        "packet_indices": [1], "captured_length": 13, "expected_length": len(record),
    }]


def test_tls_certificate_gap_and_overflow_continuations_keep_bounded_errors(tmp_path: Path) -> None:
    record = _tls12_certificate_record(b"\x30\x03one")
    split = 13
    gap = tmp_path / "tls-certificate-gap.pcap"
    gap.write_bytes(_pcap([
        _tcp_packet(record[:split], sequence=100, source_port=443, destination_port=44444),
        _tcp_packet(record[split:], sequence=100 + split + 1, source_port=443, destination_port=44444),
    ]))
    gap_raw = gap.read_bytes()
    gap_artifact = Artifact(id="tls-certificate-gap", case_id="case", path=str(gap), logical_name=gap.name, sha256=hashlib.sha256(gap_raw).hexdigest(), size=len(gap_raw))
    gap_values = {item.key: item.value for item in PcapObservationEngine().analyze(gap_artifact, gap)}
    assert gap_values["pcap.tls.certificate_errors"][0]["error"] == "TLS Certificate continuation was out of order or had a TCP sequence gap"
    assert gap_values["pcap.tls.certificate_errors"][0]["packet_indices"] == [1]

    overflow = tmp_path / "tls-certificate-overflow.pcap"
    overflow.write_bytes(_pcap([
        _tcp_packet(record[:split], sequence=100, source_port=443, destination_port=44444),
        _tcp_packet(record[split:] + b"extra", sequence=100 + split, source_port=443, destination_port=44444),
    ]))
    overflow_raw = overflow.read_bytes()
    overflow_artifact = Artifact(id="tls-certificate-overflow", case_id="case", path=str(overflow), logical_name=overflow.name, sha256=hashlib.sha256(overflow_raw).hexdigest(), size=len(overflow_raw))
    overflow_values = {item.key: item.value for item in PcapObservationEngine().analyze(overflow_artifact, overflow)}
    assert overflow_values["pcap.tls.certificate_errors"][0]["error"] == "TLS Certificate continuation exceeded its declared TLS record length"
    assert overflow_values["pcap.tls.certificate_errors"][0]["packet_indices"] == [1, 2]


def test_tls_client_server_hello_alpn_negotiation_is_correlated_by_inverse_flow(tmp_path: Path) -> None:
    client = _tls_client_hello(server_name="negotiated.ctf", alpn=["h2", "http/1.1"])
    server = _tls_server_hello(selected_alpn="h2")
    evidence = tmp_path / "tls-negotiation.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(client, sequence=100, source_port=44444, destination_port=443),
        _tcp_packet(server, sequence=200, source_port=443, destination_port=44444, source_ip=b"\x0a\x00\x00\x02", destination_ip=b"\x0a\x00\x00\x01"),
    ]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-negotiation", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.negotiations"] == [{
        "client_hello_packet_indices": [1], "server_hello_packet_index": 2, "server_name": "negotiated.ctf",
        "offered_alpn": ["h2", "http/1.1"], "selected_alpn": "h2", "selected_alpn_offered": True,
        "cipher_suite": "0x1301",
    }]


def test_tls_negotiation_marks_unoffered_selected_alpn_with_packet_provenance(tmp_path: Path) -> None:
    client = _tls_client_hello(server_name="mismatch.ctf", alpn=["h2"])
    server = _tls_server_hello(selected_alpn="http/1.1")
    evidence = tmp_path / "tls-negotiation-mismatch.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(client, sequence=100, source_port=44444, destination_port=443),
        _tcp_packet(server, sequence=200, source_port=443, destination_port=44444, source_ip=b"\x0a\x00\x00\x02", destination_ip=b"\x0a\x00\x00\x01"),
    ]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-negotiation-mismatch", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.negotiations"] == [{
        "client_hello_packet_indices": [1], "server_hello_packet_index": 2, "server_name": "mismatch.ctf",
        "offered_alpn": ["h2"], "selected_alpn": "http/1.1", "selected_alpn_offered": False,
        "cipher_suite": "0x1301",
    }]


def test_tls_server_hello_parse_error_keeps_packet_provenance(tmp_path: Path) -> None:
    malformed = b"\x16\x03\x03\x00\x04\x02\x00\x00\x00"
    evidence = tmp_path / "tls-server-malformed.pcap"
    evidence.write_bytes(_pcap([_tcp_packet(malformed, sequence=100, source_port=443, destination_port=44444)]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-server-error", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.server_hellos"] == []
    assert values["pcap.tls.server_hello_errors"] == [{
        "packet_index": 1, "source": "10.0.0.1", "destination": "10.0.0.2", "source_port": 443,
        "destination_port": 44444, "packet_indices": [1], "captured_length": len(malformed), "expected_length": len(malformed), "incomplete": False,
        "error": "TLS ServerHello record or extension bounds did not validate",
    }]


def test_tls_server_hello_incomplete_record_keeps_declared_length_provenance(tmp_path: Path) -> None:
    incomplete = b"\x16\x03\x03\x00\x20\x02\x00\x00\x1c\x03\x03"
    evidence = tmp_path / "tls-server-incomplete.pcap"
    evidence.write_bytes(_pcap([_tcp_packet(incomplete, sequence=100, source_port=443, destination_port=44444)]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-server-incomplete", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.server_hello_errors"] == []
    assert values["pcap.tls.server_hello_incomplete_flows"] == [{
        "source": "10.0.0.1", "source_port": 443, "destination": "10.0.0.2", "destination_port": 44444,
        "packet_indices": [1], "captured_length": len(incomplete), "expected_length": 37,
    }]


def test_tls_server_hello_split_across_in_order_tcp_segments_is_reassembled(tmp_path: Path) -> None:
    hello = _tls_server_hello(selected_alpn="h2")
    split = 19
    evidence = tmp_path / "tls-server-split.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(hello[:split], sequence=100, source_port=443, destination_port=44444),
        _tcp_packet(hello[split:], sequence=100 + split, source_port=443, destination_port=44444),
    ]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-server-split", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.server_hello_errors"] == []
    assert values["pcap.tls.server_hellos"][0]["selected_alpn"] == "h2"
    assert values["pcap.tls.server_hellos"][0]["packet_indices"] == [1, 2]


def test_tls_server_hello_out_of_order_continuation_keeps_bounded_error_provenance(tmp_path: Path) -> None:
    hello = _tls_server_hello(selected_alpn="h2")
    split = 19
    evidence = tmp_path / "tls-server-gap.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(hello[:split], sequence=100, source_port=443, destination_port=44444),
        _tcp_packet(hello[split:], sequence=100 + split + 1, source_port=443, destination_port=44444),
    ]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-server-gap", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.server_hellos"] == []
    assert values["pcap.tls.server_hello_errors"] == [{
        "packet_index": 2, "source": "10.0.0.1", "destination": "10.0.0.2", "source_port": 443,
        "destination_port": 44444, "packet_indices": [1], "captured_length": split,
        "expected_length": len(hello), "incomplete": False,
        "error": "TLS ServerHello continuation was out of order or had a TCP sequence gap",
    }]


def test_tls_server_hello_exact_retransmission_does_not_duplicate_or_abort_state(tmp_path: Path) -> None:
    hello = _tls_server_hello(selected_alpn="h2")
    first_split = 19
    second_split = 35
    evidence = tmp_path / "tls-server-retransmit.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(hello[:first_split], sequence=100, source_port=443, destination_port=44444),
        _tcp_packet(hello[first_split:second_split], sequence=100 + first_split, source_port=443, destination_port=44444),
        _tcp_packet(hello[first_split:second_split], sequence=100 + first_split, source_port=443, destination_port=44444),
        _tcp_packet(hello[second_split:], sequence=100 + second_split, source_port=443, destination_port=44444),
    ]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-server-retransmit", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.server_hello_errors"] == []
    assert values["pcap.tls.server_hellos"][0]["selected_alpn"] == "h2"
    assert values["pcap.tls.server_hellos"][0]["packet_indices"] == [1, 2, 4]


def test_tls_client_hello_split_across_in_order_tcp_segments_is_reassembled(tmp_path: Path) -> None:
    hello = _tls_client_hello(server_name="split.ctf.example", alpn=["h2"])
    split = 18
    evidence = tmp_path / "tls-split.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(hello[:split], sequence=100, source_port=44444, destination_port=443),
        _tcp_packet(hello[split:], sequence=100 + split, source_port=44444, destination_port=443),
    ]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-split", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.client_hello_errors"] == []
    assert values["pcap.tls.client_hellos"][0]["server_name"] == "split.ctf.example"
    assert values["pcap.tls.client_hellos"][0]["packet_indices"] == [1, 2]


def test_tls_client_hello_incomplete_flow_is_reported_at_capture_end(tmp_path: Path) -> None:
    hello = _tls_client_hello(server_name="incomplete.ctf", alpn=["h2"])
    evidence = tmp_path / "tls-incomplete.pcap"
    evidence.write_bytes(_pcap([_tcp_packet(hello[:18], sequence=100, source_port=44444, destination_port=443)]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-incomplete", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.client_hello_incomplete_flows"] == [{
        "source": "10.0.0.1", "source_port": 44444, "destination": "10.0.0.2", "destination_port": 443,
        "packet_indices": [1], "captured_length": 18, "expected_length": len(hello),
    }]


def test_tls_client_hello_out_of_order_continuation_is_not_reassembled(tmp_path: Path) -> None:
    hello = _tls_client_hello(server_name="gap.ctf", alpn=["h2"])
    split = 18
    evidence = tmp_path / "tls-gap.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(hello[:split], sequence=100, source_port=44444, destination_port=443),
        _tcp_packet(hello[split:], sequence=101 + split, source_port=44444, destination_port=443),
    ]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-gap", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.client_hellos"] == []
    assert values["pcap.tls.client_hello_errors"][0]["error"] == "TLS ClientHello continuation was out of order or had a TCP sequence gap"


def test_tls_client_hello_exact_retransmission_does_not_duplicate_or_abort_state(tmp_path: Path) -> None:
    hello = _tls_client_hello(server_name="retransmit.ctf", alpn=["h2"])
    split = 18
    evidence = tmp_path / "tls-retransmit.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(hello[:split], sequence=100, source_port=44444, destination_port=443),
        _tcp_packet(hello[:split], sequence=100, source_port=44444, destination_port=443),
        _tcp_packet(hello[split:], sequence=100 + split, source_port=44444, destination_port=443),
    ]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-retransmit", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.client_hello_errors"] == []
    assert values["pcap.tls.client_hellos"][0]["server_name"] == "retransmit.ctf"
    assert values["pcap.tls.client_hellos"][0]["packet_indices"] == [1, 3]


def test_tls_client_hello_overlong_continuation_records_declared_length_detail(tmp_path: Path) -> None:
    hello = _tls_client_hello(server_name="overlong.ctf", alpn=["h2"])
    split = 18
    evidence = tmp_path / "tls-overlong.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(hello[:split], sequence=100, source_port=44444, destination_port=443),
        _tcp_packet(hello[split:] + b"x", sequence=100 + split, source_port=44444, destination_port=443),
    ]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-overlong", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.client_hellos"] == []
    assert values["pcap.tls.client_hello_errors"] == [{
        "packet_index": 2, "source": "10.0.0.1", "destination": "10.0.0.2", "source_port": 44444,
        "destination_port": 443, "packet_indices": [1, 2], "captured_length": len(hello) + 1,
        "expected_length": len(hello), "error": "TLS ClientHello continuation exceeded its declared TLS record length",
    }]


def test_tls_client_hello_parse_error_keeps_packet_provenance(tmp_path: Path) -> None:
    malformed = b"\x16\x03\x01\x00\x04\x01\x00\x00\x00"
    evidence = tmp_path / "tls-malformed.pcap"
    evidence.write_bytes(_pcap([_tcp_packet(malformed, sequence=100, source_port=44444, destination_port=443)]))
    raw = evidence.read_bytes()
    artifact = Artifact(id="tls-error", case_id="case", path=str(evidence), logical_name=evidence.name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.tls.client_hellos"] == []
    assert values["pcap.tls.client_hello_errors"] == [{
        "packet_index": 1, "source": "10.0.0.1", "destination": "10.0.0.2",
        "source_port": 44444, "destination_port": 443,
        "error": "TLS ClientHello record or extension bounds did not validate",
    }]


def test_recovers_when_the_first_two_tcp_segments_arrive_out_of_order(tmp_path: Path) -> None:
    body = b"out-of-order-body"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    split = 19
    evidence = tmp_path / "reordered.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(response[split:], sequence=7000 + split),
        _tcp_packet(response[:split], sequence=7000),
    ]))

    assert list(iter_http_response_bodies(evidence)) == [("http_object_0000.bin", body)]


def test_recovers_chunked_response_and_ignores_retransmission(tmp_path: Path) -> None:
    response = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n"
        b"4\r\nflag\r\n5\r\n-data\r\n0\r\n\r\n"
    )
    split = 67
    evidence = tmp_path / "chunked.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(response[:split], sequence=2000),
        _tcp_packet(response[:split], sequence=2000),
        _tcp_packet(response[split:], sequence=2000 + split),
    ]))

    assert list(iter_http_response_bodies(evidence)) == [("http_object_0000.txt", b"flag-data")]


def test_recovers_bounded_http_gzip_and_deflate_content_encoded_bodies(tmp_path: Path) -> None:
    plain_gzip = b"CTF{http_gzip_object}"
    plain_deflate = b"CTF{http_deflate_object}"
    gzip_body = gzip.compress(plain_gzip)
    deflate_body = zlib.compress(plain_deflate)
    gzip_response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\n"
        + f"Content-Length: {len(gzip_body)}\r\n\r\n".encode() + gzip_body
    )
    deflate_response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: deflate\r\n"
        + f"Content-Length: {len(deflate_body)}\r\n\r\n".encode() + deflate_body
    )
    evidence = tmp_path / "compressed-http.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(gzip_response, sequence=1000),
        _tcp_packet(deflate_response, sequence=1000 + len(gzip_response)),
    ]))

    objects = list(iter_http_response_objects(evidence))
    assert [(item.logical_name, item.body, item.content_encoding, item.decoded_content_encoding) for item in objects] == [
        ("http_object_0000.txt", plain_gzip, ("gzip",), ("gzip",)),
        ("http_object_0001.txt", plain_deflate, ("deflate",), ("deflate",)),
    ]
    assert all(item.decode_error is None for item in objects)


def test_recovers_http_multipart_response_parts_with_content_disposition(tmp_path: Path) -> None:
    boundary = b"forensickit-boundary"
    body = (
        b"--" + boundary + b"\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=one.txt\r\n\r\none\r\n"
        b"--" + boundary + b"\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=two.bin\r\n\r\ntwo\r\n"
        b"--" + boundary + b"--"
    )
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: multipart/mixed; boundary=forensickit-boundary\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
    )
    evidence = tmp_path / "multipart.pcap"
    evidence.write_bytes(_pcap([_tcp_packet(response, sequence=1000)]))

    objects = list(iter_http_response_objects(evidence))
    assert [(item.logical_name, item.body, item.multipart_part_index) for item in objects] == [
        ("one.txt", b"one", 0), ("two.bin", b"two", 1),
    ]
    assert objects[0].content_disposition == "attachment; filename=one.txt"
    assert all(item.packet_indices == (1,) and item.packet_provenance_complete for item in objects)


def test_recovers_bounded_multipart_base64_transfer_encoded_part(tmp_path: Path) -> None:
    boundary = b"base64-part"
    decoded = b"CTF{multipart_base64_part}"
    body = (
        b"--" + boundary + b"\r\nContent-Type: text/plain\r\n"
        b"Content-Disposition: attachment; filename=decoded.txt\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        + base64.encodebytes(decoded) + b"\r\n--" + boundary + b"--"
    )
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: multipart/mixed; boundary=base64-part\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
    )
    evidence = tmp_path / "multipart-base64.pcap"
    evidence.write_bytes(_pcap([_tcp_packet(response, sequence=1000)]))

    response_object = next(iter_http_response_objects(evidence))
    assert (
        response_object.logical_name, response_object.body,
        response_object.multipart_content_transfer_encoding,
        response_object.decoded_multipart_content_transfer_encoding,
        response_object.multipart_decode_error,
    ) == ("decoded.txt", decoded, "base64", "base64", None)


def test_recovers_bounded_multipart_quoted_printable_transfer_encoded_part(tmp_path: Path) -> None:
    boundary = b"quoted-printable-part"
    body = (
        b"--" + boundary + b"\r\nContent-Type: text/plain\r\n"
        b"Content-Disposition: attachment; filename=note.txt\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
        b"CTF{quoted=5Fprintable}=0A\r\n--" + boundary + b"--"
    )
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: multipart/mixed; boundary=quoted-printable-part\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
    )
    evidence = tmp_path / "multipart-quoted-printable.pcap"
    evidence.write_bytes(_pcap([_tcp_packet(response, sequence=1000)]))

    response_object = next(iter_http_response_objects(evidence))
    assert (
        response_object.body, response_object.multipart_content_transfer_encoding,
        response_object.decoded_multipart_content_transfer_encoding, response_object.multipart_decode_error,
    ) == (b"CTF{quoted_printable}\n", "quoted-printable", "quoted-printable", None)


def test_http_object_packet_provenance_excludes_retransmissions_and_isolates_responses(tmp_path: Path) -> None:
    first = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none"
    second = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo"
    split = 21
    evidence = tmp_path / "packet-provenance.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(first[:split], sequence=1000),
        _tcp_packet(first[split:], sequence=1000 + split),
        _tcp_packet(first[split:], sequence=1000 + split),
        _tcp_packet(second, sequence=1000 + len(first)),
    ]))

    objects = list(iter_http_response_objects(evidence))
    assert [(item.body, item.packet_indices, item.packet_provenance_complete) for item in objects] == [
        (b"one", (1, 2), True),
        (b"two", (4,), True),
    ]


def test_http_response_pairs_only_exact_inverse_request_flow_with_packet_provenance(tmp_path: Path) -> None:
    request = b"GET /downloads/flag.txt HTTP/1.1\r\nHost: ctf.example\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nflag"
    evidence = tmp_path / "request-response-provenance.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(request[:25], sequence=4000, source_port=41000, destination_port=80,
                    source_ip=b"\x0a\x00\x00\x02", destination_ip=b"\x0a\x00\x00\x01"),
        _tcp_packet(request[25:], sequence=4025, source_port=41000, destination_port=80,
                    source_ip=b"\x0a\x00\x00\x02", destination_ip=b"\x0a\x00\x00\x01"),
        _tcp_packet(response, sequence=8000),
    ]))

    response_object = next(iter_http_response_objects(evidence))
    assert (
        response_object.request_method, response_object.request_host, response_object.request_target,
        response_object.request_packet_indices, response_object.request_packet_provenance_complete,
    ) == ("GET", "ctf.example", "/downloads/flag.txt", (1, 2), True)

    unrelated = tmp_path / "unrelated-request.pcap"
    unrelated.write_bytes(_pcap([
        _tcp_packet(request, sequence=4000, source_port=41001, destination_port=80,
                    source_ip=b"\x0a\x00\x00\x02", destination_ip=b"\x0a\x00\x00\x01"),
        _tcp_packet(response, sequence=8000),
    ]))
    unmatched = next(iter_http_response_objects(unrelated))
    assert unmatched.request_method is None
    assert unmatched.request_packet_indices == ()


def test_recursive_engine_registers_http_multipart_parts_with_provenance(tmp_path: Path) -> None:
    boundary = b"multipart-lineage"
    encoded_flag = base64.b64encode(b"CTF{http_multipart_lineage}")
    body = (
        b"--" + boundary + b"\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=note.txt\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n" + encoded_flag + b"\r\n"
        b"--" + boundary + b"\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=unused.bin\r\n\r\nignored\r\n"
        b"--" + boundary + b"--"
    )
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: multipart/mixed; boundary=\"multipart-lineage\"\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
    )
    evidence = tmp_path / "multipart-lineage.pcap"
    request = b"GET /evidence HTTP/1.1\r\nHost: ctf.example\r\n\r\n"
    evidence.write_bytes(_pcap([
        _tcp_packet(request, sequence=4000, source_port=41000, destination_port=80,
                    source_ip=b"\x0a\x00\x00\x02", destination_ip=b"\x0a\x00\x00\x01"),
        _tcp_packet(response, sequence=6000),
    ]))

    result = AnalysisEngine(ForensicKitConfig()).analyze(
        evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False
    )

    assert [artifact.logical_name for artifact in result.artifacts] == [
        "multipart-lineage.pcap", "note.txt", "unused.bin",
    ]
    assert any(flag.value == "CTF{http_multipart_lineage}" for flag in result.flags)
    multipart_findings = [item for item in result.findings if item.category == "pcap_http_multipart_extraction"]
    assert len(multipart_findings) == 2
    assert any("logical_name=note.txt" in item.supporting_evidence for item in multipart_findings)
    assert all("flow=10.0.0.1:80->10.0.0.2:41000" in item.supporting_evidence for item in multipart_findings)
    assert all("packet_indices=2" in item.supporting_evidence for item in multipart_findings)
    assert all("request_method=GET" in item.supporting_evidence for item in multipart_findings)
    assert all("request_host=ctf.example" in item.supporting_evidence for item in multipart_findings)
    assert all("request_target=/evidence" in item.supporting_evidence for item in multipart_findings)
    assert all("request_packet_indices=1" in item.supporting_evidence for item in multipart_findings)
    note_finding = next(item for item in multipart_findings if "logical_name=note.txt" in item.supporting_evidence)
    assert "content_transfer_encoding=base64" in note_finding.supporting_evidence
    assert "decoded_content_transfer_encoding=base64" in note_finding.supporting_evidence


def test_recursive_engine_preserves_http_content_decoding_child_provenance(tmp_path: Path) -> None:
    decoded = base64.b64encode(b"CTF{http_gzip_lineage}")
    encoded = gzip.compress(decoded)
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\n"
        b"Content-Disposition: attachment; filename=decoded.txt\r\n"
        + f"Content-Length: {len(encoded)}\r\n\r\n".encode() + encoded
    )
    evidence = tmp_path / "http-gzip-lineage.pcap"
    evidence.write_bytes(_pcap([_tcp_packet(response, sequence=4000)]))

    result = AnalysisEngine(ForensicKitConfig()).analyze(
        evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False
    )

    assert [artifact.logical_name for artifact in result.artifacts] == ["http-gzip-lineage.pcap", "decoded.txt"]
    assert any(flag.value == "CTF{http_gzip_lineage}" for flag in result.flags)
    finding = next(item for item in result.findings if item.category == "pcap_http_content_decoding")
    assert "content_encoding=gzip" in finding.supporting_evidence
    assert any(item.startswith("child_artifact_id=") for item in finding.supporting_evidence)


def test_recursive_engine_chain_recovers_split_http_zip_and_flag(tmp_path: Path) -> None:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("flag.txt", "CTF{split_pcap_zip}")
    body = archive.getvalue()
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\n"
        b"Content-Disposition: attachment; filename=payload.zip\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode()
        + body
    )
    evidence = tmp_path / "network.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(response[:55], sequence=3000),
        _tcp_packet(response[55:200], sequence=3055),
        _tcp_packet(response[200:], sequence=3200),
    ]))

    result = AnalysisEngine(ForensicKitConfig()).analyze(
        evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False
    )

    assert [artifact.logical_name for artifact in result.artifacts] == ["network.pcap", "payload.zip", "flag.txt"]
    assert any(flag.value == "CTF{split_pcap_zip}" for flag in result.flags)


def test_recovers_http_object_from_pcapng_tcp_segments(tmp_path: Path) -> None:
    body = b"CTF{pcapng_object}"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    evidence = tmp_path / "split.pcapng"
    evidence.write_bytes(_pcapng([
        _tcp_packet(response[:22], sequence=4000),
        _tcp_packet(response[22:], sequence=4022),
    ]))

    assert list(iter_http_response_bodies(evidence)) == [("http_object_0000.bin", body)]


def test_ipv6_dns_is_observed_without_external_tshark(tmp_path: Path) -> None:
    evidence = tmp_path / "ipv6.pcap"
    evidence.write_bytes(_pcap([_ipv6_udp_dns_packet("flag.example")]))
    data = evidence.read_bytes()
    artifact = Artifact(
        id="ipv6", case_id="case", path=str(evidence), logical_name=evidence.name,
        sha256=hashlib.sha256(data).hexdigest(), size=len(data),
    )

    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.protocol_counts"]["ipv6"] == 1
    assert values["pcap.protocol_counts"]["udp"] == 1
    assert values["pcap.protocol_counts"]["dns"] == 1
    assert values["pcap.dns.queries"] == ["flag.example"]
    assert "2001:db8::1" in values["pcap.endpoints"]


def test_recovers_ipv6_http_response_split_across_tcp_segments(tmp_path: Path) -> None:
    body = b"CTF{ipv6_http_object}"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    evidence = tmp_path / "ipv6-http.pcap"
    evidence.write_bytes(_pcap([
        _ipv6_tcp_packet(response[:20], sequence=100),
        _ipv6_tcp_packet(response[20:], sequence=120),
    ]))

    assert list(iter_http_response_bodies(evidence)) == [("http_object_0000.bin", body)]


def test_ipv6_dns_txt_response_is_a_deterministic_lead(tmp_path: Path) -> None:
    question = b"\x04flag\x07example\x00\x00\x10\x00\x01"
    txt = b"CTF{dns_txt}"
    rdata = bytes((len(txt),)) + txt
    answer = b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c" + len(rdata).to_bytes(2, "big") + rdata
    dns = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + answer
    evidence = tmp_path / "dns-txt.pcap"
    evidence.write_bytes(_pcap([_ipv6_udp_packet(dns, source_port=53, destination_port=53000)]))
    data = evidence.read_bytes()
    artifact = Artifact(
        id="dns-txt", case_id="case", path=str(evidence), logical_name=evidence.name,
        sha256=hashlib.sha256(data).hexdigest(), size=len(data),
    )

    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.dns.txt_records"] == [{"text": "CTF{dns_txt}"}]


def test_dns_txt_base64_fragments_are_reassembled_with_packet_provenance(tmp_path: Path) -> None:
    question = b"\x04flag\x07example\x00\x00\x10\x00\x01"
    encoded = base64.b64encode(b"CTF{dns_txt_fragments}").decode()

    def response(text: str) -> bytes:
        rdata = bytes((len(text),)) + text.encode()
        answer = b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c" + len(rdata).to_bytes(2, "big") + rdata
        return b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + answer

    evidence = tmp_path / "dns-fragments.pcap"
    evidence.write_bytes(_pcap([
        _ipv6_udp_packet(response(encoded[:12]), source_port=53, destination_port=53000),
        _ipv6_udp_packet(response(encoded[12:]), source_port=53, destination_port=53000),
    ]))
    data = evidence.read_bytes()
    artifact = Artifact(id="dns-fragments", case_id="case", path=str(evidence), logical_name=evidence.name,
                        sha256=hashlib.sha256(data).hexdigest(), size=len(data))

    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}

    assert values["pcap.dns.txt_reassemblies"] == [{
        "source": "2001:db8::53", "destination": "2001:db8::1", "packet_indices": [1, 2],
        "fragment_count": 2, "text": encoded, "transform": "base64", "decoded_text": "CTF{dns_txt_fragments}",
    }]
    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)
    candidate = next(item for item in result.flags if item.value == "CTF{dns_txt_fragments}")
    assert candidate.source == "dns_txt_fragment_flag_hunter"
    assert candidate.transform_chain[:2] == ["dns_txt_fragment_reassembly", "base64"]
    assert "packets [1, 2]" in (candidate.location or "")


def test_dns_txt_retransmission_does_not_duplicate_reconstruction(tmp_path: Path) -> None:
    encoded = base64.b64encode(b"CTF{dns_txt_retransmission}").decode()
    question = b"\x04flag\x07example\x00\x00\x10\x00\x01"
    def response(text: str) -> bytes:
        rdata = bytes((len(text),)) + text.encode()
        answer = b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c" + len(rdata).to_bytes(2, "big") + rdata
        return b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + answer
    evidence = tmp_path / "dns-txt-retransmit.pcap"
    evidence.write_bytes(_pcap([
        _ipv6_udp_packet(response(encoded[:16]), source_port=53, destination_port=53000),
        _ipv6_udp_packet(response(encoded[:16]), source_port=53, destination_port=53000),
        _ipv6_udp_packet(response(encoded[16:]), source_port=53, destination_port=53000),
    ]))
    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)
    candidate = next(item for item in result.flags if item.value == "CTF{dns_txt_retransmission}")
    assert candidate.transform_chain[:2] == ["dns_txt_fragment_reassembly", "base64"]
    assert "packets [1, 3]" in (candidate.location or "")


def test_dns_query_label_fragments_reconstruct_to_flag(tmp_path: Path) -> None:
    encoded = base64.b64encode(b"CTF{dns_labels}").decode()
    evidence = tmp_path / "dns-labels.pcap"
    evidence.write_bytes(_pcap([_ipv6_udp_dns_packet(f"{encoded[:8]}.ctf.test"), _ipv6_udp_dns_packet(f"{encoded[8:]}.ctf.test")]))
    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)
    candidate = next(item for item in result.flags if item.value == "CTF{dns_labels}")
    assert candidate.transform_chain[:2] == ["dns_label_fragment_reassembly", "base64"]
    assert "packets [1, 2]" in (candidate.location or "")


def test_dns_query_label_retransmission_does_not_duplicate_reconstruction(tmp_path: Path) -> None:
    encoded = base64.b64encode(b"CTF{dns_label_retransmission}").decode()
    evidence = tmp_path / "dns-label-retransmit.pcap"
    evidence.write_bytes(_pcap([
        _ipv6_udp_dns_packet(f"{encoded[:16]}.ctf.test"),
        _ipv6_udp_dns_packet(f"{encoded[:16]}.ctf.test"),
        _ipv6_udp_dns_packet(f"{encoded[16:]}.ctf.test"),
    ]))
    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)
    candidate = next(item for item in result.flags if item.value == "CTF{dns_label_retransmission}")
    assert candidate.transform_chain[:2] == ["dns_label_fragment_reassembly", "base64"]
    assert "packets [1, 3]" in (candidate.location or "")


def test_dns_query_hex_labels_reconstruct_to_flag(tmp_path: Path) -> None:
    encoded = b"CTF{dns_hex_labels}".hex()
    evidence = tmp_path / "dns-hex-labels.pcap"
    evidence.write_bytes(_pcap([_ipv6_udp_dns_packet(f"{encoded[:12]}.ctf.test"), _ipv6_udp_dns_packet(f"{encoded[12:]}.ctf.test")]))
    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)
    candidate = next(item for item in result.flags if item.value == "CTF{dns_hex_labels}")
    assert candidate.transform_chain[:2] == ["dns_label_fragment_reassembly", "hex"]


def test_printable_non_dns_udp_payload_retains_packet_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "udp.pcap"
    evidence.write_bytes(_pcap([_ipv6_udp_packet(b"CTF{udp_payload}", source_port=4444, destination_port=5555)]))
    data = evidence.read_bytes()
    artifact = Artifact(id="udp", case_id="case", path=str(evidence), logical_name=evidence.name,
                        sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}
    assert values["pcap.udp.printable_payloads"] == [{
        "packet_index": 1, "source": "2001:db8::53", "destination": "2001:db8::1", "source_port": 4444,
        "destination_port": 5555, "length": len(b"CTF{udp_payload}"), "text": "CTF{udp_payload}",
    }]
    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)
    assert any(item.category == "pcap_udp_payload_lead" for item in result.findings)


def test_printable_icmp_payload_retains_packet_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "icmp.pcap"
    evidence.write_bytes(_pcap([_ipv6_icmp_packet(b"CTF{icmp_payload}")]))
    data = evidence.read_bytes()
    artifact = Artifact(id="icmp", case_id="case", path=str(evidence), logical_name=evidence.name,
                        sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}
    assert values["pcap.icmp.printable_payloads"] == [{
        "packet_index": 1, "protocol": "icmpv6", "source": "2001:db8::1", "destination": "2001:db8::2",
        "type": 128, "code": 0, "length": len(b"CTF{icmp_payload}"), "text": "CTF{icmp_payload}",
    }]
    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)
    assert any(item.category == "pcap_icmp_payload_lead" for item in result.findings)


def test_printable_non_http_tcp_payload_retains_packet_provenance(tmp_path: Path) -> None:
    evidence = tmp_path / "tcp.pcap"
    evidence.write_bytes(_pcap([_ipv6_tcp_packet(b"CTF{tcp_payload}", sequence=99)]))
    data = evidence.read_bytes()
    artifact = Artifact(id="tcp", case_id="case", path=str(evidence), logical_name=evidence.name,
                        sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}
    assert values["pcap.tcp.printable_payloads"] == [{
        "packet_index": 1, "source": "2001:db8::80", "destination": "2001:db8::1", "source_port": 80,
        "destination_port": 41000, "length": len(b"CTF{tcp_payload}"), "text": "CTF{tcp_payload}",
    }]
    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)
    assert any(item.category == "pcap_tcp_payload_lead" for item in result.findings)
    summary = next(item.value for item in result.observations if item.key == "pcap.printable_payload_leads")
    assert summary == [{
        "protocol": "tcp", "packet_index": 1, "source": "2001:db8::80", "destination": "2001:db8::1",
        "source_port": 80, "destination_port": 41000, "length": len(b"CTF{tcp_payload}"), "text": "CTF{tcp_payload}",
    }]
    report = next((tmp_path / "cases").glob("*/reports/report.json")).read_text(encoding="utf-8")
    assert "pcap.printable_payload_leads" in report and "CTF{tcp_payload}" in report
    assert "pcap_payload_flag_hunter" in report and "tcp packet 1" in report
    candidate = next(item for item in result.flags if item.value == "CTF{tcp_payload}" and item.source == "pcap_payload_flag_hunter")
    assert candidate.transform_chain == ["raw"]
    assert "tcp packet 1" in (candidate.location or "")


def test_http_continuation_is_not_inventoried_as_non_http_tcp_payload(tmp_path: Path) -> None:
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nCTF{split_http}"
    evidence = tmp_path / "http-continuation.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(response[:35], sequence=100),
        _tcp_packet(response[35:], sequence=135),
    ]))
    data = evidence.read_bytes()
    artifact = Artifact(id="http-continuation", case_id="case", path=str(evidence), logical_name=evidence.name,
                        sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}
    assert values["pcap.tcp.printable_payloads"] == []


def test_out_of_order_http_continuation_is_removed_from_tcp_payload_inventory(tmp_path: Path) -> None:
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nCTF{split_http}"
    split = 35
    evidence = tmp_path / "http-out-of-order.pcap"
    evidence.write_bytes(_pcap([
        _tcp_packet(response[split:], sequence=100 + split),
        _tcp_packet(response[:split], sequence=100),
    ]))
    data = evidence.read_bytes()
    artifact = Artifact(id="http-out-of-order", case_id="case", path=str(evidence), logical_name=evidence.name,
                        sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}
    assert values["pcap.tcp.printable_payloads"] == []


def test_http_flow_state_tracking_is_bounded() -> None:
    stats = _PcapStats()
    engine = PcapObservationEngine()
    payload = b"GET / HTTP/1.1\r\n\r\n"
    tcp = struct.pack("!HHII", 1000, 80, 1, 0) + b"\x50\x18\x00\x00\x00\x00\x00\x00" + payload
    for index in range(4097):
        stats.packets = index + 1
        engine._decode_tcp(tcp, f"10.0.0.{index // 256}", f"192.0.2.{index % 256}", stats)
    assert len(stats.http_flows) == 4096
    assert stats.http_flow_state_truncated is True


def test_duplicate_pcap_payload_observation_does_not_duplicate_same_packet_candidate(tmp_path: Path) -> None:
    artifact = Artifact(id="payload-dedupe", case_id="case", path="unused", logical_name="capture.pcap", sha256="0" * 64, size=0)
    payload = [{"packet_index": 7, "source": "a", "destination": "b", "text": "CTF{dedupe}"}]
    observations = [
        Observation(artifact.id, "pcap.tcp.printable_payloads", payload, "test"),
        Observation(artifact.id, "pcap.tcp.printable_payloads", payload, "test"),
    ]
    candidates = AnalysisEngine()._scan_printable_pcap_payload_flags(artifact, observations)
    assert len(candidates) == 1
    assert candidates[0].value == "CTF{dedupe}"
    assert (candidates[0].location or "").startswith("tcp packet 7 a->b")


def test_dns_txt_response_retains_exact_matching_request_packet(tmp_path: Path) -> None:
    question = b"\x04flag\x07example\x00\x00\x10\x00\x01"
    request = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    text = b"fragment"
    rdata = bytes((len(text),)) + text
    answer = b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c" + len(rdata).to_bytes(2, "big") + rdata
    response = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + answer
    evidence = tmp_path / "dns-transaction.pcap"
    request_packet = bytearray(_ipv6_udp_packet(request, source_port=53000, destination_port=53))
    request_packet[22:38] = ipaddress.IPv6Address("2001:db8::1").packed
    request_packet[38:54] = ipaddress.IPv6Address("2001:db8::53").packed
    evidence.write_bytes(_pcap([bytes(request_packet), _ipv6_udp_packet(response, source_port=53, destination_port=53000)]))
    data = evidence.read_bytes()
    artifact = Artifact(id="dns-transaction", case_id="case", path=str(evidence), logical_name=evidence.name,
                        sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}
    assert values["pcap.dns.txt_fragments"] == [{
        "text": "fragment", "packet_index": 2, "source": "2001:db8::53", "destination": "2001:db8::1",
        "transaction_id": 0x1234, "request_packet_index": 1,
    }]
    assert values["pcap.dns.transaction_matches"] == [{
        "transaction_id": 0x1234, "request_packet_index": 1, "response_packet_index": 2,
        "client": "2001:db8::1", "server": "2001:db8::53",
    }]
    result = AnalysisEngine().analyze(evidence, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False)
    assert any(item.key == "pcap.dns.transaction_matches" for item in result.observations)
    assert any(item.category == "pcap_dns_transaction_inventory" for item in result.findings)
    report = next((tmp_path / "cases").glob("*/reports/report.json")).read_text(encoding="utf-8")
    assert "pcap.dns.transaction_matches" in report and "request_packet_index" in report


def test_dns_txt_fragments_do_not_cross_transaction_ids(tmp_path: Path) -> None:
    question = b"\x04flag\x07example\x00\x00\x10\x00\x01"
    def response(transaction_id: int, text: bytes) -> bytes:
        rdata = bytes((len(text),)) + text
        answer = b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c" + len(rdata).to_bytes(2, "big") + rdata
        return transaction_id.to_bytes(2, "big") + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + answer
    evidence = tmp_path / "dns-isolation.pcap"
    evidence.write_bytes(_pcap([
        _ipv6_udp_packet(response(1, b"Q1RGe2Ei"), source_port=53, destination_port=53000),
        _ipv6_udp_packet(response(2, b"Yl9taXh9"), source_port=53, destination_port=53000),
    ]))
    data = evidence.read_bytes()
    artifact = Artifact(id="dns-isolation", case_id="case", path=str(evidence), logical_name=evidence.name,
                        sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}
    assert values["pcap.dns.txt_reassemblies"] == []


def test_dns_txt_reassembly_carries_request_packet_provenance() -> None:
    results = _reassemble_dns_txt_fragments([
        {"text": "Q1RGe3Jl", "packet_index": 8, "request_packet_index": 4, "transaction_id": 7, "source": "server", "destination": "client"},
        {"text": "cXVlc3R9", "packet_index": 8, "request_packet_index": 4, "transaction_id": 7, "source": "server", "destination": "client"},
    ])
    assert results[0]["request_packet_indices"] == [4]


def test_dns_transaction_id_expires_after_bounded_packet_window(tmp_path: Path) -> None:
    question = b"\x04flag\x07example\x00\x00\x10\x00\x01"
    request = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    text = b"stale"
    rdata = bytes((len(text),)) + text
    answer = b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c" + len(rdata).to_bytes(2, "big") + rdata
    response = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + answer
    request_packet = bytearray(_ipv6_udp_packet(request, source_port=53000, destination_port=53))
    request_packet[22:38] = ipaddress.IPv6Address("2001:db8::1").packed
    request_packet[38:54] = ipaddress.IPv6Address("2001:db8::53").packed
    evidence = tmp_path / "dns-expired.pcap"
    evidence.write_bytes(_pcap([bytes(request_packet), *([b"\x00" * 14] * 4096), _ipv6_udp_packet(response, source_port=53, destination_port=53000)]))
    data = evidence.read_bytes()
    artifact = Artifact(id="dns-expired", case_id="case", path=str(evidence), logical_name=evidence.name,
                        sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    values = {item.key: item.value for item in PcapObservationEngine().analyze(artifact, evidence)}
    assert values["pcap.dns.txt_fragments"][0]["request_packet_index"] is None
