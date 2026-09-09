from __future__ import annotations

import binascii
import hashlib
from pathlib import Path

from .models import Artifact, Observation


_VRS_BLOCK_SIZE = 2_048
_VRS_START_SECTOR = 16
_VRS_DESCRIPTOR_LIMIT = 16
_VDS_DESCRIPTOR_LIMIT = 256
_VDS_BYTE_LIMIT = 8 * 1_024 * 1_024
_DIRECTORY_BYTE_LIMIT = 8 * 1_024 * 1_024
_DIRECTORY_ENTRY_LIMIT = 4_096
_DIRECTORY_LIMIT = 32
_ALLOCATION_DESCRIPTOR_LIMIT = 1_024
_ALLOCATION_EXTENT_LIMIT = 32
_ALLOCATION_EXTENT_GLOBAL_LIMIT = 256
_ALLOCATION_EXTENT_BYTE_LIMIT = 8 * 1_024 * 1_024
_LOGICAL_BLOCK_SIZES = (512, 1_024, 2_048, 4_096)


class UdfObservationEngine:
    """Validate bounded UDF recognition, anchor, and volume descriptors."""

    def __init__(
        self,
        *,
        max_bytes: int = _VDS_BYTE_LIMIT,
        max_descriptors: int = _VDS_DESCRIPTOR_LIMIT,
        max_directory_entries: int = _DIRECTORY_ENTRY_LIMIT,
    ) -> None:
        if (
            max_bytes <= 0
            or max_descriptors <= 0
            or max_directory_entries <= 0
        ):
            raise ValueError("UDF bounds must be positive")
        self.max_bytes = min(max_bytes, _VDS_BYTE_LIMIT)
        self.max_descriptors = min(max_descriptors, _VDS_DESCRIPTOR_LIMIT)
        self.max_directory_bytes = min(max_bytes, _DIRECTORY_BYTE_LIMIT)
        self.max_directory_entries = min(
            max_directory_entries, _DIRECTORY_ENTRY_LIMIT,
        )

    @staticmethod
    def _observation(
        artifact: Artifact,
        key: str,
        value: object,
        *,
        confidence: float = 1.0,
    ) -> Observation:
        return Observation(
            artifact_id=artifact.id,
            key=key,
            value=value,
            source="udf_triage",
            confidence=confidence,
        )

    @classmethod
    def detect(cls, path: Path, size: int) -> bool:
        """Recognize a fixed-location BEA/NSR sequence, even if later invalid."""
        return bool(cls._volume_recognition_sequence(path, size)["recognized"])

    def analyze(
        self,
        artifact: Artifact,
        path: Path,
        size: int | None = None,
    ) -> list[Observation]:
        size = path.stat().st_size if size is None else size
        vrs = self._volume_recognition_sequence(path, size)
        anchors: list[dict[str, object]] = []
        errors = list(vrs["errors"])
        active_anchor: dict[str, object] | None = None
        main_vds: dict[str, object] | None = None
        reserve_vds: dict[str, object] | None = None
        comparison: dict[str, object] = {
            "performed": False,
            "consistent": False,
            "failed_checks": ["anchor_unavailable"],
        }
        file_set: dict[str, object] | None = None
        file_set_errors: list[dict[str, object]] = []

        if vrs["valid"]:
            anchors = self._anchor_candidates(path, size)
            valid_anchors = [
                anchor for anchor in anchors if anchor.get("valid") is True
            ]
            valid_anchors.sort(
                key=lambda item: (
                    item.get("logical_sector") != 256,
                    item.get("block_size") != _VRS_BLOCK_SIZE,
                    int(item.get("offset", 0)),
                )
            )
            active_anchor = valid_anchors[0] if valid_anchors else None
            if active_anchor is None:
                errors.append({
                    "reason": "no_valid_anchor_volume_descriptor_pointer",
                    "candidates_checked": len(anchors),
                })
            else:
                block_size = int(active_anchor["block_size"])
                try:
                    with path.open("rb") as stream:
                        main_vds = self._volume_descriptor_sequence(
                            stream,
                            size,
                            active_anchor["main_volume_descriptor_sequence"],
                            block_size,
                            copy_name="main",
                        )
                        reserve_vds = self._volume_descriptor_sequence(
                            stream,
                            size,
                            active_anchor["reserve_volume_descriptor_sequence"],
                            block_size,
                            copy_name="reserve",
                        )
                except OSError as exc:
                    errors.append({
                        "reason": "volume_descriptor_sequence_read_error",
                        "error": str(exc)[:2_000],
                    })
                if main_vds is not None and reserve_vds is not None:
                    comparison = self._compare_volume_descriptor_sequences(
                        main_vds, reserve_vds,
                    )
                    if comparison["consistent"] is not True:
                        errors.append({
                            "reason": "main_reserve_volume_descriptor_mismatch",
                            "failed_checks": comparison["failed_checks"],
                        })
                if main_vds is not None and main_vds.get("valid") is not True:
                    errors.extend(main_vds.get("errors", []))
                if reserve_vds is not None and reserve_vds.get("valid") is not True:
                    errors.extend(reserve_vds.get("errors", []))

                volume_valid = bool(
                    main_vds is not None
                    and main_vds.get("valid") is True
                    and reserve_vds is not None
                    and reserve_vds.get("valid") is True
                    and comparison.get("consistent") is True
                    and not errors
                )
                if volume_valid:
                    try:
                        with path.open("rb") as stream:
                            file_set = self._file_set_metadata(
                                stream, size, main_vds, block_size,
                            )
                    except OSError as exc:
                        file_set_errors.append({
                            "reason": "file_set_read_error",
                            "error": str(exc)[:2_000],
                        })
                    if file_set is not None:
                        file_set_errors.extend(file_set.get("errors", []))
                    if file_set_errors:
                        errors.extend(file_set_errors)

        valid = bool(
            vrs["valid"]
            and active_anchor is not None
            and main_vds is not None
            and main_vds.get("valid") is True
            and reserve_vds is not None
            and reserve_vds.get("valid") is True
            and comparison.get("consistent") is True
            and file_set is not None
            and file_set.get("valid") is True
            and not errors
        )
        revision = vrs.get("namespace_identifier")
        return [
            self._observation(artifact, "archive.udf.detected", bool(vrs["recognized"])),
            self._observation(artifact, "archive.udf.revision_identifier", revision),
            self._observation(artifact, "archive.udf.volume_recognition_sequence", vrs),
            self._observation(artifact, "archive.udf.anchor_candidates", anchors),
            self._observation(artifact, "archive.udf.active_anchor", active_anchor),
            self._observation(artifact, "archive.udf.main_volume_descriptor_sequence", main_vds),
            self._observation(artifact, "archive.udf.reserve_volume_descriptor_sequence", reserve_vds),
            self._observation(artifact, "archive.udf.volume_descriptor_comparison", comparison),
            self._observation(artifact, "archive.udf.file_set", file_set),
            self._observation(artifact, "archive.udf.file_set_errors", file_set_errors),
            self._observation(artifact, "archive.udf.errors", errors),
            self._observation(artifact, "archive.udf.valid", valid),
        ]

    @staticmethod
    def _volume_recognition_sequence(
        path: Path,
        size: int,
    ) -> dict[str, object]:
        records: list[dict[str, object]] = []
        errors: list[dict[str, object]] = []
        begin_index: int | None = None
        namespace_index: int | None = None
        terminator_index: int | None = None
        namespace_identifier: str | None = None
        bytes_read = 0
        try:
            with path.open("rb") as stream:
                for index in range(_VRS_DESCRIPTOR_LIMIT):
                    sector = _VRS_START_SECTOR + index
                    offset = sector * _VRS_BLOCK_SIZE
                    if offset + _VRS_BLOCK_SIZE > size:
                        break
                    stream.seek(offset)
                    raw = stream.read(_VRS_BLOCK_SIZE)
                    bytes_read += len(raw)
                    if len(raw) != _VRS_BLOCK_SIZE:
                        errors.append({
                            "reason": "truncated_volume_structure_descriptor",
                            "sector": sector,
                            "offset": offset,
                        })
                        break
                    identifier_raw = raw[1:6]
                    identifier = identifier_raw.decode("ascii", errors="replace")
                    header_valid = (
                        raw[0] == 0
                        and raw[6] == 1
                        and (
                            identifier not in {"NSR02", "NSR03"}
                            or raw[7] == 0
                        )
                    )
                    record = {
                        "index": index,
                        "sector": sector,
                        "offset": offset,
                        "structure_type": raw[0],
                        "standard_identifier": identifier,
                        "structure_version": raw[6],
                        "reserved": (
                            raw[7] if identifier in {"NSR02", "NSR03"}
                            else None
                        ),
                        "header_valid": header_valid,
                        "raw_sha256": hashlib.sha256(raw).hexdigest(),
                    }
                    records.append(record)
                    if begin_index is None:
                        if identifier == "BEA01":
                            begin_index = index
                            if not header_valid:
                                errors.append({
                                    "reason": "invalid_bea01_header",
                                    "record": record,
                                })
                        continue
                    if identifier in {"NSR02", "NSR03"}:
                        if namespace_index is not None:
                            errors.append({
                                "reason": "multiple_namespace_descriptors",
                                "record": record,
                            })
                        else:
                            namespace_index = index
                            namespace_identifier = identifier
                        if not header_valid:
                            errors.append({
                                "reason": "invalid_namespace_descriptor_header",
                                "record": record,
                            })
                    elif identifier == "BEA01":
                        errors.append({
                            "reason": "nested_begin_extended_area_descriptor",
                            "record": record,
                        })
                    elif identifier == "TEA01":
                        terminator_index = index
                        if not header_valid:
                            errors.append({
                                "reason": "invalid_tea01_header",
                                "record": record,
                            })
                        break
        except OSError as exc:
            errors.append({
                "reason": "volume_recognition_sequence_read_error",
                "error": str(exc)[:2_000],
            })

        if begin_index is None:
            errors.append({"reason": "bea01_not_found"})
        if namespace_index is None:
            errors.append({"reason": "nsr02_or_nsr03_not_found"})
        if terminator_index is None:
            errors.append({"reason": "tea01_not_found"})
        if (
            begin_index is not None
            and namespace_index is not None
            and terminator_index is not None
            and not begin_index < namespace_index < terminator_index
        ):
            errors.append({"reason": "volume_recognition_sequence_order"})
        return {
            "start_sector": _VRS_START_SECTOR,
            "descriptor_size": _VRS_BLOCK_SIZE,
            "descriptor_limit": _VRS_DESCRIPTOR_LIMIT,
            "records": records,
            "begin_index": begin_index,
            "namespace_index": namespace_index,
            "namespace_identifier": namespace_identifier,
            "terminator_index": terminator_index,
            "bytes_read": bytes_read,
            "errors": errors,
            "recognized": bool(
                begin_index is not None
                and namespace_index is not None
                and begin_index < namespace_index
            ),
            "valid": not errors,
        }

    def _anchor_candidates(
        self,
        path: Path,
        size: int,
    ) -> list[dict[str, object]]:
        candidates: list[dict[str, object]] = []
        seen: set[tuple[int, int]] = set()
        try:
            with path.open("rb") as stream:
                for block_size in _LOGICAL_BLOCK_SIZES:
                    sector_count = size // block_size
                    logical_sectors = [256]
                    if size % block_size == 0 and sector_count:
                        logical_sectors.extend(
                            (sector_count - 257, sector_count - 1)
                        )
                    for logical_sector in logical_sectors:
                        key = (block_size, logical_sector)
                        if (
                            logical_sector < 0
                            or key in seen
                            or (logical_sector + 1) * block_size > size
                        ):
                            continue
                        seen.add(key)
                        offset = logical_sector * block_size
                        stream.seek(offset)
                        raw = stream.read(block_size)
                        tag = self._descriptor_tag(raw, logical_sector)
                        main_extent = self._extent_ad(
                            raw[16:24], block_size, size,
                        )
                        reserve_extent = self._extent_ad(
                            raw[24:32], block_size, size,
                        )
                        failed_checks: list[str] = []
                        if tag["identifier"] != 2:
                            failed_checks.append("descriptor_identifier")
                        if tag["valid"] is not True:
                            failed_checks.append("descriptor_tag")
                        if tag["crc_length"] != 496:
                            failed_checks.append("descriptor_crc_coverage")
                        if any(raw[32:512]):
                            failed_checks.append("reserved_bytes")
                        if main_extent["valid"] is not True:
                            failed_checks.append("main_sequence_extent")
                        if reserve_extent["valid"] is not True:
                            failed_checks.append("reserve_sequence_extent")
                        if (
                            main_extent["valid"] is True
                            and reserve_extent["valid"] is True
                            and max(
                                int(main_extent["offset"]),
                                int(reserve_extent["offset"]),
                            ) < min(
                                int(main_extent["end_offset"]),
                                int(reserve_extent["end_offset"]),
                            )
                        ):
                            failed_checks.append("sequence_extent_overlap")
                        candidate = {
                            "block_size": block_size,
                            "logical_sector": logical_sector,
                            "offset": offset,
                            "tag": tag,
                            "main_volume_descriptor_sequence": main_extent,
                            "reserve_volume_descriptor_sequence": reserve_extent,
                            "raw_sha256": hashlib.sha256(raw).hexdigest(),
                            "failed_checks": failed_checks,
                            "valid": len(raw) == block_size and not failed_checks,
                        }
                        candidates.append(candidate)
        except OSError as exc:
            candidates.append({
                "valid": False,
                "reason": "anchor_read_error",
                "error": str(exc)[:2_000],
            })
        return candidates

    def _extent_ad(
        self,
        raw: bytes,
        block_size: int,
        size: int,
    ) -> dict[str, object]:
        if len(raw) != 8:
            return {"valid": False, "reason": "truncated_extent_ad"}
        length = int.from_bytes(raw[0:4], "little")
        location = int.from_bytes(raw[4:8], "little")
        offset = location * block_size
        end_offset = offset + length
        valid = bool(
            block_size <= length <= self.max_bytes
            and length % block_size == 0
            and offset >= 0
            and end_offset <= size
            and length // block_size <= self.max_descriptors
        )
        return {
            "raw_hex": raw.hex(),
            "raw_length": length,
            "length": length,
            "location": location,
            "offset": offset,
            "end_offset": end_offset,
            "block_count": length // block_size if block_size else None,
            "valid": valid,
        }

    @staticmethod
    def _descriptor_tag(
        raw: bytes,
        expected_location: int,
    ) -> dict[str, object]:
        if len(raw) < 16:
            return {
                "valid": False,
                "identifier": None,
                "reason": "truncated_descriptor_tag",
            }
        identifier = int.from_bytes(raw[0:2], "little")
        version = int.from_bytes(raw[2:4], "little")
        stored_checksum = raw[4]
        reserved = raw[5]
        serial_number = int.from_bytes(raw[6:8], "little")
        stored_crc = int.from_bytes(raw[8:10], "little")
        crc_length = int.from_bytes(raw[10:12], "little")
        location = int.from_bytes(raw[12:16], "little")
        calculated_checksum = (
            sum(raw[0:4]) + sum(raw[5:16])
        ) & 0xFF
        checksum_valid = calculated_checksum == stored_checksum
        crc_range_valid = crc_length <= len(raw) - 16
        calculated_crc = (
            binascii.crc_hqx(raw[16:16 + crc_length], 0)
            if crc_range_valid else None
        )
        crc_valid = bool(
            crc_range_valid and calculated_crc == stored_crc
        )
        location_valid = location == expected_location
        valid = bool(
            identifier != 0
            and version in {2, 3}
            and reserved == 0
            and checksum_valid
            and crc_valid
            and location_valid
        )
        return {
            "identifier": identifier,
            "descriptor_version": version,
            "stored_checksum": stored_checksum,
            "calculated_checksum": calculated_checksum,
            "checksum_valid": checksum_valid,
            "reserved": reserved,
            "serial_number": serial_number,
            "stored_crc": stored_crc,
            "calculated_crc": calculated_crc,
            "crc_length": crc_length,
            "crc_range_valid": crc_range_valid,
            "crc_valid": crc_valid,
            "location": location,
            "expected_location": expected_location,
            "location_valid": location_valid,
            "valid": valid,
        }

    def _volume_descriptor_sequence(
        self,
        stream,
        size: int,
        extent: object,
        block_size: int,
        *,
        copy_name: str,
    ) -> dict[str, object]:
        descriptors: list[dict[str, object]] = []
        partitions: list[dict[str, object]] = []
        logical_volumes: list[dict[str, object]] = []
        primary_volumes: list[dict[str, object]] = []
        errors: list[dict[str, object]] = []
        terminator_found = False
        bytes_read = 0
        if not isinstance(extent, dict) or extent.get("valid") is not True:
            return {
                "copy": copy_name,
                "valid": False,
                "errors": [{"reason": "invalid_sequence_extent"}],
                "descriptors": [],
            }
        start_lba = int(extent["location"])
        block_count = int(extent["block_count"])
        for index in range(block_count):
            if index >= self.max_descriptors:
                errors.append({"reason": "descriptor_count_limit"})
                break
            logical_sector = start_lba + index
            offset = logical_sector * block_size
            if offset + block_size > size:
                errors.append({
                    "reason": "descriptor_outside_evidence",
                    "logical_sector": logical_sector,
                })
                break
            stream.seek(offset)
            raw = stream.read(block_size)
            bytes_read += len(raw)
            if len(raw) != block_size:
                errors.append({
                    "reason": "truncated_volume_descriptor",
                    "logical_sector": logical_sector,
                })
                break
            if not any(raw):
                errors.append({
                    "reason": "zero_block_before_terminator",
                    "logical_sector": logical_sector,
                })
                break
            tag = self._descriptor_tag(raw, logical_sector)
            descriptor: dict[str, object] = {
                "index": index,
                "logical_sector": logical_sector,
                "offset": offset,
                "length": block_size,
                "tag": tag,
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
            }
            identifier = tag.get("identifier")
            descriptor["type"] = {
                1: "primary_volume",
                2: "anchor_volume_descriptor_pointer",
                3: "volume_descriptor_pointer",
                4: "implementation_use",
                5: "partition",
                6: "logical_volume",
                7: "unallocated_space",
                8: "terminating",
                9: "logical_volume_integrity",
            }.get(identifier, f"unknown_{identifier}")
            expected_crc_length = self._expected_descriptor_crc_length(
                raw, identifier,
            )
            descriptor["expected_crc_length"] = expected_crc_length
            descriptor["crc_coverage_valid"] = (
                expected_crc_length is not None
                and tag.get("crc_length") == expected_crc_length
            )
            crc_length = tag.get("crc_length")
            descriptor["body_sha256"] = (
                hashlib.sha256(raw[16:16 + crc_length]).hexdigest()
                if isinstance(crc_length, int)
                and not isinstance(crc_length, bool)
                and 0 <= crc_length <= len(raw) - 16
                else None
            )
            descriptors.append(descriptor)
            if tag.get("valid") is not True:
                errors.append({
                    "reason": "invalid_descriptor_tag",
                    "logical_sector": logical_sector,
                    "tag": tag,
                })
                continue
            if descriptor["crc_coverage_valid"] is not True:
                errors.append({
                    "reason": "invalid_descriptor_crc_coverage",
                    "logical_sector": logical_sector,
                    "identifier": identifier,
                    "stored_crc_length": tag.get("crc_length"),
                    "expected_crc_length": expected_crc_length,
                })
                continue
            if identifier == 1:
                parsed = self._primary_volume_descriptor(raw)
                descriptor["parsed"] = parsed
                primary_volumes.append(parsed)
                if parsed["valid"] is not True:
                    errors.append({
                        "reason": "invalid_primary_volume_descriptor",
                        "logical_sector": logical_sector,
                    })
            elif identifier == 5:
                parsed = self._partition_descriptor(raw, block_size, size)
                descriptor["parsed"] = parsed
                partitions.append(parsed)
                if parsed["valid"] is not True:
                    errors.append({
                        "reason": "invalid_partition_descriptor",
                        "logical_sector": logical_sector,
                        "failed_checks": parsed["failed_checks"],
                    })
            elif identifier == 6:
                parsed = self._logical_volume_descriptor(raw, block_size, size)
                descriptor["parsed"] = parsed
                logical_volumes.append(parsed)
                if parsed["valid"] is not True:
                    errors.append({
                        "reason": "invalid_logical_volume_descriptor",
                        "logical_sector": logical_sector,
                        "failed_checks": parsed["failed_checks"],
                    })
            elif identifier == 8:
                terminator_found = True
                break
            elif identifier not in {4, 7}:
                errors.append({
                    "reason": "unsupported_volume_descriptor_type",
                    "logical_sector": logical_sector,
                    "identifier": identifier,
                })

        partition_numbers = {
            int(item["partition_number"])
            for item in partitions
            if item.get("valid") is True
        }
        for logical_volume in logical_volumes:
            missing_partitions = sorted(
                {
                    int(item["partition_number"])
                    for item in logical_volume.get("partition_maps", [])
                    if isinstance(item, dict)
                    and isinstance(item.get("partition_number"), int)
                }
                - partition_numbers
            )
            logical_volume["missing_partition_numbers"] = missing_partitions
            if missing_partitions:
                logical_volume["valid"] = False
                logical_volume["failed_checks"].append(
                    "partition_map_reference"
                )
                errors.append({
                    "reason": "logical_volume_partition_map_unresolved",
                    "missing_partition_numbers": missing_partitions,
                })
        if not terminator_found:
            errors.append({"reason": "terminating_descriptor_not_found"})
        if not primary_volumes:
            errors.append({"reason": "primary_volume_descriptor_not_found"})
        if not partitions:
            errors.append({"reason": "partition_descriptor_not_found"})
        if not logical_volumes:
            errors.append({"reason": "logical_volume_descriptor_not_found"})
        return {
            "copy": copy_name,
            "extent": extent,
            "block_size": block_size,
            "descriptor_count": len(descriptors),
            "descriptor_limit": self.max_descriptors,
            "bytes_read": bytes_read,
            "descriptors": descriptors,
            "primary_volumes": primary_volumes,
            "partitions": partitions,
            "logical_volumes": logical_volumes,
            "terminator_found": terminator_found,
            "errors": errors,
            "valid": not errors,
        }

    @staticmethod
    def _expected_descriptor_crc_length(
        raw: bytes,
        identifier: object,
    ) -> int | None:
        if identifier in {1, 2, 3, 4, 5, 8}:
            return 496
        if identifier == 6:
            map_table_length = int.from_bytes(raw[264:268], "little")
            expected = 424 + map_table_length
            return expected if expected <= len(raw) - 16 else None
        if identifier == 7:
            allocation_descriptor_count = int.from_bytes(
                raw[20:24], "little"
            )
            expected = 8 + allocation_descriptor_count * 8
            return expected if expected <= len(raw) - 16 else None
        return None

    @staticmethod
    def _decode_dstring(raw: bytes) -> dict[str, object]:
        if not raw:
            return {"text": None, "valid": False, "reason": "empty_field"}
        used_length = raw[-1]
        if used_length == 0:
            return {
                "text": "",
                "valid": not any(raw[:-1]),
                "compression_id": None,
                "used_length": 0,
                "raw_hex": raw.hex(),
            }
        if used_length > len(raw) - 1:
            return {
                "text": None,
                "valid": False,
                "reason": "used_length_out_of_range",
                "used_length": used_length,
                "raw_hex": raw.hex(),
            }
        encoded = raw[:used_length]
        compression_id = encoded[0]
        content = encoded[1:]
        valid = not any(raw[used_length:-1])
        text: str | None = None
        try:
            if compression_id == 8:
                text = content.decode("latin-1")
            elif compression_id == 16 and len(content) % 2 == 0:
                text = content.decode("utf-16-be")
            else:
                valid = False
        except UnicodeDecodeError:
            valid = False
        return {
            "text": text,
            "valid": valid,
            "compression_id": compression_id,
            "used_length": used_length,
            "raw_hex": raw.hex(),
        }

    @staticmethod
    def _entity_identifier(raw: bytes) -> dict[str, object]:
        if len(raw) != 32:
            return {"valid": False, "raw_hex": raw.hex()}
        identifier_raw = raw[1:24].split(b"\x00", 1)[0]
        try:
            identifier = identifier_raw.decode("ascii")
            valid = bool(identifier) and all(32 <= byte <= 126 for byte in identifier_raw)
        except UnicodeDecodeError:
            identifier = None
            valid = False
        return {
            "flags": raw[0],
            "identifier": identifier,
            "identifier_raw_hex": raw[1:24].hex(),
            "suffix_raw_hex": raw[24:32].hex(),
            "valid": valid and raw[0] & ~0x03 == 0,
        }

    def _primary_volume_descriptor(self, raw: bytes) -> dict[str, object]:
        volume_identifier = self._decode_dstring(raw[24:56])
        volume_set_identifier = self._decode_dstring(raw[72:200])
        descriptor_character_set = self._character_set_spec(raw[200:264])
        explanatory_character_set = self._character_set_spec(raw[264:328])
        sequence_number = int.from_bytes(raw[56:58], "little")
        maximum_sequence_number = int.from_bytes(raw[58:60], "little")
        return {
            "volume_descriptor_sequence_number": int.from_bytes(
                raw[16:20], "little"
            ),
            "primary_volume_descriptor_number": int.from_bytes(
                raw[20:24], "little"
            ),
            "volume_identifier": volume_identifier,
            "volume_sequence_number": sequence_number,
            "maximum_volume_sequence_number": maximum_sequence_number,
            "interchange_level": int.from_bytes(raw[60:62], "little"),
            "maximum_interchange_level": int.from_bytes(
                raw[62:64], "little"
            ),
            "volume_set_identifier": volume_set_identifier,
            "descriptor_character_set": descriptor_character_set,
            "explanatory_character_set": explanatory_character_set,
            "valid": bool(
                volume_identifier["valid"] is True
                and volume_set_identifier["valid"] is True
                and descriptor_character_set["valid"] is True
                and explanatory_character_set["valid"] is True
                and 1 <= sequence_number <= maximum_sequence_number
            ),
        }

    def _partition_descriptor(
        self,
        raw: bytes,
        block_size: int,
        size: int,
    ) -> dict[str, object]:
        start = int.from_bytes(raw[188:192], "little")
        length = int.from_bytes(raw[192:196], "little")
        offset = start * block_size
        end_offset = offset + length * block_size
        contents = self._entity_identifier(raw[24:56])
        access_type = int.from_bytes(raw[184:188], "little")
        failed_checks: list[str] = []
        if int.from_bytes(raw[20:22], "little") & ~1:
            failed_checks.append("partition_flags")
        if contents["valid"] is not True:
            failed_checks.append("partition_contents_identifier")
        elif contents["identifier"] not in {"+NSR02", "+NSR03"}:
            failed_checks.append("partition_contents_revision")
        if access_type not in {0, 1, 2, 3, 4}:
            failed_checks.append("access_type")
        if length == 0 or end_offset > size:
            failed_checks.append("partition_range")
        return {
            "volume_descriptor_sequence_number": int.from_bytes(
                raw[16:20], "little"
            ),
            "partition_flags": int.from_bytes(raw[20:22], "little"),
            "partition_number": int.from_bytes(raw[22:24], "little"),
            "partition_contents": contents,
            "access_type": access_type,
            "access_type_name": {
                0: "pseudo_overwritable",
                1: "read_only",
                2: "write_once",
                3: "rewritable",
                4: "overwritable",
            }.get(access_type, "reserved"),
            "start_location": start,
            "block_count": length,
            "offset": offset,
            "length": length * block_size,
            "end_offset": end_offset,
            "failed_checks": failed_checks,
            "valid": not failed_checks,
        }

    def _logical_volume_descriptor(
        self,
        raw: bytes,
        block_size: int,
        size: int,
    ) -> dict[str, object]:
        logical_block_size = int.from_bytes(raw[212:216], "little")
        descriptor_character_set = self._character_set_spec(raw[20:84])
        domain_identifier = self._entity_identifier(raw[216:248])
        logical_volume_identifier = self._decode_dstring(raw[84:212])
        map_table_length = int.from_bytes(raw[264:268], "little")
        map_count = int.from_bytes(raw[268:272], "little")
        failed_checks: list[str] = []
        if logical_block_size not in _LOGICAL_BLOCK_SIZES:
            failed_checks.append("logical_block_size")
        if logical_block_size != block_size:
            failed_checks.append("anchor_logical_block_size_mismatch")
        if logical_volume_identifier["valid"] is not True:
            failed_checks.append("logical_volume_identifier")
        if descriptor_character_set["valid"] is not True:
            failed_checks.append("descriptor_character_set")
        if domain_identifier["valid"] is not True:
            failed_checks.append("domain_identifier")
        elif domain_identifier["identifier"] != "*OSTA UDF Compliant":
            failed_checks.append("domain_identifier_value")
        if map_table_length > len(raw) - 440 or map_count > 64:
            failed_checks.append("partition_map_bounds")
            partition_maps: list[dict[str, object]] = []
            map_table_valid = False
        else:
            partition_maps, map_table_valid = self._partition_maps(
                raw[440:440 + map_table_length], map_count,
            )
            if not map_table_valid:
                failed_checks.append("partition_map_framing")
        file_set_descriptor = self._long_ad(raw[248:264])
        if file_set_descriptor["valid"] is not True:
            failed_checks.append("file_set_descriptor_address")
        elif int(file_set_descriptor["partition_reference_number"]) >= map_count:
            failed_checks.append("file_set_descriptor_partition_reference")
        integrity_sequence = self._extent_ad(
            raw[432:440], block_size, size,
        )
        if integrity_sequence["valid"] is not True:
            failed_checks.append("integrity_sequence_extent")
        return {
            "volume_descriptor_sequence_number": int.from_bytes(
                raw[16:20], "little"
            ),
            "descriptor_character_set": descriptor_character_set,
            "logical_volume_identifier": logical_volume_identifier,
            "logical_block_size": logical_block_size,
            "domain_identifier": domain_identifier,
            "file_set_descriptor_address": file_set_descriptor,
            "map_table_length": map_table_length,
            "partition_map_count": map_count,
            "partition_maps": partition_maps,
            "integrity_sequence_extent": integrity_sequence,
            "failed_checks": failed_checks,
            "valid": not failed_checks,
        }

    @staticmethod
    def _character_set_spec(raw: bytes) -> dict[str, object]:
        if len(raw) != 64:
            return {"valid": False, "raw_hex": raw.hex()}
        information_raw = raw[1:].split(b"\x00", 1)[0]
        try:
            information = information_raw.decode("ascii")
        except UnicodeDecodeError:
            information = None
        valid = bool(
            raw[0] == 0
            and information == "OSTA Compressed Unicode"
            and not any(raw[1 + len(information_raw):])
        )
        return {
            "character_set_type": raw[0],
            "information": information,
            "information_raw_hex": raw[1:].hex(),
            "valid": valid,
        }

    def _partition_maps(
        self,
        raw: bytes,
        expected_count: int,
    ) -> tuple[list[dict[str, object]], bool]:
        maps: list[dict[str, object]] = []
        cursor = 0
        valid = True
        while cursor < len(raw) and len(maps) < expected_count:
            if cursor + 2 > len(raw):
                valid = False
                break
            map_type = raw[cursor]
            length = raw[cursor + 1]
            if length < 2 or cursor + length > len(raw):
                valid = False
                break
            payload = raw[cursor:cursor + length]
            record: dict[str, object] = {
                "index": len(maps),
                "type": map_type,
                "length": length,
                "raw_hex": payload.hex(),
            }
            if map_type == 1 and length == 6:
                record.update({
                    "kind": "type_1",
                    "volume_sequence_number": int.from_bytes(
                        payload[2:4], "little"
                    ),
                    "partition_number": int.from_bytes(
                        payload[4:6], "little"
                    ),
                    "valid": True,
                })
            elif map_type == 2 and length == 64:
                identifier = self._entity_identifier(payload[4:36])
                record.update({
                    "kind": "type_2",
                    "partition_type_identifier": identifier,
                    "volume_sequence_number": int.from_bytes(
                        payload[36:38], "little"
                    ),
                    "partition_number": int.from_bytes(
                        payload[38:40], "little"
                    ),
                    "valid": identifier["valid"],
                })
                if identifier["valid"] is not True:
                    valid = False
            else:
                record.update({"kind": "unsupported", "valid": False})
                valid = False
            maps.append(record)
            cursor += length
        if cursor != len(raw) or len(maps) != expected_count:
            valid = False
        return maps, valid

    @staticmethod
    def _long_ad(raw: bytes) -> dict[str, object]:
        if len(raw) != 16:
            return {"valid": False, "raw_hex": raw.hex()}
        raw_length = int.from_bytes(raw[0:4], "little")
        extent_type = raw_length >> 30
        length = raw_length & 0x3FFFFFFF
        logical_block_number = int.from_bytes(raw[4:8], "little")
        partition_reference_number = int.from_bytes(raw[8:10], "little")
        return {
            "raw_hex": raw.hex(),
            "raw_length": raw_length,
            "extent_type": extent_type,
            "length": length,
            "logical_block_number": logical_block_number,
            "partition_reference_number": partition_reference_number,
            "implementation_use_raw_hex": raw[10:16].hex(),
            "implementation_use_flags": int.from_bytes(
                raw[10:12], "little"
            ),
            "valid": bool(
                extent_type == 0
                and length > 0
                and int.from_bytes(raw[10:12], "little") & ~0x0001 == 0
            ),
        }

    @staticmethod
    def _compare_volume_descriptor_sequences(
        main: dict[str, object],
        reserve: dict[str, object],
    ) -> dict[str, object]:
        def semantic(sequence: dict[str, object]) -> dict[str, object]:
            primary = sequence.get("primary_volumes", [])
            partitions = sequence.get("partitions", [])
            logical_volumes = sequence.get("logical_volumes", [])
            return {
                "descriptor_bodies": [
                    {
                        "type": item.get("type"),
                        "body_sha256": item.get("body_sha256"),
                        "expected_crc_length": item.get(
                            "expected_crc_length"
                        ),
                    }
                    for item in sequence.get("descriptors", [])
                    if isinstance(item, dict)
                ],
                "primary_volumes": [
                    {
                        "volume_descriptor_sequence_number": item.get(
                            "volume_descriptor_sequence_number"
                        ),
                        "volume_identifier": item.get("volume_identifier"),
                        "volume_set_identifier": item.get("volume_set_identifier"),
                        "volume_sequence_number": item.get("volume_sequence_number"),
                    }
                    for item in primary if isinstance(item, dict)
                ],
                "partitions": [
                    {
                        key: item.get(key)
                        for key in (
                            "volume_descriptor_sequence_number",
                            "partition_flags", "partition_number",
                            "partition_contents", "access_type",
                            "start_location", "block_count",
                        )
                    }
                    for item in partitions if isinstance(item, dict)
                ],
                "logical_volumes": [
                    {
                        key: item.get(key)
                        for key in (
                            "volume_descriptor_sequence_number",
                            "logical_volume_identifier", "logical_block_size",
                            "domain_identifier", "file_set_descriptor_address",
                            "map_table_length", "partition_map_count",
                            "partition_maps", "integrity_sequence_extent",
                        )
                    }
                    for item in logical_volumes if isinstance(item, dict)
                ],
            }

        main_semantic = semantic(main)
        reserve_semantic = semantic(reserve)
        failed_checks = [
            key for key in main_semantic
            if main_semantic[key] != reserve_semantic[key]
        ]
        if main.get("valid") is not True:
            failed_checks.append("main_sequence_validity")
        if reserve.get("valid") is not True:
            failed_checks.append("reserve_sequence_validity")
        return {
            "performed": True,
            "main_semantic": main_semantic,
            "reserve_semantic": reserve_semantic,
            "failed_checks": list(dict.fromkeys(failed_checks)),
            "consistent": not failed_checks,
        }

    def _file_set_metadata(
        self,
        stream,
        size: int,
        sequence: dict[str, object],
        block_size: int,
    ) -> dict[str, object]:
        errors: list[dict[str, object]] = []
        logical_volumes = [
            item for item in sequence.get("logical_volumes", [])
            if isinstance(item, dict) and item.get("valid") is True
        ]
        if not logical_volumes:
            return {
                "valid": False,
                "errors": [{"reason": "no_valid_logical_volume_for_file_set"}],
            }
        highest_sequence = max(
            int(item.get("volume_descriptor_sequence_number", 0))
            for item in logical_volumes
        )
        active_logical_volumes = [
            item for item in logical_volumes
            if item.get("volume_descriptor_sequence_number") == highest_sequence
        ]
        if len(active_logical_volumes) != 1:
            return {
                "valid": False,
                "errors": [{
                    "reason": "ambiguous_active_logical_volume_descriptor",
                    "sequence_number": highest_sequence,
                    "candidate_count": len(active_logical_volumes),
                }],
            }
        logical_volume = active_logical_volumes[0]
        file_set_address = logical_volume.get("file_set_descriptor_address")
        resolved_file_set = self._resolve_partition_address(
            file_set_address,
            logical_volume,
            sequence,
            block_size,
            size,
        )
        if resolved_file_set.get("valid") is not True:
            return {
                "logical_volume_descriptor_sequence_number": highest_sequence,
                "file_set_address": file_set_address,
                "resolved_file_set": resolved_file_set,
                "valid": False,
                "errors": [{
                    "reason": "file_set_address_resolution_failed",
                    "failed_checks": resolved_file_set.get("failed_checks", []),
                }],
            }
        if file_set_address.get("length") != block_size:
            errors.append({
                "reason": "unsupported_file_set_extent_length",
                "length": file_set_address.get("length"),
                "expected": block_size,
            })
        file_set_offset = int(resolved_file_set["offset"])
        stream.seek(file_set_offset)
        raw = stream.read(block_size)
        if len(raw) != block_size:
            errors.append({
                "reason": "truncated_file_set_descriptor",
                "offset": file_set_offset,
            })
            return {
                "logical_volume_descriptor_sequence_number": highest_sequence,
                "file_set_address": file_set_address,
                "resolved_file_set": resolved_file_set,
                "valid": False,
                "errors": errors,
            }
        file_set_location = int(file_set_address["logical_block_number"])
        tag = self._descriptor_tag(raw, file_set_location)
        if tag["identifier"] != 0x0100:
            errors.append({
                "reason": "file_set_descriptor_identifier",
                "identifier": tag["identifier"],
            })
        if tag["valid"] is not True:
            errors.append({"reason": "invalid_file_set_descriptor_tag"})
        if tag["crc_length"] != 496:
            errors.append({
                "reason": "file_set_descriptor_crc_coverage",
                "stored": tag["crc_length"],
                "expected": 496,
            })
        if any(raw[480:512]):
            errors.append({"reason": "file_set_descriptor_reserved_bytes"})

        logical_volume_identifier = self._decode_dstring(raw[112:240])
        file_set_identifier = self._decode_dstring(raw[304:336])
        copyright_identifier = self._decode_dstring(raw[336:368])
        abstract_identifier = self._decode_dstring(raw[368:400])
        logical_volume_character_set = self._character_set_spec(raw[48:112])
        file_set_character_set = self._character_set_spec(raw[240:304])
        domain_identifier = self._entity_identifier(raw[416:448])
        root_directory_icb = self._long_ad(raw[400:416])
        next_extent = self._optional_long_ad(raw[448:464])
        stream_directory_icb = self._optional_long_ad(raw[464:480])
        if logical_volume_character_set["valid"] is not True:
            errors.append({"reason": "file_set_logical_volume_character_set"})
        if file_set_character_set["valid"] is not True:
            errors.append({"reason": "file_set_character_set"})
        if logical_volume_identifier["valid"] is not True:
            errors.append({"reason": "file_set_logical_volume_identifier"})
        elif logical_volume_identifier != logical_volume.get(
            "logical_volume_identifier"
        ):
            errors.append({"reason": "logical_volume_identifier_mismatch"})
        if file_set_identifier["valid"] is not True:
            errors.append({"reason": "file_set_identifier"})
        if copyright_identifier["valid"] is not True:
            errors.append({"reason": "copyright_file_identifier"})
        if abstract_identifier["valid"] is not True:
            errors.append({"reason": "abstract_file_identifier"})
        if (
            domain_identifier["valid"] is not True
            or domain_identifier["identifier"] != "*OSTA UDF Compliant"
        ):
            errors.append({"reason": "file_set_domain_identifier"})
        if root_directory_icb["valid"] is not True:
            errors.append({"reason": "root_directory_icb_address"})
        elif root_directory_icb.get("length") != block_size:
            errors.append({
                "reason": "unsupported_root_directory_icb_extent_length",
                "length": root_directory_icb.get("length"),
                "expected": block_size,
            })
        if next_extent["valid"] is not True:
            errors.append({"reason": "next_file_set_extent"})
        if stream_directory_icb["valid"] is not True:
            errors.append({"reason": "stream_directory_icb_address"})

        resolved_root = self._resolve_partition_address(
            root_directory_icb,
            logical_volume,
            sequence,
            block_size,
            size,
        )
        root_icb: dict[str, object] | None = None
        root_directory: dict[str, object] | None = None
        if resolved_root.get("valid") is not True:
            errors.append({
                "reason": "root_directory_icb_resolution_failed",
                "failed_checks": resolved_root.get("failed_checks", []),
            })
        elif not errors:
            root_icb = self._root_icb_metadata(
                stream,
                int(resolved_root["offset"]),
                block_size,
                int(root_directory_icb["logical_block_number"]),
            )
            errors.extend(root_icb.get("errors", []))
            if root_icb.get("valid") is True:
                root_directory = self._root_directory_metadata(
                    stream,
                    size,
                    root_icb,
                    root_directory_icb,
                    logical_volume,
                    sequence,
                    block_size,
                )
                errors.extend(root_directory.get("errors", []))
        return {
            "logical_volume_descriptor_sequence_number": highest_sequence,
            "file_set_address": file_set_address,
            "resolved_file_set": resolved_file_set,
            "offset": file_set_offset,
            "length": block_size,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "tag": tag,
            "interchange_level": int.from_bytes(raw[28:30], "little"),
            "maximum_interchange_level": int.from_bytes(raw[30:32], "little"),
            "character_set_list": int.from_bytes(raw[32:36], "little"),
            "maximum_character_set_list": int.from_bytes(raw[36:40], "little"),
            "file_set_number": int.from_bytes(raw[40:44], "little"),
            "file_set_descriptor_number": int.from_bytes(raw[44:48], "little"),
            "logical_volume_character_set": logical_volume_character_set,
            "logical_volume_identifier": logical_volume_identifier,
            "file_set_character_set": file_set_character_set,
            "file_set_identifier": file_set_identifier,
            "copyright_file_identifier": copyright_identifier,
            "abstract_file_identifier": abstract_identifier,
            "root_directory_icb_address": root_directory_icb,
            "resolved_root_directory_icb": resolved_root,
            "domain_identifier": domain_identifier,
            "next_extent": next_extent,
            "stream_directory_icb_address": stream_directory_icb,
            "root_icb": root_icb,
            "root_directory": root_directory,
            "errors": errors,
            "valid": not errors,
        }

    def _resolve_partition_address(
        self,
        address: object,
        logical_volume: dict[str, object],
        sequence: dict[str, object],
        block_size: int,
        size: int,
    ) -> dict[str, object]:
        failed_checks: list[str] = []
        if not isinstance(address, dict) or address.get("valid") is not True:
            return {
                "valid": False,
                "failed_checks": ["address"],
            }
        partition_reference = address.get("partition_reference_number")
        logical_block_number = address.get("logical_block_number")
        length = address.get("length")
        partition_maps = logical_volume.get("partition_maps", [])
        if (
            not isinstance(partition_reference, int)
            or isinstance(partition_reference, bool)
            or not isinstance(logical_block_number, int)
            or isinstance(logical_block_number, bool)
            or not isinstance(length, int)
            or isinstance(length, bool)
            or not isinstance(partition_maps, list)
            or not 0 <= partition_reference < len(partition_maps)
        ):
            return {
                "valid": False,
                "failed_checks": ["address_fields_or_partition_reference"],
            }
        partition_map = partition_maps[partition_reference]
        if (
            not isinstance(partition_map, dict)
            or partition_map.get("valid") is not True
            or partition_map.get("kind") != "type_1"
        ):
            failed_checks.append("unsupported_partition_map")
        primary_volume_sequence_numbers = {
            int(item["volume_sequence_number"])
            for item in sequence.get("primary_volumes", [])
            if isinstance(item, dict)
            and item.get("valid") is True
            and isinstance(item.get("volume_sequence_number"), int)
        }
        if (
            isinstance(partition_map, dict)
            and partition_map.get("volume_sequence_number")
            not in primary_volume_sequence_numbers
        ):
            failed_checks.append("partition_map_volume_sequence")
        partition_number = (
            partition_map.get("partition_number")
            if isinstance(partition_map, dict) else None
        )
        partitions = [
            item for item in sequence.get("partitions", [])
            if isinstance(item, dict)
            and item.get("valid") is True
            and item.get("partition_number") == partition_number
        ]
        active_partition: dict[str, object] | None = None
        if partitions:
            highest_sequence = max(
                int(item.get("volume_descriptor_sequence_number", 0))
                for item in partitions
            )
            active = [
                item for item in partitions
                if item.get("volume_descriptor_sequence_number")
                == highest_sequence
            ]
            if len(active) == 1:
                active_partition = active[0]
        if active_partition is None:
            failed_checks.append("partition_descriptor_resolution")
            partition_start = None
            partition_blocks = None
            offset = None
            end_offset = None
        else:
            partition_start = int(active_partition["start_location"])
            partition_blocks = int(active_partition["block_count"])
            offset = (partition_start + logical_block_number) * block_size
            end_offset = offset + length
            if logical_block_number >= partition_blocks:
                failed_checks.append("logical_block_outside_partition")
            if (
                length <= 0
                or logical_block_number * block_size + length
                > partition_blocks * block_size
                or end_offset > size
            ):
                failed_checks.append("extent_outside_partition_or_evidence")
        return {
            "partition_reference_number": partition_reference,
            "partition_map": partition_map,
            "partition_number": partition_number,
            "partition_descriptor": active_partition,
            "partition_start_location": partition_start,
            "partition_block_count": partition_blocks,
            "logical_block_number": logical_block_number,
            "logical_block_size": block_size,
            "length": length,
            "offset": offset,
            "end_offset": end_offset,
            "failed_checks": failed_checks,
            "valid": not failed_checks,
        }

    @staticmethod
    def _optional_long_ad(raw: bytes) -> dict[str, object]:
        if len(raw) == 16 and not any(raw):
            return {
                "present": False,
                "raw_hex": raw.hex(),
                "valid": True,
            }
        result = UdfObservationEngine._long_ad(raw)
        result["present"] = True
        return result

    def _root_icb_metadata(
        self,
        stream,
        offset: int,
        block_size: int,
        logical_block_number: int,
    ) -> dict[str, object]:
        result = self._icb_metadata(
            stream,
            offset,
            block_size,
            logical_block_number,
        )
        errors = result.setdefault("errors", [])
        if result.get("file_type") != 4:
            errors.append({
                "reason": "root_icb_not_directory",
                "file_type": result.get("file_type"),
            })
        result["role"] = "root_directory"
        result["valid"] = not errors
        return result

    def _icb_metadata(
        self,
        stream,
        offset: int,
        block_size: int,
        logical_block_number: int,
    ) -> dict[str, object]:
        stream.seek(offset)
        raw = stream.read(block_size)
        errors: list[dict[str, object]] = []
        if len(raw) != block_size:
            return {
                "offset": offset,
                "valid": False,
                "errors": [{"reason": "truncated_icb"}],
            }
        tag = self._descriptor_tag(raw, logical_block_number)
        identifier = tag.get("identifier")
        if identifier == 0x0105:
            descriptor_kind = "file_entry"
            fixed_length = 176
            extended_attribute_length = int.from_bytes(raw[168:172], "little")
            allocation_descriptor_length = int.from_bytes(raw[172:176], "little")
            information_length = int.from_bytes(raw[56:64], "little")
            logical_blocks_recorded = int.from_bytes(raw[64:72], "little")
        elif identifier == 0x010A:
            descriptor_kind = "extended_file_entry"
            fixed_length = 216
            extended_attribute_length = int.from_bytes(raw[208:212], "little")
            allocation_descriptor_length = int.from_bytes(raw[212:216], "little")
            information_length = int.from_bytes(raw[56:64], "little")
            logical_blocks_recorded = int.from_bytes(raw[72:80], "little")
        else:
            descriptor_kind = "unsupported"
            fixed_length = 0
            extended_attribute_length = 0
            allocation_descriptor_length = 0
            information_length = 0
            logical_blocks_recorded = 0
            errors.append({
                "reason": "icb_descriptor_identifier",
                "identifier": identifier,
            })
        expected_crc_length = (
            fixed_length - 16
            + extended_attribute_length
            + allocation_descriptor_length
            if fixed_length else None
        )
        if tag.get("valid") is not True:
            errors.append({"reason": "invalid_icb_descriptor_tag"})
        if (
            expected_crc_length is None
            or expected_crc_length > block_size - 16
            or tag.get("crc_length") != expected_crc_length
        ):
            errors.append({
                "reason": "icb_descriptor_crc_coverage",
                "stored": tag.get("crc_length"),
                "expected": expected_crc_length,
            })
        strategy_type = int.from_bytes(raw[20:22], "little")
        icb_reserved = raw[26]
        file_type = raw[27]
        allocation_flags = int.from_bytes(raw[34:36], "little")
        allocation_descriptor_type = allocation_flags & 0x0007
        permissions = int.from_bytes(raw[44:48], "little")
        file_link_count = int.from_bytes(raw[48:50], "little")
        record_format = raw[50]
        record_display_attributes = raw[51]
        if strategy_type != 4:
            errors.append({
                "reason": "unsupported_icb_strategy",
                "strategy_type": strategy_type,
            })
        if icb_reserved != 0:
            errors.append({"reason": "icb_reserved_byte"})
        if allocation_descriptor_type not in {0, 1, 2, 3}:
            errors.append({
                "reason": "icb_allocation_descriptor_type",
                "type": allocation_descriptor_type,
            })
        if allocation_flags & 0xC000:
            errors.append({"reason": "icb_reserved_flags"})
        if int.from_bytes(raw[24:26], "little") != 1:
            errors.append({"reason": "icb_maximum_entries"})
        if file_type not in range(1, 14):
            errors.append({
                "reason": "icb_file_type",
                "file_type": file_type,
            })
        if permissions & ~0x00007FFF:
            errors.append({"reason": "icb_permissions_reserved_bits"})
        if file_link_count == 0:
            errors.append({"reason": "icb_zero_file_link_count"})
        if record_format > 0x0B:
            errors.append({"reason": "icb_record_format"})
        if record_display_attributes > 0x03:
            errors.append({"reason": "icb_record_display_attributes"})
        if descriptor_kind == "extended_file_entry":
            if any(raw[132:136]):
                errors.append({"reason": "extended_file_entry_reserved_bytes"})
            if int.from_bytes(raw[64:72], "little") < information_length:
                errors.append({"reason": "extended_file_entry_object_size"})
        data_end = fixed_length + extended_attribute_length + allocation_descriptor_length
        if data_end > block_size:
            errors.append({
                "reason": "icb_variable_fields_outside_descriptor",
                "end_offset": data_end,
                "block_size": block_size,
            })
        extended_attributes = raw[
            fixed_length:fixed_length + extended_attribute_length
        ] if fixed_length else b""
        allocation_descriptors = raw[
            fixed_length + extended_attribute_length:data_end
        ] if fixed_length and data_end <= block_size else b""
        return {
            "offset": offset,
            "length": block_size,
            "logical_block_number": logical_block_number,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "tag": tag,
            "descriptor_kind": descriptor_kind,
            "expected_crc_length": expected_crc_length,
            "strategy_type": strategy_type,
            "strategy_parameter": int.from_bytes(raw[22:24], "little"),
            "maximum_entries": int.from_bytes(raw[24:26], "little"),
            "file_type": file_type,
            "file_type_name": {
                0: "undefined",
                1: "unallocated_space_entry",
                2: "partition_integrity_entry",
                3: "indirect_entry",
                4: "directory",
                5: "regular_file",
                6: "block_device",
                7: "character_device",
                8: "extended_attributes",
                9: "fifo",
                10: "socket",
                11: "terminal_entry",
                12: "symbolic_link",
                13: "stream_directory",
            }.get(file_type, "reserved"),
            "parent_icb_logical_block_number": int.from_bytes(
                raw[28:32], "little"
            ),
            "parent_icb_partition_reference_number": int.from_bytes(
                raw[32:34], "little"
            ),
            "allocation_descriptor_type": allocation_descriptor_type,
            "allocation_flags": allocation_flags,
            "information_length": information_length,
            "logical_blocks_recorded": logical_blocks_recorded,
            "extended_attribute_length": extended_attribute_length,
            "extended_attribute_raw_sha256": hashlib.sha256(
                extended_attributes
            ).hexdigest(),
            "allocation_descriptor_length": allocation_descriptor_length,
            "allocation_descriptor_raw_hex": allocation_descriptors.hex(),
            "allocation_descriptor_raw_sha256": hashlib.sha256(
                allocation_descriptors
            ).hexdigest(),
            "uid": int.from_bytes(raw[36:40], "little"),
            "gid": int.from_bytes(raw[40:44], "little"),
            "permissions": permissions,
            "file_link_count": file_link_count,
            "record_format": record_format,
            "record_display_attributes": record_display_attributes,
            "record_length": int.from_bytes(raw[52:56], "little"),
            "object_size": (
                int.from_bytes(raw[64:72], "little")
                if descriptor_kind == "extended_file_entry" else None
            ),
            "unique_id": int.from_bytes(
                raw[160:168] if descriptor_kind == "file_entry"
                else raw[200:208],
                "little",
            ) if fixed_length else None,
            "errors": errors,
            "valid": not errors,
        }

    def _root_directory_metadata(
        self,
        stream,
        size: int,
        root_icb: dict[str, object],
        root_icb_address: dict[str, object],
        logical_volume: dict[str, object],
        sequence: dict[str, object],
        block_size: int,
    ) -> dict[str, object]:
        budget: dict[str, object] = {
            "bytes_read": 0,
            "entry_count": 0,
            "directory_extents": [],
            "allocation_extent_count": 0,
            "allocation_extent_bytes_read": 0,
            "allocation_extent_ranges": [],
        }
        root = self._directory_metadata(
            stream,
            size,
            root_icb,
            root_icb_address,
            root_icb_address,
            logical_volume,
            sequence,
            block_size,
            budget,
            directory_index=0,
            parent_directory_index=None,
            path_components=[],
        )
        subdirectories: list[dict[str, object]] = []
        tree_errors: list[dict[str, object]] = []
        root_key = self._icb_address_key(root_icb_address)
        seen: dict[tuple[int, int, int], int] = (
            {root_key: 0} if root_key is not None else {}
        )
        queue: list[tuple[dict[str, object], dict[str, object]]] = []
        if root.get("valid") is True:
            queue.append((root, root_icb_address))
        while queue:
            directory, directory_address = queue.pop(0)
            child_inventory = directory.get("child_icbs", {})
            children = (
                child_inventory.get("children", [])
                if isinstance(child_inventory, dict) else []
            )
            for child in children:
                if (
                    not isinstance(child, dict)
                    or child.get("valid") is not True
                ):
                    continue
                child_icb = child.get("icb")
                if (
                    not isinstance(child_icb, dict)
                    or child_icb.get("file_type") != 4
                ):
                    continue
                address = child.get("address")
                key = self._icb_address_key(address)
                relationships = child.get("relationships", [])
                valid_relationships = [
                    item for item in relationships
                    if isinstance(item, dict) and item.get("valid") is True
                ] if isinstance(relationships, list) else []
                if (
                    key is None
                    or not isinstance(address, dict)
                    or len(valid_relationships) != 1
                ):
                    child["directory_traversal_status"] = (
                        "ambiguous_directory_reference"
                    )
                    tree_errors.append({
                        "reason": "ambiguous_directory_icb_reference",
                        "parent_directory_index": directory.get(
                            "directory_index"
                        ),
                        "child_index": child.get("index"),
                    })
                    continue
                if key in seen:
                    child["directory_traversal_status"] = "shared_or_cyclic_icb"
                    tree_errors.append({
                        "reason": "shared_or_cyclic_directory_icb",
                        "parent_directory_index": directory.get(
                            "directory_index"
                        ),
                        "child_index": child.get("index"),
                        "existing_directory_index": seen[key],
                    })
                    continue
                if 1 + len(subdirectories) >= _DIRECTORY_LIMIT:
                    child["directory_traversal_status"] = "directory_limit"
                    tree_errors.append({
                        "reason": "directory_limit_reached",
                        "limit": _DIRECTORY_LIMIT,
                    })
                    continue
                relationship = valid_relationships[0]
                name = relationship.get("name")
                parent_components = directory.get("path_components", [])
                path_components = (
                    list(parent_components) + [name]
                    if isinstance(parent_components, list)
                    and isinstance(name, str)
                    else list(parent_components)
                    if isinstance(parent_components, list) else []
                )
                directory_index = 1 + len(subdirectories)
                seen[key] = directory_index
                child["directory_index"] = directory_index
                child["directory_traversal_status"] = "parsed"
                parsed = self._directory_metadata(
                    stream,
                    size,
                    child["icb"],
                    address,
                    directory_address,
                    logical_volume,
                    sequence,
                    block_size,
                    budget,
                    directory_index=directory_index,
                    parent_directory_index=int(directory["directory_index"]),
                    path_components=path_components,
                )
                subdirectories.append(parsed)
                if parsed.get("valid") is not True:
                    tree_errors.append({
                        "reason": "subdirectory_validation_failed",
                        "directory_index": directory_index,
                        "failed_checks": parsed.get("failed_checks", []),
                    })
                else:
                    queue.append((parsed, address))

        if tree_errors:
            root["failed_checks"].append("directory_tree_validation")
            root["errors"].append({
                "reason": "directory_tree_validation_failed",
                "tree_errors": tree_errors,
            })
            root["valid"] = False
        root["subdirectories"] = subdirectories
        root["directory_count"] = 1 + len(subdirectories)
        root["directory_limit"] = _DIRECTORY_LIMIT
        root["tree_entry_count"] = budget["entry_count"]
        root["tree_entry_limit"] = self.max_directory_entries
        root["tree_bytes_read"] = budget["bytes_read"]
        root["tree_byte_limit"] = self.max_directory_bytes
        root["tree_allocation_extent_count"] = budget[
            "allocation_extent_count"
        ]
        root["tree_allocation_extent_limit"] = _ALLOCATION_EXTENT_GLOBAL_LIMIT
        root["tree_allocation_extent_bytes_read"] = budget[
            "allocation_extent_bytes_read"
        ]
        root["tree_allocation_extent_byte_limit"] = (
            _ALLOCATION_EXTENT_BYTE_LIMIT
        )
        root["tree_allocation_extent_ranges"] = budget[
            "allocation_extent_ranges"
        ]
        root["tree_errors"] = tree_errors
        return root

    def _directory_metadata(
        self,
        stream,
        size: int,
        root_icb: dict[str, object],
        root_icb_address: dict[str, object],
        expected_parent_icb_address: dict[str, object],
        logical_volume: dict[str, object],
        sequence: dict[str, object],
        block_size: int,
        budget: dict[str, object],
        *,
        directory_index: int,
        parent_directory_index: int | None,
        path_components: list[str],
    ) -> dict[str, object]:
        information_length = root_icb.get("information_length")
        logical_blocks_recorded = root_icb.get("logical_blocks_recorded")
        descriptor_type = root_icb.get("allocation_descriptor_type")
        failed_checks: list[str] = []
        if (
            not isinstance(information_length, int)
            or isinstance(information_length, bool)
            or not 0 < information_length <= self.max_directory_bytes
        ):
            failed_checks.append("directory_information_length")
        elif information_length > (
            self.max_directory_bytes - int(budget["bytes_read"])
        ):
            failed_checks.append("directory_tree_byte_limit")
        if (
            not isinstance(logical_blocks_recorded, int)
            or isinstance(logical_blocks_recorded, bool)
            or logical_blocks_recorded <= 0
        ):
            failed_checks.append("directory_logical_blocks_recorded")
        if descriptor_type not in {0, 1}:
            failed_checks.append("unsupported_directory_allocation_descriptor_type")

        try:
            allocation_raw = bytes.fromhex(
                str(root_icb.get("allocation_descriptor_raw_hex", ""))
            )
        except ValueError:
            allocation_raw = b""
            encoding_failed = True
        else:
            encoding_failed = False
        retained_allocation = root_icb.get("allocation_descriptor_metadata")
        if isinstance(retained_allocation, dict):
            allocation_chain = retained_allocation
        else:
            allocation_chain = self._allocation_descriptor_chain(
                stream,
                allocation_raw,
                descriptor_type,
                int(root_icb_address.get("partition_reference_number", -1)),
                logical_volume,
                sequence,
                block_size,
                size,
                initial_encoding_failed=encoding_failed,
                allocation_extent_budget=budget,
            )
        descriptors = allocation_chain["descriptors"]
        if allocation_chain.get("valid") is not True:
            failed_checks.append("allocation_descriptor_chain")
        extents: list[dict[str, object]] = []
        allocated_length = 0
        recorded_blocks = 0
        if not failed_checks:
            for descriptor in descriptors:
                address = descriptor.get("address", {})
                resolved = descriptor.get("resolved", {})
                descriptor_failed_checks = descriptor.get("failed_checks", [])
                extent_length = address.get("length")
                if address.get("extent_type") != 0:
                    descriptor_failed_checks.append("unrecorded_or_continuation_extent")
                if (
                    not isinstance(extent_length, int)
                    or isinstance(extent_length, bool)
                    or extent_length <= 0
                ):
                    descriptor_failed_checks.append("extent_length")
                    extent_length = 0
                descriptor["failed_checks"] = list(dict.fromkeys(
                    descriptor_failed_checks
                ))
                descriptor["valid"] = not descriptor["failed_checks"]
                if descriptor_failed_checks:
                    failed_checks.append("allocation_descriptor")
                    continue
                extent = {
                    "index": len(extents),
                    "descriptor_index": descriptor["index"],
                    "chain_descriptor_index": descriptor[
                        "chain_descriptor_index"
                    ],
                    "source_kind": descriptor["source_kind"],
                    "source_extent_index": descriptor[
                        "source_extent_index"
                    ],
                    "file_offset": allocated_length,
                    "logical_block_number": address["logical_block_number"],
                    "partition_reference_number": address[
                        "partition_reference_number"
                    ],
                    "logical_block_size": block_size,
                    "offset": resolved["offset"],
                    "length": extent_length,
                    "end_offset": resolved["end_offset"],
                }
                extents.append(extent)
                allocated_length += extent_length
                recorded_blocks += (
                    extent_length + block_size - 1
                ) // block_size

        if allocated_length > self.max_directory_bytes:
            failed_checks.append("allocated_directory_byte_limit")
        if any(
            int(extent["length"]) % block_size
            for extent in extents[:-1]
        ):
            failed_checks.append("nonfinal_allocation_extent_alignment")
        if isinstance(information_length, int) and not isinstance(
            information_length, bool
        ):
            if allocated_length < information_length:
                failed_checks.append("allocation_shorter_than_information_length")
            elif allocated_length - information_length >= block_size:
                failed_checks.append("excess_directory_allocation")
        if (
            isinstance(logical_blocks_recorded, int)
            and not isinstance(logical_blocks_recorded, bool)
            and logical_blocks_recorded != recorded_blocks
        ):
            failed_checks.append("logical_blocks_recorded_mismatch")
        for left_index, left in enumerate(extents):
            for right in extents[left_index + 1:]:
                if max(int(left["offset"]), int(right["offset"])) < min(
                    int(left["end_offset"]), int(right["end_offset"])
                ):
                    failed_checks.append("allocation_extent_overlap")
        known_directory_extents = budget["directory_extents"]
        if isinstance(known_directory_extents, list):
            for extent in extents:
                for known in known_directory_extents:
                    if (
                        isinstance(known, dict)
                        and max(int(extent["offset"]), int(known["offset"]))
                        < min(
                            int(extent["end_offset"]),
                            int(known["end_offset"]),
                        )
                    ):
                        failed_checks.append("directory_tree_extent_overlap")
            if not failed_checks:
                known_directory_extents.extend({
                    "directory_index": directory_index,
                    "offset": extent["offset"],
                    "end_offset": extent["end_offset"],
                } for extent in extents)

        data_parts: list[bytes] = []
        bytes_read = 0
        remaining = (
            information_length
            if isinstance(information_length, int)
            and not isinstance(information_length, bool)
            and information_length > 0
            else 0
        )
        if not failed_checks:
            for extent in extents:
                read_length = min(int(extent["length"]), remaining)
                if read_length <= 0:
                    extent["data_length"] = 0
                    extent["data_sha256"] = hashlib.sha256(b"").hexdigest()
                    continue
                stream.seek(int(extent["offset"]))
                data = stream.read(read_length)
                bytes_read += len(data)
                budget["bytes_read"] = int(budget["bytes_read"]) + len(data)
                extent["data_length"] = len(data)
                extent["data_sha256"] = hashlib.sha256(data).hexdigest()
                if len(data) != read_length:
                    failed_checks.append("truncated_directory_extent")
                    break
                data_parts.append(data)
                remaining -= read_length
            if remaining:
                failed_checks.append("incomplete_directory_data")
        data = b"".join(data_parts)

        entries: list[dict[str, object]] = []
        entry_errors: list[dict[str, object]] = []
        cursor = 0
        if not failed_checks:
            while cursor < len(data):
                if int(budget["entry_count"]) >= self.max_directory_entries:
                    failed_checks.append("directory_tree_entry_limit")
                    break
                if len(data) - cursor < 38:
                    failed_checks.append("truncated_file_identifier_descriptor")
                    break
                implementation_use_length = int.from_bytes(
                    data[cursor + 36:cursor + 38], "little"
                )
                identifier_length = data[cursor + 19]
                unpadded_length = (
                    38 + implementation_use_length + identifier_length
                )
                record_length = (unpadded_length + 3) & ~3
                if (
                    record_length < 40
                    or record_length > block_size
                    or cursor + record_length > len(data)
                ):
                    failed_checks.append("file_identifier_descriptor_bounds")
                    break
                record = self._file_identifier_descriptor(
                    data[cursor:cursor + record_length],
                    cursor,
                    extents,
                    expected_parent_icb_address,
                    logical_volume,
                    sequence,
                    block_size,
                    size,
                )
                record["index"] = len(entries)
                record["tree_index"] = int(budget["entry_count"])
                record["directory_index"] = directory_index
                record["directory_path_components"] = list(path_components)
                budget["entry_count"] = int(budget["entry_count"]) + 1
                entries.append(record)
                if record.get("valid") is not True:
                    entry_errors.append({
                        "reason": "invalid_file_identifier_descriptor",
                        "index": record.get("index"),
                        "directory_offset": cursor,
                        "failed_checks": record.get("failed_checks", []),
                    })
                cursor += record_length

        parent_entries = [
            item for item in entries
            if isinstance(item, dict) and item.get("parent") is True
        ]
        parent_record_valid = bool(
            len(parent_entries) == 1
            and parent_entries[0].get("index") == 0
            and parent_entries[0].get("valid") is True
            and parent_entries[0].get("file_identifier_length") == 0
            and parent_entries[0].get("directory") is True
            and parent_entries[0].get("deleted") is False
            and self._same_icb_address(
                parent_entries[0].get("icb_address"),
                expected_parent_icb_address,
            )
        )
        if not parent_record_valid:
            failed_checks.append("directory_parent_file_identifier_descriptor")
        if entry_errors:
            failed_checks.append("file_identifier_descriptor_validation")
        child_icbs = self._child_icb_inventory(
            stream,
            entries,
            root_icb_address,
            logical_volume,
            sequence,
            block_size,
            size,
            budget,
        )
        if child_icbs["valid"] is not True:
            failed_checks.append("child_icb_validation")
        failed_checks = list(dict.fromkeys(failed_checks))
        return {
            "allocation_descriptor_type": descriptor_type,
            "directory_index": directory_index,
            "parent_directory_index": parent_directory_index,
            "path_components": path_components,
            "icb_address": root_icb_address,
            "expected_parent_icb_address": expected_parent_icb_address,
            "allocation_descriptor_kind": {
                0: "short_ad",
                1: "long_ad",
            }.get(descriptor_type, "unsupported"),
            "allocation_descriptor_limit": _ALLOCATION_DESCRIPTOR_LIMIT,
            "allocation_descriptors": descriptors,
            "allocation_descriptor_chain": allocation_chain,
            "allocation_extents": allocation_chain["allocation_extents"],
            "extents": extents,
            "information_length": information_length,
            "allocated_length": allocated_length,
            "logical_blocks_recorded": logical_blocks_recorded,
            "calculated_logical_blocks_recorded": recorded_blocks,
            "byte_limit": self.max_directory_bytes,
            "entry_limit": self.max_directory_entries,
            "bytes_read": bytes_read,
            "data_sha256": hashlib.sha256(data).hexdigest(),
            "entries": entries,
            "entry_count": len(entries),
            "parent_record": parent_entries[0] if len(parent_entries) == 1 else None,
            "parent_record_valid": parent_record_valid,
            "entry_errors": entry_errors,
            "child_icbs": child_icbs,
            "failed_checks": failed_checks,
            "errors": [
                {
                    "reason": "directory_validation_failed",
                    "failed_checks": failed_checks,
                    "entry_errors": entry_errors,
                }
            ] if failed_checks else [],
            "valid": not failed_checks,
        }

    def _file_identifier_descriptor(
        self,
        raw: bytes,
        directory_offset: int,
        extents: list[dict[str, object]],
        expected_parent_icb_address: dict[str, object],
        logical_volume: dict[str, object],
        sequence: dict[str, object],
        block_size: int,
        size: int,
    ) -> dict[str, object]:
        source_segments = self._directory_source_segments(
            extents, directory_offset, len(raw),
        )
        expected_location = (
            int(source_segments[0]["logical_block_number"])
            if source_segments else -1
        )
        tag = self._descriptor_tag(raw, expected_location)
        version = int.from_bytes(raw[16:18], "little")
        characteristics = raw[18]
        identifier_length = raw[19]
        icb_address = self._long_ad(raw[20:36])
        implementation_use_length = int.from_bytes(raw[36:38], "little")
        name_start = 38 + implementation_use_length
        name_end = name_start + identifier_length
        padding = raw[name_end:]
        implementation_use = raw[38:name_start]
        identifier_raw = raw[name_start:name_end]
        parent = bool(characteristics & 0x08)
        directory = bool(characteristics & 0x02)
        deleted = bool(characteristics & 0x04)
        name = (
            {
                "text": "..",
                "compression_id": None,
                "raw_hex": "",
                "path_safe": True,
                "valid": identifier_length == 0,
            }
            if parent else (
                {
                    "text": None,
                    "compression_id": None,
                    "raw_hex": "",
                    "path_safe": False,
                    "valid": True,
                }
                if deleted and not identifier_raw
                else self._decode_cs0_name(identifier_raw)
            )
        )
        resolved_icb = (
            self._resolve_partition_address(
                icb_address,
                logical_volume,
                sequence,
                block_size,
                size,
            )
            if icb_address.get("valid") is True else {
                "valid": False,
                "failed_checks": ["deleted_or_invalid_icb_address"],
            }
        )
        failed_checks: list[str] = []
        if tag.get("identifier") != 0x0101:
            failed_checks.append("descriptor_identifier")
        if sum(int(item["length"]) for item in source_segments) != len(raw):
            failed_checks.append("descriptor_source_mapping")
        if tag.get("valid") is not True:
            failed_checks.append("descriptor_tag")
        if tag.get("crc_length") != len(raw) - 16:
            failed_checks.append("descriptor_crc_coverage")
        if version != 1:
            failed_checks.append("file_version_number")
        if characteristics & ~0x1F:
            failed_checks.append("reserved_file_characteristics")
        if implementation_use_length & 3:
            failed_checks.append("implementation_use_alignment")
        if any(padding):
            failed_checks.append("descriptor_padding")
        if not deleted:
            if icb_address.get("valid") is not True:
                failed_checks.append("icb_address")
            if resolved_icb.get("valid") is not True:
                failed_checks.append("icb_partition_resolution")
        if name.get("valid") is not True:
            failed_checks.append("file_identifier")
        if parent:
            if characteristics != 0x0A:
                failed_checks.append("parent_file_characteristics")
            if not self._same_icb_address(
                icb_address, expected_parent_icb_address,
            ):
                failed_checks.append("parent_icb_address")
        elif identifier_length == 0 and not deleted:
            failed_checks.append("empty_file_identifier")
        return {
            "index": None,
            "directory_offset": directory_offset,
            "record_length": len(raw),
            "unpadded_length": name_end,
            "padding_length": len(padding),
            "padding_raw_hex": padding.hex(),
            "source_segments": source_segments,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "tag": tag,
            "file_version_number": version,
            "file_characteristics": characteristics,
            "hidden": bool(characteristics & 0x01),
            "directory": directory,
            "deleted": deleted,
            "parent": parent,
            "metadata": bool(characteristics & 0x10),
            "file_identifier_length": identifier_length,
            "file_identifier": name,
            "icb_address": icb_address,
            "resolved_icb": resolved_icb,
            "implementation_use_length": implementation_use_length,
            "implementation_use_raw_hex": implementation_use.hex(),
            "implementation_use_sha256": hashlib.sha256(
                implementation_use
            ).hexdigest(),
            "failed_checks": failed_checks,
            "valid": not failed_checks,
        }

    @staticmethod
    def _directory_source_segments(
        extents: list[dict[str, object]],
        directory_offset: int,
        length: int,
    ) -> list[dict[str, object]]:
        segments: list[dict[str, object]] = []
        end = directory_offset + length
        for extent in extents:
            extent_start = int(extent["file_offset"])
            extent_data_length = int(extent.get("data_length", 0))
            extent_end = extent_start + extent_data_length
            overlap_start = max(directory_offset, extent_start)
            overlap_end = min(end, extent_end)
            if overlap_start >= overlap_end:
                continue
            relative = overlap_start - extent_start
            block_size = int(extent["logical_block_size"])
            segments.append({
                "extent_index": extent["index"],
                "directory_offset": overlap_start,
                "offset": int(extent["offset"]) + relative,
                "length": overlap_end - overlap_start,
                "end_offset": int(extent["offset"]) + relative
                + overlap_end - overlap_start,
                "logical_block_number": int(extent["logical_block_number"])
                + relative // block_size,
                "partition_reference_number": extent[
                    "partition_reference_number"
                ],
            })
        return segments

    @staticmethod
    def _decode_cs0_name(raw: bytes) -> dict[str, object]:
        compression_id = raw[0] if raw else None
        text: str | None = None
        valid = bool(raw and compression_id in {8, 16})
        if valid:
            content = raw[1:]
            try:
                if compression_id == 8:
                    text = content.decode("latin-1")
                elif len(content) % 2 == 0:
                    text = content.decode("utf-16-be")
                else:
                    valid = False
            except UnicodeDecodeError:
                valid = False
        path_safe = bool(
            valid
            and text
            and text not in {".", ".."}
            and "\x00" not in text
            and "/" not in text
            and "\\" not in text
            and not (len(text) >= 2 and text[0].isalpha() and text[1] == ":")
        )
        if not path_safe:
            valid = False
        return {
            "text": text,
            "compression_id": compression_id,
            "raw_hex": raw.hex(),
            "path_safe": path_safe,
            "valid": valid,
        }

    @staticmethod
    def _same_icb_address(left: object, right: object) -> bool:
        if not isinstance(left, dict) or not isinstance(right, dict):
            return False
        return all(
            left.get(key) == right.get(key)
            for key in (
                "length",
                "logical_block_number",
                "partition_reference_number",
            )
        )

    @staticmethod
    def _icb_address_key(address: object) -> tuple[int, int, int] | None:
        if not isinstance(address, dict):
            return None
        values = tuple(
            address.get(key)
            for key in (
                "partition_reference_number",
                "logical_block_number",
                "length",
            )
        )
        if not all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in values
        ):
            return None
        return (int(values[0]), int(values[1]), int(values[2]))

    def _child_icb_inventory(
        self,
        stream,
        entries: list[dict[str, object]],
        root_icb_address: dict[str, object],
        logical_volume: dict[str, object],
        sequence: dict[str, object],
        block_size: int,
        size: int,
        allocation_extent_budget: dict[str, object],
    ) -> dict[str, object]:
        groups: dict[tuple[int, int, int], list[dict[str, object]]] = {}
        errors: list[dict[str, object]] = []
        skipped_deleted = 0
        for entry in entries:
            if entry.get("parent") is True:
                entry["child_icb_status"] = "parent_record"
                continue
            if entry.get("deleted") is True:
                entry["child_icb_status"] = "deleted_not_followed"
                skipped_deleted += 1
                continue
            if entry.get("valid") is not True:
                entry["child_icb_status"] = "invalid_fid_not_followed"
                continue
            address = entry.get("icb_address")
            resolved = entry.get("resolved_icb")
            if (
                not isinstance(address, dict)
                or not isinstance(resolved, dict)
                or address.get("length") != block_size
                or resolved.get("valid") is not True
            ):
                entry["child_icb_status"] = "unsupported_icb_extent"
                errors.append({
                    "reason": "child_icb_extent",
                    "fid_index": entry.get("index"),
                    "address": address,
                })
                continue
            if self._same_icb_address(address, root_icb_address):
                entry["child_icb_status"] = "root_cycle"
                errors.append({
                    "reason": "child_fid_references_root_icb",
                    "fid_index": entry.get("index"),
                })
                continue
            key = (
                int(address["partition_reference_number"]),
                int(address["logical_block_number"]),
                int(address["length"]),
            )
            groups.setdefault(key, []).append(entry)

        children: list[dict[str, object]] = []
        for key, references in groups.items():
            first = references[0]
            resolved = first["resolved_icb"]
            parsed = self._icb_metadata(
                stream,
                int(resolved["offset"]),
                block_size,
                key[1],
            )
            parsed["role"] = "root_child"
            allocation = self._icb_allocation_descriptor_metadata(
                stream,
                parsed,
                key[0],
                logical_volume,
                sequence,
                block_size,
                size,
                allocation_extent_budget,
            )
            parsed["allocation_descriptor_metadata"] = allocation
            child_errors = list(parsed.get("errors", []))
            if allocation["valid"] is not True:
                child_errors.append({
                    "reason": "child_icb_allocation_descriptors",
                    "failed_checks": allocation["failed_checks"],
                })
            relationships: list[dict[str, object]] = []
            for reference in references:
                relationship_failed_checks: list[str] = []
                if bool(reference.get("directory")) != (
                    parsed.get("file_type") == 4
                ):
                    relationship_failed_checks.append("directory_file_type")
                relationship = {
                    "fid_index": reference.get("index"),
                    "fid_tree_index": reference.get("tree_index"),
                    "name": (
                        reference.get("file_identifier", {}).get("text")
                        if isinstance(reference.get("file_identifier"), dict)
                        else None
                    ),
                    "fid_directory": reference.get("directory"),
                    "icb_file_type": parsed.get("file_type"),
                    "icb_file_type_name": parsed.get("file_type_name"),
                    "failed_checks": relationship_failed_checks,
                    "valid": not relationship_failed_checks,
                }
                relationships.append(relationship)
                reference["child_icb_index"] = len(children)
                reference["child_icb_status"] = (
                    "validated" if not relationship_failed_checks
                    else "type_mismatch"
                )
                if relationship_failed_checks:
                    child_errors.append({
                        "reason": "fid_child_icb_relationship",
                        "fid_index": reference.get("index"),
                        "failed_checks": relationship_failed_checks,
                    })
            link_count = parsed.get("file_link_count")
            if (
                not isinstance(link_count, int)
                or isinstance(link_count, bool)
                or link_count <= 0
            ):
                child_errors.append({"reason": "child_icb_link_count"})
            elif len(references) > link_count:
                child_errors.append({
                    "reason": "sampled_fid_count_exceeds_link_count",
                    "sampled_count": len(references),
                    "link_count": link_count,
                })
            child = {
                "index": len(children),
                "partition_reference_number": key[0],
                "logical_block_number": key[1],
                "length": key[2],
                "address": first["icb_address"],
                "resolved": resolved,
                "offset": resolved["offset"],
                "end_offset": resolved["end_offset"],
                "fid_indices": [item.get("index") for item in references],
                "fid_tree_indices": [
                    item.get("tree_index") for item in references
                ],
                "relationships": relationships,
                "icb": parsed,
                "errors": child_errors,
                "valid": not child_errors,
            }
            children.append(child)
            if child_errors:
                errors.append({
                    "reason": "invalid_child_icb",
                    "child_index": child["index"],
                    "logical_block_number": key[1],
                    "errors": child_errors,
                })
        return {
            "children": children,
            "unique_icb_count": len(children),
            "active_fid_count": sum(len(items) for items in groups.values()),
            "deleted_fids_not_followed": skipped_deleted,
            "errors": errors,
            "valid": not errors,
        }

    def _icb_allocation_descriptor_metadata(
        self,
        stream,
        icb: dict[str, object],
        implicit_partition_reference: int,
        logical_volume: dict[str, object],
        sequence: dict[str, object],
        block_size: int,
        size: int,
        allocation_extent_budget: dict[str, object],
    ) -> dict[str, object]:
        descriptor_type = icb.get("allocation_descriptor_type")
        information_length = icb.get("information_length")
        logical_blocks_recorded = icb.get("logical_blocks_recorded")
        try:
            raw = bytes.fromhex(str(icb.get("allocation_descriptor_raw_hex", "")))
        except ValueError:
            raw = b""
            encoding_failed = True
        else:
            encoding_failed = False
        kind = {
            0: "short_ad",
            1: "long_ad",
            2: "extended_ad",
            3: "embedded_data",
        }.get(descriptor_type, "unsupported")
        if descriptor_type == 3:
            failed_checks: list[str] = []
            if encoding_failed:
                failed_checks.append("allocation_descriptor_encoding")
            if information_length != len(raw):
                failed_checks.append("embedded_information_length")
            if logical_blocks_recorded != 0:
                failed_checks.append("embedded_logical_blocks_recorded")
            return {
                "kind": kind,
                "descriptor_count": 0,
                "descriptors": [],
                "embedded_length": len(raw),
                "embedded_sha256": hashlib.sha256(raw).hexdigest(),
                "failed_checks": failed_checks,
                "valid": not failed_checks,
            }
        chain = self._allocation_descriptor_chain(
            stream,
            raw,
            descriptor_type,
            implicit_partition_reference,
            logical_volume,
            sequence,
            block_size,
            size,
            initial_encoding_failed=encoding_failed,
            allocation_extent_budget=allocation_extent_budget,
        )
        descriptors = chain["descriptors"]
        failed_checks = list(chain["failed_checks"])
        covered_length = 0
        calculated_recorded_blocks = 0
        for descriptor in descriptors:
            address = descriptor.get("address")
            if not isinstance(address, dict):
                continue
            extent_type = address.get("extent_type")
            if descriptor_type == 2:
                recorded_length = int(address.get("recorded_length", 0))
                extent_information_length = int(
                    address.get("information_length", 0)
                )
            else:
                recorded_length = int(address.get("length", 0))
                extent_information_length = int(address.get("length", 0))
            if extent_type == 0:
                calculated_recorded_blocks += (
                    recorded_length + block_size - 1
                ) // block_size
            covered_length += extent_information_length
        if isinstance(information_length, int) and not isinstance(
            information_length, bool
        ):
            if covered_length < information_length:
                failed_checks.append("allocation_shorter_than_information_length")
            elif covered_length - information_length >= block_size:
                failed_checks.append("excess_allocation_length")
        else:
            failed_checks.append("information_length")
        if logical_blocks_recorded != calculated_recorded_blocks:
            failed_checks.append("logical_blocks_recorded_mismatch")
        failed_checks = list(dict.fromkeys(failed_checks))
        result = {
            "kind": kind,
            "covered_information_length": covered_length,
            "declared_information_length": information_length,
            "calculated_logical_blocks_recorded": calculated_recorded_blocks,
            "declared_logical_blocks_recorded": logical_blocks_recorded,
            "failed_checks": failed_checks,
            "valid": not failed_checks,
        }
        result.update({
            key: value for key, value in chain.items()
            if key not in {"failed_checks", "valid"}
        })
        return result

    def _allocation_descriptor_chain(
        self,
        stream,
        initial_raw: bytes,
        descriptor_type: object,
        implicit_partition_reference: int,
        logical_volume: dict[str, object],
        sequence: dict[str, object],
        block_size: int,
        size: int,
        *,
        initial_encoding_failed: bool = False,
        allocation_extent_budget: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Resolve a bounded Type-1 AED chain and retain every exact source range."""
        descriptor_size = {0: 8, 1: 16, 2: 20}.get(descriptor_type)
        failed_checks: list[str] = []
        if initial_encoding_failed:
            failed_checks.append("allocation_descriptor_encoding")
        if descriptor_size is None:
            failed_checks.append("unsupported_allocation_descriptor_type")
            descriptor_size = 1

        descriptors: list[dict[str, object]] = []
        continuation_descriptors: list[dict[str, object]] = []
        allocation_extents: list[dict[str, object]] = []
        seen_extent_keys: set[tuple[int, int]] = set()
        total_descriptor_count = 0
        chain_complete = False
        current_raw = initial_raw
        source_kind = "icb"
        source_extent_index: int | None = None
        previous_extent_location = 0

        while True:
            if (
                len(current_raw) % descriptor_size
                or total_descriptor_count + len(current_raw) // descriptor_size
                > _ALLOCATION_DESCRIPTOR_LIMIT
            ):
                failed_checks.append("allocation_descriptor_framing")
                break
            next_descriptor: dict[str, object] | None = None
            for raw_offset in range(0, len(current_raw), descriptor_size):
                item_raw = current_raw[raw_offset:raw_offset + descriptor_size]
                if descriptor_type == 0:
                    raw_length = int.from_bytes(item_raw[0:4], "little")
                    address: dict[str, object] = {
                        "raw_hex": item_raw.hex(),
                        "raw_length": raw_length,
                        "extent_type": raw_length >> 30,
                        "length": raw_length & 0x3FFFFFFF,
                        "logical_block_number": int.from_bytes(
                            item_raw[4:8], "little"
                        ),
                        "partition_reference_number": implicit_partition_reference,
                        "implementation_use_raw_hex": None,
                        "implementation_use_flags": None,
                        "valid": bool(raw_length & 0x3FFFFFFF),
                    }
                elif descriptor_type == 1:
                    address = self._allocation_long_ad(item_raw)
                else:
                    address = self._allocation_extended_ad(item_raw)
                extent_type = address.get("extent_type")
                extent_length = address.get("length")
                item_failed_checks: list[str] = []
                if address.get("valid") is not True:
                    item_failed_checks.append("allocation_descriptor")
                if (
                    not isinstance(extent_length, int)
                    or isinstance(extent_length, bool)
                    or extent_length <= 0
                ):
                    item_failed_checks.append("extent_length")
                resolved: dict[str, object] | None = None
                if extent_type in {0, 1, 3}:
                    resolved = self._resolve_partition_address(
                        address,
                        logical_volume,
                        sequence,
                        block_size,
                        size,
                    )
                    if resolved.get("valid") is not True:
                        item_failed_checks.append("partition_resolution")
                elif extent_type == 2:
                    if (
                        address.get("logical_block_number") != 0
                        or address.get("partition_reference_number") not in {
                            0, implicit_partition_reference,
                        }
                    ):
                        item_failed_checks.append("unallocated_extent_location")
                else:
                    item_failed_checks.append("extent_type")
                descriptor = {
                    "index": len(descriptors),
                    "chain_descriptor_index": total_descriptor_count,
                    "source_kind": source_kind,
                    "source_extent_index": source_extent_index,
                    "raw_offset": raw_offset,
                    "address": address,
                    "resolved": resolved,
                    "failed_checks": item_failed_checks,
                    "valid": not item_failed_checks,
                }
                total_descriptor_count += 1
                if extent_type == 3:
                    descriptor["index"] = len(continuation_descriptors)
                    descriptor["kind"] = "continuation"
                    if raw_offset + descriptor_size != len(current_raw):
                        item_failed_checks.append("continuation_not_final_descriptor")
                    if next_descriptor is not None:
                        item_failed_checks.append("multiple_continuations_in_extent")
                    descriptor["valid"] = not item_failed_checks
                    continuation_descriptors.append(descriptor)
                    next_descriptor = descriptor
                else:
                    descriptor["kind"] = "data"
                    descriptors.append(descriptor)
                if item_failed_checks:
                    failed_checks.append("allocation_descriptor")

            if next_descriptor is None:
                chain_complete = True
                break
            if next_descriptor.get("valid") is not True:
                failed_checks.append("allocation_extent_reference")
                break
            if len(allocation_extents) >= _ALLOCATION_EXTENT_LIMIT:
                failed_checks.append("allocation_extent_limit")
                break
            address = next_descriptor["address"]
            resolved = next_descriptor["resolved"]
            extent_length = int(address["length"])
            partition_reference = int(address["partition_reference_number"])
            logical_block_number = int(address["logical_block_number"])
            extent_key = (partition_reference, logical_block_number)
            if extent_key in seen_extent_keys:
                next_descriptor["failed_checks"].append("allocation_extent_cycle")
                next_descriptor["valid"] = False
                failed_checks.extend(("allocation_descriptor", "allocation_extent_cycle"))
                break
            seen_extent_keys.add(extent_key)
            extent_failed_checks: list[str] = []
            if extent_length < 24 or extent_length > block_size:
                extent_failed_checks.append("allocation_extent_length")
            budget_count_before: int | None = None
            budget_bytes_before: int | None = None
            if allocation_extent_budget is not None:
                budget_count_before = int(
                    allocation_extent_budget["allocation_extent_count"]
                )
                budget_bytes_before = int(
                    allocation_extent_budget["allocation_extent_bytes_read"]
                )
                if budget_count_before >= _ALLOCATION_EXTENT_GLOBAL_LIMIT:
                    extent_failed_checks.append("allocation_extent_global_limit")
                if extent_length > (
                    _ALLOCATION_EXTENT_BYTE_LIMIT - budget_bytes_before
                ):
                    extent_failed_checks.append(
                        "allocation_extent_global_byte_limit"
                    )
                current_offset = int(resolved["offset"])
                current_end_offset = int(resolved["end_offset"])
                known_aed_ranges = allocation_extent_budget[
                    "allocation_extent_ranges"
                ]
                if isinstance(known_aed_ranges, list) and any(
                    isinstance(known, dict)
                    and max(current_offset, int(known["offset"]))
                    < min(current_end_offset, int(known["end_offset"]))
                    for known in known_aed_ranges
                ):
                    extent_failed_checks.append(
                        "shared_or_overlapping_allocation_extent"
                    )
                known_directory_ranges = allocation_extent_budget[
                    "directory_extents"
                ]
                if isinstance(known_directory_ranges, list) and any(
                    isinstance(known, dict)
                    and max(current_offset, int(known["offset"]))
                    < min(current_end_offset, int(known["end_offset"]))
                    for known in known_directory_ranges
                ):
                    extent_failed_checks.append(
                        "allocation_extent_directory_data_overlap"
                    )
            if extent_failed_checks:
                extent_raw = b""
                read_error: str | None = None
            else:
                if allocation_extent_budget is not None:
                    allocation_extent_budget["allocation_extent_count"] = (
                        int(budget_count_before) + 1
                    )
                    allocation_extent_budget[
                        "allocation_extent_bytes_read"
                    ] = int(budget_bytes_before) + extent_length
                    known_aed_ranges = allocation_extent_budget[
                        "allocation_extent_ranges"
                    ]
                    if isinstance(known_aed_ranges, list):
                        known_aed_ranges.append({
                            "global_index": int(budget_count_before),
                            "partition_reference_number": partition_reference,
                            "logical_block_number": logical_block_number,
                            "offset": resolved["offset"],
                            "end_offset": resolved["end_offset"],
                            "length": extent_length,
                        })
                try:
                    stream.seek(int(resolved["offset"]))
                    extent_raw = stream.read(extent_length)
                except OSError as exc:
                    extent_raw = b""
                    extent_failed_checks.append("allocation_extent_read")
                    read_error = str(exc)[:2_000]
                else:
                    read_error = None
                    if len(extent_raw) != extent_length:
                        extent_failed_checks.append("truncated_allocation_extent")
            tag = self._descriptor_tag(extent_raw, logical_block_number)
            previous_location = (
                int.from_bytes(extent_raw[16:20], "little")
                if len(extent_raw) >= 20 else None
            )
            allocation_length = (
                int.from_bytes(extent_raw[20:24], "little")
                if len(extent_raw) >= 24 else None
            )
            if tag.get("identifier") != 0x0102:
                extent_failed_checks.append("allocation_extent_descriptor_identifier")
            if tag.get("valid") is not True:
                extent_failed_checks.append("allocation_extent_descriptor_tag")
            if previous_location != previous_extent_location:
                extent_failed_checks.append("previous_allocation_extent_location")
            if (
                not isinstance(allocation_length, int)
                or allocation_length < 0
                or 24 + allocation_length > len(extent_raw)
                or allocation_length % descriptor_size
            ):
                extent_failed_checks.append("allocation_extent_descriptor_framing")
                allocation_raw = b""
            else:
                allocation_raw = extent_raw[24:24 + allocation_length]
                if tag.get("crc_length") != 8 + allocation_length:
                    extent_failed_checks.append("allocation_extent_crc_coverage")
            allocation_extent = {
                "index": len(allocation_extents),
                "partition_reference_number": partition_reference,
                "logical_block_number": logical_block_number,
                "length": extent_length,
                "offset": resolved["offset"],
                "end_offset": resolved["end_offset"],
                "raw_sha256": hashlib.sha256(extent_raw).hexdigest(),
                "descriptor_length": (
                    24 + allocation_length
                    if isinstance(allocation_length, int) else None
                ),
                "descriptor_raw_sha256": hashlib.sha256(
                    extent_raw[:24 + allocation_length]
                    if isinstance(allocation_length, int)
                    and 24 + allocation_length <= len(extent_raw)
                    else extent_raw
                ).hexdigest(),
                "tag": tag,
                "previous_allocation_extent_location": previous_location,
                "expected_previous_allocation_extent_location": previous_extent_location,
                "allocation_descriptor_length": allocation_length,
                "allocation_descriptor_raw_hex": allocation_raw.hex(),
                "allocation_descriptor_raw_sha256": hashlib.sha256(
                    allocation_raw
                ).hexdigest(),
                "continuation_descriptor": next_descriptor,
                "global_count_before": budget_count_before,
                "global_bytes_before": budget_bytes_before,
                "read_error": read_error,
                "failed_checks": extent_failed_checks,
                "valid": not extent_failed_checks,
            }
            allocation_extents.append(allocation_extent)
            if extent_failed_checks:
                failed_checks.append("allocation_extent_descriptor")
                break
            previous_extent_location = logical_block_number
            current_raw = allocation_raw
            source_kind = "allocation_extent"
            source_extent_index = int(allocation_extent["index"])

        physical_sources: list[tuple[str, int, int, dict[str, object]]] = []
        for descriptor in descriptors:
            address = descriptor.get("address")
            resolved = descriptor.get("resolved")
            if (
                isinstance(address, dict)
                and address.get("extent_type") in {0, 1}
                and isinstance(resolved, dict)
                and resolved.get("valid") is True
            ):
                physical_sources.append((
                    "data",
                    int(resolved["offset"]),
                    int(resolved["end_offset"]),
                    descriptor,
                ))
        for extent in allocation_extents:
            physical_sources.append((
                "allocation_extent",
                int(extent["offset"]),
                int(extent["end_offset"]),
                extent,
            ))
        for left_index, left in enumerate(physical_sources):
            for right in physical_sources[left_index + 1:]:
                if max(left[1], right[1]) < min(left[2], right[2]):
                    check = (
                        "allocation_extent_overlap"
                        if "allocation_extent" in {left[0], right[0]}
                        else "physical_extent_overlap"
                    )
                    for item in (left[3], right[3]):
                        item.setdefault("failed_checks", []).append(check)
                        item["valid"] = False
                    failed_checks.append(check)

        failed_checks = list(dict.fromkeys(failed_checks))
        return {
            "descriptor_size": descriptor_size,
            "descriptor_limit": _ALLOCATION_DESCRIPTOR_LIMIT,
            "descriptor_count": len(descriptors),
            "total_descriptor_count": total_descriptor_count,
            "descriptors": descriptors,
            "continuation_descriptor_count": len(continuation_descriptors),
            "continuation_descriptors": continuation_descriptors,
            "allocation_extent_count": len(allocation_extents),
            "allocation_extent_limit": _ALLOCATION_EXTENT_LIMIT,
            "allocation_extents": allocation_extents,
            "chain_complete": chain_complete,
            "failed_checks": failed_checks,
            "valid": not failed_checks and chain_complete,
        }

    @staticmethod
    def _allocation_long_ad(raw: bytes) -> dict[str, object]:
        if len(raw) != 16:
            return {"valid": False, "raw_hex": raw.hex()}
        raw_length = int.from_bytes(raw[0:4], "little")
        flags = int.from_bytes(raw[10:12], "little")
        return {
            "raw_hex": raw.hex(),
            "raw_length": raw_length,
            "extent_type": raw_length >> 30,
            "length": raw_length & 0x3FFFFFFF,
            "logical_block_number": int.from_bytes(raw[4:8], "little"),
            "partition_reference_number": int.from_bytes(raw[8:10], "little"),
            "implementation_use_raw_hex": raw[10:16].hex(),
            "implementation_use_flags": flags,
            "valid": bool(raw_length & 0x3FFFFFFF and flags & ~0x0001 == 0),
        }

    @staticmethod
    def _allocation_extended_ad(raw: bytes) -> dict[str, object]:
        if len(raw) != 20:
            return {"valid": False, "raw_hex": raw.hex()}
        raw_length = int.from_bytes(raw[0:4], "little")
        length = raw_length & 0x3FFFFFFF
        raw_recorded_length = int.from_bytes(raw[4:8], "little")
        recorded_length = raw_recorded_length & 0x3FFFFFFF
        information_length = int.from_bytes(raw[8:12], "little")
        extent_type = raw_length >> 30
        logical_block_number = int.from_bytes(raw[12:16], "little")
        partition_reference_number = int.from_bytes(raw[16:18], "little")
        if extent_type == 0:
            length_relationship_valid = bool(
                recorded_length > 0
                and recorded_length <= length
                and information_length > 0
            )
        elif extent_type in {1, 2}:
            length_relationship_valid = bool(
                recorded_length == 0
                and 0 < information_length <= length
            )
        else:
            length_relationship_valid = bool(
                recorded_length == 0 and information_length == 0
            )
        location_valid = bool(
            length > 0
            or (
                logical_block_number == 0
                and partition_reference_number == 0
            )
        )
        return {
            "raw_hex": raw.hex(),
            "raw_length": raw_length,
            "extent_type": extent_type,
            "length": length,
            "raw_recorded_length": raw_recorded_length,
            "recorded_length": recorded_length,
            "recorded_length_reserved_bits": raw_recorded_length >> 30,
            "information_length": information_length,
            "logical_block_number": logical_block_number,
            "partition_reference_number": partition_reference_number,
            "implementation_use_raw_hex": raw[18:20].hex(),
            "valid": bool(
                length > 0
                and raw_recorded_length >> 30 == 0
                and length_relationship_valid
                and location_valid
            ),
        }
