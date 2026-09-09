from __future__ import annotations

import re

from ..models import AnalysisMode
from .base import BaseProfile, ProfileContext, ProfileResult


class PdfProfile(BaseProfile):
    name = "pdf"
    priority = 760

    def match_reasons(self, context: ProfileContext) -> list[str]:
        if context.classified_as("pdf") or context.format_is("pdf"):
            return ["signature classification identifies a PDF document"]
        if (context.artifact.mime or "").lower() == "application/pdf":
            return [f"MIME is {context.artifact.mime}"]
        return []

    def analyze(self, context: ProfileContext) -> ProfileResult:
        result = ProfileResult(profile=self.name, matched=True)
        result.recommendations.extend(
            [
                self.recommendation("pdfid", (AnalysisMode.AUTO, AnalysisMode.DEEP), "enumerate PDF objects and active-content indicators", 110),
                self.recommendation("pdfinfo", (AnalysisMode.AUTO, AnalysisMode.DEEP), "recover document metadata and encryption status with Poppler", 95),
                self.recommendation("pdftotext", (AnalysisMode.AUTO, AnalysisMode.DEEP), "recover bounded text evidence for content and flag leads", 90),
                self.recommendation("qpdf", (AnalysisMode.AUTO, AnalysisMode.DEEP), "validate PDF syntax and stream structure without rewriting the evidence", 88),
                self.recommendation("pdfimages", (AnalysisMode.DEEP,), "extract embedded images into recursive image/steganography triage", 75),
                self.recommendation("pdf_parser", (AnalysisMode.DEEP,), "deep mode permits object/statistics inspection", 70),
            ]
        )
        javascript = context.number("pdf.javascript_marker_count") or 0
        open_action = context.number("pdf.open_action_marker_count") or 0
        trailing = context.number("pdf.bytes_after_eof") or 0
        if javascript or open_action:
            result.findings.append(
                self.finding(
                    context,
                    title="PDF active-content marker observed",
                    category="pdf_active_content",
                    confidence=0.75,
                    explanation="Static PDF markers indicate JavaScript or an automatic action; object-level verification is recommended.",
                    evidence=[f"JavaScript={int(javascript)}", f"OpenAction={int(open_action)}"],
                )
            )
        if trailing > 0:
            result.findings.append(
                self.finding(
                    context,
                    title="Data exists after PDF EOF marker",
                    category="structural_anomaly",
                    confidence=0.85,
                    explanation="Trailing bytes after the final %%EOF may be an appended payload.",
                    evidence=[f"{int(trailing)} byte(s) after %%EOF"],
                )
            )
        embedded_files = context.number("pdf.embedded_file_marker_count") or 0
        if embedded_files > 0:
            result.recommendations.append(
                self.recommendation(
                    "pdfdetach", (AnalysisMode.DEEP,),
                    "native triage observed EmbeddedFile markers; use Poppler attachment recovery as an independent recursive extraction path",
                    80,
                )
            )
        return result


class OfficeProfile(BaseProfile):
    name = "office"
    priority = 760

    def match_reasons(self, context: ProfileContext) -> list[str]:
        if context.classified_as("office") or context.format_is("ole", "docx", "xlsx", "pptx", "ooxml"):
            return ["signature/container classification identifies an Office artifact"]
        return []

    def analyze(self, context: ProfileContext) -> ProfileResult:
        result = ProfileResult(profile=self.name, matched=True)
        reason = "inspect macros, streams, and embedded Office objects"
        result.recommendations.extend(
            [
                self.recommendation("olevba", (AnalysisMode.AUTO, AnalysisMode.DEEP), reason, 110),
                self.recommendation("oledump", (AnalysisMode.AUTO, AnalysisMode.DEEP), reason, 100),
            ]
        )
        vba_parts = next((value for value in context.values("office.ooxml.vba_parts") if isinstance(value, list)), [])
        external_links = next((value for value in context.values("office.ooxml.external_relationships") if isinstance(value, list)), [])
        embedded_parts = next((value for value in context.values("office.ooxml.embedded_parts") if isinstance(value, list)), [])
        ole_macro_streams = next((value for value in context.values("office.ole.macro_stream_names") if isinstance(value, list)), [])
        if vba_parts:
            result.findings.append(
                self.finding(
                    context,
                    title="OOXML package contains a VBA project",
                    category="office_macro",
                    confidence=0.98,
                    explanation="A vbaProject.bin part was found in the OOXML package; macro code should be inspected without enabling execution.",
                    evidence=[str(part)[:1_000] for part in vba_parts[:50]],
                )
            )
        if external_links:
            result.findings.append(
                self.finding(
                    context,
                    title="OOXML package has external relationships",
                    category="office_external_relationship",
                    confidence=0.9,
                    explanation="Relationship metadata references external targets. The engine records them as evidence and never dereferences them.",
                    evidence=[str(link)[:2_000] for link in external_links[:50]],
                )
            )
        if embedded_parts:
            result.findings.append(
                self.finding(
                    context,
                    title="OOXML package contains embedded object parts",
                    category="office_embedded_object",
                    confidence=0.85,
                    explanation="Embedded OLE/package parts were found and become recursive artifacts through the bounded ZIP extractor.",
                    evidence=[str(part)[:1_000] for part in embedded_parts[:50]],
                    severity="low",
                )
            )
        if ole_macro_streams:
            result.findings.append(
                self.finding(
                    context,
                    title="OLE compound document exposes macro-associated streams",
                    category="office_macro",
                    confidence=0.82,
                    explanation="The bounded Compound File directory inventory contains VBA/project/dir stream names. Use olevba or oledump for content-level confirmation.",
                    evidence=[str(name)[:512] for name in ole_macro_streams[:50]],
                )
            )
        return result


class SqliteProfile(BaseProfile):
    name = "sqlite"
    priority = 750

    def match_reasons(self, context: ProfileContext) -> list[str]:
        if context.classified_as("sqlite") or context.format_is("sqlite"):
            return ["SQLite header signature was identified"]
        return []

    def analyze(self, context: ProfileContext) -> ProfileResult:
        result = ProfileResult(profile=self.name, matched=True)
        result.recommendations.append(
            self.recommendation(
                "sqlite3",
                (AnalysisMode.AUTO, AnalysisMode.DEEP),
                "perform readonly schema/table inventory before targeted queries",
                105,
            )
        )
        suspicious_values = context.values("sqlite.suspicious_table_names")
        suspicious = next((value for value in suspicious_values if isinstance(value, list)), [])
        if suspicious:
            result.findings.append(
                self.finding(
                    context,
                    title="SQLite schema contains investigation-relevant table names",
                    category="sqlite_schema_lead",
                    confidence=0.8,
                    explanation="The read-only SQLite schema inventory found table names commonly associated with credentials, messages, history, or CTF flags.",
                    evidence=[str(name)[:512] for name in suspicious[:50]],
                )
            )
        if context.truthy("sqlite.wal_mode"):
            result.findings.append(
                self.finding(
                    context,
                    title="SQLite database indicates WAL journaling",
                    category="sqlite_wal",
                    confidence=0.85,
                    explanation="The header reports WAL journaling; a companion -wal file, when separately available as evidence, can contain recent records.",
                    evidence=["sqlite.wal_mode=true"],
                )
            )
        samples = next((value for value in context.values("sqlite.sample_rows") if isinstance(value, list)), [])
        suspicious_samples = [
            row for row in samples
            if isinstance(row, dict) and re.search(r"(?:flag|secret|password|credential|token|cookie|history|message|chat)", str(row.get("table", "")), re.I)
        ]
        if suspicious_samples:
            result.findings.append(
                self.finding(
                    context,
                    title="SQLite row samples recovered from investigation-relevant tables",
                    category="sqlite_row_lead",
                    confidence=0.84,
                    explanation="A bounded read-only query sampled rows from tables whose names indicate likely investigative value. Full raw data remains in the immutable evidence file.",
                    evidence=[str(row)[:2_000] for row in suspicious_samples[:20]],
                    severity="low",
                )
            )
        browser_records = next(
            (value for value in context.values("browser.wal_records") if isinstance(value, list) and value),
            next((value for value in context.values("browser.records") if isinstance(value, list)), []),
        )
        browser_family = next(
            (value for value in context.values("browser.wal_family") if isinstance(value, str)),
            next((value for value in context.values("browser.family") if isinstance(value, str)), None),
        )
        if browser_family and browser_records:
            kinds: dict[str, int] = {}
            for record in browser_records:
                if isinstance(record, dict):
                    kind = str(record.get("kind") or "unknown")
                    kinds[kind] = kinds.get(kind, 0) + 1
            result.findings.append(self.finding(
                context,
                title=f"{browser_family.title()} browser activity records normalized",
                category="browser_activity_inventory",
                confidence=0.92,
                explanation=(
                    "Fixed, read-only queries matched a known browser schema and normalized bounded visit, download, search, or form-history rows. "
                    "Raw timestamps and their epoch/unit are retained beside UTC conversions; a history record is evidence of stored application state, not proof of a particular user's action."
                ),
                evidence=[f"record_counts={kinds}", *[str(item)[:2_000] for item in browser_records[:50]]],
                severity="info",
            ))
        if context.truthy("browser.wal_applied"):
            companions = next(
                (value for value in context.values("browser.wal_companions") if isinstance(value, list)), []
            )
            result.findings.append(self.finding(
                context,
                title="Supplied browser SQLite WAL included in read-only snapshot",
                category="browser_sqlite_wal",
                confidence=0.97,
                explanation=(
                    "An exactly named, independently ingested WAL companion with a valid SQLite WAL signature was copied beside the database in case cache and read in query-only mode. "
                    "The original database, WAL, and optional SHM evidence were not modified."
                ),
                evidence=[str(item)[:2_000] for item in companions],
                severity="info",
            ))
        return result
