from __future__ import annotations

from ..models import AnalysisMode
from .base import BaseProfile, ProfileContext, ProfileResult


_IOS_MANIFEST_PATH_KINDS: tuple[tuple[str, tuple[str, ...], str, str], ...] = (
    (
        "messages",
        ("library/sms/sms.db", "library/sms/attachments"),
        "iOS backup references Messages data",
        "ios_backup_messages_lead",
    ),
    (
        "call_history",
        ("library/callhistorydb/", "callhistory.storedata"),
        "iOS backup references call-history data",
        "ios_backup_call_history_lead",
    ),
    (
        "safari_history",
        ("library/safari/history.db",),
        "iOS backup references Safari history",
        "ios_backup_browser_history_lead",
    ),
    (
        "notes",
        ("library/notes/notes", "notes.sqlite"),
        "iOS backup references Notes data",
        "ios_backup_notes_lead",
    ),
    (
        "location",
        ("consolidated.db", "cache.encrypteda.db"),
        "iOS backup references location-related data",
        "ios_backup_location_lead",
    ),
    (
        "wifi",
        ("com.apple.wifi.known-networks.plist",),
        "iOS backup references known Wi-Fi network metadata",
        "ios_backup_wifi_lead",
    ),
    (
        "keychain",
        ("keychain-2.db", "keychain"),
        "iOS backup references Keychain data",
        "ios_backup_keychain_lead",
    ),
)


class MobileProfile(BaseProfile):
    """Offline-first routing for Android backups and iOS backup metadata."""

    name = "mobile"
    priority = 690

    def match_reasons(self, context: ProfileContext) -> list[str]:
        if context.classified_as("android", "ios", "mobile"):
            return ["artifact classification identifies mobile backup evidence"]
        if context.truthy("mobile.android_backup_valid"):
            return ["Android backup header is structurally valid"]
        if context.truthy("mobile.ios_manifest_detected", "mobile.ios_backup_info_plist"):
            return ["iOS backup metadata was identified by bounded native triage"]
        return []

    def analyze(self, context: ProfileContext) -> ProfileResult:
        result = ProfileResult(profile=self.name, matched=True)
        is_android_backup = context.format_is("android_backup") or context.truthy("mobile.android_backup_valid")
        if is_android_backup:
            encryption = next((value for value in context.values("mobile.android_backup_encryption") if isinstance(value, str)), None)
            if encryption and encryption.lower() != "none":
                result.findings.append(self.finding(
                    context, title="Android backup payload is encrypted", category="mobile_backup_encryption",
                    confidence=0.98,
                    explanation="The plaintext Android Backup header declares encryption; payload analysis requires credentials and is not attempted automatically.",
                    evidence=[f"encryption={encryption}"],
                ))
            else:
                result.recommendations.append(self.recommendation(
                    "aleapp", (AnalysisMode.DEEP,),
                    "Android backup/header evidence warrants offline ALEAPP artifact parsing", 90,
                ))
        if context.format_is("apk"):
            result.recommendations.extend([
                self.recommendation(
                    "jadx", (AnalysisMode.AUTO, AnalysisMode.DEEP),
                    "APK ZIP entries include AndroidManifest.xml and classes.dex; decompile code and resources offline", 100,
                ),
                self.recommendation(
                    "apktool", (AnalysisMode.DEEP,),
                    "APK structure warrants a second resource/manifest decode path", 85,
                ),
            ])
            package_name = next(
                (value for value in context.values("android.apk.package_name") if isinstance(value, str) and value), None
            )
            dex_count = context.number("android.apk.dex_count")
            native_libraries = next(
                (value for value in context.values("android.apk.native_libraries") if isinstance(value, list)), []
            )
            if package_name or dex_count is not None or native_libraries:
                evidence = []
                if package_name:
                    evidence.append(f"package={package_name}")
                if dex_count is not None:
                    evidence.append(f"classes_dex_count={int(dex_count)}")
                evidence.extend(f"native_library={name}" for name in native_libraries[:20])
                result.findings.append(self.finding(
                    context, title="APK package structure metadata recovered", category="android_apk_metadata",
                    confidence=0.9,
                    explanation="Bounded ZIP/manifest inspection recovered APK package structure before external decompilation; binary Android XML remains delegated to JADX/APKTool.",
                    evidence=evidence, severity="info",
                ))
            suspicious_permissions = next(
                (value for value in context.values("android.apk.suspicious_permissions") if isinstance(value, list)), []
            )
            if suspicious_permissions:
                result.findings.append(self.finding(
                    context, title="APK plaintext manifest requests high-impact permissions", category="android_apk_permission_lead",
                    confidence=0.82,
                    explanation="A bounded plaintext AndroidManifest.xml inspection found permissions commonly relevant to SMS, accessibility, overlays, recording, installation, or broad storage access. This is a triage lead, not a maliciousness verdict.",
                    evidence=[str(permission)[:512] for permission in suspicious_permissions[:50]], severity="low",
                ))
        is_ios_backup = context.classified_as("ios") or context.truthy(
            "mobile.ios_manifest_detected", "mobile.ios_backup_info_plist",
        )
        if is_ios_backup:
            result.recommendations.append(self.recommendation(
                "ileapp", (AnalysisMode.DEEP,),
                "iOS backup metadata warrants offline iLEAPP backup parsing", 90,
            ))
            tables = next((value for value in context.values("sqlite.tables") if isinstance(value, list)), [])
            if context.truthy("mobile.ios_backup_info_plist"):
                metadata = next((value for value in context.values("plist.scalar_metadata") if isinstance(value, dict)), {})
                result.findings.append(self.finding(
                    context, title="iOS backup Info.plist identified", category="ios_backup_info",
                    confidence=0.94,
                    explanation="A structurally valid Info.plist contains backup identity and product-version fields; supply its sibling Manifest.db and hashed payload files for full offline correlation.",
                    evidence=[f"{key}={value}" for key, value in list(metadata.items())[:30]], severity="info",
                ))
            else:
                samples = next(
                    (value for value in context.values("mobile.ios_manifest_file_samples") if isinstance(value, list)), []
                )
                domains = next(
                    (value for value in context.values("mobile.ios_manifest_domain_counts") if isinstance(value, list)), []
                )
                result.findings.append(self.finding(
                    context, title="iOS backup Manifest.db identified", category="ios_backup_manifest",
                    confidence=0.9,
                    explanation="A SQLite Manifest.db with iOS backup schema tables was identified; a bounded Files table sample links backup file IDs to domains and paths without decoding metadata BLOBs.",
                    evidence=[str(item)[:2_000] for item in (samples[:20] or domains[:20] or tables[:50])], severity="info",
                ))
                references = next(
                    (value for value in context.values("mobile.ios_manifest_file_references") if isinstance(value, list)),
                    samples,
                )
                semantic_paths = self._ios_manifest_semantic_paths(references)
                if semantic_paths:
                    result.observations.append(self.observation(
                        context, "mobile.ios_manifest_semantic_paths", semantic_paths, confidence=0.98,
                    ))
                    result.findings.append(self.finding(
                        context,
                        title="iOS backup contains investigation-relevant artifact paths",
                        category="ios_backup_semantic_path_inventory",
                        confidence=0.98,
                        explanation=(
                            "Manifest.db fixed-column file IDs, domains, and relative paths identify recoverable "
                            "artifact classes. No opaque Manifest.db file BLOB was decoded or modified."
                        ),
                        evidence=[
                            f"{kind}: {len(paths)} reference(s)"
                            for kind, paths in semantic_paths.items()
                        ],
                        severity="info",
                    ))
                    for kind, _needles, title, category in _IOS_MANIFEST_PATH_KINDS:
                        paths = semantic_paths.get(kind, [])
                        if not paths:
                            continue
                        result.findings.append(self.finding(
                            context,
                            title=title,
                            category=category,
                            confidence=0.95,
                            explanation=(
                                "A fixed-column Manifest.db path reference identifies this artifact class. "
                                "The result is a collection lead; payload bytes and opaque metadata were not decoded."
                            ),
                            evidence=[
                                f"{item['domain']}/{item['relative_path']} (fileID={item['file_id']})"
                                for item in paths[:20]
                            ],
                            severity="info",
                        ))
        leapp_count = context.number("mobile.leapp.record_count")
        leapp_records = next((value for value in context.values("mobile.leapp.records") if isinstance(value, list)), [])
        if leapp_count is not None and leapp_count > 0:
            result.findings.append(self.finding(
                context, title="Mobile artifact parser produced normalized records", category="mobile_artifact_lead",
                confidence=0.82,
                explanation="ALEAPP/iLEAPP generated structured records that were boundedly normalized; preserved report artifacts provide full context for follow-up.",
                evidence=[str(item)[:2_000] for item in leapp_records[:20]] or [f"record_count={int(leapp_count)}"],
                severity="info",
            ))
        return result

    @staticmethod
    def _ios_manifest_semantic_paths(references: object) -> dict[str, list[dict[str, str]]]:
        """Classify only bounded, fixed-column Manifest.db references.

        ``fileID``, ``domain``, and ``relativePath`` are read by the native
        SQLite inventory.  Deliberately ignore all other columns, especially
        the opaque ``file`` BLOB, so semantic routing remains reproducible and
        cannot turn into implicit metadata decoding.
        """
        if not isinstance(references, list):
            return {}
        classified: dict[str, list[dict[str, str]]] = {}
        for reference in references[:1_000]:
            if not isinstance(reference, dict):
                continue
            file_id = reference.get("file_id")
            domain = reference.get("domain")
            relative_path = reference.get("relative_path")
            if not all(isinstance(value, str) and value for value in (file_id, domain, relative_path)):
                continue
            normalized = relative_path.replace("\\", "/").casefold().lstrip("/")
            item = {"file_id": file_id[:40], "domain": domain[:512], "relative_path": relative_path[:2_000]}
            for kind, needles, _title, _category in _IOS_MANIFEST_PATH_KINDS:
                if any(needle in normalized for needle in needles):
                    bucket = classified.setdefault(kind, [])
                    if len(bucket) < 50:
                        bucket.append(item)
        return classified
