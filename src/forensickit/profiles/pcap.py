from __future__ import annotations

from ..models import AnalysisMode
from .base import BaseProfile, ProfileContext, ProfileResult


PCAP_TYPES = {"pcap", "pcapng", "network_capture", "packet_capture", "capture"}


class PcapProfile(BaseProfile):
    name = "pcap"
    priority = 800

    def match_reasons(self, context: ProfileContext) -> list[str]:
        reasons: list[str] = []
        matched_types = context.artifact_types & PCAP_TYPES
        if matched_types:
            reasons.append(f"classification includes packet capture type: {sorted(matched_types)}")
        if context.format_is("pcap", "pcapng"):
            reasons.append(f"observed capture format is {context.format}")
        magic = (context.artifact.magic or "").lower()
        mime = (context.artifact.mime or "").lower()
        if "capture file" in magic or "tcpdump" in magic or "pcap" in mime:
            reasons.append("magic/MIME identifies a packet capture")
        return reasons

    def analyze(self, context: ProfileContext) -> ProfileResult:
        result = ProfileResult(profile=self.name, matched=True)
        result.recommendations.extend(
            [
                self.recommendation(
                    "capinfos",
                    (AnalysisMode.AUTO, AnalysisMode.DEEP),
                    "collect capture bounds, packet counts, and link-layer metadata",
                    115,
                ),
                self.recommendation(
                    "tshark",
                    (AnalysisMode.AUTO, AnalysisMode.DEEP),
                    "enumerate protocols, endpoints, conversations, DNS, and HTTP evidence",
                    105,
                ),
            ]
        )

        long_labels = context.truthy("pcap.dns.long_labels", "pcap.dns.suspicious_labels")
        query_count = context.number("pcap.dns.query_count", "pcap.dns.queries")
        if long_labels and (query_count is None or query_count > 20):
            count_text = f" across {int(query_count)} queries" if query_count is not None else ""
            reason = f"unusually long DNS labels were observed{count_text}"
            result.findings.append(
                self.finding(
                    context,
                    title="Suspicious DNS label pattern",
                    category="possible_dns_encoding",
                    confidence=0.78 if query_count is not None else 0.68,
                    explanation="Long repeated labels can carry encoded CTF data or DNS-tunnel payloads.",
                    evidence=[reason],
                    severity="medium",
                )
            )
            result.recommendations.append(
                self.recommendation(
                    "tshark", (AnalysisMode.AUTO, AnalysisMode.DEEP),
                    "extract and order suspicious DNS query names", 125,
                )
            )

        if context.truthy("pcap.http.objects", "pcap.http.has_objects", "pcap.exportable_objects"):
            result.recommendations.append(
                self.recommendation(
                    "tshark", (AnalysisMode.AUTO, AnalysisMode.DEEP),
                    "capture contains exportable application-layer objects for recursive analysis", 120,
                )
            )
        tls_names = next((value for value in context.values("pcap.tls.server_names") if isinstance(value, list)), [])
        if tls_names:
            result.findings.append(
                self.finding(
                    context,
                    title="TLS ClientHello server names recovered",
                    category="pcap_tls_sni",
                    confidence=0.85,
                    explanation="Plaintext TLS ClientHello metadata reveals requested server names without decrypting traffic.",
                    evidence=[str(name)[:1_000] for name in tls_names[:50]],
                    severity="info",
                )
            )
        tls_hellos = next((value for value in context.values("pcap.tls.client_hellos") if isinstance(value, list)), [])
        tls_alpn = [item for item in tls_hellos if isinstance(item, dict) and item.get("alpn_protocols")]
        if tls_alpn:
            result.findings.append(
                self.finding(
                    context,
                    title="TLS ClientHello application protocols recovered",
                    category="pcap_tls_alpn",
                    confidence=0.84,
                    explanation="Plaintext TLS ClientHello ALPN values identify requested application protocols without decrypting traffic; packet and endpoint provenance are retained.",
                    evidence=[str(item)[:2_000] for item in tls_alpn[:50]],
                    severity="info",
                )
            )
        server_hellos = next((value for value in context.values("pcap.tls.server_hellos") if isinstance(value, list)), [])
        selected_alpn = [item for item in server_hellos if isinstance(item, dict) and item.get("selected_alpn")]
        if selected_alpn:
            result.findings.append(
                self.finding(
                    context, title="TLS ServerHello selected application protocol recovered", category="pcap_tls_alpn",
                    confidence=0.86,
                    explanation="A plaintext TLS ServerHello selected an ALPN application protocol. Packet/endpoint provenance and cipher suite are retained without decrypting application data.",
                    evidence=[str(item)[:2_000] for item in selected_alpn[:50]], severity="info",
                )
            )
        tls_certificates = next((value for value in context.values("pcap.tls.certificates") if isinstance(value, list)), [])
        if tls_certificates:
            result.findings.append(
                self.finding(
                    context,
                    title="TLS certificate chain inventory recovered",
                    category="pcap_tls_certificate_inventory",
                    confidence=0.9,
                    explanation="A complete plaintext TLS Certificate record exposed bounded certificate lengths and SHA-256 fingerprints with exact packet and endpoint provenance. Certificate subject/issuer semantics are deliberately left to tshark or X.509 tooling.",
                    evidence=[str(item)[:2_000] for item in tls_certificates[:50]],
                    severity="info",
                )
            )
        tls_certificate_errors = next((value for value in context.values("pcap.tls.certificate_errors") if isinstance(value, list)), [])
        if tls_certificate_errors:
            result.findings.append(
                self.finding(
                    context,
                    title="TLS Certificate metadata could not be structurally parsed",
                    category="pcap_tls_structure_anomaly",
                    confidence=0.78,
                    explanation="A complete-looking TLS Certificate record failed bounded handshake/list validation. It may be truncated, malformed, encrypted, or outside native single-record inventory scope.",
                    evidence=[str(item)[:2_000] for item in tls_certificate_errors[:50]],
                    severity="low",
                )
            )
        tls_certificate_incomplete = next((value for value in context.values("pcap.tls.certificate_incomplete_flows") if isinstance(value, list)), [])
        if tls_certificate_incomplete:
            result.findings.append(
                self.finding(
                    context,
                    title="TLS Certificate capture ended before the bounded record completed",
                    category="pcap_analysis_limit",
                    confidence=0.8,
                    explanation="The capture ended with one or more in-order TLS Certificate records short of their declared length. This can be ordinary capture truncation; only collected packet provenance is reported.",
                    evidence=[str(item)[:2_000] for item in tls_certificate_incomplete[:50]],
                    severity="info",
                )
            )
        if context.truthy("pcap.tls.certificate_flow_state_truncated"):
            result.findings.append(
                self.finding(
                    context,
                    title="TLS Certificate flow-state limit reached",
                    category="pcap_analysis_limit",
                    confidence=0.9,
                    explanation="Native Certificate continuation tracking reached its 4,096-flow safety limit. Additional incomplete TLS certificate flows were not retained, while complete single-packet records remain independently parsed.",
                    evidence=["pcap.tls.certificate_flow_state_truncated=true"],
                    severity="info",
                )
            )
        tls_negotiations = next((value for value in context.values("pcap.tls.negotiations") if isinstance(value, list)), [])
        alpn_mismatches = [
            item for item in tls_negotiations
            if isinstance(item, dict)
            and item.get("selected_alpn_offered") is False
            and isinstance(item.get("selected_alpn"), str)
        ]
        if alpn_mismatches:
            result.findings.append(
                self.finding(
                    context,
                    title="TLS selected ALPN was absent from the correlated ClientHello offer",
                    category="pcap_tls_negotiation_anomaly",
                    confidence=0.84,
                    explanation="A complete ClientHello and later inverse-flow ServerHello were correlated by exact endpoint/port tuple, but the selected ALPN was not among the captured offer. This is a bounded verification lead: retransmission loss, capture gaps, or nonstandard traffic can still require tshark or packet-level review.",
                    evidence=[str(item)[:2_000] for item in alpn_mismatches[:50]],
                    severity="low",
                )
            )
        server_hello_errors = next((value for value in context.values("pcap.tls.server_hello_errors") if isinstance(value, list)), [])
        if server_hello_errors:
            result.findings.append(
                self.finding(
                    context, title="TLS ServerHello metadata could not be structurally parsed", category="pcap_tls_structure_anomaly",
                    confidence=0.78,
                    explanation="A packet advertised a TLS ServerHello but failed bounded record or extension validation. It may be truncated, malformed, or outside native triage's single-record scope.",
                    evidence=[str(item)[:2_000] for item in server_hello_errors[:50]], severity="low",
                )
            )
        tls_errors = next((value for value in context.values("pcap.tls.client_hello_errors") if isinstance(value, list)), [])
        if tls_errors:
            result.findings.append(
                self.finding(
                    context, title="TLS ClientHello metadata could not be structurally parsed", category="pcap_tls_structure_anomaly",
                    confidence=0.78,
                    explanation="A packet advertised a TLS ClientHello but failed bounded record or extension validation. It may be truncated, fragmented, malformed, or outside native triage's single-record scope.",
                    evidence=[str(item)[:2_000] for item in tls_errors[:50]], severity="low",
                )
            )
        tls_incomplete = next((value for value in context.values("pcap.tls.client_hello_incomplete_flows") if isinstance(value, list)), [])
        if tls_incomplete:
            result.findings.append(
                self.finding(
                    context, title="TLS ClientHello capture ended before the bounded record completed", category="pcap_analysis_limit",
                    confidence=0.8,
                    explanation="The capture ended with one or more in-order TLS ClientHello records short of their declared length. This can be ordinary capture truncation; only collected packet provenance is reported.",
                    evidence=[str(item)[:2_000] for item in tls_incomplete[:50]], severity="info",
                )
            )
        tls_server_incomplete = next((value for value in context.values("pcap.tls.server_hello_incomplete_flows") if isinstance(value, list)), [])
        if tls_server_incomplete:
            result.findings.append(
                self.finding(
                    context, title="TLS ServerHello capture ended before the bounded record completed", category="pcap_analysis_limit",
                    confidence=0.8,
                    explanation="The capture ended with one or more in-order TLS ServerHello records short of their declared length. This can be ordinary capture truncation; only collected packet provenance is reported.",
                    evidence=[str(item)[:2_000] for item in tls_server_incomplete[:50]], severity="info",
                )
            )
        if context.truthy("pcap.tls.client_hello_flow_state_truncated"):
            result.findings.append(
                self.finding(
                    context, title="TLS ClientHello flow-state limit reached", category="pcap_analysis_limit",
                    confidence=0.9,
                    explanation="Native ClientHello continuation tracking reached its 4,096-flow safety limit. Additional incomplete TLS flows were not retained, while complete single-packet records remain independently parsed.",
                    evidence=["pcap.tls.client_hello_flow_state_truncated=true"], severity="info",
                )
            )
        if context.truthy("pcap.tls.server_hello_flow_state_truncated"):
            result.findings.append(
                self.finding(
                    context, title="TLS ServerHello flow-state limit reached", category="pcap_analysis_limit",
                    confidence=0.9,
                    explanation="Native ServerHello continuation tracking reached its 4,096-flow safety limit. Additional incomplete TLS flows were not retained, while complete single-packet records remain independently parsed.",
                    evidence=["pcap.tls.server_hello_flow_state_truncated=true"], severity="info",
                )
            )
        txt_records = next((value for value in context.values("pcap.dns.txt_records") if isinstance(value, list)), [])
        suspicious_txt = [
            item for item in txt_records
            if isinstance(item, dict) and any(marker in str(item.get("text", "")).lower() for marker in ("ctf{", "flag{", "base64", "token", "secret"))
        ]
        if suspicious_txt:
            result.findings.append(
                self.finding(
                    context,
                    title="DNS TXT response contains investigation-relevant text",
                    category="pcap_dns_txt_lead",
                    confidence=0.84,
                    explanation="A bounded DNS response parser recovered plaintext TXT data with CTF or secret-like markers. Original packet bytes remain the authoritative evidence.",
                    evidence=[str(item)[:2_000] for item in suspicious_txt[:50]],
                    severity="low",
                )
            )
        txt_reassemblies = next(
            (value for value in context.values("pcap.dns.txt_reassemblies") if isinstance(value, list)), []
        )
        decoded_reassemblies = [
            item for item in txt_reassemblies
            if isinstance(item, dict) and item.get("transform") == "base64" and item.get("decoded_text")
        ]
        if decoded_reassemblies:
            result.findings.append(
                self.finding(
                    context,
                    title="DNS TXT fragments reconstruct to Base64-decoded content",
                    category="pcap_dns_txt_reassembly",
                    confidence=0.86,
                    explanation="Adjacent encoding-shaped DNS TXT records from one endpoint pair were boundedly joined; packet indices retain the original evidence locations.",
                    evidence=[str(item)[:2_000] for item in decoded_reassemblies[:50]],
                    severity="low",
                )
            )
        txt_request_links = next((value for value in context.values("pcap.dns.txt_reassembly_request_packets") if isinstance(value, list)), [])
        if txt_request_links:
            result.observations.append(self.observation(context, "pcap.dns.txt_reassembly_request_packet_count", len(txt_request_links), 0.9))
        udp_payloads = next((value for value in context.values("pcap.udp.printable_payloads") if isinstance(value, list)), [])
        flagged_udp = [item for item in udp_payloads if isinstance(item, dict) and any(marker in str(item.get("text", "")).casefold() for marker in ("ctf{", "flag{", "base64", "token", "secret"))]
        if flagged_udp:
            result.findings.append(self.finding(
                context, title="Printable non-DNS UDP payload contains investigation-relevant text", category="pcap_udp_payload_lead",
                confidence=0.8, explanation="Bounded native UDP triage recovered printable payload bytes with endpoint, port, and packet provenance. Inspect the immutable capture for full context.",
                evidence=[str(item)[:2_000] for item in flagged_udp[:50]], severity="low",
            ))
        icmp_payloads = next((value for value in context.values("pcap.icmp.printable_payloads") if isinstance(value, list)), [])
        flagged_icmp = [item for item in icmp_payloads if isinstance(item, dict) and any(marker in str(item.get("text", "")).casefold() for marker in ("ctf{", "flag{", "base64", "token", "secret"))]
        if flagged_icmp:
            result.findings.append(self.finding(
                context, title="Printable ICMP payload contains investigation-relevant text", category="pcap_icmp_payload_lead",
                confidence=0.8, explanation="Bounded native ICMP triage recovered printable payload bytes with packet and endpoint provenance. This is a content lead, not a network-behavior verdict.",
                evidence=[str(item)[:2_000] for item in flagged_icmp[:50]], severity="low",
            ))
        tcp_payloads = next((value for value in context.values("pcap.tcp.printable_payloads") if isinstance(value, list)), [])
        flagged_tcp = [item for item in tcp_payloads if isinstance(item, dict) and any(marker in str(item.get("text", "")).casefold() for marker in ("ctf{", "flag{", "base64", "token", "secret"))]
        if flagged_tcp:
            result.findings.append(self.finding(
                context, title="Printable non-HTTP TCP payload contains investigation-relevant text", category="pcap_tcp_payload_lead",
                confidence=0.8, explanation="Bounded native TCP triage recovered printable non-HTTP payload bytes with endpoint, port, and packet provenance. Preserve the capture and validate application protocol context before attribution.",
                evidence=[str(item)[:2_000] for item in flagged_tcp[:50]], severity="low",
            ))
        payload_summary = []
        for protocol, rows in (("udp", flagged_udp), ("icmp", flagged_icmp), ("tcp", flagged_tcp)):
            for row in rows[:200 - len(payload_summary)]:
                payload_summary.append({"protocol": protocol, **row})
            if len(payload_summary) >= 200:
                break
        if payload_summary:
            result.observations.append(self.observation(context, "pcap.printable_payload_leads", payload_summary, 0.8))
        transactions = next((value for value in context.values("pcap.dns.transaction_matches") if isinstance(value, list)), [])
        if transactions:
            result.findings.append(self.finding(
                context, title="DNS request/response transactions correlated", category="pcap_dns_transaction_inventory",
                confidence=0.9, explanation="Bounded DNS transaction IDs and inverse UDP endpoint tuples linked requests to responses; packet indices preserve the evidence chain.",
                evidence=[str(item)[:2_000] for item in transactions[:50]], severity="info",
            ))
        if context.truthy("pcap.http.flow_state_truncated"):
            result.findings.append(self.finding(
                context, title="PCAP HTTP flow-state tracking reached its bound", category="pcap_analysis_limit",
                confidence=1.0, explanation="Native packet triage capped HTTP flow-state tracking to preserve deterministic memory bounds. Use tshark for exhaustive flow dissection.",
                evidence=["pcap.http.flow_state_truncated=true"], severity="info",
            ))
        return result
