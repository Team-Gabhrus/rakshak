"""
Export Service — FR-15, FR-20: JSON, XML, CSV, PDF export.
"""
import csv
import json
import io
import os
from datetime import datetime
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select


REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)


async def generate_report_file(db: AsyncSession, modules: list, fmt: str, report_id: int, password: str = None) -> str:
    """Generate a report file in the specified format and return path."""
    data = await collect_report_data(db, modules)
    filename = f"rakshak_report_{report_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{fmt}"
    filepath = str(REPORTS_DIR / filename)

    if fmt == "json":
        _export_json(data, filepath)
    elif fmt == "xml":
        _export_xml(data, filepath)
    elif fmt == "csv":
        _export_csv(data, filepath)
    elif fmt == "pdf":
        _export_pdf(data, filepath, password)

    return filepath


async def collect_report_data(db: AsyncSession, modules: list) -> dict:
    """Collect data from requested modules."""
    from app.models.asset import Asset, PQCLabel
    from app.models.cbom import CBOMSnapshot
    from app.models.scan import ScanResult
    from app.engine.rating_engine import compute_enterprise_score

    data = {"generated_at": datetime.utcnow().isoformat(), "modules": modules}

    if "inventory" in modules:
        result = await db.execute(select(Asset))
        assets = result.scalars().all()
        data["inventory"] = [{"name": a.name, "url": a.url, "pqc_label": a.pqc_label.value if a.pqc_label else None,
                               "risk": a.risk_level.value if a.risk_level else None,
                               "tls_version": a.tls_version, "last_scan": str(a.last_scan)} for a in assets]

    if "cbom" in modules:
        # Fetch the latest snapshot for each target (using a simple distinct by target logic or fetching all for now)
        result = await db.execute(select(CBOMSnapshot).order_by(CBOMSnapshot.created_at.desc()))
        snaps = result.scalars().all()
        seen_targets = set()
        unique_snaps = []
        for s in snaps:
            if s.target_url not in seen_targets:
                seen_targets.add(s.target_url)
                unique_snaps.append(s)
        
        data["cbom"] = [{"target": s.target_url, "pqc_label": s.pqc_label,
                          "created_at": str(s.created_at),
                          "algorithms": json.loads(s.algorithms_json or "[]"),
                          "protocols": json.loads(s.protocols_json or "[]"),
                          "certificates": json.loads(s.certificates_json or "[]"),
                          "keys": json.loads(s.keys_json or "[]")} for s in unique_snaps]

    if "rating" in modules:
        result = await db.execute(select(Asset))
        assets = result.scalars().all()
        counts = {
            "fully_quantum_safe": sum(1 for a in assets if a.pqc_label == PQCLabel.fully_quantum_safe),
            "pqc_ready": sum(1 for a in assets if a.pqc_label == PQCLabel.pqc_ready),
            "partially_quantum_safe": sum(1 for a in assets if a.pqc_label == PQCLabel.partially_quantum_safe),
            "not_quantum_safe": sum(1 for a in assets if a.pqc_label == PQCLabel.not_quantum_safe),
            "unknown": sum(1 for a in assets if a.pqc_label == PQCLabel.unknown),
        }
        data["cyber_rating"] = compute_enterprise_score(counts)

    return data


def _export_json(data: dict, filepath: str):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)


def _export_xml(data: dict, filepath: str):
    try:
        import dicttoxml
        xml_bytes = dicttoxml.dicttoxml(data, custom_root="rakshak_report", attr_type=False)
        with open(filepath, "wb") as f:
            f.write(xml_bytes)
    except ImportError:
        # Fallback: simple XML
        with open(filepath, "w") as f:
            f.write("<rakshak_report>")
            f.write(json.dumps(data, default=str))
            f.write("</rakshak_report>")


def _export_csv(data: dict, filepath: str):
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        inventory = data.get("inventory", [])
        if inventory:
            writer.writerow(inventory[0].keys())
            for row in inventory:
                writer.writerow(row.values())
        else:
            writer.writerow(["No inventory data available"])


def _get_safety_color(safety: str) -> str:
    s = str(safety).lower()
    if s == 'safe': return "#2ecc71"
    elif s == 'ok': return "#3498db"
    elif s == 'warn': return "#f1c40f"
    elif s == 'danger': return "#e67e22"
    elif s == 'broken': return "#e74c3c"
    return "#7f8c8d"

def _get_pqc_label_color(label: str) -> str:
    lbl = str(label).lower()
    if "fully" in lbl: return "#2ecc71"
    if "ready" in lbl: return "#3498db"
    if "partially" in lbl: return "#f1c40f"
    if "not_" in lbl or "classical" in lbl: return "#e67e22"
    if "broken" in lbl: return "#e74c3c"
    return "#7f8c8d"

def _format_pqc_label(label: str) -> str:
    lbl = str(label).lower()
    if 'fully' in lbl: return 'Fully Quantum Safe'
    if 'ready' in lbl: return 'PQC Ready'
    if 'partially' in lbl: return 'Partially QS'
    if 'not_' in lbl or 'classical' in lbl: return 'Classical'
    if 'broken' in lbl: return 'Broken'
    return label.replace("_", " ").title()

def cbom_row_safety(item: dict, cat: str) -> str:
    if cat == "protocols":
        v = str(item.get("version", "")).upper().replace(" ", "").replace(".", "")
        if any(x in v for x in ["SSL20", "SSL30", "TLS10", "TLS11"]): return "broken"
        if "TLS12" in v: return "marginal"
        return "ok"
    elif cat == "keys":
        ka = str(item.get("key_algorithm", "")).upper().replace("-", "").replace("_", "")
        pqc_k = ["MLDSA", "MLKEM", "KYBER", "SLHDSA", "SPHINCS", "FALCON", "FNDSA", "DILITHIUM", "PQC"]
        clas_k = ["RSA", "EC", "ECDSA", "DSA", "DH", "ED25519", "ED448"]
        if any(ka.startswith(p) or ka == p for p in pqc_k): return "safe"
        if any(ka.startswith(p) or ka == p for p in clas_k): return "classical"
        import re
        size_str = re.sub(r'[^0-9]', '', str(item.get("size", "")))
        if size_str:
            sb = int(size_str)
            if sb <= 112: return "broken"
            if sb <= 521: return "classical"
        return "ok"
    elif cat == "certificates":
        ka = str(item.get("key_algorithm", "")).upper().replace("-", "").replace("_", "")
        sig = str(item.get("signature_algorithm_reference", "")).upper().replace("-", "").replace("_", "")
        pqc = ["MLDSA", "MLKEM", "KYBER", "SLHDSA", "SPHINCS", "FALCON", "FNDSA", "DILITHIUM", "PQC"]
        broken = ["SHA1", "MD5", "MD4", "RC4", "3DES", "TRIPLEDES", "DES", "RC2", "EXPORT"]
        if any(p in ka for p in broken) or any(p in sig for p in broken): return "broken"
        is_pqc_k = any(ka.startswith(p) or ka == p for p in pqc)
        is_pqc_s = any(sig.startswith(p) or sig == p for p in pqc)
        if is_pqc_k and is_pqc_s: return "safe"
        if is_pqc_k or is_pqc_s: return "ok"
        return "classical"
    elif cat == "algorithms":
        parts = [str(item.get("name", "")), str(item.get("primitive", ""))]
        parts = [p.upper().replace("-", "").replace("_", "") for p in parts]
        pqc = ["MLDSA", "MLKEM", "KYBER", "SLHDSA", "SPHINCS", "FALCON", "FNDSA", "DILITHIUM"]
        broken = ["SHA1", "MD5", "MD4", "RC4", "3DES", "TRIPLEDES", "DES", "RC2", "EXPORT"]
        marginal = ["AES128", "CAMELLIA128", "ARIA128"]
        classical = ["RSA", "ECDSA", "ECDHE", "DHE", "X25519", "X448", "SECP", "P256", "P384", "ED25519", "ED448"]
        if any(p in n for p in broken for n in parts): return "broken"
        if any(n.startswith(p) or n == p for p in classical for n in parts): return "classical"
        if any(n.startswith(p) for p in marginal for n in parts): return "marginal"
        if any(n.startswith(p) for p in pqc for n in parts): return "safe"
        return "ok"
    return "ok"

def _export_pdf(data: dict, filepath: str, password: str = None):
    try:
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor, white, black, lightgrey
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.units import inch

        # Generate landscape for wider tables
        doc = SimpleDocTemplate(filepath, pagesize=landscape(A4), rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
        styles = getSampleStyleSheet()
        story = []

        # PNB Branding Styles
        title_style = ParagraphStyle("Title", parent=styles["Title"], textColor=HexColor("#A3112E"), fontSize=28, spaceAfter=20)
        heading_style = ParagraphStyle("Heading", parent=styles["Heading1"], textColor=HexColor("#1A0509"), fontSize=18, spaceBefore=20, spaceAfter=10)
        subheading_style = ParagraphStyle("SubHeading", parent=styles["Heading2"], textColor=HexColor("#A3112E"), fontSize=14, spaceBefore=15, spaceAfter=8)
        normal_style = ParagraphStyle("Normal", parent=styles["Normal"], fontSize=10, textColor=HexColor("#333333"))
        cell_style = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=9, wordWrap='CJK', splitLongWords=True)

        # Cover Page / Header
        story.append(Paragraph("<b>PNB Rakshak Security Report</b>", title_style))
        story.append(Paragraph(f"<b>Generated:</b> {data['generated_at']}", normal_style))
        story.append(Paragraph("<b>Scope:</b> Quantum-Proof Systems Scanner Annexure-A CBOM", normal_style))
        story.append(Spacer(1, 30))

        # Cyber Rating
        if "cyber_rating" in data:
            rating = data["cyber_rating"]
            story.append(Paragraph("Enterprise Cyber Rating", heading_style))
            score_val = rating.get("score", 0)
            tier_val = rating.get("tier_label", "Unknown")
            
            # Tier Coloring
            tier_color = "#2ecc71" if score_val >= 90 else "#3498db" if score_val >= 70 else "#f1c40f" if score_val >= 50 else "#e74c3c"
            
            summary_html = f"""
            <b>Score:</b> <font color="{tier_color}">{score_val}</font><br/>
            <b>Tier:</b> <font color="{tier_color}">{tier_val}</font><br/>
            <b>Total Assets Assessed:</b> {rating.get("total_assets", 0)}<br/>
            <b>Fully Quantum Safe:</b> <font color="#2ecc71">{rating.get("breakdown", {}).get("fully_quantum_safe", 0)}</font><br/>
            <b>PQC Ready:</b> <font color="#2ecc71">{rating.get("breakdown", {}).get("pqc_ready", 0)}</font><br/>
            <b>Partially Quantum Safe:</b> <font color="#f1c40f">{rating.get("breakdown", {}).get("partially_quantum_safe", 0)}</font><br/>
            <b>Classical:</b> <font color="#e67e22">{rating.get("breakdown", {}).get("not_quantum_safe", 0)}</font>
            """
            story.append(Paragraph(summary_html, normal_style))
            story.append(Spacer(1, 20))

        # Asset Inventory Dashboard
        if "inventory" in data and data["inventory"]:
            story.append(Paragraph("Asset Inventory Overview", heading_style))
            inv_data = [["Name", "URL", "PQC Label", "Risk Level", "TLS Ver.", "Last Scan"]]
            for asset in data["inventory"]:
                label = asset.get('pqc_label') or 'Unknown'
                lbl_color = _get_pqc_label_color(label)
                pqc_para = Paragraph(f'<b><font color="{lbl_color}">{_format_pqc_label(label)}</font></b>', cell_style)
                
                inv_data.append([
                    Paragraph(str(asset.get("name", "")), cell_style),
                    Paragraph(str(asset.get("url", "")), cell_style),
                    pqc_para,
                    str(asset.get("risk", "")),
                    str(asset.get("tls_version", "")),
                    str(asset.get("last_scan", ""))[:19],
                ])
            
            t = Table(inv_data, colWidths=[120, 250, 120, 80, 60, 110])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1A0509")),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, lightgrey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F8F9FA"), white]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(t)
            story.append(PageBreak())

        # CBOM Snapshot Details
        if "cbom" in data and data["cbom"]:
            story.append(Paragraph("Detailed Cryptographic Bill of Materials (CBOM)", heading_style))
            
            for snap in data["cbom"]:
                target = snap.get("target") or "Unknown"
                label = snap.get('pqc_label') or 'Unknown'
                display_label = _format_pqc_label(label)
                lbl_color = _get_pqc_label_color(label)
                
                story.append(Paragraph(f"Target: {target} &nbsp;&bull;&nbsp; <font color='{lbl_color}'>[{display_label}]</font>", subheading_style))
                story.append(Paragraph(f"<font size=8 color='#777777'>Scan Date: {snap.get('created_at', '')[:19]}</font>", normal_style))
                story.append(Spacer(1, 10))

                # --- Algorithms Table ---
                algs = snap.get("algorithms", [])
                if algs:
                    story.append(Paragraph("<b>Algorithms Used</b>", normal_style))
                    alg_header = [["Safety", "Name", "Type"]]
                    alg_rows = alg_header + [
                        [
                            Paragraph(f'<b><font color="{_get_safety_color(cbom_row_safety(a, "algorithms"))}">{cbom_row_safety(a, "algorithms").upper()}</font></b>', cell_style),
                            str(a.get("name", "")),
                            str(a.get("primitive", ""))
                        ] for a in algs
                    ]
                    t_alg = Table(alg_rows, colWidths=[80, 200, 150])
                    t_alg.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#A3112E")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("GRID", (0, 0), (-1, -1), 0.5, lightgrey),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F8F9FA"), white]),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]))
                    story.append(t_alg)
                    story.append(Spacer(1, 10))

                # --- Protocols Table ---
                protos = snap.get("protocols", [])
                if protos:
                    story.append(Paragraph("<b>Connection Protocols</b>", normal_style))
                    proto_rows = [["Safety", "Protocol", "Status"]] + [
                        [
                            Paragraph(f'<b><font color="{_get_safety_color(cbom_row_safety(p, "protocols"))}">{cbom_row_safety(p, "protocols").upper()}</font></b>', cell_style),
                            str(p.get("version", p.get("name", ""))),
                            "Active"
                        ] for p in protos
                    ]
                    t_pro = Table(proto_rows, colWidths=[80, 200, 150])
                    t_pro.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#A3112E")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, lightgrey),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]))
                    story.append(t_pro)
                    story.append(Spacer(1, 10))

                # --- Keys Table ---
                klist = snap.get("keys", [])
                if klist:
                    import textwrap
                    story.append(Paragraph("<b>Cryptographic Keys</b>", normal_style))
                    key_rows = [["Safety", "Key Name", "Algorithm", "Size", "Validity"]] + [
                        [
                            Paragraph(f'<b><font color="{_get_safety_color(cbom_row_safety(k, "keys"))}">{cbom_row_safety(k, "keys").upper()}</font></b>', cell_style),
                            Paragraph("<br/>".join(textwrap.wrap(str(k.get("name", "")), 22)), cell_style),
                            str(k.get("key_algorithm", "")),
                            str(k.get("size", "")),
                            str(k.get("state", "")).title()
                        ] for k in klist
                    ]
                    t_key = Table(key_rows, colWidths=[80, 220, 80, 75, 75])
                    t_key.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#A3112E")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, lightgrey),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F8F9FA"), white]),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]))
                    story.append(t_key)
                    story.append(Spacer(1, 10))

                # --- Certificates Table ---
                certs = snap.get("certificates", [])
                if certs:
                    story.append(Paragraph("<b>Certificate Chain</b>", normal_style))
                    cert_rows = [["Safety", "Subject", "Issuer", "Signature Algorithm", "Valid Until"]] + [
                        [
                            Paragraph(f'<b><font color="{_get_safety_color(cbom_row_safety(c, "certificates"))}">{cbom_row_safety(c, "certificates").upper()}</font></b>', cell_style),
                            Paragraph(str(c.get("subject_name", "")), cell_style),
                            Paragraph(str(c.get("issuer_name", "")), cell_style),
                            str(c.get("signature_algorithm_reference", "")),
                            str(c.get("not_valid_after", ""))[:10]
                        ] for c in certs
                    ]
                    t_cert = Table(cert_rows, colWidths=[60, 250, 220, 120, 80])
                    t_cert.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#A3112E")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, lightgrey),
                    ]))
                    story.append(t_cert)
                    story.append(Spacer(1, 10))
                
                story.append(Spacer(1, 15))

        # Append Legend
        story.append(PageBreak())
        story.append(Paragraph("Appendix: Row Colour Legend", heading_style))
        story.append(Paragraph("The safety column in the CBOM maps to the following NIST FIPS 203/204/205 quantum tier classifications:", normal_style))
        story.append(Spacer(1, 10))
        
        legend_data = [
            ["Tier", "Definition", "Examples"],
            [Paragraph('<b><font color="#2ecc71">PQC SAFE</font></b>', cell_style), "NIST-standardised Post-Quantum Cryptography algorithm.", "ML-DSA, ML-KEM, SLH-DSA"],
            [Paragraph('<b><font color="#3498db">SAFE</font></b>', cell_style), "Classical algorithm safe against Grover's (256-bit key). Not vulnerable to Shor's.", "AES-256-GCM, SHA-256, TLS 1.3"],
            [Paragraph('<b><font color="#f1c40f">MARGINAL</font></b>', cell_style), "128-bit symmetric — halved to ~64 bits by Grover's algorithm.", "AES-128-GCM, TLS 1.2"],
            [Paragraph('<b><font color="#e67e22">CLASSICAL (DANGER)</font></b>', cell_style), "Vulnerable to Shor's algorithm on a CRQC.", "RSA, ECDSA, X25519"],
            [Paragraph('<b><font color="#e74c3c">BROKEN</font></b>', cell_style), "Broken by classical cryptanalysis. Immediate remediation required.", "MD5, SHA-1, RC4, TLS 1.0"]
        ]
        t_leg = Table(legend_data, colWidths=[120, 350, 250])
        t_leg.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1A0509")),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F8F9FA"), white]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t_leg)

        doc.build(story)

        # Encrypt if password is given
        if password:
            from pypdf import PdfReader, PdfWriter
            import os
            reader = PdfReader(filepath)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            writer.encrypt(password)
            temp_path = filepath + ".enc"
            with open(temp_path, "wb") as f_out:
                writer.write(f_out)
            os.replace(temp_path, filepath)

    except Exception as e:

        # Fallback: write plain text
        with open(filepath, "w") as f:
            f.write(f"Rakshak Report\nGenerated: {data.get('generated_at')}\n\n")
            f.write(json.dumps(data, indent=2, default=str))
