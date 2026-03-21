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
        result = await db.execute(select(CBOMSnapshot).order_by(CBOMSnapshot.created_at.desc()).limit(50))
        snaps = result.scalars().all()
        data["cbom"] = [{"target": s.target_url, "pqc_label": s.pqc_label,
                          "created_at": str(s.created_at),
                          "algorithms": json.loads(s.algorithms_json or "[]"),
                          "protocols": json.loads(s.protocols_json or "[]")} for s in snaps]

    if "rating" in modules:
        result = await db.execute(select(Asset))
        assets = result.scalars().all()
        counts = {
            "fully_quantum_safe": sum(1 for a in assets if a.pqc_label == PQCLabel.fully_quantum_safe),
            "pqc_ready": sum(1 for a in assets if a.pqc_label == PQCLabel.pqc_ready),
            "quantum_safe": sum(1 for a in assets if a.pqc_label == PQCLabel.quantum_safe),
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


def _export_pdf(data: dict, filepath: str, password: str = None):
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor, white, black
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.units import inch

        doc = SimpleDocTemplate(filepath, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle("Title", parent=styles["Title"], textColor=HexColor("#1E3A5F"), fontSize=24, spaceAfter=12)
        story.append(Paragraph("🛡️ Rakshak Security Report", title_style))
        story.append(Paragraph(f"Generated: {data['generated_at']}", styles["Normal"]))
        story.append(Spacer(1, 20))

        # Cyber Rating
        if "cyber_rating" in data:
            rating = data["cyber_rating"]
            story.append(Paragraph("Enterprise Cyber Rating", styles["Heading1"]))
            rating_data = [
                ["Score", "Tier", "Total Assets", "Fully Quantum Safe", "Not Quantum Safe"],
                [
                    str(rating.get("score", 0)),
                    rating.get("tier_label", ""),
                    str(rating.get("total_assets", 0)),
                    str(rating.get("breakdown", {}).get("fully_quantum_safe", 0)),
                    str(rating.get("breakdown", {}).get("not_quantum_safe", 0)),
                ]
            ]
            t = Table(rating_data, colWidths=[80, 150, 80, 100, 100])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1E3A5F")),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F8F9FA"), white]),
            ]))
            story.append(t)
            story.append(Spacer(1, 20))


        # CBOM Snapshot Data
        if "cbom" in data and data["cbom"]:
            story.append(Spacer(1, 10))
            story.append(Paragraph("Latest CBOM Snapshots", styles["Heading2"]))
            cbom_cell_style = ParagraphStyle("CBOMCell", parent=styles["Normal"], fontSize=9, wordWrap='CJK')
            cbom_data = [["Target", "PQC Label", "Created At"]]
            for snap in data["cbom"][:20]:
                cbom_data.append([
                    Paragraph(str(snap.get("target", "")), cbom_cell_style),
                    str(snap.get("pqc_label", "")),
                    str(snap.get("created_at", ""))[:19]
                ])
            t2 = Table(cbom_data, colWidths=[240, 100, 120])
            t2.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#3B6A99")),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F8F9FA"), white]),
            ]))
            story.append(t2)
            story.append(Spacer(1, 20))

        # Asset Inventory
        if "inventory" in data and data["inventory"]:
            story.append(Paragraph("Asset Inventory", styles["Heading1"]))
            cell_style = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=8, wordWrap='CJK')
            inv_data = [["Name", "URL", "PQC Label", "Risk Level", "TLS Version", "Last Scan"]]
            for asset in data["inventory"][:50]:  # limit for PDF
                inv_data.append([
                    Paragraph(str(asset.get("name", "")), cell_style),
                    Paragraph(str(asset.get("url", "")), cell_style),
                    str(asset.get("pqc_label", "")),
                    str(asset.get("risk", "")),
                    str(asset.get("tls_version", "")),
                    str(asset.get("last_scan", ""))[:19],
                ])
            t = Table(inv_data, colWidths=[110, 150, 70, 60, 50, 80])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#2C5F8A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F8F9FA"), white]),
            ]))
            story.append(t)

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
