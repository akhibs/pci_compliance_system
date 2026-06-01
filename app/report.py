from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from datetime import datetime


def generate_pdf_report(scan_results, target_name, target_ip, filename="pci_report.pdf"):

    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # ── TITLE ──
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Title'],
        fontSize=20,
        textColor=colors.darkblue,
        spaceAfter=10
    )
    elements.append(Paragraph("PCI-DSS Compliance Report", title_style))
    elements.append(Spacer(1, 0.2 * inch))

    # ── SCAN INFO ──
    info_style = styles["Normal"]
    elements.append(Paragraph(f"<b>Target System:</b> {target_name}", info_style))
    elements.append(Paragraph(f"<b>IP Address:</b> {target_ip}", info_style))
    elements.append(Paragraph(f"<b>Scan Date:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", info_style))
    elements.append(Spacer(1, 0.3 * inch))

    # ── SUMMARY ──
    passed   = sum(1 for r in scan_results if r["status"] == "PASS")
    failed   = sum(1 for r in scan_results if r["status"] == "FAIL")
    warnings = sum(1 for r in scan_results if r["status"] == "WARNING")
    total    = len(scan_results)
    score    = int((passed / total) * 100) if total > 0 else 0

    elements.append(Paragraph("<b>Compliance Summary</b>", styles["Heading2"]))

    summary_data = [
        ["Total Checks", "Passed", "Failed", "Warnings", "Compliance Score"],
        [str(total), str(passed), str(failed), str(warnings), f"{score}%"]
    ]

    summary_table = Table(summary_data, colWidths=[100, 80, 80, 80, 120])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND",  (0, 1), (-1, 1), colors.lightblue),
        ("FONTNAME",    (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 1), (-1, 1), 13),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.3 * inch))

    # ── DETAILED RESULTS ──
    elements.append(Paragraph("<b>Detailed Findings</b>", styles["Heading2"]))
    elements.append(Spacer(1, 0.1 * inch))

    table_data = [["Requirement", "Description", "Status", "Risk", "Evidence"]]

    for r in scan_results:
        # color code status
        if r["status"] == "PASS":
            status_color = colors.green
        elif r["status"] == "FAIL":
            status_color = colors.red
        else:
            status_color = colors.orange

        table_data.append([
            r["requirement"],
            r["description"],
            r["status"],
            r["risk_level"],
            r["evidence"][:60] + "..." if len(r["evidence"]) > 60 else r["evidence"]
        ])

    results_table = Table(table_data, colWidths=[80, 150, 55, 55, 160])
    results_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.grey),
        ("WORDWRAP",      (0, 0), (-1, -1), True),
    ]))
    elements.append(results_table)
    elements.append(Spacer(1, 0.3 * inch))

    # ── FOOTER ──
    elements.append(Paragraph(
        "This report was generated automatically by the PCI-DSS Compliance Automation System.",
        styles["Italic"]
    ))

    doc.build(elements)
    return filename
