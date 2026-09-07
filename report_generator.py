from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from datetime import datetime
import os


def generate_security_report(
    filepath,
    url,
    result,
    confidence,
    analysis,
    model_name,
    model_accuracy,
    model_features,
    accuracy,
    precision,
    recall,
    f1_score,
    tn,
    fp,
    fn,
    tp
):

    # ---------------------------------------------------------
    # PDF DOCUMENT
    # ---------------------------------------------------------

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()

    # ---------------------------------------------------------
    # CUSTOM STYLES
    # ---------------------------------------------------------

    title_style = ParagraphStyle(
        "TitleCustom",
        parent=styles["Title"],
        fontSize=22,
        leading=28,
        alignment=TA_CENTER,
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "SubtitleCustom",
        parent=styles["Normal"],
        fontSize=10,
        leading=15,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#555555"),
        spaceAfter=18
    )

    heading_style = ParagraphStyle(
        "HeadingCustom",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        spaceBefore=10,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "NormalCustom",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=14
    )

    small_style = ParagraphStyle(
        "SmallCustom",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#555555")
    )

    url_style = ParagraphStyle(
        "URLCustom",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=12,
        wordWrap="CJK"
    )

    result_style = ParagraphStyle(
        "ResultCustom",
        parent=styles["Normal"],
        fontSize=18,
        leading=22,
        alignment=TA_CENTER
    )

    # ---------------------------------------------------------
    # HELPERS
    # ---------------------------------------------------------

    def safe(value, default="N/A"):
        if value is None or value == "":
            return default
        return str(value)

    def paragraph(value, style=normal_style):
        return Paragraph(
            safe(value).replace("&", "&amp;"),
            style
        )

    def yes_no(value):
        return "YES" if value else "NO"

    # ---------------------------------------------------------
    # PAGE HEADER / FOOTER
    # ---------------------------------------------------------

    def add_page_number(canvas, doc):
        canvas.saveState()

        width, height = A4

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#666666"))

        canvas.drawString(
            18 * mm,
            10 * mm,
            "Phishing URL Detector"
        )

        canvas.drawRightString(
            width - 18 * mm,
            10 * mm,
            f"Page {doc.page}"
        )

        canvas.restoreState()

    # ---------------------------------------------------------
    # STORY
    # ---------------------------------------------------------

    story = []

    # ---------------------------------------------------------
    # COVER / TITLE
    # ---------------------------------------------------------

    story.append(Spacer(1, 15 * mm))

    story.append(
        Paragraph(
            "PHISHING URL DETECTOR",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Professional Security Analysis Report",
            subtitle_style
        )
    )

    story.append(Spacer(1, 5 * mm))

    # ---------------------------------------------------------
    # RESULT BOX
    # ---------------------------------------------------------

    result_upper = safe(result, "UNKNOWN").upper()

    if result_upper == "PHISHING":
        result_text = "⚠ PHISHING DETECTED"
        result_bg = colors.HexColor("#FEE2E2")
        result_fg = colors.HexColor("#B91C1C")
    elif result_upper == "LEGITIMATE":
        result_text = "✓ LEGITIMATE URL"
        result_bg = colors.HexColor("#DCFCE7")
        result_fg = colors.HexColor("#15803D")
    else:
        result_text = result_upper
        result_bg = colors.HexColor("#E5E7EB")
        result_fg = colors.HexColor("#374151")

    result_table = Table(
        [
            [
                Paragraph(
                    result_text,
                    ParagraphStyle(
                        "ResultInside",
                        parent=result_style,
                        textColor=result_fg
                    )
                )
            ]
        ],
        colWidths=[170 * mm]
    )

    result_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), result_bg),
                ("BOX", (0, 0), (-1, -1), 1, result_fg),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 15),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 15),
            ]
        )
    )

    story.append(result_table)
    story.append(Spacer(1, 8 * mm))

    # ---------------------------------------------------------
    # SCAN SUMMARY
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Scan Summary",
            heading_style
        )
    )

    scan_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    risk_score = analysis.get("risk_score", 0)
    risk_level = analysis.get("risk_level", "N/A")

    summary_data = [
        [
            paragraph("<b>Checked URL</b>"),
            paragraph(url, url_style)
        ],
        [
            paragraph("<b>Prediction</b>"),
            paragraph(result_upper)
        ],
        [
            paragraph("<b>ML Confidence</b>"),
            paragraph(f"{safe(confidence, 0)}%")
        ],
        [
            paragraph("<b>Risk Score</b>"),
            paragraph(f"{risk_score}/100")
        ],
        [
            paragraph("<b>Risk Level</b>"),
            paragraph(risk_level)
        ],
        [
            paragraph("<b>Scan Time</b>"),
            paragraph(scan_time)
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[48 * mm, 122 * mm]
    )

    summary_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F4F6")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(summary_table)

    # ---------------------------------------------------------
    # DOMAIN INFORMATION
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Domain & URL Information",
            heading_style
        )
    )

    domain_info = [
        [
            paragraph("<b>Domain</b>"),
            paragraph(analysis.get("domain"))
        ],
        [
            paragraph("<b>Domain Length</b>"),
            paragraph(analysis.get("domain_length"))
        ],
        [
            paragraph("<b>Subdomains</b>"),
            paragraph(analysis.get("subdomains"))
        ],
        [
            paragraph("<b>URL Length</b>"),
            paragraph(analysis.get("url_length"))
        ],
        [
            paragraph("<b>HTTPS</b>"),
            paragraph(yes_no(analysis.get("https")))
        ],
        [
            paragraph("<b>IP Address</b>"),
            paragraph(yes_no(analysis.get("ip_address")))
        ],
        [
            paragraph("<b>Obfuscation</b>"),
            paragraph(yes_no(analysis.get("obfuscation")))
        ]
    ]

    domain_table = Table(
        domain_info,
        colWidths=[55 * mm, 115 * mm]
    )

    domain_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F9FAFB")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(domain_table)

    # ---------------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Suspicious Indicators",
            heading_style
        )
    )

    keywords = analysis.get("found_keywords", [])

    if keywords:
        keyword_text = ", ".join(
            [str(item) for item in keywords]
        )
    else:
        keyword_text = "No suspicious keywords detected."

    story.append(
        paragraph(keyword_text)
    )

    story.append(Spacer(1, 3 * mm))

    # ---------------------------------------------------------
    # BRANDS
    # ---------------------------------------------------------

    brands = analysis.get("brands_found", [])

    if brands:
        brand_text = ", ".join(
            [str(item) for item in brands]
        )
    else:
        brand_text = "No known brand names detected."

    story.append(
        Paragraph(
            f"<b>Brands detected:</b> {brand_text}",
            normal_style
        )
    )

    # ---------------------------------------------------------
    # WHY FLAGGED
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Why This URL Was Flagged",
            heading_style
        )
    )

    explanation = analysis.get(
        "explanation",
        "No detailed explanation available."
    )

    story.append(
        paragraph(explanation)
    )

    reasons = analysis.get("reasons", [])

    if reasons:

        story.append(Spacer(1, 3 * mm))

        reason_rows = []

        for index, reason in enumerate(reasons, start=1):
            reason_rows.append(
                [
                    paragraph(f"<b>{index}</b>"),
                    paragraph(reason)
                ]
            )

        reason_table = Table(
            reason_rows,
            colWidths=[12 * mm, 158 * mm]
        )

        reason_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F4F6")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )

        story.append(reason_table)

    # ---------------------------------------------------------
    # SECURITY CHECKS
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Advanced Security Checks",
            heading_style
        )
    )

    checks = analysis.get("security_checks", [])

    if checks:

        check_rows = [
            [
                paragraph("<b>Security Check</b>"),
                paragraph("<b>Status</b>")
            ]
        ]

        for check in checks:

            if isinstance(check, dict):

                name = check.get(
                    "name",
                    check.get("check", "Security Check")
                )

                status = check.get(
                    "status",
                    check.get("result", "N/A")
                )

            else:
                name = str(check)
                status = "Detected"

            check_rows.append(
                [
                    paragraph(name),
                    paragraph(status)
                ]
            )

        check_table = Table(
            check_rows,
            colWidths=[120 * mm, 50 * mm],
            repeatRows=1
        )

        check_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E7EB")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )

        story.append(check_table)

    else:

        story.append(
            paragraph(
                "No advanced security checks were available."
            )
        )

    # ---------------------------------------------------------
    # MODEL INFORMATION
    # ---------------------------------------------------------

    story.append(PageBreak())

    story.append(
        Paragraph(
            "Machine Learning Model",
            heading_style
        )
    )

    model_data = [
        [
            paragraph("<b>Model</b>"),
            paragraph(model_name)
        ],
        [
            paragraph("<b>Features Used</b>"),
            paragraph(model_features)
        ],
        [
            paragraph("<b>Model Accuracy</b>"),
            paragraph(f"{model_accuracy}%")
        ]
    ]

    model_table = Table(
        model_data,
        colWidths=[55 * mm, 115 * mm]
    )

    model_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F4F6")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(model_table)

    # ---------------------------------------------------------
    # PERFORMANCE
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Model Performance",
            heading_style
        )
    )

    performance_data = [
        [
            paragraph("<b>Metric</b>"),
            paragraph("<b>Score</b>")
        ],
        [
            paragraph("Accuracy"),
            paragraph(f"{accuracy}%")
        ],
        [
            paragraph("Precision"),
            paragraph(f"{precision}%")
        ],
        [
            paragraph("Recall"),
            paragraph(f"{recall}%")
        ],
        [
            paragraph("F1 Score"),
            paragraph(f"{f1_score}%")
        ]
    ]

    performance_table = Table(
        performance_data,
        colWidths=[120 * mm, 50 * mm],
        repeatRows=1
    )

    performance_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E7EB")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (1, 1), (1, -1), "CENTER"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    story.append(performance_table)

    # ---------------------------------------------------------
    # CONFUSION MATRIX
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Confusion Matrix",
            heading_style
        )
    )

    matrix_data = [
        [
            paragraph("<b></b>"),
            paragraph("<b>Predicted Negative</b>"),
            paragraph("<b>Predicted Positive</b>")
        ],
        [
            paragraph("<b>Actual Negative</b>"),
            paragraph(tn),
            paragraph(fp)
        ],
        [
            paragraph("<b>Actual Positive</b>"),
            paragraph(fn),
            paragraph(tp)
        ]
    ]

    matrix_table = Table(
        matrix_data,
        colWidths=[60 * mm, 55 * mm, 55 * mm]
    )

    matrix_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.7, colors.HexColor("#9CA3AF")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E7EB")),
                ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#F3F4F6")),
                ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    story.append(matrix_table)

    story.append(Spacer(1, 8 * mm))

    # ---------------------------------------------------------
    # SECURITY RECOMMENDATION
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Security Recommendation",
            heading_style
        )
    )

    if result_upper == "PHISHING":

        recommendation = (
            "<b>Do not open or submit sensitive information to this URL.</b> "
            "The analysis detected indicators associated with potentially "
            "malicious or deceptive URLs. Verify the website through an "
            "official source before continuing."
        )

    else:

        recommendation = (
            "The URL was classified as legitimate by the current model "
            "and security analysis. However, HTTPS and a machine-learning "
            "prediction do not guarantee that a website is completely safe. "
            "Always verify the domain before entering sensitive information."
        )

    story.append(
        paragraph(recommendation)
    )

    # ---------------------------------------------------------
    # DISCLAIMER
    # ---------------------------------------------------------

    story.append(Spacer(1, 10 * mm))

    story.append(
        Paragraph(
            "Disclaimer",
            heading_style
        )
    )

    disclaimer = (
        "This report is generated automatically by the Phishing URL Detector. "
        "The prediction is based on machine-learning classification and "
        "URL-based security heuristics. It should be treated as a security "
        "assessment aid rather than a guarantee of website safety."
    )

    story.append(
        paragraph(disclaimer, small_style)
    )

    # ---------------------------------------------------------
    # BUILD PDF
    # ---------------------------------------------------------

    doc.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number
    )

    return filepath