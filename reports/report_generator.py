from io import BytesIO
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
IST = ZoneInfo("Asia/Kolkata")

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def generate_analysis_report(analysis):
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title="CyberLens Static Analysis Report",
        author="CyberLens",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CyberLensTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "CyberLensSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=9,
        textColor=colors.grey,
        spaceAfter=18,
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=12,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
    )

    story = []

    story.append(
        Paragraph(
            "CYBERLENS",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "Static File Threat Triage & Malware Analysis Report",
            subtitle_style,
        )
    )

    story.append(
        Paragraph(
            "See the file. Understand the risk.",
            subtitle_style,
        )
    )

    story.append(
        Paragraph(
            "Analysis Overview",
            heading_style,
        )
    )

    overview_data = [
        ["Analysis ID", str(analysis.id)],
        ["Filename", analysis.filename or "Unknown"],
        ["File Type", analysis.file_type or "Unknown"],
        ["MIME Type", analysis.mime_type or "Unknown"],
        ["File Size", format_file_size(analysis.file_size)],
        [
            "Analysis Date",
            format_datetime(analysis.created_at),
        ],
    ]

    story.append(
        create_table(overview_data)
    )

    story.append(
        Spacer(1, 8)
    )

    story.append(
        Paragraph(
            "Cryptographic Hashes",
            heading_style,
        )
    )

    hash_data = [
        ["MD5", analysis.md5 or "N/A"],
        ["SHA-1", analysis.sha1 or "N/A"],
        ["SHA-256", analysis.sha256 or "N/A"],
    ]

    story.append(
        create_table(hash_data)
    )

    story.append(
        Spacer(1, 8)
    )

    story.append(
        Paragraph(
            "Risk Assessment",
            heading_style,
        )
    )

    risk_data = [
        [
            "Risk Score",
            f"{analysis.risk_score or 0}/100",
        ],
        [
            "Risk Level",
            analysis.severity or "UNKNOWN",
        ],
        [
            "Entropy",
            (
                f"{analysis.entropy:.4f}"
                if analysis.entropy is not None
                else "N/A"
            ),
        ],
    ]

    story.append(
        create_table(risk_data)
    )

    story.append(
        Spacer(1, 8)
    )

    analysis_data = analysis.analysis_data or {}

    risk = analysis_data.get(
        "risk",
        {}
    )

    verdict = analysis_data.get(
        "verdict",
        {}
    )

    if not isinstance(risk, dict):
        risk = {}

    if not isinstance(verdict, dict):
        verdict = {}

    story.append(
        Paragraph(
            "Analyst Verdict",
            heading_style,
        )
    )

    verdict_data = [
        [
            "Verdict",
            verdict.get(
                "verdict",
                "Unknown"
            ),
        ],
        [
            "Risk Level",
            risk.get(
                "risk_level",
                analysis.severity or "UNKNOWN",
            ),
        ],
        [
            "Recommendation",
            verdict.get(
                "recommendation",
                "No recommendation available.",
            ),
        ],
    ]

    story.append(
        create_table(verdict_data)
    )

    story.append(
        Spacer(1, 8)
    )

    indicators = analysis.indicators or []

    if isinstance(indicators, dict):
        indicators = indicators.get(
            "detected_indicators",
            []
        )

    if not isinstance(indicators, list):
        indicators = []

    indicators = [
        indicator
        for indicator in indicators
        if isinstance(indicator, dict)
    ]

    story.append(
        Paragraph(
            f"Detected Indicators ({len(indicators)})",
            heading_style,
        )
    )

    if indicators:
        indicator_data = [
            [
                "ID",
                "Indicator",
                "Category",
                "Severity",
                "Score",
            ]
        ]

        for indicator in indicators:
            indicator_data.append(
                [
                    str(
                        indicator.get(
                            "id",
                            "N/A"
                        )
                    ),
                    str(
                        indicator.get(
                            "name",
                            "Unknown"
                        )
                    ),
                    str(
                        indicator.get(
                            "category",
                            "Unknown"
                        )
                    ),
                    str(
                        indicator.get(
                            "severity",
                            "Unknown"
                        )
                    ),
                    str(
                        indicator.get(
                            "score",
                            0
                        )
                    ),
                ]
            )

        indicator_table = Table(
            indicator_data,
            repeatRows=1,
            colWidths=[
                18 * mm,
                65 * mm,
                35 * mm,
                25 * mm,
                18 * mm,
            ],
        )

        indicator_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#1E1E1B"),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold",
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.grey,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [
                            colors.white,
                            colors.HexColor("#F5F1E8"),
                        ],
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                ]
            )
        )

        story.append(
            indicator_table
        )

    else:
        story.append(
            Paragraph(
                "No suspicious indicators were detected.",
                body_style,
            )
        )

    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "Analysis Details",
            heading_style,
        )
    )

    identification = analysis_data.get(
        "identification",
        {}
    )

    if not isinstance(identification, dict):
        identification = {}

    identification_data = []

    for key, value in identification.items():
        if isinstance(value, (dict, list)):
            value = str(value)

        identification_data.append(
            [
                str(key),
                str(value),
            ]
        )

    if identification_data:
        story.append(
            Paragraph(
                "File Identification",
                heading_style,
            )
        )

        story.append(
            create_table(
                identification_data
            )
        )

    strings_data = analysis_data.get(
        "strings",
        {}
    )

    if strings_data:
        story.append(
            Paragraph(
                "String Analysis",
                heading_style,
            )
        )

        string_summary = []

        if isinstance(strings_data, dict):
            for key, value in strings_data.items():
                if isinstance(
                    value,
                    (str, int, float, bool)
                ):
                    string_summary.append(
                        [
                            str(key),
                            str(value),
                        ]
                    )

        if string_summary:
            story.append(
                create_table(
                    string_summary
                )
            )

    entropy_data = analysis_data.get(
        "entropy",
        {}
    )

    if entropy_data:
        story.append(
            Paragraph(
                "Entropy Analysis",
                heading_style,
            )
        )

        entropy_summary = []

        if isinstance(entropy_data, dict):
            for key, value in entropy_data.items():
                if isinstance(
                    value,
                    (str, int, float, bool)
                ):
                    entropy_summary.append(
                        [
                            str(key),
                            str(value),
                        ]
                    )

        if entropy_summary:
            story.append(
                create_table(
                    entropy_summary
                )
            )

    pe_data = analysis_data.get(
        "pe_analysis",
        {}
    )

    if pe_data:
        story.append(
            Paragraph(
                "PE Analysis",
                heading_style,
            )
        )

        pe_summary = []

        if isinstance(pe_data, dict):
            for key, value in pe_data.items():
                if isinstance(
                    value,
                    (str, int, float, bool)
                ):
                    pe_summary.append(
                        [
                            str(key),
                            str(value),
                        ]
                    )

        if pe_summary:
            story.append(
                create_table(
                    pe_summary
                )
            )

    story.append(
        Spacer(1, 15)
    )

    story.append(
        Paragraph(
            "CyberLens performs static analysis only. "
            "Uploaded files are not executed during analysis.",
            body_style,
        )
    )

    document.build(
        story,
        onFirstPage=add_footer,
        onLaterPages=add_footer,
    )

    buffer.seek(0)

    return buffer


def create_table(data):
    table = Table(
        data,
        colWidths=[
            45 * mm,
            125 * mm,
        ],
        repeatRows=0,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#B8B0A2"),
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#F2E8D5"),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    return table


def format_file_size(size):
    if size is None:
        return "N/A"

    size = float(size)

    if size < 1024:
        return f"{size:.0f} B"

    if size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"

    return f"{size / (1024 * 1024):.2f} MB"


def format_datetime(value):
    if not value:
        return "N/A"

    if isinstance(value, datetime):
        # Database stores naive UTC timestamps.
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        value = value.astimezone(IST)

        return value.strftime("%Y-%m-%d %H:%M:%S")

    return str(value)


def add_footer(canvas, document):
    canvas.saveState()

    canvas.setFont(
        "Helvetica",
        7,
    )

    canvas.setFillColor(
        colors.grey
    )

    canvas.drawString(
        15 * mm,
        8 * mm,
        "CyberLens - Static File Threat Triage",
    )

    canvas.drawRightString(
        A4[0] - 15 * mm,
        8 * mm,
        f"Page {document.page}",
    )

    canvas.restoreState()