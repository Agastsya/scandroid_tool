"""PDF report generation (reportlab, zero system dependencies).

Renders the same validated dataset as the HTML report into a clean, printable,
light-theme PDF — the format you hand to a client or attach to a ticket. Uses
only reportlab's built-in fonts so it renders identically on Kali, Parrot and
macOS with nothing extra to install.
"""
from __future__ import annotations

from pathlib import Path

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, Flowable, HRFlowable, KeepTogether)
    _OK = True
except Exception:  # noqa: BLE001
    _OK = False

# palette (light theme, print-friendly) — status colors reserved & labelled
INK = colors.HexColor("#1a1f2b")
DIM = colors.HexColor("#5b6472")
LINE = colors.HexColor("#e3e7ee")
ACCENT = colors.HexColor("#2b6cff")
BG_CARD = colors.HexColor("#f6f8fc")
SEV = {
    "critical": colors.HexColor("#d11149"),
    "high": colors.HexColor("#e8590c"),
    "medium": colors.HexColor("#f08c00"),
    "low": colors.HexColor("#1c7ed6"),
    "info": colors.HexColor("#868e96"),
}
STATUS_C = {2: colors.HexColor("#2f9e44"), 3: colors.HexColor("#f08c00"),
            4: colors.HexColor("#e8590c"), 5: colors.HexColor("#d11149")}


def available() -> bool:
    return _OK


class SeverityBar(Flowable):
    """A single horizontal stacked bar of finding severities, with a legend."""
    def __init__(self, counts: dict, width=460, height=26):
        super().__init__()
        self.counts = counts
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        total = sum(self.counts.values()) or 1
        x = 0
        order = ["critical", "high", "medium", "low", "info"]
        c.setLineWidth(0)
        for sev in order:
            n = self.counts.get(sev, 0)
            if not n:
                continue
            w = self.width * (n / total)
            c.setFillColor(SEV[sev])
            c.roundRect(x, 4, max(w - 2, 1), self.height - 8, 3, stroke=0, fill=1)
            if w > 26:
                c.setFillColor(colors.white)
                c.setFont("Helvetica-Bold", 9)
                c.drawCentredString(x + w / 2, 10, str(n))
            x += w


class Donut(Flowable):
    """Severity donut — status encoding, always paired with a labelled legend."""
    def __init__(self, counts: dict, size=110):
        super().__init__()
        self.counts = counts
        self.width = size
        self.height = size

    def draw(self):
        c = self.canv
        total = sum(self.counts.values())
        cx = cy = self.height / 2
        r = self.height / 2
        if total == 0:
            c.setFillColor(LINE)
            c.circle(cx, cy, r, stroke=0, fill=1)
        else:
            start = 90.0
            for sev in ["critical", "high", "medium", "low", "info"]:
                n = self.counts.get(sev, 0)
                if not n:
                    continue
                extent = -360.0 * (n / total)
                c.setFillColor(SEV[sev])
                c.wedge(cx - r, cy - r, cx + r, cy + r, start, extent, stroke=0, fill=1)
                start += extent
        # punch the hole
        c.setFillColor(colors.white)
        c.circle(cx, cy, r * 0.58, stroke=0, fill=1)
        c.setFillColor(INK)
        c.setFont("Helvetica-Bold", 17)
        c.drawCentredString(cx, cy + 2, str(total))
        c.setFillColor(DIM)
        c.setFont("Helvetica", 7)
        c.drawCentredString(cx, cy - 10, "FINDINGS")


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("H1x", parent=ss["Title"], fontName="Helvetica-Bold",
                          fontSize=22, textColor=INK, spaceAfter=2, leading=25))
    ss.add(ParagraphStyle("Subx", parent=ss["Normal"], fontSize=9.5, textColor=DIM, spaceAfter=2))
    ss.add(ParagraphStyle("H2x", parent=ss["Heading2"], fontName="Helvetica-Bold",
                          fontSize=13, textColor=INK, spaceBefore=14, spaceAfter=6))
    ss.add(ParagraphStyle("Body", parent=ss["Normal"], fontSize=9, textColor=INK, leading=13))
    ss.add(ParagraphStyle("Cell", parent=ss["Normal"], fontSize=8, textColor=INK, leading=10))
    ss.add(ParagraphStyle("CellMono", parent=ss["Normal"], fontName="Courier",
                          fontSize=7.5, textColor=INK, leading=10))
    ss.add(ParagraphStyle("Muted", parent=ss["Normal"], fontSize=8, textColor=DIM, leading=11))
    return ss


def _stat_cards(d: dict, ss) -> Table:
    s = d["stats"]
    cards = [
        ("DISCOVERED", s.get("discovered", s["subdomains"]), INK),
        ("RESOLVED", s["resolved"], ACCENT),
        ("LIVE (VALIDATED)", s["live"], colors.HexColor("#2f9e44")),
        ("OPEN PORTS", s["open_ports"], INK),
        ("URLS", s["urls"], INK),
        ("FINDINGS", s["findings"], SEV["high"] if s["findings"] else INK),
    ]
    row_n, row_l = [], []
    for label, val, col in cards:
        row_n.append(Paragraph(f'<font color="#{col.hexval()[2:]}"><b>{val:,}</b></font>',
                               ParagraphStyle("n", fontName="Helvetica-Bold", fontSize=19,
                                              alignment=TA_CENTER, textColor=col)))
        row_l.append(Paragraph(label, ParagraphStyle("l", fontSize=6.5, alignment=TA_CENTER,
                                                     textColor=DIM)))
    t = Table([row_n, row_l], colWidths=[86] * 6)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BG_CARD),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.white),
        ("TOPPADDING", (0, 0), (-1, 0), 8), ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def _sev_legend(counts: dict, ss):
    cells = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        n = counts.get(sev, 0)
        dot = f'<font color="#{SEV[sev].hexval()[2:]}">■</font>'
        cells.append(Paragraph(f'{dot} {sev.title()} <b>{n}</b>', ss["Cell"]))
    t = Table([[c] for c in cells], colWidths=[120])
    t.setStyle(TableStyle([("TOPPADDING", (0, 0), (-1, -1), 1),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]))
    return t


def _table(headers, rows, col_widths, ss, header_bg=INK):
    data = [[Paragraph(f'<b>{h}</b>', ParagraphStyle("th", fontSize=8,
             textColor=colors.white, fontName="Helvetica-Bold")) for h in headers]]
    data += rows
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafd")]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def build(d: dict, out_path: Path) -> Path | None:
    if not _OK:
        return None
    ss = _styles()
    doc = SimpleDocTemplate(str(out_path), pagesize=A4,
                            topMargin=16 * mm, bottomMargin=14 * mm,
                            leftMargin=15 * mm, rightMargin=15 * mm,
                            title=f"Recon Report — {d['target']}", author="ScamRecon")
    E = []

    # ── Header ──
    E.append(Paragraph("🛰&nbsp; Reconnaissance Report", ss["H1x"]))
    E.append(Paragraph(
        f"<b>{d['target']}</b> &nbsp;·&nbsp; {d['started']} → {d['finished']} "
        f"&nbsp;·&nbsp; {d['duration']} &nbsp;·&nbsp; profile: <b>{d['profile']}</b>",
        ss["Subx"]))
    E.append(Paragraph("Every host and vector below was DNS-resolved, HTTP-probed "
                       "and independently curl-validated.", ss["Muted"]))
    E.append(Spacer(1, 8))
    E.append(HRFlowable(width="100%", thickness=1.2, color=ACCENT))
    E.append(Spacer(1, 10))

    # ── Stat cards ──
    E.append(_stat_cards(d, ss))
    E.append(Spacer(1, 12))

    # ── Findings overview: donut + severity bar + legend ──
    sev = d["severity"]
    if d["stats"]["findings"]:
        overview = Table([[Donut(sev), _sev_legend(sev, ss),
                           SeverityBar(sev, width=250)]],
                         colWidths=[120, 130, 260])
        overview.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        E.append(KeepTogether([Paragraph("Findings by Severity", ss["H2x"]), overview]))

    # ── Attack Surface Highlights ──
    if d.get("highlights"):
        E.append(Paragraph("Attack Surface Highlights", ss["H2x"]))
        for hl in d["highlights"]:
            lvl = hl["level"]
            col = SEV.get(lvl, DIM)
            E.append(Paragraph(
                f'<font color="#{col.hexval()[2:]}"><b>[{lvl.upper()}]</b></font> {hl["text"]}',
                ss["Body"]))
            E.append(Spacer(1, 2))

    # ── Findings table ──
    if d["findings"]:
        E.append(Paragraph(f"Findings ({len(d['findings'])})", ss["H2x"]))
        rows = []
        for f in d["findings"][:60]:
            col = SEV.get(f["severity"], DIM)
            rows.append([
                Paragraph(f'<font color="#{col.hexval()[2:]}"><b>{f["severity"].upper()}</b></font>', ss["Cell"]),
                Paragraph(f["name"] or f["template"], ss["Cell"]),
                Paragraph(f["host"], ss["CellMono"]),
            ])
        E.append(_table(["Severity", "Finding", "Host"], rows, [70, 230, 190], ss))

    # ── Live hosts ──
    if d["live_hosts"]:
        E.append(Paragraph(f"Live Web Services ({len(d['live_hosts'])})", ss["H2x"]))
        rows = []
        for h in d["live_hosts"][:80]:
            sc = STATUS_C.get(h["status"] // 100, DIM)
            rows.append([
                Paragraph(f'<font color="#{sc.hexval()[2:]}"><b>{h["status"]}</b></font>', ss["Cell"]),
                Paragraph(h["url"], ss["CellMono"]),
                Paragraph((h["title"] or "")[:60], ss["Cell"]),
                Paragraph(", ".join(h["tech"][:3]), ss["Muted"]),
            ])
        E.append(_table(["St", "URL", "Title", "Tech"], rows, [34, 230, 140, 86], ss))

    # ── Validated attack vectors ──
    if d.get("validated_vectors"):
        E.append(Paragraph("Validated Attack Vectors (reachable, parameterized)", ss["H2x"]))
        rows = []
        for cls, urls in sorted(d["validated_vectors"].items(), key=lambda x: -len(x[1])):
            rows.append([Paragraph(f"<b>{cls}</b>", ss["Cell"]),
                         Paragraph(str(len(urls)), ss["Cell"]),
                         Paragraph(urls[0] if urls else "", ss["CellMono"])])
        E.append(_table(["Attack class", "Count", "Example"], rows, [150, 45, 295], ss))

    # ── Open ports ──
    if d.get("ports"):
        note = " (network interception detected — treat as unreliable)" if d.get("ports_unreliable") else ""
        E.append(Paragraph(f"Open Ports{note}", ss["H2x"]))
        rows = [[Paragraph(host, ss["CellMono"]),
                 Paragraph(", ".join(map(str, ports)), ss["Cell"])]
                for host, ports in list(d["ports"].items())[:40]]
        E.append(_table(["Host", "Ports"], rows, [230, 260], ss))

    # ── Footer ──
    E.append(Spacer(1, 14))
    E.append(HRFlowable(width="100%", thickness=0.5, color=LINE))
    E.append(Paragraph(f"Generated by ScamRecon · {d['finished']} · "
                       f"{d['stats']['subdomains']} subdomains → {d['stats']['live']} validated live hosts",
                       ss["Muted"]))

    def _page(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(DIM)
        canvas.drawRightString(A4[0] - 15 * mm, 8 * mm, f"Page {_doc.page}")
        canvas.drawString(15 * mm, 8 * mm, f"ScamRecon · {d['target']}")
        canvas.restoreState()

    try:
        doc.build(E, onFirstPage=_page, onLaterPages=_page)
        return out_path
    except Exception:  # noqa: BLE001
        return None
