import os
import re
import sys
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#1e293b"))
        
        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 11 * inch - 36, "NETVISOR ENGINEERING AUDIT REPORT")
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawRightString(8.5 * inch - 54, 11 * inch - 36, "AUGUST 2026")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)

        # Footer (all pages)
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawString(54, 36, "CONFIDENTIAL - NETVISOR SECURITY OPERATIONS PLATFORM")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * inch - 54, 36, page_str)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 46, 8.5 * inch - 54, 46)
        
        self.restoreState()

def clean_md_inline(text):
    text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'<b>\1</b>', text)
    text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'\*([^*]+)\*', r'<i>\1</i>', text)
    text = re.sub(r'`([^`]+)`', r'<font face="Courier" color="#0f172a" bgcolor="#f1f5f9"> \1 </font>', text)
    return text

def parse_markdown_to_flowables(md_filepath, styles):
    with open(md_filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    flowables = []
    in_code_block = False
    code_block_lines = []
    in_table = False
    table_lines = []

    body_style = styles['CustomBody']
    h1_style = styles['CustomH1']
    h2_style = styles['CustomH2']
    h3_style = styles['CustomH3']
    bullet_style = styles['CustomBullet']
    code_style = styles['CustomCode']

    def flush_table(lines):
        if not lines:
            return None
        table_data = []
        for l in lines:
            if not l.strip().startswith('|'):
                continue
            # Skip separator line like |---|---|
            if re.match(r'^\s*\|(?:\s*:?-+:?\s*\|)+\s*$', l):
                continue
            cols = [c.strip() for c in l.strip().strip('|').split('|')]
            row = [Paragraph(clean_md_inline(c), styles['TableCell']) for c in cols]
            table_data.append(row)
        
        if not table_data:
            return None
        
        # Calculate col widths based on max cols
        max_cols = max(len(r) for r in table_data)
        col_width = 504.0 / max_cols if max_cols > 0 else 504.0
        
        # Style table
        t = Table(table_data, colWidths=[col_width] * max_cols)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 9),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
            ('RIGHTPADDING', (0,0), (-1,-1), 5),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        return t

    for line in lines:
        raw_line = line.rstrip('\r\n')
        stripped = raw_line.strip()

        # Code blocks
        if stripped.startswith('```'):
            if in_code_block:
                code_text = '\n'.join(code_block_lines)
                code_text_clean = code_text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                p = Paragraph(f"<pre>{code_text_clean}</pre>", code_style)
                flowables.append(p)
                flowables.append(Spacer(1, 8))
                code_block_lines = []
                in_code_block = False
            else:
                in_code_block = True
            continue

        if in_code_block:
            code_block_lines.append(raw_line)
            continue

        # Tables
        if stripped.startswith('|'):
            if not in_table:
                in_table = True
                table_lines = []
            table_lines.append(raw_line)
            continue
        else:
            if in_table:
                t = flush_table(table_lines)
                if t:
                    flowables.append(Spacer(1, 6))
                    flowables.append(t)
                    flowables.append(Spacer(1, 8))
                in_table = False
                table_lines = []

        if not stripped:
            flowables.append(Spacer(1, 4))
            continue

        if stripped == '---':
            flowables.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceBefore=10, spaceAfter=10))
            continue

        # Headers
        if stripped.startswith('# '):
            text = clean_md_inline(stripped[2:])
            flowables.append(Spacer(1, 10))
            flowables.append(Paragraph(text, h1_style))
            flowables.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0f172a"), spaceBefore=4, spaceAfter=12))
            continue
        elif stripped.startswith('## '):
            text = clean_md_inline(stripped[3:])
            flowables.append(Spacer(1, 10))
            flowables.append(Paragraph(text, h2_style))
            flowables.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0284c7"), spaceBefore=2, spaceAfter=8))
            continue
        elif stripped.startswith('### '):
            text = clean_md_inline(stripped[4:])
            flowables.append(Spacer(1, 8))
            flowables.append(Paragraph(text, h3_style))
            flowables.append(Spacer(1, 4))
            continue

        # Bullets
        if stripped.startswith('- ') or stripped.startswith('* '):
            text = clean_md_inline(stripped[2:])
            flowables.append(Paragraph(f"• {text}", bullet_style))
            continue
        
        # Numbered list
        m_num = re.match(r'^(\d+)\.\s+(.*)$', stripped)
        if m_num:
            num, text = m_num.groups()
            text = clean_md_inline(text)
            flowables.append(Paragraph(f"<b>{num}.</b> {text}", bullet_style))
            continue

        # Standard paragraph
        text = clean_md_inline(stripped)
        flowables.append(Paragraph(text, body_style))
        flowables.append(Spacer(1, 4))

    if in_table:
        t = flush_table(table_lines)
        if t:
            flowables.append(t)

    return flowables

def generate_pdf(input_md, output_pdf):
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name='CustomH1',
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6
    ))

    styles.add(ParagraphStyle(
        name='CustomH2',
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0369a1"),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    ))

    styles.add(ParagraphStyle(
        name='CustomH3',
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=6,
        spaceAfter=2,
        keepWithNext=True
    ))

    styles.add(ParagraphStyle(
        name='CustomBody',
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=4
    ))

    styles.add(ParagraphStyle(
        name='CustomBullet',
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#1e293b"),
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=3
    ))

    styles.add(ParagraphStyle(
        name='CustomCode',
        fontName='Courier',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderColor=colors.HexColor("#cbd5e1"),
        borderWidth=0.5,
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=6
    ))

    styles.add(ParagraphStyle(
        name='TableCell',
        fontName='Helvetica',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0f172a")
    ))

    doc = SimpleDocTemplate(
        output_pdf,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    flowables = parse_markdown_to_flowables(input_md, styles)
    doc.build(flowables, canvasmaker=NumberedCanvas)
    print(f"SUCCESS: PDF generated at {output_pdf}")

if __name__ == "__main__":
    input_md = r"C:\Users\prem\.gemini\antigravity\brain\3d1dec1e-ee8b-4f0b-8680-789244687977\netvisor_engineering_audit_report.md"
    output_pdf1 = r"C:\Users\prem\Network\netvisor_engineering_audit_report.pdf"
    output_pdf2 = r"C:\Users\prem\.gemini\antigravity\brain\3d1dec1e-ee8b-4f0b-8680-789244687977\netvisor_engineering_audit_report.pdf"
    
    if os.path.exists(input_md):
        generate_pdf(input_md, output_pdf1)
        generate_pdf(input_md, output_pdf2)
    else:
        print(f"❌ Input markdown not found: {input_md}")
