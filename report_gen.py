import os
import csv
import argparse
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch


def generate_pdf_report(directory, output_pdf):
    # Create a PDF document
    doc = SimpleDocTemplate(output_pdf, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()

    # Add the title "HaxUnit PDF Report"
    title_style = ParagraphStyle(
        'Title',
        fontSize=24,
        leading=28,
        alignment=1,  # Centered
        spaceAfter=20,
    )
    elements.append(Paragraph("HaxUnit PDF Report", title_style))
    elements.append(Spacer(1, 0.2 * inch))

    # List of files to include in the report
    files_to_include = [
        "all_ips.txt",
        "all_subdomains.txt",
        "all_subdomains_up.txt",
        "ffuf_result.txt",
        "httpx_ips.txt",
        "httpx_result.csv",
        "naabu_portscan.txt",
        "dnsx_result.txt",
        "dnsx_ips.txt",
        "subfinder_subdomains.txt",
        "katana_domains.txt",
        "alterx_result.txt",
        "wordpress_domains.txt",
        "nuclei_result.txt",
        "nuclei_result_formatted.txt"
    ]

    for filename in files_to_include:
        filepath = os.path.join(directory, filename)

        if os.path.exists(filepath):
            # Add a heading for each file
            elements.append(Paragraph(f"<b>{filename}</b>", styles['Heading2']))
            elements.append(Spacer(1, 0.2 * inch))

            with open(filepath, 'r') as file:
                content = file.read()
                for line in content.splitlines():
                    elements.append(Paragraph(line, styles['BodyText']))

            elements.append(Spacer(1, 0.5 * inch))
        else:
            elements.append(Paragraph(f"<b>{filename} not found in the directory.</b>", styles['BodyText']))
            elements.append(Spacer(1, 0.5 * inch))

    # Build the PDF document
    doc.build(elements)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a PDF report from files in a specified directory.")
    parser.add_argument("-d", '--directory', help="Path to the directory containing the files.")
    parser.add_argument("-o", "--output", default="report.html", help="Name of the output PDF file. Default is 'report.html'.")
    args = parser.parse_args()

    generate_pdf_report(args.directory, args.output)