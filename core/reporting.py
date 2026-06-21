# core/reporting.py
import os
import json
from datetime import datetime
from jinja2 import Template
from config import Config

def generate_pdf_report(result, output_path=None):
    """
    Generate an HTML report from the scan result.
    If pdfkit is installed and wkhtmltopdf is available, also generate PDF.
    """
    if output_path is None:
        os.makedirs(Config.REPORTS_DIR, exist_ok=True)
        output_path = os.path.join(
            Config.REPORTS_DIR,
            f"{result.get('file', 'report')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )

    # Load the template
    template_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'report.html')
    if not os.path.exists(template_path):
        # Fallback: use a simple inline template
        template_str = """
        <html>
        <body>
            <h1>Malware Analysis Report</h1>
            <p><b>File:</b> {{ result.file }}</p>
            <p><b>Verdict:</b> {{ result.verdict }}</p>
            <p><b>Score:</b> {{ result.score }}</p>
            <h3>Findings</h3>
            <ul>
            {% for f in result.findings %}
                <li><b>{{ f.source }}</b>: {{ f }}</li>
            {% endfor %}
            </ul>
        </body>
        </html>
        """
    else:
        with open(template_path, 'r', encoding='utf-8') as f:
            template_str = f.read()

    template = Template(template_str)
    html = template.render(
        result=result,
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    )

    # Save HTML
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    # Try to generate PDF if pdfkit is installed
    try:
        import pdfkit
        pdf_path = output_path.replace('.html', '.pdf')
        pdfkit.from_string(html, pdf_path)
        print(f"✅ PDF report saved to: {pdf_path}")
        return pdf_path
    except ImportError:
        print("ℹ️ pdfkit not installed – HTML report only.")
        return output_path
    except Exception as e:
        print(f"⚠️ PDF generation failed: {e}")
        return output_path