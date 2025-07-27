import os
import csv
from typing import List, Dict
from core.vulnerability_checker import Vulnerability
from core.sbom_generator import SBOMComponent

class ReportWriter:
    @staticmethod
    def write_csv_report(vulnerabilities: List[Vulnerability], sbom_components: List[SBOMComponent], output_path: str):
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Component', 'Version', 'CVE', 'Severity', 'CVSS Score', 'Remediation', 'License', 'Supplier', 'File Path'])
            for vuln in vulnerabilities:
                comp = next((c for c in sbom_components if c.name == vuln.package_name and c.version == vuln.version), None)
                writer.writerow([
                    vuln.package_name,
                    vuln.version,
                    vuln.cve_id,
                    vuln.severity,
                    vuln.cvss_score,
                    vuln.remediation or '',
                    comp.license if comp else '',
                    comp.supplier if comp else '',
                    comp.file_path if comp else ''
                ])

    @staticmethod
    def write_html_report(vulnerabilities: List[Vulnerability], sbom_components: List[SBOMComponent], output_path: str, compliance_flags: Dict[str, bool] = None):
        # (Unchanged, not the main report)
        pass

    @staticmethod
    def write_unified_html_report(
        output_path: str,
        cyclonedx_json_path: str = None,
        spdx_json_path: str = None,
        depcheck_html_path: str = None,
        compliance_summaries: dict = None,
        sbom_components: list = None,
        project_name: str = None,
        scanned_files: list = None
    ):
        import datetime
        report_title = f"{project_name} SCA & SBOM Report" if project_name else "Unified SCA & SBOM Report"
        html = [f"""<!DOCTYPE html>
<html lang='en'>
<head>
<title>{report_title}</title>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1.0'>
<link href='https://fonts.googleapis.com/css2?family=Trebuchet+MS:wght@400;700&display=swap' rel='stylesheet'>
<style>
:root {{
  --primary: #2a3b8f;
  --accent: #00e6d8;
  --bg: #181c24;
  --card-bg: rgba(255,255,255,0.08);
  --glass: rgba(255,255,255,0.18);
  --border: #2a3b8f33;
  --shadow: 0 4px 32px 0 #0002;
  --success: #1ad88f;
  --fail: #ff3b3b;
  --warn: #ffb300;
  --text: #e6e6e6;
  --text-light: #bfc9d1;
  --badge-bg: #232a3a;
  --badge-shadow: 0 2px 8px #00e6d822;
}}
html, body {{
  background: linear-gradient(120deg, #232a3a 0%, #181c24 100%);
  color: var(--text);
  font-family: 'Trebuchet MS', Arial, sans-serif;
  margin: 0; padding: 0;
  min-height: 100vh;
}}
body {{ min-height: 100vh; }}
header {{
  position:sticky;top:0;z-index:10;
  background:linear-gradient(90deg,#232a3a 60%,#2a3b8f 100%);
  box-shadow:0 2px 16px #0004;
  padding:0 0 0 0.5em;
  display:flex;align-items:center;gap:1.5em;
  justify-content:center;
}}
header h1 {{
  font-family: 'Trebuchet MS', Arial, sans-serif;
  font-size:2.5em; letter-spacing:2px; color:var(--accent);
  margin:0.5em auto; flex:1; text-align:center;
}}
header .brand {{
  font-size:1.1em; color:var(--text-light); letter-spacing:1px;
}}
section {{
  margin: 2.5em auto;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: flex-start;
  min-height: 90vh;
  width: 100vw;
  max-width: 100vw;
}}
.card {{
  background: var(--card-bg);
  border-radius: 18px;
  box-shadow: var(--shadow);
  padding: 2.2em 2em 2em 2em;
  margin-bottom: 2.5em;
  border: 1.5px solid var(--border);
  backdrop-filter: blur(8px);
  width: fit-content;
  min-width: 350px;
  max-width: 98vw;
  display: flex;
  flex-direction: column;
  align-items: center;
}}
h2, h3 {{
  color: var(--accent);
  font-family: 'Trebuchet MS', Arial, sans-serif;
  letter-spacing:1px;
  text-align:center;
  font-size:2em;
}}
h3 {{ font-size:1.3em; }}
table {{
  margin: 1.5em auto;
  border-radius: 12px;
  overflow: hidden;
  background: var(--glass);
  box-shadow: var(--shadow);
  font-size:1.08em;
  width: fit-content;
  min-width: 900px;
  max-width: 98vw;
}}
th, td {{
  padding: 14px 18px;
  border-bottom: 1px solid #2a3b8f33;
  font-family: 'Trebuchet MS', Arial, sans-serif;
}}
th {{
  background: #232a3a;
  color: var(--accent);
  font-size:1.15em;
  text-align:center;
}}
td {{ text-align:center; }}
tr:last-child td {{ border-bottom: none; }}
tr:hover {{ background: #232a3a44; }}
.badge {{
  display:inline-block; padding:0.2em 0.8em; border-radius:1em;
  font-size:1.08em; font-family:'Trebuchet MS', Arial, sans-serif;
  background:var(--badge-bg); color:var(--accent); box-shadow:var(--badge-shadow); margin-right:0.5em;
}}
.pass {{ color:var(--success); font-weight:bold; }}
.fail {{ color:var(--fail); font-weight:bold; }}
.warn {{ color:var(--warn); font-weight:bold; }}
ul {{ margin-left: 2.5em; }}
footer {{
  margin-top: 3em; text-align: center; color: var(--text-light); font-size: 1.1em; padding: 2em 0 1em 0; border-top: 1px solid #2a3b8f33;
  font-family: 'Trebuchet MS', Arial, sans-serif;
}}
@media (max-width: 1200px) {{
  section {{ width: 98vw; min-width: 0; }}
}}
@media (max-width: 800px) {{
  section, .card {{ padding: 1.2em 0.5em; }}
  th, td {{ padding: 8px 6px; font-size:0.98em; }}
  h2, h3 {{ font-size:1.2em; }}
}}
</style>
</head>
<body>
<header>
  <h1>{report_title}</h1>
  <span class='brand'>YSP_SBOM_Generator</span>
</header>
<section>
"""]
        # SBOM Metadata
        html.append('<div class="card"><h2>SBOM Metadata</h2>')
        # Extract compliance timestamps
        compliance_timestamps = {}
        if compliance_summaries:
            for mode, summary_path in compliance_summaries.items():
                if os.path.exists(summary_path):
                    compliance_time = ''
                    with open(summary_path, encoding='utf-8') as f:
                        lines = f.readlines()
                        for line in lines:
                            if 'Compliance Mode:' in line or '<h1>' in line:
                                import re
                                ts_match = re.search(r'(\d{{4}}-\d{{2}}-\d{{2}}[ T]\d{{2}}:\d{{2}}:\d{{2}})', line)
                                if ts_match:
                                    compliance_time = ts_match.group(1)
                    if not compliance_time:
                        compliance_time = datetime.datetime.fromtimestamp(os.path.getmtime(summary_path)).strftime('%Y-%m-%d %H:%M:%S')
                    compliance_timestamps[mode.upper()] = compliance_time
        if compliance_timestamps:
            # Use the most recent timestamp among all compliance modes
            latest_ts = max(compliance_timestamps.values())
            html.append(f'<p>SBOM Generation Timestamp: <span class="badge">{latest_ts}</span></p>')
        else:
            html.append(f'<p>SBOM Generation Timestamp: <span class="badge">{datetime.datetime.utcnow().isoformat()}Z</span></p>')
        html.append(f'<p>Generated By: <span class="badge">YSP_SBOM_Generator</span></p></div>')
        # Scanned Files Section
        if scanned_files:
            html.append('<div class="card"><h2>Scanned Files</h2>')
            html.append('<table><tr><th>File Path</th><th>Type</th><th>SHA-256</th></tr>')
            for f in scanned_files:
                html.append(f'<tr><td>{f.get("path","-")}</td><td>{f.get("type","Unknown")}</td><td>{f.get("hash","N/A")}</td></tr>')
            html.append('</table></div>')
        # Component Inventory Table (Unified SCA + SBOM)
        if sbom_components:
            html.append('<div class="card"><h2>Unified Component Inventory (SBOM + SCA)</h2>')
            html.append('<table><tr>'
                '<th>Component Name</th><th>Version</th><th>Supplier/Vendor</th><th>License Type</th>'
                '<th>Cryptographic Hash (SHA-256)</th>'
                '<th>CVE IDs</th><th>Severity</th>'
                '<th>Component Release Date</th><th>SBOM Generation Timestamp</th>'
                '<th>SBOM Author/Tool</th><th>Is Executable (Yes/No)</th><th>Is Archive (Yes/No)</th>'
                '<th>Has Known Unknowns (Yes/No)</th><th>CI/CD Integration (Yes/No)</th><th>Patch Available (Yes/No)</th>'
                '<th>Policy Reference</th>'
                '<th>Quarterly Risk Review Date</th><th>SBOM Audit Trail Reference</th>'
                '</tr>')
            cve_link_map = {}
            if depcheck_html_path and os.path.exists(depcheck_html_path):
                try:
                    from core.depcheck_parser import parse_depcheck_html
                    depcheck_vulns = parse_depcheck_html(depcheck_html_path)
                    for v in depcheck_vulns:
                        key = (v.package_name, v.version, v.cve_id)
                        cve_link_map[key] = getattr(v, 'cve_href', None)
                except Exception:
                    pass
            for comp in sbom_components:
                cve_links = []
                if hasattr(comp, "cve_ids") and comp.cve_ids:
                    for cve in comp.cve_ids:
                        cve_url = cve_link_map.get((comp.name, comp.version, cve))
                        if cve_url:
                            cve_links.append(f'<a href="{cve_url}" target="_blank">{cve}</a>')
                        else:
                            cve_links.append(cve)
                html.append(f'<tr>'
                    f'<td>{comp.name}</td>'
                    f'<td>{comp.version}</td>'
                    f'<td>{comp.supplier or "Unknown"}</td>'
                    f'<td>{comp.license or "Unknown"}</td>'
                    f'<td>{comp.hash_sha256 or "Unknown"}</td>'
                    f'<td>' + (", ".join(cve_links) if cve_links else "N/A") + '</td>'
                    f'<td>{comp.severity or "N/A"}</td>'
                    f'<td>{comp.release_date or "Unknown"}</td>'
                    f'<td>{comp.sbom_timestamp or "Unknown"}</td>'
                    f'<td>{"YSP_SBOM_Generator"}</td>'
                    f'<td>{"Yes" if comp.executable_flag else "No"}</td>'
                    f'<td>{"Yes" if getattr(comp, "is_archive", False) else "No"}</td>'
                    f'<td>{"Yes" if comp.known_unknown else "No"}</td>'
                    f'<td>{"Yes" if getattr(comp, "ci_cd_integration", False) else "No"}</td>'
                    f'<td>{"Yes" if getattr(comp, "patch_available", False) else "No"}</td>'
                    f'<td>{getattr(comp, "policy_reference", "N/A")}</td>'
                    f'<td>{getattr(comp, "quarterly_risk_review_date", "N/A")}</td>'
                    f'<td>{getattr(comp, "sbom_audit_trail_reference", "N/A")}</td>'
                    '</tr>')
            html.append('</table></div>')
        # Compliance summaries
        if compliance_summaries:
            html.append('<div class="card" style="background:rgba(0,230,216,0.04);border:2px solid #00e6d8;width:auto;display:inline-block;margin:0 auto;padding:24px 24px 20px 24px;">')
            html.append('<h2 style="margin-top:0;text-align:center;">Compliance Summaries</h2>')
            html.append('<table style="width:auto;margin:0 auto;border-collapse:collapse;margin-top:10px;table-layout:auto;">')
            html.append('<tr><th style="text-align:center;padding:4px 10px;background:#232a3a;color:#00e6d8;">Compliance Mode</th><th style="text-align:center;padding:4px 10px;background:#232a3a;color:#00e6d8;">Status</th><th style="text-align:center;padding:4px 10px;background:#232a3a;color:#00e6d8;">Timestamp</th></tr>')
            for mode, summary_path in compliance_summaries.items():
                if os.path.exists(summary_path):
                    with open(summary_path, encoding='utf-8') as f:
                        lines = f.readlines()
                        overall_status = 'PASS'
                        compliance_time = ''
                        for line in lines:
                            if '<li>' in line:
                                import re
                                match = re.search(r'<li>(.*?)\s*:\s*(PASS|FAIL)</li>', line, re.IGNORECASE)
                                if match:
                                    status_val = match.group(2).strip().upper()
                                    if status_val == 'FAIL':
                                        overall_status = 'FAIL'
                            if 'Compliance Mode:' in line or '<h1>' in line:
                                import re
                                # Try to extract a timestamp from the file (if present)
                                ts_match = re.search(r'(\d{{4}}-\d{{2}}-\d{{2}}[ T]\d{{2}}:\d{{2}}:\d{{2}})', line)
                                if ts_match:
                                    compliance_time = ts_match.group(1)
                        if not compliance_time:
                            # Fallback to file modification time
                            compliance_time = datetime.datetime.fromtimestamp(os.path.getmtime(summary_path)).strftime('%Y-%m-%d %H:%M:%S')
                        status = f'<span class="pass" style="white-space:nowrap;display:inline-block;min-width:60px;">PASS</span>' if overall_status == 'PASS' else f'<span class="fail" style="white-space:nowrap;display:inline-block;min-width:60px;">FAIL</span>'
                        html.append(f'<tr><td style="padding:6px 10px;text-align:center;">{mode.upper()}</td><td style="padding:6px 10px;text-align:center;">{status}</td><td style="padding:6px 10px;text-align:center;">{compliance_time}</td></tr>')
            html.append('</table></div>')
        html.append('<footer>Report generated by <span class="brand">YSP_SBOM_Generator</span> &mdash; {}</footer>'.format(datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')))
        html.append('</section></body></html>')
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(html))
