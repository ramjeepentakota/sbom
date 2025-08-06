import os
import csv
import datetime
import re
import collections
import json
import logging
from typing import List, Dict, Optional
from core.depcheck_parser import parse_depcheck_html, parse_depcheck_json
from core.vulnerability_checker import Vulnerability
from core.sbom_generator import SBOMComponent

logging.basicConfig(level=logging.INFO)

# --- Helper Functions ---
def map_sbom_and_vulns_with_depcheck(sbom_components: List[SBOMComponent], depcheck_json_path: str) -> List[dict]:
    """
    Returns a list of dicts, each representing a file/package with strictly its own SBOM and vulnerability data,
    using only the OWASP Dependency-Check JSON report for CVEs.
    """
    cve_map = parse_depcheck_json(depcheck_json_path) if depcheck_json_path else {}
    result = []
    for comp in sbom_components:
        # Try to match by filename (preferred), then by hash, then by (name, version)
        matched = None
        cve_entry = None
        # 1. Filename match (case-insensitive, basename only)
        comp_file = os.path.basename(comp.file_path or '').lower()
        for key in cve_map:
            if isinstance(key, tuple):
                key_file = key[0].lower()
                if comp_file and comp_file == key_file:
                    matched = key
                    break
        # 2. Hash match (SHA256)
        if not matched and comp.checksums and 'sha256' in comp.checksums:
            sha256 = comp.checksums['sha256']
            if sha256 in cve_map:
                matched = sha256
        # 3. (name, version) match
        if not matched:
            for key in cve_map:
                if isinstance(key, tuple):
                    key_name, key_version = key
                    if comp.name.lower() == key_name.lower() and (comp.version or 'UNKNOWN') == (key_version or 'UNKNOWN'):
                        matched = key
                        break
        if matched:
            cve_entry = cve_map[matched]
        cve_ids = cve_entry['cve_ids'] if cve_entry and 'cve_ids' in cve_entry else []
        cve_details = cve_entry['details'] if cve_entry and 'details' in cve_entry else []
        entry = {
            'name': comp.name,
            'version': comp.version,
            'description': comp.description or "N/A",
            'supplier': comp.supplier or "N/A",
            'license': comp.license or "N/A",
            'origin': comp.origin or "N/A",
            'dependencies': comp.dependencies_field if hasattr(comp, 'dependencies_field') and comp.dependencies_field else (', '.join(comp.dependencies) if hasattr(comp, 'dependencies') and comp.dependencies else 'N/A'),
            'patch_status': comp.patch_status or "N/A",
            'release_date': comp.release_date or "N/A",
            'end_of_life_date': comp.end_of_life_date or "N/A",
            'criticality': comp.criticality or "N/A",
            'usage_restrictions': comp.usage_restrictions or "N/A",
            'checksums': comp.checksums or {},
            'comments': comp.comments or "N/A",
            'executable_property': comp.executable_property or "N/A",
            'archive_property': comp.archive_property or "N/A",
            'structured_property': comp.structured_property or "N/A",
            'unique_identifier': comp.unique_identifier or "N/A",
            'file_path': comp.file_path or "N/A",
            'cyclonedx': comp.to_cyclonedx(),
            'spdx': comp.to_spdx(),
            'vulnerabilities': cve_details if cve_details else [],
            'cve_ids': cve_ids if cve_ids else []
        }
        result.append(entry)
    return result

class ReportWriter:
    @staticmethod
    def write_csv_report(sbom_components: List[SBOMComponent], depcheck_json_path: str, output_path: str):
        """
        Write a CSV report with strict 1:1 mapping between files/packages and their SBOM+vulnerability data using Dependency-Check JSON.
        """
        mapped = map_sbom_and_vulns_with_depcheck(sbom_components, depcheck_json_path)
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                'Component Name', 'Version', 'Description', 'Supplier', 'License', 'Origin', 'Dependencies',
                'Patch Status', 'Release Date', 'End of Life Date', 'Criticality',
                'Usage Restrictions', 'Checksums (SHA-256/MD5)', 'Comments', 'Executable Property',
                'Archive Property', 'Structured Property', 'Unique Identifier', 'File Path',
                'CVE IDs', 'Vulnerability Details'
            ])
            for entry in mapped:
                checksums = entry['checksums']
                sha256_val = checksums.get('sha256', 'N/A')
                md5_val = checksums.get('md5', 'N/A')
                checksums_str = f"SHA-256: {sha256_val}<br>MD5: {md5_val}"
                def format_cve_ids_per_line(cve_list, per_line=3):
                    if not cve_list:
                        return 'No known CVEs'
                    lines = []
                    for i in range(0, len(cve_list), per_line):
                        lines.append(', '.join(cve_list[i:i+per_line]))
                    return '<br>'.join(lines)
                cve_ids = format_cve_ids_per_line(entry['cve_ids']) if entry['cve_ids'] else 'No known CVEs'
                vuln_details = json.dumps(entry['vulnerabilities'], ensure_ascii=False) if entry['vulnerabilities'] else 'No known CVEs'
                writer.writerow([
                    entry['name'],
                    entry['version'],
                    entry['description'],
                    entry['supplier'],
                    entry['license'],
                    entry['origin'],
                    entry['dependencies'],
                    entry['patch_status'],
                    entry['release_date'],
                    entry['end_of_life_date'],
                    entry['criticality'],
                    entry['usage_restrictions'],
                    checksums_str,
                    entry['comments'],
                    entry['executable_property'],
                    entry['archive_property'],
                    entry['structured_property'],
                    entry['unique_identifier'],
                    entry['file_path'],
                    cve_ids,
                    vuln_details
                ])

    @staticmethod
    def write_json_report(sbom_components: List[SBOMComponent], depcheck_json_path: str, output_path: str):
        """
        Write a JSON report with strict 1:1 mapping between files/packages and their SBOM+vulnerability data using Dependency-Check JSON.
        """
        mapped = map_sbom_and_vulns_with_depcheck(sbom_components, depcheck_json_path)
        # Remove CycloneDX and SPDX metadata from JSON output
        for entry in mapped:
            entry.pop('cyclonedx', None)
            entry.pop('spdx', None)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(mapped, f, indent=2, ensure_ascii=False)

    @staticmethod
    def write_html_report(sbom_components: List[SBOMComponent], depcheck_json_path: str, output_path: str, compliance_flags: Optional[Dict[str, bool]] = None, project_name: str = None):
        """
        Write an HTML report with strict 1:1 mapping between files/packages and their SBOM+vulnerability data using Dependency-Check JSON, using the audit_report.html template.
        """
        mapped = map_sbom_and_vulns_with_depcheck(sbom_components, depcheck_json_path)
        # Build thead and tbody HTML
        table_headers = [
            'Component Name', 'Version', 'Description', 'Supplier', 'License', 'Origin', 'Dependencies',
            'Patch Status', 'Release Date', 'End of Life Date', 'Criticality',
            'Usage Restrictions', 'Checksums', 'File Path', 'CVE IDs', 'Vulnerability Details'
        ]
        thead_html = '<thead><tr>' + ''.join(f'<th>{h}</th>' for h in table_headers) + '</tr></thead>'
        tbody_html = '<tbody>'
        for entry in mapped:
            checksums = entry['checksums']
            sha256_val = checksums.get('sha256', 'N/A')
            md5_val = checksums.get('md5', 'N/A')
            checksums_str = f"SHA-256: {sha256_val}<br>MD5: {md5_val}"
            def format_cve_ids_per_line(cve_list, per_line=3):
                if not cve_list:
                    return 'No known CVEs'
                lines = []
                for i in range(0, len(cve_list), per_line):
                    lines.append(', '.join(cve_list[i:i+per_line]))
                return '<br>'.join(lines)
            cve_ids = format_cve_ids_per_line(entry['cve_ids']) if entry['cve_ids'] else 'No known CVEs'
            vuln_details = '<ul>' + ''.join([
                f"<li><b>{v.get('cve', v.get('cve_id', ''))}</b>: {v.get('severity', 'N/A')} - {v.get('description', v.get('summary', ''))}</li>" for v in entry['vulnerabilities']
            ]) + '</ul>' if entry['vulnerabilities'] else 'No known CVEs'
            row = [
                entry['name'],
                entry['version'],
                entry['description'],
                entry['supplier'],
                entry['license'],
                entry['origin'],
                entry['dependencies'],
                entry['patch_status'],
                entry['release_date'],
                entry['end_of_life_date'],
                entry['criticality'],
                entry['usage_restrictions'],
                checksums_str,
                entry['file_path'],
                cve_ids,
                vuln_details
            ]
            tbody_html += '<tr>' + ''.join(f'<td>{cell}</td>' for cell in row) + '</tr>'
        tbody_html += '</tbody>'
        table_html = thead_html + tbody_html
        # Load audit_report.html template
        template_path = os.path.join(os.path.dirname(__file__), '../templates/audit_report.html')
        with open(template_path, encoding='utf-8') as f:
            template_html = f.read()
        # Embed logo as base64, inject directly into .navbar
        logo_path = os.path.join(os.path.dirname(__file__), '../templates/logo.png')
        import base64
        try:
            with open(logo_path, 'rb') as logo_file:
                logo_data = base64.b64encode(logo_file.read()).decode('utf-8')
            logo_data_uri = f'data:image/png;base64,{logo_data}'
            # Remove any <img ...logo.png...> tags
            template_html = re.sub(r'<img[^>]+src=["\"][^"\"]*logo.png[^"\"]*["\"][^>]*>', '', template_html)
            # Inject logo as first element after <body>
            template_html = re.sub(
                r'(<body[^>]*>)',
                r'\1\n<img src="' + logo_data_uri + '" style="height:54px;display:block;margin:16px auto 0 auto;" alt="Logo">',
                template_html,
                flags=re.IGNORECASE
            )
        except Exception:
            pass
        # Replace the Recent Reports table with the SBOM table
        import re
        # Use a function for replacement to avoid backslash escape issues
        def table_replacer(match):
            return f'<table class="report-table" id="sbom-table">{table_html}</table>'
        template_html = re.sub(
            r'(<table class="report-table"[\s\S]*?<thead>[\s\S]*?</thead>[\s\S]*?<tbody>[\s\S]*?</tbody>[\s\S]*?</table>)',
            table_replacer,
            template_html,
            count=1
        )
        # Set project name and IST timestamp in hero section
        if not project_name:
            # Try to infer project name from sbom_components or depcheck_json_path
            project_name = None
            if sbom_components and hasattr(sbom_components[0], 'file_path') and sbom_components[0].file_path:
                project_name = os.path.basename(os.path.dirname(sbom_components[0].file_path))
            elif depcheck_json_path:
                project_name = os.path.basename(os.path.dirname(depcheck_json_path))
            if not project_name:
                project_name = 'Project'
        template_html = template_html.replace('<h1>Audit Report Tool</h1>', f'<h1 id="sbom-heading">{project_name} SBOM Report</h1>')
        import re
        template_html = re.sub(r"\{\{\s*project_name\s*\}\}", project_name, template_html)

        # Inject compliance checker section if compliance_flags is provided
        compliance_html = ''
        compliance_html = '<div class="card"><div class="section-title">Compliance Checker</div>'
        if compliance_flags and len(compliance_flags) > 0:
            compliance_html += '<table class="report-table"><thead><tr><th>Guideline</th><th>Status</th></tr></thead><tbody>'
            for guideline, result in compliance_flags.items():
                status = result["status"] if isinstance(result, dict) and "status" in result else result
                status_str = '<span style="color: #fff; font-weight: 600; background: #ffb600; padding: 0.2em 0.7em; border-radius: 4px;">PASS</span>' if status else '<span style="color: #fff; font-weight: 600; background: #ff3b3b; padding: 0.2em 0.7em; border-radius: 4px;">FAIL</span>'
                compliance_html += f'<tr><td>{guideline}</td><td>{status_str}</td></tr>'
            compliance_html += '</tbody></table>'
        else:
            compliance_html += '<div style="padding:1em;color:#888;text-align:center;">No compliance data available.</div>'
        compliance_html += '</div>'
        template_html = template_html.replace('<!-- COMPLIANCE_SUMMARY -->', compliance_html)

        # Insert IST timestamp
        from datetime import datetime, timedelta, timezone
        import pytz
        try:
            ist = pytz.timezone('Asia/Kolkata')
            now_ist = datetime.now(ist)
        except Exception:
            now_ist = datetime.utcnow() + timedelta(hours=5, minutes=30)
        day = now_ist.day
        ist_str = now_ist.strftime(f'%B {day}, %Y – %I:%M %p IST')
        template_html = re.sub(
            r'<div class="sbom-timestamp" id="sbom-timestamp"[^>]*>.*?</div>',
            f'<div class="sbom-timestamp" id="sbom-timestamp">Report generated on: {ist_str}</div>',
            template_html,
            flags=re.DOTALL
        )
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(template_html)

    @staticmethod
    def write_unified_html_report(
        output_path: str,
        cyclonedx_json_path: str = None,
        spdx_json_path: str = None,
        depcheck_html_path: str = None,
        compliance_summaries: dict = None,
        sbom_components: list = None,
        project_name: str = None,
        scanned_files: list = None,
        all_cveids: list = None
        ):
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
  --primary-black: #111;
  --accent-gold: #ffb600;
  --bg: #fff;
  --card-bg: #fff;
  --border: #ffb600;
  --shadow: 0 4px 32px 0 #0002;
  --success: #ffb600;
  --fail: #ff3b3b;
  --warn: #ffb600;
  --text: #111;
  --text-light: #444;
  --badge-bg: #fffbe6;
  --badge-shadow: 0 2px 8px #ffb60022;
}}
html, body {{
  background: #fff;
  color: var(--text);
  font-family: 'Trebuchet MS', Arial, sans-serif;
  margin: 0; padding: 0;
  min-height: 100vh;
}}
body {{ min-height: 100vh; }}
header {{
  position:sticky;top:0;z-index:10;
  background: #fff;
  box-shadow:0 2px 16px #0002;
  padding:0 0 0 0.5em;
  display:flex;align-items:center;gap:1.5em;
  justify-content:center;
  border-bottom: 4px solid var(--accent-gold);
}}
header h1 {{
  font-family: 'Trebuchet MS', Arial, sans-serif;
  font-size:2.5em; letter-spacing:2px; color:var(--primary-black);
  margin:0.5em auto; flex:1; text-align:center;
}}
header .brand {{
  font-size:1.1em; color:var(--accent-gold); letter-spacing:1px;
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
  border: 2px solid var(--accent-gold);
  width: fit-content;
  min-width: 350px;
  max-width: 98vw;
  display: flex;
  flex-direction: column;
  align-items: center;
}}
h2, h3 {{
  color: var(--accent-gold);
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
  background: #fff;
  box-shadow: var(--shadow);
  font-size:1.08em;
  width: fit-content;
  min-width: 900px;
  max-width: 98vw;
}}
th, td {{
  padding: 14px 18px;
  border-bottom: 1px solid #ffb60033;
  font-family: 'Trebuchet MS', Arial, sans-serif;
}}
.cveid-nowrap {{
  white-space: nowrap;
}}
th {{
  background: var(--accent-gold);
  color: var(--primary-black);
  font-size:1.15em;
  text-align:center;
}}
td {{ text-align:center; }}
tr:last-child td {{ border-bottom: none; }}
tr:hover {{ background: #fffbe6; }}
.badge {{
  display:inline-block; padding:0.2em 0.8em; border-radius:1em;
  font-size:1.08em; font-family:'Trebuchet MS', Arial, sans-serif;
  background:var(--badge-bg); color:var(--primary-black); box-shadow:var(--badge-shadow); margin-right:0.5em;
}}
.pass {{ color:var(--accent-gold); font-weight:bold; }}
.fail {{ color:var(--fail); font-weight:bold; }}
.warn {{ color:var(--warn); font-weight:bold; }}
ul {{ margin-left: 2.5em; }}
footer {{
  margin-top: 3em; text-align: center; color: var(--text-light); font-size: 1.1em; padding: 2em 0 1em 0; border-top: 2px solid var(--accent-gold);
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
            html.append('<table class="report-table"><tr><th>File Path</th><th>Type</th><th>SHA-256</th></tr>')
            for f in scanned_files:
                html.append(f'<tr><td>{f.get("path","-")}</td><td>{f.get("type","Unknown")}</td><td>{f.get("hash","N/A")}</td></tr>')
            html.append('</table></div>')
        # Component Inventory Table (Unified SCA + SBOM)
        if sbom_components:
            html.append('<div class="card"><h2>Unified Component Inventory (SBOM + SCA)</h2>')
            html.append('<table class="report-table"><tr>'
                '<th>Component Name</th>'
                '<th>Version</th>'
                '<th>Description</th>'
                '<th>Supplier</th>'
                '<th>License</th>'
                '<th>Origin</th>'
                '<th>Dependencies</th>'
                '<th class="cveid-nowrap">CVE ID</th>'
                '<th>Patch Status</th>'
                '<th>Release Date</th>'
                '<th>End of Life Date</th>'
                '<th>Usage Restrictions</th>'
                '<th>Checksums (SHA-256/MD5)</th>'
                '<th>Authors of SBOM Data</th>'
                '</tr>')
            cve_link_map = {}
            if depcheck_html_path and os.path.exists(depcheck_html_path):
                try:
                    depcheck_vulns = parse_depcheck_html(depcheck_html_path)
                    for v in depcheck_vulns:
                        key = (v.package_name, v.version, v.cve_id)
                        cve_link_map[key] = getattr(v, 'cve_href', None)
                except Exception:
                    pass
            # Merge CVE IDs from vulnerabilities into sbom_components before rendering
            vuln_map = collections.defaultdict(list)
            if 'vulnerabilities' in locals() or 'vulns' in locals():
                vulns_list = locals().get('vulnerabilities') or locals().get('vulns')
                for v in vulns_list:
                    v_name = (getattr(v, 'package_name', '') or '').strip().lower()
                    v_version = (getattr(v, 'version', '') or '').strip().lower()
                    key = (v_name, v_version)
                    cve = getattr(v, 'cve_id', None)
                    if cve:
                        vuln_map[key].append(cve)
            for comp in sbom_components:
                c_name = (getattr(comp, 'name', '') or '').strip().lower()
                c_version = (getattr(comp, 'version', '') or '').strip().lower()
                cve_ids = vuln_map.get((c_name, c_version), [])
                if not hasattr(comp, 'cve_ids') or comp.cve_ids is None:
                    comp.cve_ids = []
                for cve in cve_ids:
                    if cve and cve not in comp.cve_ids:
                        comp.cve_ids.append(cve)
                dependencies_val = comp.dependencies_field if hasattr(comp, 'dependencies_field') and comp.dependencies_field else (', '.join(comp.dependencies) if hasattr(comp, 'dependencies') and comp.dependencies else 'N/A')
                def format_cve_ids(cve_list):
                    if not cve_list:
                        return 'N/A'
                    lines = []
                    for i in range(0, len(cve_list), 5):
                        lines.append(', '.join(cve_list[i:i+5]))
                    return '<br>'.join(lines)
                if hasattr(comp, 'vulnerabilities_field') and comp.vulnerabilities_field and hasattr(comp, 'cve_ids') and comp.cve_ids:
                    vset = set([v.strip() for v in comp.vulnerabilities_field.split(',')])
                    cset = set(comp.cve_ids)
                    merged = sorted(vset.union(cset))
                    vulnerabilities_val = format_cve_ids(merged)
                elif hasattr(comp, 'vulnerabilities_field') and comp.vulnerabilities_field:
                    vlist = [v.strip() for v in comp.vulnerabilities_field.split(',') if v.strip()]
                    vulnerabilities_val = format_cve_ids(sorted(vlist))
                elif hasattr(comp, 'cve_ids') and comp.cve_ids:
                    vulnerabilities_val = format_cve_ids(sorted(comp.cve_ids))
                else:
                    vulnerabilities_val = 'N/A'
                sha256_val = comp.hash_sha256 or (comp.checksums.get('sha256') if hasattr(comp, 'checksums') and comp.checksums else None)
                md5_val = comp.checksums.get('md5') if hasattr(comp, 'checksums') and comp.checksums and 'md5' in comp.checksums else None
                checksums_str = f"SHA-256: {sha256_val if sha256_val else 'N/A'}<br>MD5: {md5_val if md5_val else 'N/A'}"
                html.append(f'<tr>'
                    f'<td>{comp.name}</td>'
                    f'<td>{comp.version}</td>'
                    f'<td>{comp.description or "N/A"}</td>'
                    f'<td>{comp.supplier or "N/A"}</td>'
                    f'<td>{comp.license or "N/A"}</td>'
                    f'<td>{comp.origin or "N/A"}</td>'
                    f'<td>{dependencies_val}</td>'
                    f'<td class="cveid-nowrap">{vulnerabilities_val}</td>'
                    f'<td>{comp.patch_status or "N/A"}</td>'
                    f'<td>{comp.release_date or "N/A"}</td>'
                    f'<td>{comp.end_of_life_date or "N/A"}</td>'
                    f'<td>{comp.usage_restrictions or "N/A"}</td>'
                    f'<td>{checksums_str}</td>'
                    f'<td>{comp.generated_by or "N/A"}</td>'
                    '</tr>')
            html.append('</table></div>')

        # Vulnerability Table (from vulns list)
        if 'vulnerabilities' in locals() or 'vulns' in locals():
            vulns_list = locals().get('vulnerabilities') or locals().get('vulns')
        else:
            vulns_list = None
        if vulns_list:
            html.append('<div class="card"><h2>CVE ID (Detailed)</h2>')
            html.append('<table class="report-table"><tr>'
                '<th>Component Name</th>'
                '<th>Version</th>'
                '<th>CVE ID</th>'
                '<th>Severity</th>'
                '<th>Summary</th>'
                '<th>CVSS Score</th>'
                '<th>Remediation</th>'
                '<th>Exploitability</th>'
                '<th>Affected Version Range</th>'
                '</tr>')
            for v in vulns_list:
                html.append(f'<tr>'
                    f'<td>{getattr(v, "package_name", "N/A")}</td>'
                    f'<td>{getattr(v, "version", "N/A")}</td>'
                    f'<td>{getattr(v, "cve_id", "N/A")}</td>'
                    f'<td>{getattr(v, "severity", "N/A")}</td>'
                    f'<td>{getattr(v, "summary", "N/A")}</td>'
                    f'<td>{getattr(v, "cvss_score", "N/A")}</td>'
                    f'<td>{getattr(v, "remediation", "N/A")}</td>'
                    f'<td>{getattr(v, "exploitability", "N/A")}</td>'
                    f'<td>{getattr(v, "affected_version_range", "N/A")}</td>'
                    '</tr>')
            html.append('</table></div>')
        # Compliance summaries
        if compliance_summaries:
            html.append('<div class="card">')
            html.append('<h2>Compliance Summaries</h2>')
            html.append('<table class="report-table">')
            html.append('<tr><th>Compliance Mode</th><th>Status</th><th>Timestamp</th></tr>')
            for mode, summary_path in compliance_summaries.items():
                if os.path.exists(summary_path):
                    with open(summary_path, encoding='utf-8') as f:
                        lines = f.readlines()
                        overall_status = 'PASS'
                        compliance_time = ''
                        for line in lines:
                            if '<li>' in line:
                                match = re.search(r'<li>(.*?)\s*:\s*(PASS|FAIL)</li>', line, re.IGNORECASE)
                                if match:
                                    status_val = match.group(2).strip().upper()
                                    if status_val == 'FAIL':
                                        overall_status = 'FAIL'
                            if 'Compliance Mode:' in line or '<h1>' in line:
                                ts_match = re.search(r'(\d{{4}}-\d{{2}}-\d{{2}}[ T]\d{{2}}:\d{{2}}:\d{{2}})', line)
                                if ts_match:
                                    compliance_time = ts_match.group(1)
                        if not compliance_time:
                            compliance_time = datetime.datetime.fromtimestamp(os.path.getmtime(summary_path)).strftime('%Y-%m-%d %H:%M:%S')
                        status = f'<span class="pass">PASS</span>' if overall_status == 'PASS' else f'<span class="fail">FAIL</span>'
                        html.append(f'<tr><td>{mode.upper()}</td><td>{status}</td><td>{compliance_time}</td></tr>')
            html.append('</table></div>')
        html.append('<footer>Report generated by <span class="brand">YSP_SBOM_Generator</span> &mdash; {}</footer>'.format(datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')))
        html.append('</section></body></html>')
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(html))
