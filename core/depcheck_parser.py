import re
import json
from bs4 import BeautifulSoup
from core.vulnerability_checker import Vulnerability


def extract_all_cveids_from_html(html_path):
    """
    Extract all unique CVE IDs (CVE-YYYY-NNNN) from the entire HTML file, regardless of structure.
    Returns a sorted list of unique CVE IDs.
    """
    import re
    with open(html_path, encoding='utf-8') as f:
        html = f.read()
    cve_ids = sorted(set(re.findall(r'CVE-\d{4}-\d+', html)))
    return cve_ids


def parse_depcheck_json(json_path):
    """
    Parse OWASP Dependency-Check JSON report and return a mapping:
    {(package_name, version): {'cve_ids': [CVE_IDs], 'details': [dicts]}}
    """
    cve_map = {}
    try:
        with open(json_path, encoding='utf-8') as f:
            data = json.load(f)
            dependencies = data.get('dependencies', [])
            for dep in dependencies:
                pkg = dep.get('fileName') or dep.get('packagePath') or ''
                pkg = pkg.split('/')[-1].split('\\')[-1]
                sha256 = dep.get('sha256')
                # Extract version from evidenceCollected['versionEvidence']
                version = None
                evidence = dep.get('evidenceCollected', {})
                version_evidence = evidence.get('versionEvidence', []) if isinstance(evidence, dict) else []
                for ev in version_evidence:
                    if ev.get('value') and ev.get('confidence', '').upper() in ('HIGH', 'HIGHEST'):
                        version = ev.get('value')
                        break
                if not version:
                    for ev in version_evidence:
                        if ev.get('value'):
                            version = ev.get('value')
                            break
                cve_ids = []
                cvss_scores = []
                details = []
                import re
                for vuln in dep.get('vulnerabilities', []):
                    cve_id = vuln.get('name')
                    if cve_id and re.match(r"CVE-\d{4}-\d+", cve_id):
                        cve_ids.append(cve_id)
                        # Prefer CVSSv3 baseScore, fallback to CVSSv2 score
                        score = None
                        if 'cvssv3' in vuln and vuln['cvssv3'] and 'baseScore' in vuln['cvssv3']:
                            score = vuln['cvssv3']['baseScore']
                        elif 'cvssv2' in vuln and vuln['cvssv2'] and 'score' in vuln['cvssv2']:
                            score = vuln['cvssv2']['score']
                        if score is not None:
                            cvss_scores.append(str(score))
                        details.append({
                            'cve_id': cve_id,
                            'severity': vuln.get('severity'),
                            'description': vuln.get('description'),
                            'cvssScore': score,
                            'cvssv3': vuln.get('cvssv3'),
                            'cvssv2': vuln.get('cvssv2'),
                            'references': vuln.get('references', []),
                            'cwe': vuln.get('cwe'),
                        })
                key = (pkg, version or 'UNKNOWN')
                if cve_ids:
                    cve_map[key] = {'cve_ids': cve_ids, 'cvss_scores': cvss_scores, 'details': details}
                if sha256 and cve_ids:
                    cve_map[sha256] = {'cve_ids': cve_ids, 'cvss_scores': cvss_scores, 'details': details}
    except Exception as e:
        print(f"[ERROR] parse_depcheck_json: {e}")
    return cve_map

def parse_depcheck_html(html_path):
    """
    Parse OWASP Dependency-Check HTML report and return a list of Vulnerability objects.
    """
    vulns = []
    try:
        with open(html_path, encoding='utf-8') as f:
            soup = BeautifulSoup(f, 'html.parser')
            # Find the table with vulnerabilities
            tables = soup.find_all('table')
            for table in tables:
                headers = [th.get_text(strip=True) for th in table.find_all('th')]
                if any('CVE' in h for h in headers) and any('Component' in h or 'Dependency' in h for h in headers):
                    for row in table.find_all('tr')[1:]:
                        cells = row.find_all('td')
                        if len(cells) < 5:
                            continue
                        component = cells[0].get_text(strip=True)
                        version = cells[1].get_text(strip=True)
                        # Extract CVE ID and hyperlink (always extract CVE-xxxx-xxxx)
                        cve = None
                        cve_link_tag = cells[2].find('a')
                        if cve_link_tag and cve_link_tag.get('href'):
                            cve_text = cve_link_tag.get_text(strip=True)
                            # Try to extract CVE ID from the text or href
                            m = re.search(r'(CVE-\d{4}-\d+)', cve_text)
                            if not m and cve_link_tag['href']:
                                m = re.search(r'(CVE-\d{4}-\d+)', cve_link_tag['href'])
                            if m:
                                cve = m.group(1)
                            else:
                                cve = None
                            cve_href = cve_link_tag['href']
                        else:
                            cve_text = cells[2].get_text(strip=True)
                            m = re.search(r'(CVE-\d{4}-\d+)', cve_text)
                            if m:
                                cve = m.group(1)
                            else:
                                cve = None
                            cve_href = None
                        severity = cells[3].get_text(strip=True)
                        summary = cells[4].get_text(strip=True)
                        cvss_score = None
                        # Try to extract CVSS score from summary or another cell if available
                        m = re.search(r'CVSS.*?(\d+\.\d+)', summary)
                        if m:
                            cvss_score = float(m.group(1))
                        # Extract remediation from summary
                        remediation = None
                        remediation_match = re.search(r'(upgrade to [^.,;\n]+|apply patch[^.,;\n]*|fixed in [^.,;\n]+)', summary, re.IGNORECASE)
                        if remediation_match:
                            remediation = remediation_match.group(1).strip()
                        # Extract exploitability from CVSS vector if present
                        exploitability = None
                        cvss_vector_match = re.search(r'CVSS:[^\s]+', summary)
                        if cvss_vector_match:
                            vector = cvss_vector_match.group(0)
                            if 'AV:N' in vector and 'AC:L' in vector:
                                exploitability = 'High'
                            elif 'AV:L' in vector:
                                exploitability = 'Medium'
                            else:
                                exploitability = 'Unknown'
                        # Extract affected version range from summary
                        affected_version_range = None
                        avr_match = re.search(r'versions? (from [^.,;\n]+ up to [^.,;\n]+|before [^.,;\n]+|including [^.,;\n]+|up to [^.,;\n]+|through [^.,;\n]+)', summary, re.IGNORECASE)
                        if avr_match:
                            affected_version_range = avr_match.group(0).strip()
                        if cve:
                            print(f"[DEBUG] Parsed Vulnerability: component={component}, version={version}, cve_id={cve}, severity={severity}, summary={summary}, cvss_score={cvss_score}, remediation={remediation}, exploitability={exploitability}, affected_version_range={affected_version_range}")
                            vulns.append(Vulnerability(
                                package_name=component,
                                version=version,
                                cve_id=cve,
                                severity=severity,
                                summary=summary,
                                cvss_score=cvss_score,
                                remediation=remediation,
                                exploitability=exploitability,
                                affected_version_range=affected_version_range
                            ))
                            # Store CVE hyperlink for mapping
                            if not hasattr(vulns[-1], 'cve_href'):
                                vulns[-1].cve_href = cve_href
                            else:
                                vulns[-1].cve_href = cve_href
    except Exception:
        pass
    return vulns


def get_cveids_and_cvss_by_dependency_from_depcheck_html(html_path):
    import re
    from bs4 import BeautifulSoup
    cve_map = {}
    with open(html_path, encoding='utf-8') as file:
        soup = BeautifulSoup(file, "html.parser")
        # For each dependency section (panel)
        for panel in soup.find_all('div', class_='panel panel-default'):
            # Get the JAR/component name
            title = panel.find('h4', class_='panel-title')
            if not title:
                continue
            jar_name = title.get_text(strip=True).split('/')[-1].split('\\')[-1].lower()
            cve_list = []
            for link in panel.find_all("a", href=True):
                cve_text = link.text.strip()
                if re.match(r"CVE-\d{4}-\d+", cve_text):
                    cve_id = cve_text
                    score = "N/A"
                    # Look for nearby text containing CVSS score
                    surrounding_text = link.find_parent().find_next(string=re.compile(r"Base Score:", re.IGNORECASE))
                    if surrounding_text:
                        score_match = re.search(r"Base Score:\s*(?:HIGH|MEDIUM|LOW)?\s*\(?([0-9.]+)?", surrounding_text)
                        if score_match:
                            score = score_match.group(1)
                    cve_list.append((cve_id, score))
            if cve_list:
                cve_map[jar_name] = cve_list
    return cve_map
