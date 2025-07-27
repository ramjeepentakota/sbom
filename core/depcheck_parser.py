import re
from bs4 import BeautifulSoup
from core.vulnerability_checker import Vulnerability

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
                        # Extract CVE ID and hyperlink
                        cve_link_tag = cells[2].find('a')
                        if cve_link_tag and cve_link_tag.get('href'):
                            cve = cve_link_tag.get_text(strip=True)
                            cve_href = cve_link_tag['href']
                        else:
                            cve = cells[2].get_text(strip=True)
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


def get_cveids_by_dependency_from_depcheck_html(html_path):
    """
    Parse Dependency-Check HTML and return a mapping: {dependency_file_path: [CVE_IDs]}
    """
    cve_map = {}
    try:
        with open(html_path, encoding='utf-8') as f:
            soup = BeautifulSoup(f, 'html.parser')
            # Each dependency section is a <div class="panel panel-default">
            for panel in soup.find_all('div', class_='panel panel-default'):
                # Dependency file path is in <h4 class="panel-title">
                title = panel.find('h4', class_='panel-title')
                if not title:
                    continue
                dep_name = title.get_text(strip=True)
                jar_name = dep_name.split('/')[-1].split('\\')[-1].lower()  # works for both / and \ separators
                # Find Published Vulnerabilities section
                pub_vuln_header = panel.find(lambda tag: tag.name == 'h5' and 'Published Vulnerabilities' in tag.text)
                if pub_vuln_header:
                    cve_list = []
                    # Look at the next several siblings after the header for CVE IDs
                    next_tag = pub_vuln_header.find_next_sibling()
                    checked = 0
                    while next_tag and checked < 10:
                        text = next_tag.get_text(" ", strip=True) if hasattr(next_tag, 'get_text') else str(next_tag)
                        cve_matches = re.findall(r'(CVE-\d{4}-\d+)', text)
                        cve_list.extend(cve_matches)
                        next_tag = next_tag.find_next_sibling()
                        checked += 1
                    # Also check any <ul> directly after the header (legacy logic)
                    ul = pub_vuln_header.find_next('ul')
                    if ul:
                        for li in ul.find_all('li'):
                            cve_match = re.findall(r'(CVE-\d{4}-\d+)', li.get_text())
                            cve_list.extend(cve_match)
                    if cve_list:
                        cve_map[jar_name] = list(sorted(set(cve_list)))
    except Exception:
        pass
    return cve_map
