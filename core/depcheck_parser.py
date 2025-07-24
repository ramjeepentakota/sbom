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
                        cve = cells[2].get_text(strip=True)
                        severity = cells[3].get_text(strip=True)
                        summary = cells[4].get_text(strip=True)
                        cvss_score = None
                        # Try to extract CVSS score from summary or another cell if available
                        m = re.search(r'CVSS.*?(\d+\.\d+)', summary)
                        if m:
                            cvss_score = float(m.group(1))
                        vulns.append(Vulnerability(
                            package_name=component,
                            version=version,
                            cve_id=cve,
                            severity=severity,
                            summary=summary,
                            cvss_score=cvss_score,
                            remediation=None
                        ))
    except Exception:
        pass
    return vulns
