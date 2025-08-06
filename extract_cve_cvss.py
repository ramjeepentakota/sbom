from bs4 import BeautifulSoup
import re

def extract_cve_cvss(html_path):
    with open(html_path, "r", encoding="utf-8") as file:
        soup = BeautifulSoup(file, "html.parser")

    results = []
    for link in soup.find_all("a", href=True):
        cve_match = re.match(r"CVE-\d{4}-\d{4,7}", link.text.strip())
        if not cve_match:
            continue
        cve_id = link.text.strip()
        score = "N/A"

        # Aggressive search for CVSS score
        parent = link.find_parent(["tr", "div", "li", "td"]) or link.parent
        found = False

        # 1. Search parent and all descendants for Base Score or CVSS
        for tag in [parent] + list(parent.descendants):
            if not tag or not hasattr(tag, "get_text"):
                continue
            text = tag.get_text(" ", strip=True)
            m = re.search(r"CVSSv3.*?Base Score:\s*(?:HIGH|MEDIUM|LOW)?\s*\(?([0-9.]+)", text, re.IGNORECASE)
            if m:
                score = m.group(1)
                found = True
                break
            m = re.search(r"Base Score:\s*(?:HIGH|MEDIUM|LOW)?\s*\(?([0-9.]+)", text, re.IGNORECASE)
            if m:
                score = m.group(1)
                found = True
                break

        # 2. If not found, search next siblings, previous siblings, and their descendants
        if not found:
            for sib in list(parent.next_siblings) + list(parent.previous_siblings):
                if not sib or not hasattr(sib, "get_text"):
                    continue
                text = sib.get_text(" ", strip=True)
                m = re.search(r"CVSSv3.*?Base Score:\s*(?:HIGH|MEDIUM|LOW)?\s*\(?([0-9.]+)", text, re.IGNORECASE)
                if m:
                    score = m.group(1)
                    found = True
                    break
                m = re.search(r"Base Score:\s*(?:HIGH|MEDIUM|LOW)?\s*\(?([0-9.]+)", text, re.IGNORECASE)
                if m:
                    score = m.group(1)
                    found = True
                    break

        # Debug output: show what is being searched
        print(f"[DEBUG] CVE: {cve_id}")
        print(f"[DEBUG] Parent HTML: {parent}")
        print(f"[DEBUG] Extracted Score: {score}")

        results.append((cve_id, score))

    return results

# Example usage:
if __name__ == "__main__":
    cve_cvss_list = extract_cve_cvss("dependency-check-report.html")
    for cve, score in cve_cvss_list:
        print(f"{cve} => CVSS Score: {score}")
