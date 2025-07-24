from typing import List, Dict
from core.sbom_generator import SBOMComponent
from core.vulnerability_checker import Vulnerability

class ComplianceChecker:
    PCI_ALLOWED_LICENSES = {"Apache-2.0", "MIT", "BSD-3-Clause", "BSD-2-Clause"}
    RBI_ALLOWED_LICENSES = {"Apache-2.0", "MIT"}
    CRITICAL_SEVERITY = {"CRITICAL", "HIGH"}

    def __init__(self, mode: str):
        self.mode = mode.lower()
        self.flags = {}

    def check(self, sbom_components: List[SBOMComponent], vulnerabilities: List[Vulnerability]) -> Dict[str, bool]:
        self.flags = {}
        if self.mode == "pci":
            self.flags["No Critical/High Vulnerabilities"] = self._no_critical_vulns(vulnerabilities)
            self.flags["All Licenses Compliant"] = self._all_licenses_compliant(sbom_components, self.PCI_ALLOWED_LICENSES)
        elif self.mode == "rbi":
            self.flags["No Critical/High Vulnerabilities"] = self._no_critical_vulns(vulnerabilities)
            self.flags["All Licenses Compliant"] = self._all_licenses_compliant(sbom_components, self.RBI_ALLOWED_LICENSES)
        else:
            self.flags["Unknown Compliance Mode"] = False
        return self.flags

    def _no_critical_vulns(self, vulnerabilities: List[Vulnerability]) -> bool:
        for v in vulnerabilities:
            if v.severity.upper() in self.CRITICAL_SEVERITY:
                return False
        return True

    def _all_licenses_compliant(self, sbom_components: List[SBOMComponent], allowed_licenses: set) -> bool:
        for c in sbom_components:
            if c.license not in allowed_licenses:
                return False
        return True

    def generate_audit_summary(self, output_path: str):
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('<html><head><title>Compliance Audit Summary</title></head><body>')
            f.write(f'<h1>Compliance Mode: {self.mode.upper()}</h1>')
            f.write('<ul>')
            for flag, status in self.flags.items():
                f.write(f'<li>{flag}: {"PASS" if status else "FAIL"}</li>')
            f.write('</ul></body></html>')
