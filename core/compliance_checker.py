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

    def check(self, sbom_components: List[SBOMComponent], vulnerabilities: List[Vulnerability]) -> Dict[str, dict]:
        self.flags = {}
        if self.mode == "pci":
            self.flags["No Critical/High Vulnerabilities"] = self._detailed_no_critical_vulns(vulnerabilities)
            self.flags["All Licenses Compliant"] = self._detailed_all_licenses_compliant(sbom_components, self.PCI_ALLOWED_LICENSES)
            self.flags["No End-of-Life Components"] = self._detailed_no_eol_components(sbom_components)
            self.flags["All Critical/High Vulns Patched"] = self._detailed_all_critical_high_vulns_patched(sbom_components, vulnerabilities)
            self.flags["All Components Have Supplier"] = self._detailed_all_have_supplier(sbom_components)
            self.flags["All Key Fields Populated"] = self._detailed_all_key_fields_populated(sbom_components)
        elif self.mode == "rbi":
            self.flags["No Critical/High Vulnerabilities"] = self._detailed_no_critical_vulns(vulnerabilities)
            self.flags["All Licenses Compliant"] = self._detailed_all_licenses_compliant(sbom_components, self.RBI_ALLOWED_LICENSES)
            self.flags["No End-of-Life Components"] = self._detailed_no_eol_components(sbom_components)
            self.flags["All Critical/High Vulns Patched"] = self._detailed_all_critical_high_vulns_patched(sbom_components, vulnerabilities)
            self.flags["All Components Have Supplier"] = self._detailed_all_have_supplier(sbom_components)
            self.flags["All Key Fields Populated"] = self._detailed_all_key_fields_populated(sbom_components)
        else:
            self.flags["Unknown Compliance Mode"] = {"status": False, "details": ["Unknown mode"]}
        return self.flags

    def _detailed_no_critical_vulns(self, vulnerabilities: List[Vulnerability]) -> dict:
        failed = []
        for v in vulnerabilities:
            severity = v.severity if hasattr(v, 'severity') else v.get('severity', '').upper()
            if severity and severity.upper() in self.CRITICAL_SEVERITY:
                pkg = v.package_name if hasattr(v, 'package_name') else v.get('package_name', '')
                ver = v.version if hasattr(v, 'version') else v.get('version', '')
                cve = v.cve_id if hasattr(v, 'cve_id') else v.get('cve_id', '')
                failed.append(f"{pkg} {ver} - {cve} ({severity})")
        return {"status": len(failed) == 0, "details": failed}

    def _detailed_all_licenses_compliant(self, sbom_components: List[SBOMComponent], allowed_licenses: set) -> dict:
        failed = []
        for c in sbom_components:
            if c.license not in allowed_licenses:
                failed.append(f"{c.name} {c.version or ''} - {c.license}")
        return {"status": len(failed) == 0, "details": failed}

    def _detailed_no_eol_components(self, sbom_components: List[SBOMComponent]) -> dict:
        import datetime
        failed = []
        for c in sbom_components:
            if getattr(c, 'end_of_life_date', None) and str(c.end_of_life_date).strip().lower() not in ('', 'n/a', 'none'):
                try:
                    eol = str(c.end_of_life_date).split('T')[0]
                    eol_date = datetime.datetime.strptime(eol, '%Y-%m-%d').date()
                    if eol_date < datetime.date.today():
                        failed.append(f"{c.name} {c.version or ''} - EOL: {c.end_of_life_date}")
                except Exception:
                    continue
        return {"status": len(failed) == 0, "details": failed}

    def _detailed_all_critical_high_vulns_patched(self, sbom_components: List[SBOMComponent], vulnerabilities: List[Vulnerability]) -> dict:
        failed = []
        for v in vulnerabilities:
            severity = v.severity if hasattr(v, 'severity') else v.get('severity', '').upper()
            pkg = v.package_name if hasattr(v, 'package_name') else v.get('package_name', '')
            ver = v.version if hasattr(v, 'version') else v.get('version', '')
            cve = v.cve_id if hasattr(v, 'cve_id') else v.get('cve_id', '')
            if severity and severity.upper() in self.CRITICAL_SEVERITY:
                for c in sbom_components:
                    if pkg.lower() == c.name.lower() and (not ver or ver == c.version):
                        if not getattr(c, 'patch_status', '').lower().startswith('patched'):
                            failed.append(f"{c.name} {c.version or ''} - {cve or ''} not patched")
        return {"status": len(failed) == 0, "details": failed}

    def _detailed_all_have_supplier(self, sbom_components: List[SBOMComponent]) -> dict:
        failed = []
        for c in sbom_components:
            if not getattr(c, 'supplier', None) or str(c.supplier).strip().lower() in ('', 'n/a', 'none'):
                # Auto-correct: fill missing supplier
                c.supplier = c.supplier or "Unknown Supplier"
                failed.append(f"{c.name} {c.version or ''} - missing supplier (auto-corrected)")
        return {"status": len(failed) == 0, "details": failed}

    def _detailed_all_key_fields_populated(self, sbom_components: List[SBOMComponent]) -> dict:
        key_fields = ['name', 'version', 'license', 'supplier', 'origin', 'criticality']
        failed = []
        for c in sbom_components:
            for field in key_fields:
                val = getattr(c, field, None)
                if not val or str(val).strip().lower() in ('', 'n/a', 'none'):
                    # Auto-correct: fill missing field with 'Unknown'
                    setattr(c, field, f"Unknown {field.title()}")
                    failed.append(f"{c.name} {c.version or ''} - missing {field} (auto-corrected)")
        return {"status": len(failed) == 0, "details": failed}

    def _no_eol_components(self, sbom_components: List[SBOMComponent]) -> bool:
        for c in sbom_components:
            if getattr(c, 'end_of_life_date', None) and str(c.end_of_life_date).strip().lower() not in ('', 'n/a', 'none'):
                try:
                    import datetime
                    eol = str(c.end_of_life_date).split('T')[0]
                    eol_date = datetime.datetime.strptime(eol, '%Y-%m-%d').date()
                    if eol_date < datetime.date.today():
                        return False
                except Exception:
                    continue
        return True

    def _all_critical_high_vulns_patched(self, sbom_components: List[SBOMComponent], vulnerabilities: List[Vulnerability]) -> bool:
        for v in vulnerabilities:
            if v.severity and v.severity.upper() in self.CRITICAL_SEVERITY:
                # Try to find the matching component
                for c in sbom_components:
                    if v.package_name.lower() == c.name.lower() and (not v.version or v.version == c.version):
                        if not getattr(c, 'patch_status', '').lower().startswith('patched'):
                            return False
        return True

    def _all_have_supplier(self, sbom_components: List[SBOMComponent]) -> bool:
        for c in sbom_components:
            if not getattr(c, 'supplier', None) or str(c.supplier).strip().lower() in ('', 'n/a', 'none'):
                return False
        return True

    def _all_key_fields_populated(self, sbom_components: List[SBOMComponent]) -> bool:
        key_fields = ['name', 'version', 'license', 'supplier', 'origin', 'criticality']
        for c in sbom_components:
            for field in key_fields:
                val = getattr(c, field, None)
                if not val or str(val).strip().lower() in ('', 'n/a', 'none'):
                    return False
        return True

    def _no_critical_vulns(self, vulnerabilities: List[Vulnerability]) -> bool:
        for v in vulnerabilities:
            severity = v.severity if hasattr(v, 'severity') else v.get('severity', '').upper()
            if severity.upper() in self.CRITICAL_SEVERITY:
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
