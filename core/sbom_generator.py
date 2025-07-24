import json
import hashlib
from typing import List, Dict, Optional

class SBOMComponent:
    def __init__(
        self,
        name: str,
        version: str,
        license: str,
        supplier: str,
        file_path: str,
        hash_sha256: str,
        component_type: str = "library",
        description: str = None,
        release_date: str = None,
        criticality: str = None,
        executable_flag: bool = False,
        known_unknown: bool = False,
        cve_ids: list = None,
        severity: str = None,
        exploitability: str = None,
        remediation: str = None,
        sbom_timestamp: str = None,
        generated_by: str = None
    ):
        self.name = name
        self.version = version
        self.license = license
        self.supplier = supplier
        self.file_path = file_path
        self.hash_sha256 = hash_sha256
        self.component_type = component_type
        self.description = description
        self.release_date = release_date
        self.criticality = criticality
        self.executable_flag = executable_flag
        self.known_unknown = known_unknown
        self.cve_ids = cve_ids or []
        self.severity = severity
        self.exploitability = exploitability
        self.remediation = remediation
        self.sbom_timestamp = sbom_timestamp
        self.generated_by = generated_by
        self.dependencies = []  # List of component names (or IDs)

    def to_cyclonedx(self):
        return {
            "type": self.component_type,
            "name": self.name,
            "version": self.version,
            "licenses": [{"license": {"id": self.license}}] if self.license else [],
            "supplier": {"name": self.supplier} if self.supplier else {},
            "hashes": [{"alg": "SHA-256", "content": self.hash_sha256}],
            "purl": None,  # Placeholder for package URL
            "externalReferences": [],
            "properties": [
                {"name": "filePath", "value": self.file_path}
            ]
        }

    def to_spdx(self):
        return {
            "SPDXID": f"SPDXRef-{self.name}-{self.version}",
            "name": self.name,
            "versionInfo": self.version,
            "licenseConcluded": self.license or "NOASSERTION",
            "supplier": self.supplier or "NOASSERTION",
            "checksums": [{"algorithm": "SHA256", "checksumValue": self.hash_sha256}],
            "externalRefs": [],
            "filesAnalyzed": False,
            "filePath": self.file_path
        }

class SBOMGenerator:
    def __init__(self, format: str = "cyclonedx"):
        self.components: List[SBOMComponent] = []
        self.dependencies: Dict[str, List[str]] = {}  # component name -> list of dependencies
        self.format = format.lower()

    def add_component(self, component: SBOMComponent):
        self.components.append(component)
        self.dependencies[component.name] = component.dependencies

    def add_dependency(self, component_name: str, dependency_name: str):
        if component_name in self.dependencies:
            self.dependencies[component_name].append(dependency_name)
        else:
            self.dependencies[component_name] = [dependency_name]

    def to_cyclonedx_json(self) -> str:
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [c.to_cyclonedx() for c in self.components],
            "dependencies": [
                {
                    "ref": c.name,
                    "dependsOn": self.dependencies.get(c.name, [])
                } for c in self.components if self.dependencies.get(c.name)
            ]
        }
        return json.dumps(bom, indent=2)

    def to_spdx_json(self) -> str:
        spdx = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Java Project SBOM",
            "documentNamespace": "http://spdx.org/spdxdocs/java-project-sbom",
            "creationInfo": {
                "created": "REPLACE_WITH_TIMESTAMP",
                "creators": ["Tool: java_sbom_sca_tool"]
            },
            "packages": [c.to_spdx() for c in self.components],
            "relationships": [
                {
                    "spdxElementId": f"SPDXRef-{c.name}-{c.version}",
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": f"SPDXRef-{dep}-{self._get_version(dep)}"
                }
                for c in self.components for dep in self.dependencies.get(c.name, [])
            ]
        }
        return json.dumps(spdx, indent=2)

    def _get_version(self, component_name: str) -> str:
        for c in self.components:
            if c.name == component_name:
                return c.version
        return "UNKNOWN"

    @staticmethod
    def compute_sha256(file_path: str) -> Optional[str]:
        try:
            with open(file_path, "rb") as f:
                sha256 = hashlib.sha256()
                while chunk := f.read(8192):
                    sha256.update(chunk)
                return sha256.hexdigest()
        except Exception:
            return None
