import os
import xml.etree.ElementTree as ET
import zipfile
from typing import List, Dict, Optional
from core.sbom_generator import SBOMComponent, SBOMGenerator

class JavaDependency:
    def __init__(self, name: str, version: str, scope: str = "compile", license: str = None, supplier: str = None, file_path: str = None):
        self.name = name
        self.version = version
        self.scope = scope
        self.license = license
        self.supplier = supplier
        self.file_path = file_path
        self.hash_sha256 = None
        self.dependencies = []

class JavaScanner:
    def __init__(self, root_path: str):
        self.root_path = os.path.abspath(root_path)
        self.dependencies: List[JavaDependency] = []
        self.embedded_jars: List[str] = []
        self.all_files: List[str] = []  # Track all files found

    def scan(self):
        for dirpath, dirnames, filenames in os.walk(self.root_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                self.all_files.append(filepath)  # Track every file
                if filename == "pom.xml":
                    self._parse_pom_xml(filepath)
                elif filename in ("build.gradle", "settings.gradle"):
                    self._parse_gradle_file(filepath)
                elif filename.endswith(".jar") or filename.endswith(".war"):
                    self.embedded_jars.append(filepath)
                elif filename.endswith(".xml") and "dependency" in filename.lower():
                    self._parse_additional_xml(filepath)
        self._scan_embedded_jars()

    def _parse_pom_xml(self, pom_path: str):
        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()
            ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
            for dep in root.findall('.//m:dependency', ns):
                group_id = dep.find('m:groupId', ns)
                artifact_id = dep.find('m:artifactId', ns)
                version = dep.find('m:version', ns)
                scope = dep.find('m:scope', ns)
                name = f"{group_id.text if group_id is not None else ''}:{artifact_id.text if artifact_id is not None else ''}"
                dep_version = version.text if version is not None else "UNKNOWN"
                dep_scope = scope.text if scope is not None else "compile"
                self.dependencies.append(JavaDependency(name, dep_version, dep_scope, file_path=pom_path))
        except Exception as e:
            pass  # Log or handle error

    def _parse_gradle_file(self, gradle_path: str):
        try:
            with open(gradle_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('implementation') or line.startswith('compile'):
                        parts = line.split()
                        if len(parts) > 1:
                            dep_str = parts[1].strip('"\'')
                            if ':' in dep_str:
                                group, artifact, version = (dep_str.split(':') + [None, None])[:3]
                                name = f"{group}:{artifact}"
                                self.dependencies.append(JavaDependency(name, version or "UNKNOWN", file_path=gradle_path))
        except Exception as e:
            pass  # Log or handle error

    def _parse_additional_xml(self, xml_path: str):
        # Placeholder for custom dependency XMLs
        pass

    def _scan_embedded_jars(self):
        for jar_path in self.embedded_jars:
            try:
                with zipfile.ZipFile(jar_path, 'r') as jar:
                    if 'META-INF/MANIFEST.MF' in jar.namelist():
                        with jar.open('META-INF/MANIFEST.MF') as manifest_file:
                            content = manifest_file.read().decode('utf-8', errors='ignore')
                            name = None
                            version = None
                            for line in content.splitlines():
                                if line.startswith('Implementation-Title:'):
                                    name = line.split(':', 1)[1].strip()
                                elif line.startswith('Implementation-Version:'):
                                    version = line.split(':', 1)[1].strip()
                                elif line.startswith('Bundle-Name:') and not name:
                                    name = line.split(':', 1)[1].strip()
                                elif line.startswith('Bundle-Version:') and not version:
                                    version = line.split(':', 1)[1].strip()
                            if name and version:
                                self.dependencies.append(JavaDependency(name, version, file_path=jar_path))
                            elif name:
                                self.dependencies.append(JavaDependency(name, "UNKNOWN", file_path=jar_path))
                            elif version:
                                self.dependencies.append(JavaDependency(os.path.basename(jar_path), version, file_path=jar_path))
                            else:
                                self.dependencies.append(JavaDependency(os.path.basename(jar_path), "UNKNOWN", file_path=jar_path))
                    else:
                        # If no manifest, use filename as name
                        self.dependencies.append(JavaDependency(os.path.basename(jar_path), "UNKNOWN", file_path=jar_path))
            except Exception:
                # If any error, fallback to filename
                self.dependencies.append(JavaDependency(os.path.basename(jar_path), "UNKNOWN", file_path=jar_path))

    def to_sbom_components(self, sbom_gen: SBOMGenerator) -> List[SBOMComponent]:
        components = []
        # Add dependency components as before
        for dep in self.dependencies:
            hash_val = sbom_gen.compute_sha256(dep.file_path) if dep.file_path else None
            comp = SBOMComponent(
                name=dep.name,
                version=dep.version,
                license=dep.license or "NOASSERTION",
                supplier=dep.supplier or "NOASSERTION",
                file_path=dep.file_path or "",
                hash_sha256=hash_val or "",
                component_type="library"
            )
            components.append(comp)
        # Add every file as a component (if not already added)
        dep_paths = set(dep.file_path for dep in self.dependencies if dep.file_path)
        for file_path in self.all_files:
            if file_path not in dep_paths:
                hash_val = sbom_gen.compute_sha256(file_path)
                comp = SBOMComponent(
                    name=os.path.basename(file_path),
                    version="N/A",
                    license="N/A",
                    supplier="N/A",
                    file_path=file_path,
                    hash_sha256=hash_val or "",
                    component_type="file"
                )
                components.append(comp)
        return components
