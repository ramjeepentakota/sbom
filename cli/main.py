import requests
import argparse
import os
import sys
import zipfile
import shutil
import tempfile
import subprocess
from core.java_scanner import JavaScanner
from core.sbom_generator import SBOMGenerator
# from core.vulnerability_checker import VulnerabilityChecker
from core.report_writer import ReportWriter
from core.compliance_checker import ComplianceChecker
from core.depcheck_parser import parse_depcheck_html

def update_dependency_check():
    print("[INFO] Checking for latest OWASP Dependency-Check...")
    api_url = "https://api.github.com/repos/jeremylong/DependencyCheck/releases/latest"
    r = requests.get(api_url)
    latest = r.json()
    zip_url = None
    for asset in latest["assets"]:
        if asset["name"].endswith("-release.zip"):
            zip_url = asset["browser_download_url"]
            break
    if not zip_url:
        print("[ERROR] Could not find Dependency-Check release ZIP.")
        sys.exit(1)
    target_dir = os.path.join(os.path.expanduser("~"), "dependency-check-latest")
    os.makedirs(target_dir, exist_ok=True)
    zip_path = os.path.join(target_dir, "dependency-check.zip")
    # Download
    with requests.get(zip_url, stream=True) as r:
        r.raise_for_status()
        with open(zip_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    # Extract
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(target_dir)
    # Find the .bat file
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            if file.lower() == "dependency-check.bat":
                return os.path.join(root, file)
    print("[ERROR] Could not find dependency-check.bat after extraction.")
    sys.exit(1)

def sanitize_path(path: str) -> str:
    # Ensure the path exists and is absolute
    abs_path = os.path.abspath(path)
    if not os.path.exists(abs_path):
        raise ValueError(f"Invalid path: {abs_path} does not exist.")
    return abs_path

def main():
    print(r"""

 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄  ▄▄       ▄▄       ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄        ▄       ▄               ▄   ▄▄▄▄         ▄▄▄▄▄▄▄▄▄  
▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░░▌     ▐░░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░▌      ▐░▌     ▐░▌             ▐░▌▄█░░░░▌       ▐░░░░░░░░░▌ 
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░▌░▌   ▐░▐░▌     ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░▌░▌     ▐░▌      ▐░▌           ▐░▌▐░░▌▐░░▌      ▐░█░█▀▀▀▀▀█░▌
▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌▐░▌ ▐░▌▐░▌     ▐░▌          ▐░▌          ▐░▌▐░▌    ▐░▌       ▐░▌         ▐░▌  ▀▀ ▐░░▌      ▐░▌▐░▌    ▐░▌
▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌▐░▌ ▐░▐░▌ ▐░▌     ▐░▌ ▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌ ▐░▌   ▐░▌        ▐░▌       ▐░▌      ▐░░▌      ▐░▌ ▐░▌   ▐░▌
▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ ▐░▌       ▐░▌▐░▌  ▐░▌  ▐░▌     ▐░▌▐░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌  ▐░▌  ▐░▌         ▐░▌     ▐░▌       ▐░░▌      ▐░▌  ▐░▌  ▐░▌
 ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░▌       ▐░▌▐░▌   ▀   ▐░▌     ▐░▌ ▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░▌   ▐░▌ ▐░▌          ▐░▌   ▐░▌        ▐░░▌      ▐░▌   ▐░▌ ▐░▌
          ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌     ▐░▌       ▐░▌▐░▌          ▐░▌    ▐░▌▐░▌           ▐░▌ ▐░▌         ▐░░▌      ▐░▌    ▐░▌▐░▌
 ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌     ▐░▐░▌            ▐░▐░▌      ▄▄▄▄█░░█▄▄▄  ▄▐░█▄▄▄▄▄█░█░▌
▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░▌       ▐░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌      ▐░░▌             ▐░▌      ▐░░░░░░░░░░░▌▐░▌▐░░░░░░░░░▌ 
 ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀   ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀       ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀        ▀▀               ▀        ▀▀▀▀▀▀▀▀▀▀▀  ▀  ▀▀▀▀▀▀▀▀▀  
                                                                                                                                                   
                                                                              
SBOM Generator - PCI RBI Compliance
Developed by Ramjee Pentakota | All Rights Reserved
© 2025 Ramjee Pentakota

SUPPORTED OUTPUT FORMATS:
  html   Generate an HTML vulnerability/license report (sca_report.html)
  csv    Generate a CSV vulnerability/license report (sca_report.csv)
  json   Generate SBOMs in CycloneDX (sbom.cyclonedx.json) and SPDX (sbom.spdx.json) formats

QUICK USAGE:
  Show help:    python -m cli.main -h
  Example run:  python -m cli.main -p /path/to/java/project -o ./reports -f html,csv,json

DISCLAIMER: This tool is provided "AS IS" without warranty of any kind. Use at your own risk. The author is not liable for any damages or losses arising from the use of this software.
""")
    parser = argparse.ArgumentParser(
        prog="java_sbom_sca_tool",
        description=(
            """
Java SCA & SBOM Tool (PCI/RBI Compliant)

Easily scan your Java project for dependencies, generate SBOMs (CycloneDX/SPDX), check for vulnerabilities, and produce compliance and license reports.

SUPPORTED OUTPUT FORMATS:
  html   Generate an HTML vulnerability/license report (sca_report.html)
  csv    Generate a CSV vulnerability/license report (sca_report.csv)
  json   Generate SBOMs in CycloneDX (sbom.cyclonedx.json) and SPDX (sbom.spdx.json) formats

To specify multiple formats, use a comma-separated list (e.g., -f html,csv,json).

OUTPUT FILES:
  sbom.cyclonedx.json         CycloneDX SBOM (JSON)
  sbom.spdx.json              SPDX SBOM (JSON)
  sca_report.csv              Vulnerability and license report (CSV)
  sca_report.html             Vulnerability and license report (HTML)
  compliance_audit_summary_pci.html  PCI Compliance audit summary
  compliance_audit_summary_rbi.html  RBI Compliance audit summary

OPTIONS:
  -p, --path        Path to the root of the Java project to scan (required)
  -o, --output      Output directory to store all generated reports (default: current directory)
  -f, --format      Output formats: html, csv, json (comma-separated, default: html,csv,json)
  -h, --help        Show this help message and exit

EXAMPLE COMMANDS:
  python -m cli.main -p /path/to/java/project
  python -m cli.main -p . -o ./reports -f html,csv
  python -m cli.main -p . -o ./out -f json
  python -m cli.main -p /my/java/project -o . -f html
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '-p', '--path', required=True,
        help='Path to the root of the Java project to scan (required).'
    )
    parser.add_argument(
        '-o', '--output', default='.',
        help='Output directory to store all generated reports (default: current directory).'
    )
    parser.add_argument(
        '-f', '--format', default='html,csv,json',
        help='Output formats (comma-separated): html, csv, json. Default: html,csv,json.'
    )
    args = parser.parse_args()


    project_path = sanitize_path(args.path)
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)
    output_types = [o.strip() for o in args.format.split(',')]

    # Step 1: Scan Java project
    scanner = JavaScanner(project_path)
    scanner.scan()

    # Step 2: Generate SBOM using CycloneDX and SPDX CLI tools if available
    import subprocess
    cyclonedx_cmd = None
    requirements_path = os.path.join(project_path, "requirements.txt")
    pipfile_path = os.path.join(project_path, "Pipfile")
    poetry_lock_path = os.path.join(project_path, "poetry.lock")
    pom_path = os.path.join(project_path, "pom.xml")
    gradle_path = os.path.join(project_path, "build.gradle")
    output_path = os.path.join(output_dir, "sbom.cyclonedx.json")
    is_python = os.path.exists(requirements_path) or os.path.exists(pipfile_path) or os.path.exists(poetry_lock_path)

    # Check for any .jar, .class, or .java files for traditional Java projects
    has_java_artifacts = False
    for root, dirs, files in os.walk(project_path):
        for file in files:
            if file.endswith('.jar') or file.endswith('.class') or file.endswith('.java'):
                has_java_artifacts = True
                break
        if has_java_artifacts:
            break

    is_java = os.path.exists(pom_path) or os.path.exists(gradle_path) or has_java_artifacts

    sbom_gen = SBOMGenerator()
    sbom_components = scanner.to_sbom_components(sbom_gen)
    for comp in sbom_components:
        sbom_gen.add_component(comp)

    if is_python:
        if os.path.exists(requirements_path):
            cyclonedx_cmd = [
                "cyclonedx-py", "requirements", "-o", output_path, "-r", requirements_path
            ]
        elif os.path.exists(pipfile_path):
            cyclonedx_cmd = [
                "cyclonedx-py", "pipenv", "-o", output_path, "-p", pipfile_path
            ]
        elif os.path.exists(poetry_lock_path):
            cyclonedx_cmd = [
                "cyclonedx-py", "poetry", "-o", output_path, "-l", poetry_lock_path
            ]
        try:
            subprocess.run(cyclonedx_cmd, check=True)
        except Exception as e:
            print(f"[ERROR] CycloneDX SBOM generation failed: {e}")
            sys.exit(1)
    elif is_java:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(sbom_gen.to_cyclonedx_json())
    else:
        print("[ERROR] No supported project file found for CycloneDX (requirements.txt, Pipfile, poetry.lock, pom.xml, build.gradle, .jar, .class, .java). Aborting.")
        sys.exit(1)

    # SPDX
    spdx_output_path = os.path.join(output_dir, "sbom.spdx.json")
    if is_python:
        spdx_cmd = [
            "spdx-sbom-generator", "-p", project_path, "-o", spdx_output_path
        ]
        try:
            subprocess.run(spdx_cmd, check=True)
        except Exception as e:
            print(f"[ERROR] SPDX SBOM generation failed: {e}")
            sys.exit(1)
    elif is_java:
        with open(spdx_output_path, 'w', encoding='utf-8') as f:
            f.write(sbom_gen.to_spdx_json())
    else:
        print("[ERROR] No supported project file found for SPDX SBOM generation. Aborting.")
        sys.exit(1)

    # Step 3: Run OWASP Dependency-Check for SCA (MANDATORY)
    # Only run Dependency-Check for Java projects
    if is_java:
        depcheck_exe = update_dependency_check()
        nvd_api_key = os.environ.get("NVD_API_KEY", "6d52d80f-ba6e-4036-94eb-282f91aef62d")
        depcheck_html_path = os.path.join(output_dir, "dependency-check-report.html")
        depcheck_json_path = os.path.join(output_dir, "dependency-check-report.json")
        try:
            # Run HTML report
            subprocess.run([
                depcheck_exe, "--project", "SCA-Scan", "--scan", project_path,
                "--format", "HTML", "--out", depcheck_html_path,
                "--nvdApiKey", nvd_api_key,
                "--disableAssembly"
            ], check=True)
            # Run JSON report
            subprocess.run([
                depcheck_exe, "--project", "SCA-Scan", "--scan", project_path,
                "--format", "JSON", "--out", depcheck_json_path,
                "--nvdApiKey", nvd_api_key,
                "--disableAssembly"
            ], check=True)
        except Exception as e:
            err_msg = str(e)
            print(f"[ERROR] OWASP Dependency-Check scan failed: {e}")
            if "SAFETY" in err_msg or "CvssV4Data$ModifiedCiaType" in err_msg:
                print("[HINT] This error is caused by a recent change in the NVD data format. Please update OWASP Dependency-Check to the latest version from https://github.com/jeremylong/DependencyCheck/releases.")
            sys.exit(1)
    else:
        depcheck_json_path = None

    # Step 5: Compliance checks (PCI and RBI)
    # Parse vulnerabilities from Dependency-Check JSON
    from core.depcheck_parser import parse_depcheck_json
    if depcheck_json_path and os.path.exists(depcheck_json_path):
        cve_map = parse_depcheck_json(depcheck_json_path)
        vulnerabilities = []
        for entry in cve_map.values():
            if 'details' in entry:
                vulnerabilities.extend(entry['details'])
    else:
        vulnerabilities = []

    # Run compliance checker for PCI and use its flags for the report
    compliance_checker = ComplianceChecker("pci")
    compliance_flags = compliance_checker.check(sbom_components, vulnerabilities)
    compliance_checker.generate_audit_summary(os.path.join(output_dir, 'compliance_audit_summary_pci.html'))
    # Optionally, also run for RBI and generate its summary
    compliance_checker_rbi = ComplianceChecker("rbi")
    compliance_checker_rbi.check(sbom_components, vulnerabilities)
    compliance_checker_rbi.generate_audit_summary(os.path.join(output_dir, 'compliance_audit_summary_rbi.html'))

    compliance_summaries = {
        "pci": os.path.join(output_dir, 'compliance_audit_summary_pci.html'),
        "rbi": os.path.join(output_dir, 'compliance_audit_summary_rbi.html')
    }
    project_name = os.path.basename(os.path.normpath(project_path))
    if 'html' in output_types:
        report_filename = f"{project_name}_sca_sbom_report.html"
        ReportWriter.write_html_report(
            sbom_components,
            depcheck_json_path,
            os.path.join(output_dir, report_filename),
            compliance_flags,
            project_name
        )
        print("SCA & SBOM HTML report generated in:", os.path.join(output_dir, report_filename))
    if 'csv' in output_types:
        csv_filename = f"{project_name}_sca_sbom_report.csv"
        ReportWriter.write_csv_report(
            sbom_components,
            depcheck_json_path,
            os.path.join(output_dir, csv_filename)
        )
        print("SCA & SBOM CSV report generated in:", os.path.join(output_dir, csv_filename))
    if 'json' in output_types:
        json_filename = f"{project_name}_sca_sbom_report.json"
        ReportWriter.write_json_report(
            sbom_components,
            depcheck_json_path,
            os.path.join(output_dir, json_filename)
        )
        print("SCA & SBOM JSON report generated in:", os.path.join(output_dir, json_filename))
        print("CycloneDX SBOM JSON generated in:", os.path.join(output_dir, 'sbom.cyclonedx.json'))
        print("SPDX SBOM JSON generated in:", os.path.join(output_dir, 'sbom.spdx.json'))

    # Move intermediate files to a subdirectory for cleanliness
    intermediate_dir = os.path.join(output_dir, "intermediate")
    os.makedirs(intermediate_dir, exist_ok=True)
    for fname in [
        'sbom.cyclonedx.json',
        'sbom.spdx.json',
        # 'dependency-check-report.html',  # Do NOT move this file, keep it in main output dir
        'compliance_audit_summary_pci.html',
        'compliance_audit_summary_rbi.html',
        'sca_report.csv',
        'sca_report.html'
    ]:
        fpath = os.path.join(output_dir, fname)
        if os.path.exists(fpath):
            os.replace(fpath, os.path.join(intermediate_dir, fname))
            

if __name__ == '__main__':
    main()
