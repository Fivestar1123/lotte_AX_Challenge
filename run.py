"""PoC 전체 파이프라인을 처음부터 끝까지 실행한다.

SBOM 생성(syft) → 취약점 매칭(grype) → EPSS/KEV 보강 → 설정 기반 도달성 판정
→ 우선순위 스코어링 → 상위 N건 LLM 조치안 → HTML 리포트.

전제: poc/bin/syft.exe, poc/bin/grype.exe 가 있어야 한다 (README 참고,
없으면 install_tools.ps1으로 받는다). Docker는 필요 없다 — 이미지를
Docker Hub registry에서 직접 pull해서 스캔한다.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BIN = ROOT / "bin"
CONFIG = ROOT / "config"
OUT = ROOT / "output"
SRC = ROOT / "src"

TARGET_IMAGE = os.environ.get("TARGET_IMAGE", "tomcat:9.0.30-jdk8-openjdk")

sys.path.insert(0, str(SRC))


def run(cmd: list[str], **kw):
    print(f"$ {' '.join(cmd)}")
    subprocess.run(cmd, check=True, **kw)


def step_sbom():
    print("\n=== [1/5] SBOM 생성 (syft, registry 직접 스캔) ===")
    OUT.mkdir(parents=True, exist_ok=True)
    run([
        str(BIN / "syft.exe"), f"registry:{TARGET_IMAGE}",
        "-o", f"cyclonedx-json={OUT / 'sbom.cdx.json'}",
        "-o", f"json={OUT / 'syft.native.json'}",
    ])


def step_scan():
    print("\n=== [2/5] 취약점 매칭 (grype, java CPE 매칭 활성화) ===")
    env = os.environ.copy()
    env["GRYPE_MATCH_JAVA_USING_CPES"] = "true"
    run([
        str(BIN / "grype.exe"), f"sbom:{OUT / 'syft.native.json'}",
        "-o", "json", "--file", str(OUT / "grype.json"),
    ], env=env)
    # 비교용: 기본 설정(미탐 사례 증빙)으로도 한 번 더 — README/리포트에서 인용
    evidence = OUT / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    run([
        str(BIN / "grype.exe"), f"sbom:{OUT / 'syft.native.json'}",
        "-o", "json", "--file", str(evidence / "grype_default_no_cpe.json"),
    ])
    run([
        str(BIN / "grype.exe"), f"sbom:{OUT / 'syft.native.json'}",
        "-o", "json", "--file", str(evidence / "grype_java_cpe_enabled.json"),
    ], env=env)


def step_enrich_and_prioritize():
    print("\n=== [3/5] EPSS/KEV 보강 + 설정(server.xml/web.xml/context.xml) 도달성 판정 + 우선순위 스코어링 ===")
    from enrich import fetch_epss, fetch_kev
    from prioritize import load_grype_matches, prioritize

    grype_path = OUT / "grype.json"
    grouped = load_grype_matches(grype_path)
    cve_ids = [c for c in grouped if c.startswith("CVE")]

    epss_map = fetch_epss(cve_ids, cache_path=OUT / "epss.json")
    kev_map = fetch_kev(cache_path=OUT / "kev.json")

    rule_cve_ids = ["CVE-2020-1938", "CVE-2025-24813", "CVE-2020-9484"]
    for key in ["ajp-vulnerable", "ajp-mitigated"]:
        findings = prioritize(grype_path, CONFIG / key, epss_map, kev_map)
        (OUT / f"priority_{key}.json").write_text(
            json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"  [{key}]")
        for cve_id in rule_cve_ids:
            f = next((x for x in findings if x.cve_id == cve_id), None)
            rank = findings.index(f) + 1 if f else None
            print(f"    {cve_id} rank={rank} tier={f.tier if f else 'N/A'}")


def step_remediate():
    print("\n=== [4/5] NVD 수정 버전 조회 + 상위 N건 LLM 조치안 생성 (키 없으면 템플릿 fallback) ===")
    from remediate import load_dotenv, generate_remediations, TOP_N
    from nvd import fetch_fix_versions

    load_dotenv(ROOT / ".env")

    scenario_findings = {}
    top_cve_ids = set()
    for key in ["ajp-vulnerable", "ajp-mitigated"]:
        findings = json.loads((OUT / f"priority_{key}.json").read_text(encoding="utf-8"))
        scenario_findings[key] = findings
        top_cve_ids.update(f["cve_id"] for f in findings[:TOP_N])

    fix_versions = fetch_fix_versions(sorted(top_cve_ids), cache_path=OUT / "nvd_fix_versions.json")
    print(f"  NVD 수정 버전 조회: {fix_versions}")

    total_tokens = 0
    llm_calls = 0
    for key, findings in scenario_findings.items():
        remediations = generate_remediations(findings, scenario_label=key, fix_versions=fix_versions)
        (OUT / f"remediation_{key}.json").write_text(
            json.dumps([asdict(r) for r in remediations], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        for r in remediations:
            if r.mode == "llm" and r.usage:
                llm_calls += 1
                total_tokens += r.usage.get("total_tokens", 0)
    print(f"  LLM 실호출 {llm_calls}건, 총 토큰 {total_tokens}")


def step_report():
    print("\n=== [5/5] HTML 리포트 생성 ===")
    from report import build
    build()


if __name__ == "__main__":
    step_sbom()
    step_scan()
    step_enrich_and_prioritize()
    step_remediate()
    step_report()
    print(f"\n완료. 리포트: {OUT / 'report.html'}")
