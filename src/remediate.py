"""상위 N건에 대해서만 LLM으로 조치안을 생성한다 (룰 → 통계 → LLM 3계층 중 마지막 단계).

비용/환각 통제를 위해 전체 취약점이 아니라 prioritize.py가 뽑은 상위 N건에만 호출한다.
모델/프로바이더는 환경변수로 교체 가능 (기본값: OpenAI).

LLM API 키가 없으면 (.env 미설정) 호출을 생략하고 템플릿 기반 조치안으로
degrade한다 — 데모가 키 유무와 무관하게 end-to-end로 돌아가야 하기 때문.
운영 반영 자동화는 하지 않는다: 이 모듈의 출력은 "제안"이며, 실제 반영은
사람이 검토/승인한 뒤 별도로 수행한다 (Human-in-the-loop).
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from dataclasses import dataclass, asdict
from pathlib import Path

LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "openai").lower()
LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4o-mini")
TOP_N = int(os.environ.get("REMEDIATE_TOP_N", "3"))

# 프롬프트에 노출할 시나리오 설명. scenario key 문자열("ajp-vulnerable" 등)을 그대로 넣으면
# "ajp"라는 단어 자체가 프롬프트에 박혀 LLM이 AJP와 무관한 CVE에도 AJP 언급을 끼워넣는
# 현상을 유발한다는 것을 실제 호출로 확인해, 특정 메커니즘명을 암시하지 않는 중립적 설명으로 교체했다.
SCENARIO_PROMPT_LABELS = {
    "ajp-vulnerable": "레거시/방치된 설정 묶음 (시나리오 A)",
    "ajp-mitigated": "보안 강화 설정 묶음 (시나리오 B)",
}


def load_dotenv(path: Path) -> None:
    """외부 의존성 없이 .env를 읽어 os.environ에 주입 (이미 설정된 값은 덮어쓰지 않음)."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


@dataclass
class Remediation:
    cve_id: str
    scenario: str
    mode: str  # "llm" | "offline-template"
    evidence: dict
    recommendation: str
    model: str | None = None
    usage: dict | None = None


def _build_prompt(finding: dict, scenario_label: str, fix_version_info: dict | None) -> str:
    if fix_version_info:
        fix_line = (
            f"- 공식 수정 버전(NVD cpeMatch 기준, 설치된 버전 9.0.30이 속한 구간): "
            f"{fix_version_info['fix_version']} (취약 구간: {fix_version_info['range']})"
        )
    else:
        fix_line = "- 공식 수정 버전: NVD에서 자동 조회 실패 — 벤더 공지를 직접 확인하라고 안내할 것"

    prompt_scenario_label = SCENARIO_PROMPT_LABELS.get(scenario_label, scenario_label)
    reachable = finding.get("reachable")
    if reachable is None:
        reach_line = (
            "- 설정 기반 도달성 판정: 이 CVE에는 설정 기반 도달성 룰이 없음(reachable=None). "
            "특정 커넥터/서블릿 이름을 추측해서 언급하지 말 것 — 일반적인 패치/비활성화 수준으로만 조치안 작성."
        )
    else:
        reach_line = f"- 설정 기반 도달성 판정: reachable={reachable} / 근거: {finding.get('reachability_reason')}"

    evidence_lines = [
        f"- CVE: {finding['cve_id']} (severity: {finding['severity']})",
        f"- CVSS: {finding.get('cvss')} ({finding.get('cvss_vector')})",
        f"- EPSS(30일 내 악용 확률): {finding.get('epss')}",
        f"- CISA KEV 등재 여부: {finding.get('kev')} (등재 시 조치기한: {finding.get('kev_due_date')})",
        fix_line,
        reach_line,
        f"- 영향받는 컴포넌트: {', '.join(finding.get('affected_components', [])[:10])}",
        f"- 적용 시나리오: {prompt_scenario_label}",
    ]
    evidence_block = "\n".join(evidence_lines)
    return f"""당신은 사내 보안 엔지니어에게 조치안을 써주는 어시스턴트입니다.
아래 근거를 바탕으로 이 취약점에 대한 조치안을 한국어로 작성하세요.

[근거]
{evidence_block}

[요청사항 — 아래 4개 섹션으로, 각 2~4줄, 불필요한 수식어 없이]
1. 조치 우선순위 한 줄 요약 (왜 이 순위인지 CVSS/EPSS/KEV/설정 판정을 근거로 설명)
2. 조치안 (패치 버전 업그레이드 경로 + 설정 우회/대체 통제, 복수 옵션 제시)
3. 검증 절차 (조치 적용 전 샌드박스/스테이징에서 확인할 항목)
4. 주의사항/한계 (이 조치안은 제안이며 운영 반영은 사람 승인 필요함을 명시)

[중요 제약]
- 수정 버전은 반드시 위 근거에 적힌 "공식 수정 버전" 값만 그대로 사용하라. 다른 숫자를
  추측하거나 다른 CVE의 수정 버전과 혼동하지 마라.
- 설정 우회/대체 통제는 위 "설정 기반 도달성 판정" 근거에 실제로 등장한 메커니즘에만
  한정하라. 근거가 "reachable=None"이면 AJP/DefaultServlet/PersistentManager 같은 구체적인
  컴포넌트명을 절대로 지어내지 말고, "해당 기능/포트 비활성화"처럼 일반적인 표현만 써라.
"""


def _call_openai(prompt: str) -> tuple[str, str, dict]:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")
    body = json.dumps({
        "model": LLM_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    text = data["choices"][0]["message"]["content"]
    usage = data.get("usage", {})
    return text, data.get("model", LLM_MODEL), usage


def _call_anthropic(prompt: str) -> tuple[str, str, dict]:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    body = json.dumps({
        "model": LLM_MODEL,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    text = data["content"][0]["text"]
    usage = data.get("usage", {})
    return text, data.get("model", LLM_MODEL), usage


def _offline_template(finding: dict, scenario_label: str) -> str:
    reach = finding.get("reachable")
    reach_line = (
        "현재 설정상 공격 경로가 열려 있어 즉시 조치가 필요합니다." if reach is True
        else "현재 설정상 공격 경로가 막혀 있어 긴급도는 낮지만, 설정 변경 시 재노출될 수 있으므로 패치는 유지하세요." if reach is False
        else "이 CVE에 대한 설정 기반 도달성 룰이 없어 CVSS/EPSS/KEV만으로 판단했습니다."
    )
    return (
        f"[오프라인 템플릿 — LLM 미호출]\n"
        f"1. 우선순위 요약: CVSS {finding.get('cvss')} / EPSS {finding.get('epss')} / "
        f"KEV {finding.get('kev')} 기준 tier={finding.get('tier')}. {reach_line}\n"
        f"2. 조치안: 벤더 권고 버전으로 패치하거나(공식 변경로그 확인), 패치가 불가한 경우 "
        f"해당 기능/포트를 비활성화하거나 접근을 127.0.0.1/내부망으로 제한하는 대체 통제를 적용하세요.\n"
        f"3. 검증 절차: 스테이징 컨테이너에 동일 패치/설정을 적용한 뒤 재스캔(syft+grype)으로 "
        f"해당 CVE가 사라지는지, 기존 기능이 정상 동작하는지 확인하세요.\n"
        f"4. 주의사항: 이 내용은 제안이며 운영 반영 전 담당자 승인이 필요합니다. "
        f"(scenario: {scenario_label})"
    )


def generate_remediations(
    findings: list[dict],
    scenario_label: str,
    top_n: int = TOP_N,
    fix_versions: dict[str, dict] | None = None,
) -> list[Remediation]:
    fix_versions = fix_versions or {}
    results = []
    for finding in findings[:top_n]:
        fix_version_info = fix_versions.get(finding["cve_id"])
        prompt = _build_prompt(finding, scenario_label, fix_version_info)
        mode = "llm"
        text = None
        model_used = None
        usage = None
        try:
            if LLM_PROVIDER == "openai":
                text, model_used, usage = _call_openai(prompt)
            elif LLM_PROVIDER == "anthropic":
                text, model_used, usage = _call_anthropic(prompt)
            else:
                raise RuntimeError(f"unsupported LLM_PROVIDER={LLM_PROVIDER}, falling back")
            print(f"[remediate] LLM 호출 성공 ({finding['cve_id']}): model={model_used} usage={usage}")
        except Exception as e:
            print(f"[remediate] LLM 호출 생략 ({finding['cve_id']}): {e}")
            mode = "offline-template"
            text = _offline_template(finding, scenario_label)

        results.append(
            Remediation(
                cve_id=finding["cve_id"],
                scenario=scenario_label,
                mode=mode,
                evidence={
                    "cvss": finding.get("cvss"),
                    "cvss_vector": finding.get("cvss_vector"),
                    "epss": finding.get("epss"),
                    "kev": finding.get("kev"),
                    "kev_due_date": finding.get("kev_due_date"),
                    "reachable": finding.get("reachable"),
                    "reachability_reason": finding.get("reachability_reason"),
                    "tier": finding.get("tier"),
                    "score": finding.get("score"),
                    "nvd_fix_version": fix_version_info,
                },
                recommendation=text,
                model=model_used,
                usage=usage,
            )
        )
    return results


if __name__ == "__main__":
    from nvd import fetch_fix_versions

    root = Path(__file__).resolve().parent.parent
    load_dotenv(root / ".env")

    top_cve_ids = set()
    scenario_findings = {}
    for scenario in ["ajp-vulnerable", "ajp-mitigated"]:
        findings = json.loads((root / "output" / f"priority_{scenario}.json").read_text(encoding="utf-8"))
        scenario_findings[scenario] = findings
        top_cve_ids.update(f["cve_id"] for f in findings[:TOP_N])

    fix_versions = fetch_fix_versions(sorted(top_cve_ids), cache_path=root / "output" / "nvd_fix_versions.json")

    for scenario, findings in scenario_findings.items():
        remediations = generate_remediations(findings, scenario_label=scenario, fix_versions=fix_versions)
        out_path = root / "output" / f"remediation_{scenario}.json"
        out_path.write_text(
            json.dumps([asdict(r) for r in remediations], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"[{scenario}] wrote {len(remediations)} remediations -> {out_path}")
