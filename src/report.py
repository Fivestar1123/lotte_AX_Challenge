"""output/ 아래 JSON 산출물들을 모아 단일 HTML 리포트로 렌더링한다."""
from __future__ import annotations

import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "output"

SCENARIOS = [
    ("ajp-vulnerable", "시나리오 A — 레거시/방치된 설정 (AJP 평문 + DefaultServlet 쓰기 허용 + 세션 FileStore 역직렬화 무필터)"),
    ("ajp-mitigated", "시나리오 B — 보안 강화 설정 (AJP 인증 + DefaultServlet 읽기전용 + FileStore 미사용)"),
]

# (CVE, 표시용 이름, 두 시나리오에서 갈리는 설정 파일)
SIGNATURE_CVES = [
    ("CVE-2020-1938", "Ghostcat", "server.xml (AJP secretRequired)"),
    ("CVE-2025-24813", "Path Equivalence", "web.xml (DefaultServlet readonly)"),
    ("CVE-2020-9484", "세션 파일 역직렬화", "context.xml (PersistentManager+FileStore)"),
]

TIER_COLOR = {
    "Critical": "#b3261e",
    "High": "#c05600",
    "Medium": "#8a7000",
    "Low": "#3c6e3c",
}


def esc(x) -> str:
    return html.escape(str(x)) if x is not None else "-"


def load(name: str):
    return json.loads((OUT / name).read_text(encoding="utf-8"))


def top_rows_html(findings: list[dict], limit: int = 10, highlight_cves: set[str] = frozenset()) -> str:
    rows = []
    for i, f in enumerate(findings[:limit], start=1):
        color = TIER_COLOR.get(f["tier"], "#444")
        hl = ' style="background:#fff3cd;"' if f["cve_id"] in highlight_cves else ""
        reach = {"True": "O 도달 가능", "False": "X 도달 불가", "None": "미판정"}[str(f["reachable"])]
        rows.append(f"""
        <tr{hl}>
          <td>{i}</td>
          <td><code>{esc(f['cve_id'])}</code></td>
          <td>{esc(f['cvss'])}</td>
          <td>{esc(f['epss'])}</td>
          <td>{"O" if f['kev'] else "-"}</td>
          <td>{reach}</td>
          <td><span style="color:{color};font-weight:600;">{esc(f['tier'])}</span></td>
          <td>{esc(f['score'])}</td>
        </tr>""")
    return "".join(rows)


def remediation_cards_html(remediations: list[dict]) -> str:
    cards = []
    for r in remediations:
        ev = r["evidence"]
        if r["mode"] == "llm":
            usage = r.get("usage") or {}
            usage_str = (
                f"prompt {usage.get('prompt_tokens')} + completion {usage.get('completion_tokens')} "
                f"= {usage.get('total_tokens')} tokens"
                if usage else ""
            )
            mode_badge = (
                f'<span style="background:#e7f3ff;color:#0b5ed7;padding:2px 8px;border-radius:10px;font-size:12px;">'
                f'LLM 생성 · {esc(r.get("model"))} · {esc(usage_str)}</span>'
            )
        else:
            mode_badge = '<span style="background:#f1f1f1;color:#555;padding:2px 8px;border-radius:10px;font-size:12px;">오프라인 템플릿 (API 키 미설정)</span>'
        cards.append(f"""
        <div class="card">
          <div class="card-head">
            <code>{esc(r['cve_id'])}</code> {mode_badge}
          </div>
          <div class="evidence">
            CVSS {esc(ev['cvss'])} ({esc(ev['cvss_vector'])}) ·
            EPSS {esc(ev['epss'])} ·
            KEV {"등재" if ev['kev'] else "미등재"} ·
            설정 판정: {esc(ev['reachable'])} ({esc(ev['reachability_reason'])}) ·
            tier {esc(ev['tier'])} (score {esc(ev['score'])})
          </div>
          <pre class="reco">{esc(r['recommendation'])}</pre>
        </div>""")
    return "".join(cards)


def build():
    sbom = json.loads((OUT / "sbom.cdx.json").read_text(encoding="utf-8"))
    comp_count = len(sbom.get("components", []))
    target = sbom.get("metadata", {}).get("component", {})

    default_scan = json.loads((OUT / "evidence" / "grype_default_no_cpe.json").read_text(encoding="utf-8"))
    cpe_scan = json.loads((OUT / "evidence" / "grype_java_cpe_enabled.json").read_text(encoding="utf-8"))
    default_cves = {m["vulnerability"]["id"] for m in default_scan["matches"]}
    cpe_cves = {m["vulnerability"]["id"] for m in cpe_scan["matches"]}

    signature_ids = {c for c, _, _ in SIGNATURE_CVES}

    sections = []
    scenario_findings = {}
    for key, label in SCENARIOS:
        findings = load(f"priority_{key}.json")
        remediations = load(f"remediation_{key}.json")
        scenario_findings[key] = findings

        sections.append(f"""
        <section>
          <h2>{esc(label)}</h2>
          <table>
            <thead><tr><th>#</th><th>CVE</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>설정 도달성</th><th>Tier</th><th>Score</th></tr></thead>
            <tbody>{top_rows_html(findings, limit=10, highlight_cves=signature_ids)}</tbody>
          </table>
          <h3>조치안 (상위 {len(remediations)}건, LLM/템플릿)</h3>
          {remediation_cards_html(remediations)}
        </section>""")

    total_count = len(scenario_findings["ajp-vulnerable"])

    compare_rows = []
    for cve_id, nickname, cfg_file in SIGNATURE_CVES:
        row_cells = [f"<td><code>{esc(cve_id)}</code><br/><span style='color:#777;font-size:12px;'>{esc(nickname)} · {esc(cfg_file)}</span></td>"]
        for key, _ in SCENARIOS:
            f = next((x for x in scenario_findings[key] if x["cve_id"] == cve_id), None)
            if f is None:
                row_cells.append("<td>해당 CVE 미탐지</td>")
                continue
            rank = scenario_findings[key].index(f) + 1
            reach = {"True": "도달 가능", "False": "도달 불가", "None": "미판정"}[str(f["reachable"])]
            color = TIER_COLOR.get(f["tier"], "#000")
            row_cells.append(
                f"<td>{rank}위 / {len(scenario_findings[key])}건 중<br/>"
                f"<b style='color:{color};'>{esc(f['tier'])}</b> (score {esc(f['score'])})<br/>"
                f"<span style='color:#777;font-size:12px;'>{reach}</span></td>"
            )
        compare_rows.append(f"<tr>{''.join(row_cells)}</tr>")

    callout = f"""
    <div class="callout">
      <h3>핵심 결과 — 같은 CVE, 다른 설정, 다른 우선순위 (3개 CVE 실증)</h3>
      <p>아래 3개 CVE는 CVSS·EPSS·KEV 값이 두 시나리오에서 완전히 동일하지만, server.xml/web.xml/context.xml의
      설정값만으로 실제 우선순위(순위·Tier·Score)가 크게 달라진다. 영향 버전 범위와 KEV 등재 여부는
      NVD CVE API·CISA KEV 피드에서 직접 조회해 확인했다 (CVE-2020-9484는 KEV 미등재, CISA SSVC
      exploitation=none — 나머지 둘은 KEV 등재).</p>
      <table class="compare">
        <thead><tr><th>CVE / 판정 근거 파일</th><th>{esc(SCENARIOS[0][1].split(' — ')[0])}</th><th>{esc(SCENARIOS[1][1].split(' — ')[0])}</th></tr></thead>
        <tbody>{''.join(compare_rows)}</tbody>
      </table>
    </div>"""

    detection_note = f"""
    <div class="callout warn">
      <h3>탐지 단계에서 발견한 실제 공급망 스캐너의 한계 (미탐 사례)</h3>
      <p>grype 기본 설정(<code>match.java.using-cpes=false</code>)으로 스캔하면 Tomcat 9.0.30 이미지에서
      <b>CVE-2020-1938(Ghostcat)이 전혀 탐지되지 않는다.</b> grype가 Java fat/shaded jar의 오탐을 줄이기 위해
      Java 패키지는 기본적으로 CPE 매칭을 쓰지 않기 때문이다 (벤더 CPE 룰 vs 실제 아티팩트 이름 불일치: tomcat-coyote.jar ≠ "apache:tomcat").
      이 PoC는 <code>GRYPE_MATCH_JAVA_USING_CPES=true</code>로 재스캔해 탐지했지만, 그 결과 전체 매치 수가
      {len(default_cves)}개 → {len(cpe_cves)}개로 늘어나 오탐 위험도 같이 커졌다 (라이선스 등 비보안성 패키지까지 과매칭 가능성).
      실제 운영에서는 "CVE가 안 뜨면 안전하다"고 믿을 수 없고, 스캐너 설정 자체도 검증 대상이라는 뜻이다.</p>
    </div>"""

    html_doc = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8" />
<title>SW 공급망 스캐닝 PoC 리포트 — Tomcat 9.0.30</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", "Malgun Gothic", sans-serif; max-width: 980px; margin: 32px auto; padding: 0 16px; color: #1a1a1a; line-height: 1.55; }}
  h1 {{ font-size: 24px; }}
  h2 {{ font-size: 19px; border-bottom: 2px solid #eee; padding-bottom: 6px; margin-top: 36px; }}
  h3 {{ font-size: 16px; margin-top: 24px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }}
  th, td {{ border: 1px solid #ddd; padding: 6px 8px; text-align: left; }}
  th {{ background: #f6f6f6; }}
  code {{ background: #f1f1f1; padding: 1px 5px; border-radius: 4px; font-size: 12px; }}
  .callout {{ background: #f0f7ff; border: 1px solid #bcd8f6; border-radius: 8px; padding: 16px 20px; margin: 20px 0; }}
  .callout.warn {{ background: #fff8ec; border-color: #f0d49a; }}
  .meta {{ color: #555; font-size: 14px; }}
  .card {{ border: 1px solid #e3e3e3; border-radius: 8px; padding: 14px 16px; margin: 10px 0; }}
  .card-head {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
  .evidence {{ font-size: 12px; color: #555; margin-bottom: 8px; }}
  .reco {{ white-space: pre-wrap; font-family: inherit; font-size: 13px; background: #fafafa; padding: 10px 12px; border-radius: 6px; margin: 0; }}
  .compare td, .compare th {{ text-align: center; vertical-align: top; }}
  footer {{ margin-top: 40px; font-size: 12px; color: #888; border-top: 1px solid #eee; padding-top: 10px; }}
</style>
</head>
<body>
  <h1>SW 공급망 스캐닝 에이전트 PoC — Tomcat 9.0.30 (3개 CVE 설정 기반 도달성 판정)</h1>
  <p class="meta">
    대상 이미지: <code>{esc(target.get('name'))}:{esc(target.get('version'))}</code> (Docker Hub 공식 이미지, registry 직접 스캔) ·
    SBOM 컴포넌트 수: <b>{comp_count}</b>개 (CycloneDX, syft 생성) ·
    매칭된 고유 CVE/GHSA 수: <b>{len(cpe_cves)}</b>개 (grype) ·
    전체 우선순위 목록: <b>{total_count}</b>건
  </p>

  {callout}
  {detection_note}

  <h2>파이프라인</h2>
  <p class="meta">SBOM(syft, registry 직접 스캔) → 취약점 매칭(grype, java CPE 매칭 활성) →
  EPSS(FIRST API)·CISA KEV 보강 → server.xml/web.xml/context.xml 기반 도달성 판정(룰, CVE 3종) →
  가중합 스코어링(통계) → 상위 3건만 LLM 조치안 생성(비용/환각 통제). 모든 수치는 실제 API/도구 호출
  결과이며 임의 조작하지 않았다.</p>

  {''.join(sections)}

  <footer>
    본 리포트는 PoC 목적의 데모이며, 운영 반영을 자동화하지 않는다. 모든 조치안은 사람의 검토·승인(Human-in-the-loop)을 전제로 한 제안이다.<br/>
    생성: LOTTE AX Challenge 2026 — 롯데이노베이트 SW 공급망 스캐닝 에이전트 기획 PoC
  </footer>
</body>
</html>"""

    out_path = OUT / "report.html"
    out_path.write_text(html_doc, encoding="utf-8")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    build()
