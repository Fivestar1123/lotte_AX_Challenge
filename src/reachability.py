"""Tomcat 설정 파일 기반 도달성(reachability) 판정 룰.

각 룰은 '이 CVE가 이 설정에서 실제로 공격 가능한가'를 판단한다.
CVSS/EPSS/KEV는 "얼마나 위험한 취약점인가"를 말해주지만, 실제로 그 경로가
열려 있는지는 설정을 봐야 안다 — 이 모듈이 그 간극을 메운다.

판정 대상은 server.xml 하나가 아니라 시나리오별 설정 디렉토리
(config/ajp-vulnerable/, config/ajp-mitigated/)이며, 각 룰이 필요한 파일
(server.xml / web.xml / context.xml)을 스스로 읽는다.

새 CVE 룰을 추가할 때는 RULES 딕셔너리에 CVE ID -> 판정 함수를 등록하면 된다.
NVD/CISA KEV 출처 확인 결과(2026-10-31 기준):
- CVE-2020-1938 (Ghostcat): Tomcat 7.0.0-7.0.100 / 8.5.0-8.5.51 / 9.0.0-9.0.31. KEV 등재.
- CVE-2025-24813 (Path Equivalence): Tomcat 9.0.0.M1-9.0.98 / 10.1.0-10.1.34 / 11.0.0-11.0.2
  (+EOL 8.5.x). CVSS 9.8(~10.0). KEV 등재(2025-04-01 추가, 조치기한 2025-04-22).
- CVE-2020-9484 (세션 파일 역직렬화 RCE): Tomcat 7.0.0-7.0.103 / 8.5.0-8.5.54 / 9.0.1-9.0.43.
  CVSS 3.1 7.0(HIGH, AV:L). KEV 미등재(CISA SSVC exploitation=none).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class Verdict:
    cve_id: str
    config_name: str
    reachable: bool
    reason: str
    detail: dict


def _find_ajp_connectors(root: ET.Element) -> list[ET.Element]:
    connectors = []
    for svc in root.findall("Service"):
        for conn in svc.findall("Connector"):
            protocol = conn.get("protocol", "")
            if protocol.upper().startswith("AJP"):
                connectors.append(conn)
    return connectors


def judge_cve_2020_1938(config_dir: Path) -> Verdict:
    """Ghostcat: AJP 커넥터가 활성 + secretRequired 미설정이면 인증 없이 파일
    읽기/RFI가 가능하다. 커넥터가 없거나, secretRequired=true + secret 설정이면
    공격 경로가 막힌다. (server.xml)"""
    config_path = config_dir / "server.xml"
    tree = ET.parse(config_path)
    root = tree.getroot()
    connectors = _find_ajp_connectors(root)

    if not connectors:
        return Verdict(
            cve_id="CVE-2020-1938",
            config_name=config_dir.name,
            reachable=False,
            reason="AJP 커넥터가 server.xml에 정의되어 있지 않음 (완전 비활성)",
            detail={"ajp_connector_present": False},
        )

    # 커넥터가 여러 개면 가장 위험한(미보호) 것을 기준으로 판정
    worst = None
    for conn in connectors:
        secret_required = conn.get("secretRequired", "true").strip().lower()
        secret_value = conn.get("secret", "")
        address = conn.get("address", "0.0.0.0")
        bound_localhost_only = address in ("127.0.0.1", "localhost", "::1")

        protected = secret_required == "true" and bool(secret_value)
        exposed = not bound_localhost_only

        detail = {
            "ajp_connector_present": True,
            "address": address,
            "secretRequired": conn.get("secretRequired", "(미설정, Tomcat 기본값 true로 간주되나 secret 없으면 사실상 무의미)"),
            "secret_set": bool(secret_value),
            "bound_localhost_only": bound_localhost_only,
        }

        if not protected and exposed:
            worst = Verdict(
                cve_id="CVE-2020-1938",
                config_name=config_dir.name,
                reachable=True,
                reason="AJP 커넥터 활성 + secretRequired/secret 보호 없음 + 외부 바인딩 → 인증 없이 공격 가능",
                detail=detail,
            )
            break  # 가장 위험한 경우를 찾았으면 더 볼 필요 없음
        elif not protected and not exposed:
            worst = Verdict(
                cve_id="CVE-2020-1938",
                config_name=config_dir.name,
                reachable=False,
                reason="AJP 커넥터는 보호되어 있지 않지만 127.0.0.1에만 바인딩되어 외부에서 직접 도달 불가 "
                       "(단, 동일 호스트 내 다른 프로세스/컨테이너 네트워크 경유 위험은 별도 검토 필요)",
                detail=detail,
            )
        else:
            worst = Verdict(
                cve_id="CVE-2020-1938",
                config_name=config_dir.name,
                reachable=False,
                reason="AJP 커넥터에 secretRequired=true + secret 설정 → 인증 토큰 없는 요청은 거부됨",
                detail=detail,
            )

    return worst


def _find_default_servlet(root: ET.Element) -> ET.Element | None:
    for servlet in root.findall("servlet"):
        cls = servlet.findtext("servlet-class", "")
        if cls.strip().endswith("DefaultServlet"):
            return servlet
    return None


def judge_cve_2025_24813(config_dir: Path) -> Verdict:
    """Apache Tomcat Path Equivalence (CISA KEV 등재, CVSS 9.8~10.0): Default
    Servlet의 readonly가 false면 partial PUT을 통해 정보 유출/콘텐츠 변조가
    가능하고, 세션 파일 영속화(FileStore)까지 겹치면 역직렬화 RCE로 확대된다
    (CVE-2020-9484와 연계). Tomcat 9.0.30에는 벤더 패치에서 추가된
    allowPartialPut 토글이 없어, 9.0.30 기준으로는 readonly 값이 사실상 유일한
    스위치다. (web.xml)"""
    config_path = config_dir / "web.xml"
    tree = ET.parse(config_path)
    root = tree.getroot()
    servlet = _find_default_servlet(root)

    if servlet is None:
        return Verdict(
            cve_id="CVE-2025-24813",
            config_name=config_dir.name,
            reachable=False,
            reason="web.xml에 DefaultServlet 정의가 없음 (판정 불가 — 보수적으로 도달 불가 처리)",
            detail={"default_servlet_present": False},
        )

    readonly_value = None
    for param in servlet.findall("init-param"):
        if param.findtext("param-name", "").strip() == "readonly":
            readonly_value = param.findtext("param-value", "").strip().lower()

    # Tomcat DefaultServlet의 하드코딩된 기본값은 readonly=true
    effective_readonly = readonly_value if readonly_value is not None else "true"
    writable = effective_readonly == "false"

    detail = {
        "default_servlet_present": True,
        "readonly_param": readonly_value if readonly_value is not None else "(미설정, 기본값 true)",
        "effective_readonly": effective_readonly,
    }

    if writable:
        return Verdict(
            cve_id="CVE-2025-24813",
            config_name=config_dir.name,
            reachable=True,
            reason="DefaultServlet readonly=false → partial PUT으로 보안 민감 파일 열람/콘텐츠 주입 가능 "
                   "(세션 FileStore까지 겹치면 RCE로 확대 가능, CVE-2020-9484 판정 참고)",
            detail=detail,
        )
    return Verdict(
        cve_id="CVE-2025-24813",
        config_name=config_dir.name,
        reachable=False,
        reason="DefaultServlet readonly=true (기본값) → 쓰기 요청 자체가 거부되어 공격 경로 차단",
        detail=detail,
    )


def judge_cve_2020_9484(config_dir: Path) -> Verdict:
    """세션 파일 역직렬화 RCE: PersistentManager+FileStore가 설정되어 있고
    sessionAttributeValueClassNameFilter가 없거나(null, 기본값) 느슨하면,
    공격자가 세션 저장 파일을 제어할 수 있는 상황에서 역직렬화 RCE가 가능하다.
    이 PoC는 "서버 설정이 공격을 가능하게 열어두고 있는가"까지만 판정하며,
    공격자가 파일 내용/경로를 실제로 제어할 수 있는지는 별도 전제다. (context.xml)"""
    config_path = config_dir / "context.xml"
    tree = ET.parse(config_path)
    root = tree.getroot()

    manager = None
    for m in root.findall("Manager"):
        if "PersistentManager" in m.get("className", ""):
            manager = m
            break

    if manager is None:
        return Verdict(
            cve_id="CVE-2020-9484",
            config_name=config_dir.name,
            reachable=False,
            reason="context.xml에 PersistentManager가 설정되어 있지 않음 (기본 StandardManager, 메모리 세션)",
            detail={"persistent_manager_present": False},
        )

    store = manager.find("Store")
    uses_filestore = store is not None and "FileStore" in store.get("className", "")
    filter_value = manager.get("sessionAttributeValueClassNameFilter", "null")

    detail = {
        "persistent_manager_present": True,
        "uses_filestore": uses_filestore,
        "sessionAttributeValueClassNameFilter": filter_value,
    }

    if not uses_filestore:
        return Verdict(
            cve_id="CVE-2020-9484",
            config_name=config_dir.name,
            reachable=False,
            reason="PersistentManager는 있으나 FileStore를 쓰지 않음 → 공격자가 제어 가능한 파일 경로가 없음",
            detail=detail,
        )

    if filter_value.strip().lower() == "null" or not filter_value.strip():
        return Verdict(
            cve_id="CVE-2020-9484",
            config_name=config_dir.name,
            reachable=True,
            reason="PersistentManager+FileStore 사용 + sessionAttributeValueClassNameFilter 미설정(null, 기본값) "
                   "→ 공격자가 세션 저장 파일을 제어할 수 있는 상황이면 역직렬화 RCE 가능 "
                   "(파일 제어 가능 여부는 별도 전제)",
            detail=detail,
        )

    return Verdict(
        cve_id="CVE-2020-9484",
        config_name=config_dir.name,
        reachable=False,
        reason=f"PersistentManager+FileStore 사용하지만 sessionAttributeValueClassNameFilter={filter_value!r}로 "
               f"제한되어 있어 임의 클래스 역직렬화가 차단됨",
        detail=detail,
    )


RULES = {
    "CVE-2020-1938": judge_cve_2020_1938,
    "CVE-2025-24813": judge_cve_2025_24813,
    "CVE-2020-9484": judge_cve_2020_9484,
}


def judge(cve_id: str, config_dir: Path) -> Verdict | None:
    rule = RULES.get(cve_id)
    if rule is None:
        return None
    return rule(config_dir)


if __name__ == "__main__":
    import json

    base = Path(__file__).resolve().parent.parent / "config"
    for scenario_dir in ["ajp-vulnerable", "ajp-mitigated"]:
        for cve_id in RULES:
            v = judge(cve_id, base / scenario_dir)
            print(json.dumps(asdict(v), ensure_ascii=False, indent=2))
