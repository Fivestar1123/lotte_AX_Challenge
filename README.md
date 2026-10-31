# SW 공급망 스캐닝 에이전트 PoC

LOTTE AX Challenge 2026 — 롯데이노베이트 「SW 공급망 스캐닝 에이전트 기획」 지원용 최소 PoC.

**핵심 주장**: "스캔은 되는데 판단이 안 된다"는 문제를, CVSS·EPSS·KEV 같은 일반적 위험도
지표에 더해 **실제 설정(server.xml/web.xml/context.xml)을 파싱해 공격 경로가 열려 있는지**
까지 판정하는 파이프라인으로 보여준다. Tomcat 9.0.30에 실재하는 CVE 3건
(Ghostcat/CVE-2020-1938, Path Equivalence/CVE-2025-24813, 세션 파일 역직렬화/CVE-2020-9484)
모두, 같은 이미지인데도 설정 묶음에 따라 우선순위가 Critical/High → Medium으로 바뀌는 것이
이 PoC의 핵심 증거다. 영향 버전 범위와 KEV 등재 여부는 NVD CVE API·CISA KEV 피드에서
직접 조회해 확인했다(아래 §1 주석 참고).

## 1. 구조도

```
registry: tomcat:9.0.30-jdk8-openjdk  (Docker Hub, Docker 데몬 불필요)
        │
        ▼
 [1] syft  ──────────► sbom.cdx.json (CycloneDX)  /  syft.native.json
        │
        ▼
 [2] grype (sbom: syft.native.json, GRYPE_MATCH_JAVA_USING_CPES=true)
        │                                   ▲
        ▼                                   │ (비교용 기본 설정 스캔 → 미탐 증빙, evidence/)
     grype.json  (CVE/GHSA 매치 목록 + CVSS)
        │
        ▼
 [3] enrich.py ──► FIRST EPSS API, CISA KEV JSON (실시간 호출, 캐시)
        │
        ▼
 [3] reachability.py ◄── config/ajp-vulnerable/{server,web,context}.xml  (레거시 묶음)
        │               ◄── config/ajp-mitigated/{server,web,context}.xml (강화 묶음)
        │
        │   CVE별 룰 (RULES 딕셔너리, NVD/CISA KEV로 영향버전·KEV 확인 완료):
        │   - CVE-2020-1938  (Ghostcat)            → server.xml  AJP secretRequired/secret
        │   - CVE-2025-24813 (Path Equivalence)    → web.xml     DefaultServlet readonly
        │   - CVE-2020-9484  (세션 파일 역직렬화)   → context.xml PersistentManager+FileStore
        ▼
 [3] prioritize.py  (CVSS+EPSS+KEV 가중합 → 도달 불가 시 0.3배 감점 → tier)
        │
        ├─► output/priority_ajp-vulnerable.json
        └─► output/priority_ajp-mitigated.json
        │
        ▼
 [4] remediate.py  (상위 3건만 LLM 호출. 키 없으면 오프라인 템플릿으로 자동 degrade)
        │
        ▼
 [5] report.py ──► output/report.html  (리포트 1장, 두 시나리오 비교 포함)
```

3계층 원칙(브리프 §4): **룰**(reachability.py의 CVE 3종 판정) → **통계**(prioritize.py의
가중합 스코어링, 블랙박스 없이 공식 그대로 노출) → **LLM**(remediate.py, 상위 N건에만,
비용/환각 통제).

## 2. 실행법

### 사전 준비
- Python 3.10+ (표준 라이브러리만 사용, pip 설치 불필요)
- `poc/bin/syft.exe`, `poc/bin/grype.exe` — 없으면:
  ```powershell
  .\install_tools.ps1
  ```
  (Docker Desktop 불필요. syft/grype가 registry에서 이미지를 직접 pull해서 스캔한다.)
- (선택) LLM 조치안을 실제로 받고 싶으면 `.env.example`을 `.env`로 복사 후
  `OPENAI_API_KEY`(또는 `ANTHROPIC_API_KEY` + `LLM_PROVIDER=anthropic`) 입력.
  키가 없으면 자동으로 오프라인 템플릿 조치안으로 대체되며, 파이프라인은 끝까지 돈다.

### 실행
```bash
cd poc
python run.py
```
`poc/output/report.html`이 생성된다. 각 단계 산출물(JSON)도 `poc/output/`에 그대로 남는다.

### 개별 모듈 실행 (디버깅용)
```bash
python src/reachability.py   # 두 시나리오 × CVE 3종(Ghostcat/Path Equivalence/세션역직렬화) 도달성 판정 출력
python src/enrich.py         # EPSS/KEV 조회 테스트
python src/prioritize.py     # 우선순위 스코어링만 재실행
python src/remediate.py      # 조치안 생성만 재실행
python src/report.py         # 리포트만 재렌더링
```

## 3. 산출물

| 파일 | 내용 |
|---|---|
| `output/sbom.cdx.json` | CycloneDX SBOM (syft, 실제 Tomcat 9.0.30 이미지 스캔, 1617개 컴포넌트) |
| `output/grype.json` | grype 취약점 매칭 결과 (java CPE 매칭 활성화) |
| `output/evidence/grype_default_no_cpe.json` | 비교용: grype 기본 설정(미탐 사례 증빙) |
| `output/epss.json`, `output/kev.json` | FIRST EPSS / CISA KEV 실시간 조회 캐시 |
| `output/priority_*.json` | 시나리오별(레거시 묶음/강화 묶음) 우선순위 전체 목록(791건) |
| `output/remediation_*.json` | 시나리오별 상위 3건 조치안 (근거·모델명·토큰 사용량 포함) |
| `output/report.html` | 최종 리포트 1장 |
| `output/screenshots/report_top.jpg` | 리포트 스크린샷 |

모든 JSON은 실제 API/도구 호출 결과를 그대로 저장한 것이며 수치를 임의로 만들지 않았다.

## 4. 핵심 결과 요약

- SBOM: Tomcat 9.0.30 공식 이미지에서 1,617개 컴포넌트 탐지.
- grype 기본 설정으로는 **CVE-2020-1938(Ghostcat)이 탐지되지 않는다** — Java 패키지는
  기본적으로 CPE 매칭을 쓰지 않기 때문(오탐 방지용 설계가 여기선 미탐을 유발).
  `GRYPE_MATCH_JAVA_USING_CPES=true`로 재스캔해야 탐지되며, 그 대가로 전체 매치 수가
  704개 → 791개로 늘어난다 (오탐 가능성 증가와 트레이드오프).
- CVE 3건(전체 791건 중 순위) — 시나리오 A: 레거시/방치된 설정 묶음, 시나리오 B: 보안 강화 설정 묶음.
  CVSS·EPSS·KEV는 두 시나리오에서 완전히 동일하고, 오직 설정 판정만으로 순위/Tier가 갈린다.

  | CVE | 판정 근거 | A(레거시) | B(강화) |
  |---|---|---|---|
  | CVE-2020-1938 (Ghostcat, KEV) | server.xml AJP secretRequired | 2위 / **Critical** (98.78) | 475위 / Medium (29.63) |
  | CVE-2025-24813 (Path Equivalence, KEV) | web.xml DefaultServlet readonly | 1위 / **Critical** (99.98) | 453위 / Medium (29.99) |
  | CVE-2020-9484 (세션 파일 역직렬화, KEV 미등재) | context.xml PersistentManager+FileStore | 43위 / **High** (51.66) | 680위 / Medium (15.5) |

- CVE-2020-9484만 KEV 미등재인데도(CISA SSVC `exploitation=none`) 시나리오 A에서 43위까지
  오르는 이유는 CVSS 7.0에 더해 공격 조건(PersistentManager+FileStore+필터 미설정)이 설정
  판정에서 모두 충족되기 때문 — KEV 여부와 "설정상 도달 가능 여부"는 서로 다른 축임을 보여준다.
- **LLM 실호출 검증 완료**: `OPENAI_API_KEY` 설정 후 `python run.py` 재실행 결과, 모델
  `gpt-4o-mini-2024-07-18`로 두 시나리오 합쳐 6건 호출(각 시나리오 상위 3건), 총 4,351
  토큰 소비(prompt 2,728 + completion 1,623). 리포트의 "LLM 생성" 배지에 모델명·토큰 수를
  그대로 노출한다.

## 5. 한계 (솔직하게)

- **실제 LLM 호출에서 사실 오류(환각)를 발견했다.** CVE-2025-24813의 올바른 수정 버전은
  9.0.99(NVD 기준)인데, 생성된 조치안은 "Tomcat을 9.0.31 이상으로 업그레이드"라고 — 다른
  CVE(Ghostcat, CVE-2020-1938)의 수정 버전과 혼동한 것으로 보이는 — 틀린 번호를 제시했다.
  CVE-2023-44487(HTTP/2 Rapid Reset, AJP와 무관)의 조치안에도 "AJP 커넥터 비활성화"라는
  관련 없는 대안이 섞여 나왔다. 둘 다 프롬프트에 정확한 패치 버전을 근거로 넣지 않은 채
  모델에 맡겨서 생긴 문제이며, 사람이 검토 없이 그대로 반영하면 안 된다는 것을 실제 호출로
  확인했다 — 이 PoC가 "LLM 출력은 사람 승인 전제"를 설계 원칙으로 못박은 이유를 뒷받침하는
  실증 사례로 README/03_PoC.md에 정직하게 남긴다. (후속 개선: NVD에서 조회한 정확한 수정
  버전을 prioritize.py 단계에서 미리 근거로 넣어 프롬프트에 포함시키면 줄일 수 있다.)
- **CVE별 도달성 룰은 3개 구현**했다(Ghostcat/server.xml, Path Equivalence/web.xml, 세션 파일
  역직렬화/context.xml). `reachability.py`의 `RULES` 딕셔너리에 CVE ID → 판정 함수를 추가하는
  방식으로 계속 확장 가능한 구조다.
- **CVE-2020-9484 룰은 설정이 "공격을 가능하게 열어두고 있는가"까지만 판정한다.** 실제 NVD
  설명상 RCE 성립에는 "공격자가 세션 저장 파일의 이름/내용/경로를 제어할 수 있어야 한다"는
  추가 전제가 있는데, 이 부분은 설정 파일만으로는 판정할 수 없어 범위에서 제외했다(보수적으로
  "설정상 가능"까지만 표시).
- **CVE-2025-24813의 RCE 변종(세션 역직렬화와 결합)은 web.xml/context.xml 판정을 교차
  연계하지 않는다.** reason 텍스트에서 "CVE-2020-9484 판정 참고"로만 언급하고, 두 CVE를 AND
  조건으로 묶는 복합 룰은 구현하지 않았다(스코프 확장 방지).
- **실제 컨테이너를 기동해서 동적으로 공격을 재현하지는 않았다.** server.xml/web.xml/context.xml을
  정적으로 파싱해 판정할 뿐, 실제 네트워크 트래픽으로 익스플로잇을 쏴보지는 않았다
  (이 PoC의 범위를 "설정 기반 정적 판정"으로 한정).
- SBOM/grype가 스캔하는 베이스 이미지 취약점과, 세 설정 파일은 **서로 다른 관심사**다
  (이미지 자체의 라이브러리 CVE vs 애플리케이션 레벨 설정) — 실제로는 두 설정의 Tomcat
  컨테이너를 각각 빌드해서 스캔해야 완전히 맞아떨어지지만, 베이스 이미지 레이어는 두
  시나리오가 동일하므로 PoC에서는 SBOM/grype 스캔 1회 + 설정 판정 2회로 단순화했다.
- `config/ajp-vulnerable/`와 `config/ajp-mitigated/`는 각각 "최악의 레거시 설정 묶음"과
  "보안 강화 설정 묶음"을 임의로 번들링한 것이다. 실제 운영에서는 세 설정이 서로 독립적으로
  섞여 있을 수 있어(예: AJP는 막았지만 DefaultServlet은 열려있는 경우), 두 극단 시나리오만
  보여주는 이 PoC보다 더 세밀한 조합 분석이 필요할 수 있다.
- 우선순위 스코어링 공식(가중합 + 0.3배 감점)은 설명 가능성을 위해 의도적으로 단순하게
  설계했다. 자산 중요도·외부 노출도 등 브리프 §4의 다른 요소는 이번 PoC 범위에서 제외했다.
- grype 벌크 매치 결과에서 "같은 CVE가 여러 jar에 중복 매칭"되는 문제는 CVE ID 단위로
  묶어 1건으로 집계했지만, 패치 버전 권고 자체는 자동 검증하지 않았다(벤더 공지 링크만 노출).
- 운영 반영 자동화는 하지 않는다(브리프 제약). 조치안은 제안 단계까지만 생성한다.

## 6. 보안/운영 원칙

- 모든 조치안은 사람의 검토·승인을 전제로 한 **제안**이며, 이 파이프라인은 어떤 설정도
  자동으로 변경하지 않는다.
- API 키는 `.env`(gitignore 대상)로만 관리하며 저장소에 커밋하지 않는다.
- `poc/bin/*.exe`(syft, grype 바이너리)는 용량 문제로 저장소에 포함하지 않고
  `install_tools.ps1`로 받는다.
