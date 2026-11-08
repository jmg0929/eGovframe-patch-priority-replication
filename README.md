# eGovFrame 패치 우선순위 판단 연구 재현 자료

이 저장소는 **산업보안학과 제1회 학술제 제출 논문** **「공공 안전 영향과 미확인 정보를 반영한 eGovFrame 공급자의 패치 우선순위 판단 기준」**의 계산과 검증 자료를 제공한다. 공개 취약점 권고 47건에 SSVC 공급자 결정표를 적용해 공공 안전 영향이 대응 수준을 바꾸는 조건을 확인하고, 대표 CVE 3건과 가상 기관을 이용해 근거 요청 방식별 확인 항목 수와 회신 라운드를 비교한다.

## 빠른 실행

Python 3.10 이상이 필요하다. Windows의 Python 3.13.15에서 전체 실행을 검증했다. 기본 실행은 Python 표준 라이브러리와 동봉한 원자료만 사용하므로 추가 패키지 설치나 인터넷 연결이 필요 없다. ZIP을 풀거나 저장소를 내려받은 뒤 `reproduce.py`가 있는 폴더에서 실행한다.

```bash
python -X utf8 -B reproduce.py
```

실행하면 입력 체크섬 확인, 분석, 원고 수치 대조, 결과 체크섬 확인 순으로 진행한다. CSV와 JSON 결과 18개가 저장소 루트에 다시 생성된다. 성공하면 마지막에 `Verified 18 entries from RESULT_SHA256SUMS.txt.`가 표시된다.

## 파일 구조

```text
.
├── README.md                        실행 안내와 파일 목록
├── reproduce.py                     전체 실행과 체크섬 검증
├── sources/                         고정 원자료와 출처 기록
│   ├── ghsa/                        GitHub 보안 권고 145건
│   ├── cve/                         CVE 공개 레코드 145건
│   ├── runtime_431_poms/             eGovFrame 4.3.1 실행환경 POM 31개
│   ├── case_poms/                    대표 사례의 공식 Maven POM 3개
│   └── …                            SSVC 결정표, 공지 목록, 수집 기록
├── public_ssvc_evidence.json         대표 CVE 3건의 평가 입력과 근거
├── backport.py, bridge.py            권고 선정, SSVC 결정표 적용
├── egovframe_priority_*.py          가상 기관의 요청 방식 비교
├── *_checks.py                      보조 분석과 본문 수치 점검
├── analysis_helpers.py              공통 버전 비교·파일 처리 함수
├── audit_ghsa_snapshot.py           전체 GHSA에서 동봉 자료의 추출 검증
├── 결과 CSV·JSON 18개               아래 결과 파일 표 참조
├── INPUT_SHA256SUMS.txt              입력과 코드의 체크섬
├── RESULT_SHA256SUMS.txt             생성 결과의 체크섬
├── THIRD_PARTY_NOTICES.md            외부 자료의 출처와 이용 조건
├── third_party/                     원출처의 이용 조건과 라이선스 사본
├── .gitattributes                    Git 체크아웃 시 원본 바이트 보존
└── .gitignore                        Python 캐시 등 임시 파일 제외
```

### 고정 입력과 출처

| 경로 | 내용과 사용처 |
| --- | --- |
| [`sources/ghsa/`](sources/ghsa/) | 대상 Maven 패키지와 일치한 검토 완료 권고. 영향 버전·공개일·철회 여부를 검사해 47건을 선정한다. |
| [`sources/cve/`](sources/cve/) | 고정 CVE List V5 레코드. CISA-ADP의 SSVC 기술 입력과 평가 시점을 읽는다. |
| [`sources/runtime_431_poms/`](sources/runtime_431_poms/) | eGovFrame 4.3.1 실행환경의 Maven 프로젝트 설정. 직접 선언 모듈의 근거다. |
| [`sources/case_poms/`](sources/case_poms/), [`case_pom_sources.json`](sources/case_pom_sources.json) | 대표 CVE 사례에서 확인한 세 버전의 POM과 공식 다운로드 주소·체크섬. |
| [`egov1967_backport_ids.json`](sources/egov1967_backport_ids.json) | 센터 공지 #1967의 4.3.1 항목에 열거된 CVE 15개. 분석 대상 47건과 일치하는 14건을 확인하는 데 사용한다. |
| [`expanded_artifact_scope.json`](sources/expanded_artifact_scope.json) | 선별 전이 범위에 포함한 Maven 모듈의 고정 목록. |
| [`supplier_patch_development_priority_1_0_0.csv`](sources/supplier_patch_development_priority_1_0_0.csv) | CERT/CC SSVC 공급자 결정표 원본. |
| [`snapshot_manifest.json`](sources/snapshot_manifest.json) | 고정 커밋, 수집 시점, 대상 Maven 좌표와 버전, 전체 GHSA 아카이브 주소·해시. |
| [`public_ssvc_evidence.json`](public_ssvc_evidence.json) | 대표 CVE 3건의 기술 입력과 평가 시점, CISA-ADP 기록 또는 연구자 코딩 근거. |

### 실행 파일

| 파일 | 역할 |
| --- | --- |
| [`reproduce.py`](reproduce.py) | 아래 분석을 정해진 순서로 실행하고, 실행 전 입력과 실행 후 결과의 SHA-256을 확인한다. |
| [`egovframe_priority_reproduce.py`](egovframe_priority_reproduce.py) | 두 가상 기관의 응답 조합을 열거하고 54개 기술 입력 프로필에서 확인 항목 수와 회신 라운드를 계산한다. |
| [`egovframe_priority_review.py`](egovframe_priority_review.py) | 가중치와 확인 비용을 바꾼 108개 행에서 요청 전략과 자유 순서·선행 제약 최적 비용을 비교한다. |
| [`backport.py`](backport.py) | 권고 47건을 선정해 공지 #1967과 대조한다. |
| [`bridge.py`](bridge.py) | 선정된 권고에 SSVC 공급자 결정표를 적용한다. 기본값은 집중형이며 `--value-density diffuse`로 분산형을 계산한다. |
| [`integration_checks.py`](integration_checks.py) | 직접 선언·선별 전이 범위의 결과, 백포팅 공지 대조, 회신 비용 가중치 λ의 전환점을 계산한다. |
| [`reviewer_checks.py`](reviewer_checks.py) | 악용 상태·가치 밀도 조합과 질문 단위 묶음에 대한 민감도를 계산한다. |
| [`paper_checks.py`](paper_checks.py) | 대표 CVE의 공개 근거와 POM을 대조하고, 표·그림의 주요 수치를 점검하며 사례 경로와 비용 곡선 좌표를 출력한다. |
| [`analysis_helpers.py`](analysis_helpers.py) | 여러 분석에서 쓰는 Maven 버전 비교와 파일 처리 함수. |
| [`audit_ghsa_snapshot.py`](audit_ghsa_snapshot.py) | 전체 고정 GHSA 아카이브에서 다시 추출한 145건을 동봉한 권고 파일과 대조하는 추가 감사 도구. |

### 결과 파일과 논문에서 볼 위치

| 결과 파일 | 확인할 내용 |
| --- | --- |
| [`backport_population.csv`](backport_population.csv), [`backport_summary.json`](backport_summary.json) | 3~4절. 권고 47건의 행별 목록과 선정 결과, 공지 포함 14건 집계. |
| [`bridge_results.csv`](bridge_results.csv), [`bridge_results_diffuse.csv`](bridge_results_diffuse.csv) | 4절. 집중형·분산형 각각의 권고별 대응 후보의 최저·최고 수준, 후보 수, 안전 영향 민감 여부. |
| [`bridge_evidence.json`](bridge_evidence.json), [`bridge_evidence_diffuse.json`](bridge_evidence_diffuse.json) | 권고별 기술 입력과 원자료 경로, 안전 영향 등급별 대응 후보. |
| [`bridge_summary.json`](bridge_summary.json), [`bridge_summary_diffuse.json`](bridge_summary_diffuse.json) | 집중형·분산형 각각의 기술 입력 확인 건수와 안전 영향 민감 권고 수. |
| [`advisory_audit.csv`](advisory_audit.csv), [`advisory_audit_summary.json`](advisory_audit_summary.json), [`direct_module_evidence.json`](direct_module_evidence.json) | 4절. 전체·직접 선언·선별 전이 범위의 권고별 분류와 집계, 잠정 대응 집계 및 직접 선언 근거. |
| [`exploitation_sensitivity.csv`](exploitation_sensitivity.csv) | 그림 3. 악용 상태와 가치 밀도 조합 6개의 민감 권고 수. 둔감 권고 수는 `n − safety_sensitive`로 계산한다. |
| [`paper_case_trace.csv`](paper_case_trace.csv) | 표 3과 6절의 가상 회신 예시에서 계산한 항목·라운드 5/5, 6/2, 7/1 비교. |
| [`egovframe_priority_results.csv`](egovframe_priority_results.csv), [`egovframe_priority_sensitivity.csv`](egovframe_priority_sensitivity.csv) | 54개 기술 입력 프로필의 기본 계산과 108개 가중치·비용 민감도 행의 비교. |
| [`lambda_results.csv`](lambda_results.csv), [`paper_figure4_points.csv`](paper_figure4_points.csv) | 표 4의 구조별 평균과 그림 4의 전환점·비용 곡선 좌표. |
| [`question_grouping_sensitivity.csv`](question_grouping_sensitivity.csv) | 보조 분석. 두 영향 조건을 하나의 확인 항목으로 묶었을 때 질문 비용이 얼마나 달라지는지 확인한다. |

## 검증 범위와 해석

- `47건 중 14건`은 분석 대상 권고와 센터 공지 목록이 일치한 수다. 권고별 기관의 패치 적용 여부는 이 분석의 관측 대상에서 제외한다.
- `43/47`은 공격 경로가 성립한다고 보고, 공개 평가의 악용 상태와 집중형 가치 밀도를 적용했을 때 공공 안전 영향 입력에 따라 대응 수준이 달라진 수다. 그림 3의 `public poc`·`active`는 악용 상태를 바꿔 본 가상 입력이다.
- 질문 항목 수, 회신 라운드와 전환점은 가상 기관과 명시된 응답 분포의 계산 결과다. 표 1과 그림 1·2는 판단 절차를 설명한다. 그림 3·4는 도표에 사용된 수치를 제공하며, 원고 레이아웃은 실행 범위에서 제외한다.

### 전체 GHSA 스냅샷 추가 감사

기본 실행은 동봉한 권고 145건에서 시작한다. 그 145건의 추출 단계도 확인하려면 [`snapshot_manifest.json`](sources/snapshot_manifest.json)에 기록한 고정 GHSA 아카이브를 내려받아 다음 명령을 실행한다. 파일 경로는 내려받은 위치에 맞춘다.

```bash
python -X utf8 -B audit_ghsa_snapshot.py ghsa_snapshot.tar.gz
```

## 원고 식별과 이용 조건

대응 원고는 산업보안학과 제1회 학술제에 제출하는 6쪽 원고다. PDF SHA-256은 `f536d1bcf54a5c9458add8b01a0fe92fa077e78d637ad628aa816454bd7a9bc5`다. 논문에서 재현 자료를 인용할 때는 해당 GitHub Release 주소와 태그로 버전을 식별한다.

외부 원자료의 출처와 이용 조건은 [제3자 자료 안내](THIRD_PARTY_NOTICES.md)에 있으며, [원문 사본](third_party/)을 함께 제공한다. 연구 코드에 대한 별도 라이선스는 지정하지 않았다.

문서 구성은 실행 방법과 논문 결과의 대응을 명시하는 재현 자료 안내를 참고했다. [ACM SIGSOFT Artifact Evaluation](https://github.com/acmsigsoft/artifact-evaluation) · [World Bank 재현 자료 README 안내](https://worldbank.github.io/wb-reproducible-research-repository/reproducibility_FAQs.html)
