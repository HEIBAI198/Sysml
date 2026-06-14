# ç¥è¯å¾è°±é©±å¨ççå®æ»å»è·¯å¾ç å¤æ¥å

çææ¶é´ï¼2026-06-14 02:46:49 UTC

## é£é©æè¦

- ç»¼åé£é©è¯åï¼100 / 100
- é£é©ç­çº§ï¼critical
- æå¼é£é©ï¼14 é¡¹ï¼å¶ä¸­ä¸¥éé£é© 7 é¡¹
- å¾è°±èç¹ï¼199 ä¸ª
- å¾è°±å³ç³»ï¼174 æ¡
- ç»ä¸èµäº§ï¼143 ä¸ª
- è¯æ®çæ®µï¼145 æ¡
- è¿è¡ææ¥å¿äºä»¶ï¼5 æ¡
- å·²è¯å«æ»å»è·¯å¾ï¼3 æ¡
- å¯è¡å¨æ»å»è·¯å¾ï¼3 æ¡
- é«åº¦å¯ä¿¡çå®è·¯å¾ï¼1 æ¡
- å¹³åè·¯å¾ç½®ä¿¡åº¦ï¼68%
- è·¯å¾å¤å®åå¸ï¼likely-real-attack-path=1, provenance-risk-path=2
- åèæ¨¡åï¼GUAC è½¯ä»¶æ /è¯æ®æ å¯è¾¾æ§ãOpenCTI observable å³ç³»ä¸ç½®ä¿¡åº¦ãNetworkX è·¯å¾è¯åãin-toto/SLSA å¯ä¿¡è¯æ®é¾ãBloodHound å¼å¥å£å°ç®æ è·¯å¾åç°

## è·¯å¾å¤å®

æ¬æ¥åä¸ååªåâåç°äºåªäºæ¼æ´âï¼èæ¯å¤æ­è¿äºè¯æ®è½å¦ä¸²æä¸æ¬¡çå®æ»å»è·¯å¾ã

## æ»å»è·¯å¾

### 1. è¯æ®å¯ä¸²æä¾åºé¾ææ¯å°è¿è¡æå¼å¸¸çæ»å»è·¯å¾

ä¸å¥è¯ç»è®ºï¼è½ä¸²æä¸æ¬¡é«åº¦å¯ä¿¡ççå®æ»å»è·¯å¾ï¼å¥å£ãæå»ºãäº§ç©ãè¿è¡æè¡ä¸ºè¿ç»­å¯è¾¾ï¼ç»¼åç½®ä¿¡åº¦ 85%ã

```mermaid
flowchart LR
  N1["CodeFile: cases/3cx-supply-chain/sample-repo/.github/workflows/desktop-release.y"]
  N2["DependencyPackage: npm:axios@1.6.8"]
  N3["CIStep: è¿è¡æè¯æ®å³è"]
  N4["BuildArtifact: 3cx-desktop-app.tar.gz"]
  N5["RuntimeService: 3CX X_TRADER replay runtime"]
  N6["LogEvent: 45.83.64.12"]
  N7["AttackStage: ä¾åºé¾ææ¯é¶æ®µ"]
  N1 -->|å£°æä¾èµå¥å£| N2
  N2 -->|å¯è¿å¥æå»º| N3
  N3 -->|çæäº§ç©| N4
  N4 -->|deployed as| N5
  N5 -->|äº§çæ¥å¿| N6
  N6 -->|å³è| N7
```

- è·¯å¾å¤å®ï¼likely-real-attack-path
- ç»¼åç½®ä¿¡åº¦ï¼85%
- ä¸¥éçº§å«ï¼critical
- è·¯å¾è¯åï¼100 / 100
- å½±åèµäº§ï¼cases/3cx-supply-chain/sample-repo/.github/workflows/desktop-release.yml -> npm:axios@1.6.8 -> è¿è¡æè¯æ®å³è -> 3cx-desktop-app.tar.gz -> 3CX X_TRADER replay runtime -> 45.83.64.12
- ä¿®å¤ä¼åçº§ï¼P0
- æ»å»æ å°ï¼T1195
- åèæ¨¡åï¼GUAC, SLSA, in-toto, BloodHound CE, MITRE ATT&CK STIX

è·¯å¾æ­¥éª¤ï¼
- cases/3cx-supply-chain/sample-repo/.github/workflows/desktop-release.yml --å£°æä¾èµå¥å£--> npm:axios@1.6.8ï¼GUACï¼ç½®ä¿¡åº¦ 62%ï¼ï¼If the package is malicious or vulnerable, it can be selected during dependency resolution.
- npm:axios@1.6.8 --å¯è¿å¥æå»º--> è¿è¡æè¯æ®å³èï¼GUACï¼ç½®ä¿¡åº¦ 72%ï¼ï¼A poisoned dependency can run install-time behavior or influence generated artifacts.
- è¿è¡æè¯æ®å³è --çæäº§ç©--> 3cx-desktop-app.tar.gzï¼SLSA/in-totoï¼ç½®ä¿¡åº¦ 78%ï¼ï¼A compromised step or builder can produce a modified artifact.
- 3cx-desktop-app.tar.gz --deployed as--> 3CX X_TRADER replay runtimeï¼Runtime deploymentï¼ç½®ä¿¡åº¦ 82%ï¼ï¼Workspace runtime metadata links the verified artifact to the deployed service.
- 3CX X_TRADER replay runtime --äº§çæ¥å¿--> 45.83.64.12ï¼Runtime evidenceï¼ç½®ä¿¡åº¦ 84%ï¼ï¼Runtime logs show whether the build-time risk manifested after deployment.
- 45.83.64.12 --å³è--> ä¾åºé¾ææ¯é¶æ®µï¼evidenceï¼ç½®ä¿¡åº¦ 50%ï¼ï¼NormalizedLogEvent

å¯ä¿¡è¯æ®é¾ï¼
- GUACï¼è½¯ä»¶æ ä¸­å­å¨å¯è¾¾ä¾èµèç¹ï¼ä¸»ä½=npm:axios@1.6.8ï¼ç¶æ=observed
- in-totoï¼æå»ºæ­¥éª¤å° material è½¬æ¢ä¸º productï¼ä¸»ä½=è¿è¡æè¯æ®å³èï¼ç¶æ=needs-attestation
- SLSAï¼äº§ç©éè¦ subject digestãbuilder identity å materials provenanceï¼ä¸»ä½=3cx-desktop-app.tar.gzï¼ç¶æ=gap
- Runtime evidenceï¼è¿è¡æè¡ä¸ºè¯æé£é©å¯è½å·²ç»è§¦åï¼ä¸»ä½=45.83.64.12ï¼ç¶æ=observed

è¯æ®ç¼ºå£ï¼
- å½åè·¯å¾æªåç°ææ¾è¯æ®ç¼ºå£ã

å³é®å°å µç¹ï¼
- npm:axios@1.6.8ï¼åºå®ç§ææºãéå®çæ¬å¹¶æ¸çç¼å­åã
- è¿è¡æè¯æ®å³èï¼æ¶ææéãåºå® Action å° commit SHAï¼å¹¶ä½¿ç¨å¹²å runnerã
- 3cx-desktop-app.tar.gzï¼éæ°æå»ºå¹¶æ ¡éªäº§ç©åå¸/provenanceã
- 3CX X_TRADER replay runtimeï¼åæ»æéç¦»æå¡å®ä¾ï¼ä¿çæ¥å¿åéåè¯æ®ã
- 45.83.64.12ï¼å°ç¦ç¸å³æ¥æº/ç®çå°åå¹¶æ©å¤§åæ¶é´çªææ¥ã

è¯æ®æè¦ï¼
- Artifact provenance attestationï¼3cx-desktop-app.tar.gz sha256:ac8df1c289da9af5f94278b8e55af440077b05e905d4c61a277bad12f7294183; repo=https://github.c...
- artifact_digest_matches_subjectï¼fail: artifact sha256:ac8df1c289da9af5f94278b8e55af440077b05e905d4c61a277bad12f7294183 != attestation subject sha256:...
- artifact_hash_baselineï¼skipped: No historical hash baseline configured.
- attestation_max_ageï¼pass: attestation age is 64.78 hours
- builder_trustedï¼pass: https://github.com/actions/runner/self-hosted

### 2. è¯æ®å¯ä¸²ææå»ºé¾è·¯å®æ´æ§åæè·¯å¾

ä¸å¥è¯ç»è®ºï¼è½ä¸²ææå»ºå®æ´æ§é£é©è·¯å¾ï¼ä½è¿éè¦ provenance/attestation æè½è¯æäº§ç©ç¡®è¢«ç¯¡æ¹ï¼ç»¼åç½®ä¿¡åº¦ 68%ã

```mermaid
flowchart LR
  N1["CIStep: .github/workflows/desktop-release.yml"]
  N2["BuildArtifact: 3cx-desktop-app.tar.gz"]
  N3["RuntimeService: 3CX X_TRADER replay runtime"]
  N4["AttackStage: æå»ºé¾è·¯é£é©é¶æ®µ"]
  N1 -->|deployed as| N2
  N2 -->|deployed as| N3
  N3 -->|å³è| N4
```

- è·¯å¾å¤å®ï¼provenance-risk-path
- ç»¼åç½®ä¿¡åº¦ï¼68%
- ä¸¥éçº§å«ï¼high
- è·¯å¾è¯åï¼95 / 100
- å½±åèµäº§ï¼.github/workflows/desktop-release.yml -> 3cx-desktop-app.tar.gz -> 3CX X_TRADER replay runtime
- ä¿®å¤ä¼åçº§ï¼P1
- æ»å»æ å°ï¼Build provenance and integrity
- åèæ¨¡åï¼SLSA, in-toto, GUAC, BloodHound CE

è·¯å¾æ­¥éª¤ï¼
- .github/workflows/desktop-release.yml --å³è--> 3cx-desktop-app.tar.gzï¼evidenceï¼ç½®ä¿¡åº¦ 50%ï¼ï¼WorkspaceSummary
- 3cx-desktop-app.tar.gz --deployed as--> 3CX X_TRADER replay runtimeï¼Runtime deploymentï¼ç½®ä¿¡åº¦ 82%ï¼ï¼Workspace runtime metadata links the verified artifact to the deployed service.
- 3CX X_TRADER replay runtime --å³è--> æå»ºé¾è·¯é£é©é¶æ®µï¼evidenceï¼ç½®ä¿¡åº¦ 50%ï¼ï¼Runtime

å¯ä¿¡è¯æ®é¾ï¼
- in-totoï¼æå»ºæ­¥éª¤å° material è½¬æ¢ä¸º productï¼ä¸»ä½=.github/workflows/desktop-release.ymlï¼ç¶æ=needs-attestation
- SLSAï¼äº§ç©éè¦ subject digestãbuilder identity å materials provenanceï¼ä¸»ä½=3cx-desktop-app.tar.gzï¼ç¶æ=gap

è¯æ®ç¼ºå£ï¼
- è·¯å¾å³ç³»å¯è¾¾ï¼ä½é¨åè¾¹æ¯å¯åå¼å³èï¼å»ºè®®è¡¥åæ¶é´çº¿ãäº§ç©åå¸ææ¥æº IP è¯æ®ã

å³é®å°å µç¹ï¼
- .github/workflows/desktop-release.ymlï¼æ¶ææéãåºå® Action å° commit SHAï¼å¹¶ä½¿ç¨å¹²å runnerã
- 3cx-desktop-app.tar.gzï¼éæ°æå»ºå¹¶æ ¡éªäº§ç©åå¸/provenanceã
- 3CX X_TRADER replay runtimeï¼åæ»æéç¦»æå¡å®ä¾ï¼ä¿çæ¥å¿åéåè¯æ®ã

è¯æ®æè¦ï¼
- Artifact provenance attestationï¼3cx-desktop-app.tar.gz sha256:ac8df1c289da9af5f94278b8e55af440077b05e905d4c61a277bad12f7294183; repo=https://github.c...
- artifact_digest_matches_subjectï¼fail: artifact sha256:ac8df1c289da9af5f94278b8e55af440077b05e905d4c61a277bad12f7294183 != attestation subject sha256:...
- artifact_hash_baselineï¼skipped: No historical hash baseline configured.
- attestation_max_ageï¼pass: attestation age is 64.78 hours
- builder_trustedï¼pass: https://github.com/actions/runner/self-hosted

### 3. äº§ç©å¯ä¿¡é¾è·¯éªè¯è·¯å¾

ä¸å¥è¯ç»è®ºï¼äº§ç© 3cx-desktop-app.tar.gz çå¯ä¿¡é¾å­å¨é»æ­é¡¹ï¼éè¦å¤æ ¸ commit 2222222222222222222222222222222222222222 -> workflow -> https://github.com/actions/runner/self-hosted -> artifact -> attestation ç digestãç­¾ååç­ç¥å¹éç»æã

```mermaid
flowchart LR
  N1["SourceCommit: commit 2222222222222222222222222222222222222222"]
  N2["TrustedBuilder: https://github.com/actions/runner/self-hosted"]
  N3["BuildArtifact: 3cx-desktop-app.tar.gz"]
  N4["Attestation: 3cx-desktop-app.tar.gz"]
  N5["Finding: äº§ç© digest ä¸ attestation subject ä¸ä¸è´æç¼ºå¤±"]
  N6["AttackStage: æå»ºé¾è·¯é£é©é¶æ®µ"]
  N1 -->|produces artifact| N2
  N2 -->|produces artifact| N3
  N3 -->|attested by| N4
  N4 -->|blocks proof| N5
  N5 -->|å³è| N6
```

- è·¯å¾å¤å®ï¼provenance-risk-path
- ç»¼åç½®ä¿¡åº¦ï¼50%
- ä¸¥éçº§å«ï¼critical
- è·¯å¾è¯åï¼16 / 100
- å½±åèµäº§ï¼commit 2222222222222222222222222222222222222222 -> https://github.com/actions/runner/self-hosted -> 3cx-desktop-app.tar.gz -> 3cx-desktop-app.tar.gz
- ä¿®å¤ä¼åçº§ï¼P0
- æ»å»æ å°ï¼Verify artifact provenance
- åèæ¨¡åï¼SLSA, in-toto, Sigstore Cosign, GitHub Artifact Attestations, GUAC

è·¯å¾æ­¥éª¤ï¼
- commit 2222222222222222222222222222222222222222 --å³è--> https://github.com/actions/runner/self-hostedï¼evidenceï¼ç½®ä¿¡åº¦ 50%ï¼ï¼SLSA/in-toto
- https://github.com/actions/runner/self-hosted --produces artifact--> 3cx-desktop-app.tar.gzï¼SLSA provenanceï¼ç½®ä¿¡åº¦ 88%ï¼ï¼Trusted builder identity is the execution root that produced the artifact subject digest.
- 3cx-desktop-app.tar.gz --attested by--> 3cx-desktop-app.tar.gzï¼SLSA/in-totoï¼ç½®ä¿¡åº¦ 92%ï¼ï¼Artifact trust scan parsed a provenance attestation for this artifact digest.
- 3cx-desktop-app.tar.gz --blocks proof--> äº§ç© digest ä¸ attestation subject ä¸ä¸è´æç¼ºå¤±ï¼SLSA/in-toto policyï¼ç½®ä¿¡åº¦ 90%ï¼ï¼Artifact trust finding blocks or weakens the provenance proof chain.
- äº§ç© digest ä¸ attestation subject ä¸ä¸è´æç¼ºå¤± --å³è--> æå»ºé¾è·¯é£é©é¶æ®µï¼evidenceï¼ç½®ä¿¡åº¦ 50%ï¼ï¼SLSA/in-toto

å¯ä¿¡è¯æ®é¾ï¼
- SLSA materialsï¼source repository and commit/ref are claimed by provenanceï¼ä¸»ä½=commit 2222222222222222222222222222222222222222ï¼ç¶æ=observed
- -ï¼-ï¼ä¸»ä½=-ï¼ç¶æ=-
- SLSAï¼äº§ç©éè¦ subject digestãbuilder identity å materials provenanceï¼ä¸»ä½=3cx-desktop-app.tar.gzï¼ç¶æ=gap
- -ï¼-ï¼ä¸»ä½=-ï¼ç¶æ=-

è¯æ®ç¼ºå£ï¼
- å½åè·¯å¾æªåç°ææ¾è¯æ®ç¼ºå£ã

å³é®å°å µç¹ï¼
- 3cx-desktop-app.tar.gzï¼éæ°æå»ºå¹¶æ ¡éªäº§ç©åå¸/provenanceã

è¯æ®æè¦ï¼
- Artifact provenance attestationï¼3cx-desktop-app.tar.gz sha256:ac8df1c289da9af5f94278b8e55af440077b05e905d4c61a277bad12f7294183; repo=https://github.c...
- artifact_digest_matches_subjectï¼fail: artifact sha256:ac8df1c289da9af5f94278b8e55af440077b05e905d4c61a277bad12f7294183 != attestation subject sha256:...
- artifact_hash_baselineï¼skipped: No historical hash baseline configured.
- attestation_max_ageï¼pass: attestation age is 64.78 hours
- builder_trustedï¼pass: https://github.com/actions/runner/self-hosted

## å³èé«å±é®é¢

| ç¼å· | ç­çº§ | è¯å | é£é© | å½±åèµäº§ | æ¥æº |
| --- | --- | ---: | --- | --- | --- |
| finding-node:be9ba659727b873c | critical | 100 | axios has exploitable VEX context | axios@1.6.8 | CycloneDX |
| finding-node:81203073eb49d600 | critical | 100 | electron vulnerability needs reachability triage | electron@25.9.8 | CycloneDX |
| finding-node:fa0fd47ce39644e3 | critical | 100 | starlette has exploitable VEX context | starlette@1.0.0 | CycloneDX |
| finding-node:a68bf17582361bda | critical | 98 | äº§ç© digest ä¸ attestation subject ä¸ä¸è´æç¼ºå¤± | artifact_trust | SLSA/in-toto |
| finding-node:e33b2b17a3bb2123 | critical | 97 | ä¾èµä¸ CI/CD é£é©ååºç°è¿è¡æå¤è/æææ¥å£è®¿é® | è¯æ®é¾ | WorkspaceSummary |
| finding-node:aa024acacf3abc25 | critical | 93 | äº§ç©æ¥æº commit ä¸ç¬¦åé¢æ | artifact_trust | SLSA/in-toto |
| finding-node:8455069e2b45547b | critical | 92 | Suspicious External Egress IP | log_audit | NormalizedLogEvent |
| finding-node:04b3f26bba4e141f | critical | 92 | å¼å¸¸å¤è IP | workspace | NormalizedLogEvent |
| finding-node:57a6208d49fbbb26 | high | 88 | GitHub Token æéè¿å®½ | .github/workflows/desktop-release.yml | SARIF |
| finding-node:d170778c8d4d3ea2 | high | 87 | runner ç¯å¢ä¸ç¬¦åç­ç¥ | artifact_trust | SLSA/in-toto |
| finding-node:cdbb2c3dac29a0f7 | high | 84 | Suspicious External Egress IP | log_audit | NormalizedLogEvent |
| finding-node:8cea470b195991a9 | high | 82 | å¼å¸¸å¤è IP | workspace | NormalizedLogEvent |

## è¯æ®é¾

| åºå· | æ¶é´ | è¯æ®ç±»å | å³èèµäº§ | è¯æ®æè¦ | æ¥æºæ¨¡å |
| ---: | --- | --- | --- | --- | --- |
| 1 | 2026-06-14 02:46 | artifact-provenance | 3cx-desktop-app.tar.gz | 3cx-desktop-app.tar.gz sha256:ac8df1c289da9af5f94278b8e55af440077b05e905d4c61a277bad12f7294183; repo=https://github.com/3cx/desktop-app; commit=222222222222222222222222222222222... | SLSA/in-toto |
| 2 | 2026-06-14 02:46 | artifact-trust-check | 3cx-desktop-app.tar.gz | fail: artifact sha256:ac8df1c289da9af5f94278b8e55af440077b05e905d4c61a277bad12f7294183 != attestation subject sha256:000000000000000000000000000000000000000000000000000000000000... | SLSA/in-toto |
| 3 | 2026-06-14 02:46 | artifact-trust-check | 3cx-desktop-app.tar.gz | skipped: No historical hash baseline configured. | SLSA/in-toto |
| 4 | 2026-06-14 02:46 | artifact-trust-check | 3cx-desktop-app.tar.gz | pass: attestation age is 64.78 hours | SLSA/in-toto |
| 5 | 2026-06-14 02:46 | artifact-trust-check | 3cx-desktop-app.tar.gz | pass: https://github.com/actions/runner/self-hosted | SLSA/in-toto |
| 6 | 2026-06-14 02:46 | artifact-trust-check | 3cx-desktop-app.tar.gz | fail: provenance commit 2222222222222222222222222222222222222222 does not match expected 8f42c19 | SLSA/in-toto |
| 7 | 2026-06-14 02:46 | artifact-trust-check | 3cx-desktop-app.tar.gz | pass: https://slsa.dev/provenance/v1 | SLSA/in-toto |
| 8 | 2026-06-14 02:46 | artifact-trust-check | 3cx-desktop-app.tar.gz | fail: self-hosted runner is not allowed by policy: self-hosted | SLSA/in-toto |
| 9 | 2026-06-14 02:46 | artifact-trust-check | 3cx-desktop-app.tar.gz | warn: Error: HTTP 404: Not Found (https://api.github.com/repos/3cx/desktop-app/attestations/sha256:ac8df1c289da9af5f94278b8e55af440077b05e905d4c61a277bad12f7294183?per_page=30&p... | SLSA/in-toto |
| 10 | 2026-06-14 02:46 | artifact-trust-check | 3cx-desktop-app.tar.gz | pass: https://github.com/3cx/desktop-app | SLSA/in-toto |
| 11 | 2026-06-14 02:46 | artifact-trust-check | 3cx-desktop-app.tar.gz | pass: .github/workflows/desktop-release.yml | SLSA/in-toto |
| 12 | 2026-06-14 02:46 | artifact-trust-finding | 3cx-desktop-app.tar.gz | self-hosted runner is not allowed by policy: self-hosted | SLSA/in-toto |
| 13 | 2026-06-14 02:46 | artifact-trust-finding | 3cx-desktop-app.tar.gz | artifact sha256:ac8df1c289da9af5f94278b8e55af440077b05e905d4c61a277bad12f7294183 != attestation subject sha256:0000000000000000000000000000000000000000000000000000000000000000 | SLSA/in-toto |
| 14 | 2026-06-14 02:46 | artifact-trust-finding | 3cx-desktop-app.tar.gz | provenance commit 2222222222222222222222222222222222222222 does not match expected 8f42c19 | SLSA/in-toto |
| 15 | 2026-06-14 02:46 | artifact-trust-finding | 3cx-desktop-app.tar.gz | Error: HTTP 404: Not Found (https://api.github.com/repos/3cx/desktop-app/attestations/sha256:ac8df1c289da9af5f94278b8e55af440077b05e905d4c61a277bad12f7294183?per_page=30&predica... | SLSA/in-toto |
| 16 | 2026-06-14 02:45 | static-analysis-result | cases/3cx-supply-chain/sample-repo/.github/workflows/desktop-release.yml | permissions: write-all | SARIF |
| 17 | 2026-06-14 02:46 | sbom-component-risk | npm:axios@1.6.8 | OSV: GHSA-35jp-ww65-95wh; OSV: GHSA-3g43-6gmg-66jw; OSV: GHSA-3p68-rc4w-qgx5; OSV: GHSA-3w6x-2g7m-8v23; OSV: GHSA-43fc-jf86-j433; OSV: GHSA-445q-vr5w-6q77; OSV: GHSA-4hjh-wcwx-x... | CycloneDX |
| 18 | 2026-06-11 11:30:02 | runtime-log-finding | 45.83.64.12 | {"time":"2026-06-11T11:30:02Z","source":"app","host":"customer-pc-01","process":"3cx-desktop-app","event":"...pp beacon egress destination 45.83.64.12 for cdn-update.example.inv... | NormalizedLogEvent |

## å¤æ¨¡æè¯æ®èå

ææ å¤æ¨¡æè¯æ®ã

## ä¿®å¤å»ºè®®

- **P0 Â· è¯æ®å¯ä¸²æä¾åºé¾ææ¯å°è¿è¡æå¼å¸¸çæ»å»è·¯å¾**ï¼éç¦»é«å±ä¾èµï¼ä½¿ç¨å¹²å runner éæ°æå»ºï¼æ ¡éªäº§ç©åå¸ï¼å¹¶ææ¥è¿è¡æå¤èã
- **P1 Â· è¯æ®å¯ä¸²ææå»ºé¾è·¯å®æ´æ§åæè·¯å¾**ï¼æ¶æ workflow æéï¼ç¬¬ä¸æ¹ Action åºå®å° commit SHAï¼å¹¶ä¸ºäº§ç©å¢å  provenance/attestationã
- **P0 Â· äº§ç©å¯ä¿¡é¾è·¯éªè¯è·¯å¾**ï¼å°è¯¥äº§ç©å¯ä¿¡éªè¯ç»æä½ä¸ºåå¸é¨ç¦ï¼digestãç­¾åãbuilderãworkflow ææ¥æºä»»ä¸å¤±è´¥æ¶é»æ­åå¸ã

## éå½

### SBOM / Dependency-Track é£é©æè¦

- SBOM ç»ä»¶æ°éï¼59
- ä¾èµé£é©æ°éï¼3
- æé«ä¾èµé£é©ï¼100 / 100
- VEX statementï¼58
- VEX affected / under investigationï¼9
- VEX not affected / fixedï¼49
- ä»£ç å¯è¾¾ä¾èµï¼2
- è¿è¡ææ¥å¿å½ä¸­ï¼6

### SARIF / DefectDojo é£é©æè¦

- SARIF ç»ææ°éï¼4
- ä»£ç é£é©æ°éï¼1
- CI/CD é£é©æ°éï¼3

### äº§ç©å¯ä¿¡éªè¯æè¦

- äº§ç©ï¼3cx-desktop-app.tar.gz
- SHA256ï¼sha256:ac8df1c289da9af5f94278b8e55af440077b05e905d4c61a277bad12f7294183
- å¯ä¿¡è¯åï¼16 / 100
- æ£æ¥é¡¹æ°éï¼10
- äº§ç©å¯ä¿¡é£é©ï¼4

### æ¥å¿è¯æ®æè¦

- æ¥å¿é£é©æ°éï¼2
- å¾è°±è¯æ®æ°éï¼145

### å¼æºåè

- GUAC: https://docs.guac.sh/guac/
- GUAC Ontology: https://docs.guac.sh/guac/guac-ontology/
- MITRE ATT&CK STIX Data: https://github.com/mitre-attack/attack-stix-data
- SLSA: https://slsa.dev/spec/v1.2/provenance
- in-toto: https://github.com/in-toto/in-toto
- BloodHound CE: https://specterops.io/bloodhound-community-edition/
- NetworkX: https://networkx.org/
- React Flow: https://reactflow.dev/
- CycloneDX: https://cyclonedx.org/specification/overview/
- SARIF: https://www.oasis-open.org/standard/sarif-v2-1-0/
- OWASP Dependency-Track: https://dependencytrack.org/
- DefectDojo: https://docs.defectdojo.com/
- FFmpeg: https://www.ffmpeg.org/index.html
- OpenCV: https://opencv.org/about/

