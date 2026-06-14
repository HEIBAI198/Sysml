# 3CX X_TRADER replay 妗堜緥澶嶇幇鎽樿

## 缁撹

鏈渚嬩负闃插尽鎬у畨鍏ㄤ豢鐪燂紝鏈寘鍚湡瀹炴伓鎰忎唬鐮併€係upplyGuard KG 宸插畬鎴愮粍浠躲€丆I/CD銆佷骇鐗╁彲淇″拰鏃ュ織璇佹嵁鎵弿锛屽苟鐢熸垚宸ヤ綔鍙板浘璋变笌婧簮鎶ュ憡銆?
- 缁煎悎椋庨櫓锛?riskLevel / 100
- 渚濊禆椋庨櫓锛?depFindingCount
- CI/CD 椋庨櫓锛?cicdFindingCount
- 浜х墿鍙俊椋庨櫓锛?trustFindingCount
- 鏃ュ織椋庨櫓锛?logFindingCount
- 鏀诲嚮璺緞锛?attackPathCount

## 鍏抽敭鍙戠幇

### 渚涘簲閾剧粍浠?
- axios has exploitable VEX context
- electron vulnerability needs reachability triage
- starlette has exploitable VEX context

### CI/CD 鏋勫缓閾?
- GitHub Token æéè¿å®½
- Action æªåºå®å°å®æ´ commit SHA
- Action æªåºå®å°å®æ´ commit SHA

### 浜х墿鍙俊

- äº§ç© digest ä¸ attestation subject ä¸ä¸è´æç¼ºå¤±
- äº§ç©æ¥æº commit ä¸ç¬¦åé¢æ
- runner ç¯å¢ä¸ç¬¦åç­ç¥
- äº§ç©ç­¾åéªç­¾æªéè¿

### 鏃ュ織鍗拌瘉

- Suspicious External Egress IP
- Suspicious External Egress IP

## 椤甸潰鏌ョ湅

鎵撳紑 http://127.0.0.1:8000 锛岄噸鐐规煡鐪嬶細

- 婧簮鎬昏
- 渚涘簲閾剧粍浠?- CI/CD 鏋勫缓閾?- 浜х墿鍙俊
- 鏃ュ織鍗拌瘉
- 鏀诲嚮璺緞鍥捐氨
- 婧簮鎶ュ憡
