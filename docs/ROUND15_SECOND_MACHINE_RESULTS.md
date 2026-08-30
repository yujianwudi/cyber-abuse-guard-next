# Round 15 second-machine diagnostic results

状态：`DIAGNOSTIC PASS / NOT INDEPENDENT ATTESTATION`

## 精确输入

- CAG candidate commit：`2f49f467c7e723ab16f290b1e1b09fc0999bf280`
- CAG candidate tree：`46fab7f3e284b6d222ee1214bb2c1c1449cce098`
- CPA：`v7.2.142@1f53b2eb03b9e963bac647e5566ca2b304239116`
- CPA official Linux amd64 archive：`21193314` bytes，SHA-256
  `a7cccc8f94b07660303c1874fb6bedae6d573a0f3c4c0b17ad8cf7885dd7a051`
- CAG ELF candidate SHA-256：`4f9bbee7178725329ee7b07e3d6450758b0cd050604dbdcdf552dfe888569f2f`

## 已复测合同

| 场景 | 结果 |
|---|---|
| CPA v7.2.142 binary / CAG ELF load | PASS |
| plugin register / management status | PASS |
| 普通请求到本地 Mock Provider | HTTP 200；上游命中 `0 → 1` |
| 合成凭据窃取请求 | HTTP 403；分类 `credential_theft`；未增加上游命中 |
| 有效插件 hot reload | PASS；active/retired 路径切换已记录 |
| 无效替换文件 | 加载失败；旧插件恢复；`quiescing=false`、transitions=1、restores=1 |
| 失败替换后普通请求 | HTTP 200 |

测试使用本地无凭据 Mock Provider，不连接真实 Provider/OAuth，不执行第三方
仓库代码，不读取生产配置。此摘要只证明本轮候选在隔离主机上的诊断行为，不能替代
GitHub required checks、独立见证或发布治理门禁。
