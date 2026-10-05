# dsh-pentest 适用性评估与实现边界

参考：https://github.com/howmp/dsh-pentest ，读取版本 df15f80af58c1ebac5a903fa60c78e085c74b09b。只借鉴结构与行为，没有复制其运行时代码。

基线说明：当前工作区 package.json 为 0.1.0，最新提交 103575c，没有用户提到的 0.1.1。本次作为 0.1.2 开发，不声称已审查缺失的 0.1.1。

| 项目 | 判断 | 本次应用与原因 |
|---|---|---|
| 三处 loader 身份 | 直接借鉴 | package.name、Web patch row.name、Client ModuleLoader.id 均为 @liumiya63/dsh-cyber。row.id 是 Cordis 实例 ID，不要求等于包名。加入回归测试。 |
| Host/Client 分离 | 直接借鉴 | 根入口 inert，只承载浏览器元数据；独立 /host 子路径注册 SQLite、HTTP、工具。避免 browser 扫描跳过子路径以及业务工具双重注册。 |
| goals/intents/facts/findings/assets/edges | 调整 | 新 graph_records SQLite 表存储六种实体，保留旧资产/漏洞/任务表。目标不清空历史，漏洞要求非空复现步骤，引用必须属于同 scope。 |
| pentest_* 工具集 | 调整 | cyber_state/graph/report、cyber_add_goal/intent/fact/finding/asset/edge、task_run/cancel、knowledge_search/ingest、audit_verify；保留 cyber_manage 兼容旧流程。 |
| 预设注册 | 调整 | 使用当前 DSH 原生 @deepseek-ai/dsh-agent-preset YAML 声明，保留 cyber-agent；不采用旧 resolvedRoots 兼容分支，也不复制可能过时的完整 standard 组合。 |
| 提示词协议 | 调整 | 使用 goal→intent→fact→finding 证据协议，真实返回 ID、重复检查、审批等待。未采用强制所有执行委派、子代理 synthetic tool/call 日志写入。 |
| Web 标签页 | 调整 | 保留工作区级 Cyber 面板，与持久化数据库匹配；探索页、攻击链、审计、审批统一主题。没有把全局 key 当作当前会话已挂载证据。 |
| 会话投影 | 不直接适用 | 参考按 tool/call 重放计数推断状态，Cyber 有 HTTP 人工编辑、审批和异步任务，尝试调用也可能失败。当前采用 SQLite committed snapshot；没有注册 DSH 会话 fold 或伪造日志事件。scope 仅命名空间，不是会话 ACL。真正会话投影需以后从已提交结果事件构建。 |
| 确定性 ID | 调整 | scope+kind+规范字段 SHA-256 前 24 位，重复数据同 uid，避免每会话计数重放和数据库并发顺序不一致。这是内容去重，不是身份认证或天然权限边界。 |
| SQLite | 调整 | 沿用 Node DatabaseSync/WAL/外键；增加 additive graph 表，不覆盖旧数据。旧数据与新图分开展示，不暗中推断旧资产关系。 |
| 审计哈希链 | 保留并扩展 | 领域写入和审计同事务；JSONL 镜像、启动完整性校验。不宣称外部锚定或抵御整库/整链替换。 |
| 审批流 | 保留 | 模型没有 approval.decide 工具；所有外部 recipe 执行先等待用户。HTTP UI 决策沿用本机可信 UI 契约。 |
| WebShell/C2 | 占位 | capabilities=false，无执行器、上传或 C2 通信。 |

## 兼容与验证要求

安装使用官方 plugin_manager。前端使用 DSH theme tokens，Host 无 React/browser 依赖，Client 无 node:sqlite/child_process。本地预设不代表所选模型离线。新增 scope 暂为共享本机命名空间，不提供多租户隔离。

npm run check 覆盖原核心功能、图关系/去重/持久化以及包 loader 契约。现场验证必须区分源码构建、插件加载、HTTP 返回和截图，不能把 active 状态等同模型端到端验证。
