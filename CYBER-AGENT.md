# Cyber Agent

Cyber 内置 AI 助手页面及 Host 的 agent.run/models 已从源码移除。AI 工作交给 DSH 本地预设 cyber-agent，显示名 Cyber Agent；它使用 DSH 会话模型，通过全局 cyber_manage 工具操作插件。

## 使用

重启 DSH，创建新空白会话，选择 Cyber Agent 和所需 DSH 模型，再输入任务。例如：读取 Cyber 当前状态，运行 node-health 配方并检查执行结果与审计。

已有会话保持原预设。该预设不会改变全局默认 Agent；本地表示预设配置保存在本机，模型是否离线取决于所选 DSH 提供方。

资产、漏洞、知识库、攻击链、配方任务和审计继续由 Cyber 插件持久化。外部任务审批由用户在 Cyber 审批中心决定。WebShell/C2 仍禁用。

## 验证记录

- npm run check：TypeScript、客户端语法、两项核心测试通过。
- bundle set_bundle：application applied。
- include:preset-cyber-agent：enabled true / fiberPhase active。
- cyber_manage snapshot 可读取原有数据库。
- 当前进程的 /api/cyber models 仍返回旧版结果，禁用/启用未刷新 Host 模块缓存；需要重启 DSH 后验证旧接口返回 Action not available。
- 未执行新 cyber-agent 会话的模型端到端测试，也未完成页面截图验证。
