# Enterprise Security AI Assistant

## 1. 项目目标

构建一个可运行、可演示的企业安全知识 AI Assistant 原型。

目标用户：

* 普通企业员工
* IT Support
* Security Team

核心目标：

1. 员工可以通过自然语言咨询企业安全问题。
2. AI 必须优先基于企业内部安全知识库回答问题。
3. 回答需要显示引用的知识来源。
4. 不同角色只能访问其权限范围内的知识。
5. AI 能识别用户问题类型。
6. AI 能对安全事件进行风险分级。
7. 高风险事件必须升级给人工 Security Team。
8. 必要时可以自动创建 Security Ticket。
9. 管理员可以查看基本的安全事件和咨询统计。

## 2. 核心使用场景

### 场景 A：安全知识查询

用户：
“公司密码有什么要求？”

系统：

* 识别为 Security FAQ
* 从企业知识库检索 Password Policy
* 基于检索结果回答
* 显示来源文档

### 场景 B：钓鱼邮件

用户：
“我收到一封邮件，要求我点击链接重新登录公司邮箱，这正常吗？”

系统：

* 判断 Intent = Phishing
* 检索 Phishing Response SOP
* 给出安全建议
* 给出风险等级
* 显示知识来源

### 场景 C：疑似恶意软件

用户：
“我打开一个邮件附件之后电脑开始出现异常弹窗。”

系统：

* Intent = Security Incident
* Risk Level = High
* 输出建议操作
* 自动建议创建 Security Ticket
* 必须进入 Human Escalation

### 场景 D：VPN 故障

用户：
“我今天突然连不上公司的 VPN。”

系统：

* Intent = IT Support
* 检索 VPN Troubleshooting SOP
* 输出排查步骤
* 如果无法解决，建议创建 IT Ticket

## 3. 用户角色

### Employee

允许：

* 查看基础安全 FAQ
* 查看员工可访问的安全政策
* 查询基础安全 SOP

禁止：

* 访问 Security Team 内部调查资料
* 访问敏感事件信息
* 查看其他员工的安全工单

### IT

允许：

* Employee 全部权限
* VPN Troubleshooting
* Endpoint Troubleshooting
* IT Support SOP

### Security Team

允许：

* 全部安全知识
* Incident Response SOP
* Malware Response
* Phishing Investigation
* Security Incident Ticket

## 4. AI Pipeline

User Query
→ Intent Classification
→ Permission Check
→ Retrieval
→ LLM Response
→ Risk Classification
→ Workflow Decision
→ Ticket / Human Escalation

## 5. Knowledge Base

创建模拟企业内部安全知识文档：

* Password Policy
* Phishing Response SOP
* Malware Incident Response SOP
* VPN Troubleshooting SOP
* Remote Work Security Policy
* Data Leakage Policy
* Access Control Policy
* Incident Severity Classification
* Endpoint Security Guide
* Security Contact Guide

所有文档都必须有：

* document_id
* title
* category
* allowed_roles
* content

## 6. 技术要求

Frontend:

* React
* TypeScript

Backend:

* Python
* FastAPI

LLM:

* 可配置 LLM API
* API Key 必须通过环境变量读取

RAG:

* Embedding
* Vector Search
* Retrieval
* Context-aware generation

Vector DB:

* MVP 使用 FAISS 或 Chroma

Database:

* MVP 使用 SQLite
* 需要保存用户、角色、工单、审计日志

Authentication:

* MVP 可以使用简单模拟登录
* 但必须实现 RBAC

Deployment:

* Docker Compose

## 7. 安全要求

不得：

* 硬编码 API Key
* 提交 .env
* 将用户敏感数据写入 Git
* 让 LLM 绕过 RBAC
* 让普通用户检索受限制文档

必须：

* 提供 .env.example
* 实现基本审计日志
* 对高风险事件强制人工升级
* 对 LLM 输出进行结构化解析

## 8. 结构化 AI 输出

至少包含：

{
"intent": "...",
"risk_level": "...",
"answer": "...",
"recommended_actions": [],
"source_documents": [],
"human_escalation": true/false,
"create_ticket": true/false
}

## 9. MVP 验收标准

必须完成：

1. 用户能够登录。
2. 用户能够发送问题。
3. AI 能够识别 Intent。
4. 系统能够检索知识库。
5. 回答显示引用来源。
6. RBAC 生效。
7. 高风险事件能够识别。
8. 高风险事件能够创建 Security Ticket。
9. Ticket 能够在后台查看。
10. Docker Compose 可以启动整个系统。
11. 提供 README。
12. 提供至少 30 个测试问题。
13. 提供基本自动化测试。

## 10. Demo 场景

最终必须支持以下完整演示：

用户询问钓鱼邮件
→ AI 识别
→ RAG 检索
→ 给出答案
→ 用户表示已经输入密码
→ 风险升级为 High
→ 自动生成 Security Ticket
→ Security Team Dashboard 显示新事件

## 11. 开发原则

不要一次性完成全部功能。

采用以下阶段：

Phase 1:
Project scaffolding

Phase 2:
Knowledge base + RAG

Phase 3:
Chat UI

Phase 4:
RBAC

Phase 5:
Intent + Risk classification

Phase 6:
Ticket workflow

Phase 7:
Dashboard

Phase 8:
Testing

Phase 9:
Docker deployment

Phase 10:
README + Demo documentation

每个 Phase 完成后：

* 运行测试
* 检查功能
* 修复错误
* 更新 README
* 再进入下一阶段
