# SharpEye: 高级Linux入侵检测系统

<div align="center">
<p>
    <img width="140" src="assets/logo.png" alt="SharpEye logo">
</p>
<p>
    <b>Advanced Linux Intrusion Detection and Threat Hunting System</b>
</p>
<p>
    <b>高级Linux入侵检测与威胁狩猎系统</b>
</p>
</div>

---

[English](./README.md) | **中文**

## 项目概述

**SharpEye** 是由innora.ai设计的全面Linux入侵检测和系统安全监控框架。它采用先进的分析技术、机器学习和基于行为的检测方法，实时识别和警报可疑活动、潜在入侵和安全威胁。

### 功能特点

#### 核心检测能力
- **系统资源监控**：检测CPU、内存和磁盘使用模式中的异常
- **用户账户安全**：识别未授权账户、权限提升和可疑登录模式
- **进程分析**：通过行为分析检测恶意和可疑进程
- **网络连接监控**：识别异常网络连接和数据传输
- **文件系统完整性**：验证系统文件完整性并检测未授权更改
- **日志分析引擎**：监控和分析系统日志中的可疑活动
- **计划任务检查**：识别恶意的cron任务和计划任务
- **SSH安全性**：监控SSH配置并检测未授权访问尝试
- **内核模块分析**：检测恶意内核模块和rootkit
- **库检查**：识别动态库劫持尝试
- **权限提升检测**：发现并警报潜在的权限提升向量

#### 企业级功能（新增）
- **高级威胁检测**：基于机器学习的异常检测，支持 APT、勒索软件和加密挖矿的模式匹配
- **行为监控**：实时系统行为分析，自动基线学习
- **容器安全**：Docker 和 Kubernetes 安全扫描，包括漏洞检测
- **威胁情报集成**：MISP、AlienVault OTX 和 Mandiant 威胁源集成
- **实时告警**：通过 Email、Slack、Webhook 和 Syslog 的多通道告警
- **Web 仪表板**：支持 WebSocket 更新和响应式设计的实时监控界面
- **攻击链分析**：基于图的关联分析，识别多阶段攻击
- **基于机器学习的加密货币挖矿检测**：使用机器学习识别未授权的加密货币挖矿活动

## 安装

```bash
git clone https://github.com/sgInnora/sharpeye.git
cd sharpeye
sudo ./install.sh
```

## 基本用法

```bash
# 运行完整系统扫描
sudo sharpeye --full-scan

# 运行特定模块
sudo sharpeye --module network

# 建立基线以供将来比较
sudo sharpeye --establish-baseline

# 与基线进行比较
sudo sharpeye --compare-baseline

# 启动带Web仪表板的扫描（新功能）
sudo sharpeye --full-scan --web

# 运行行为监控
sudo sharpeye --module behavior

# 运行容器安全扫描
sudo sharpeye --module container_security
```

## 配置

安装后，配置文件存储在`/etc/sharpeye/`目录中。编辑`config.yaml`来自定义扫描参数和检测阈值。

## 系统要求

- 基于Linux的操作系统（Debian、Ubuntu、CentOS、RHEL等）
- Python 3.6+
- 需要root权限进行全面扫描

## 当前状态

截至2025年5月，SharpEye核心模块的当前实现状态如下：

| 模块 | 状态 | 测试覆盖率 |
|--------|--------|---------------|
| 文件系统完整性 | ✅ 已完成 | 95% |
| 内核模块分析 | ✅ 已完成 | 94% |
| 库检查 | ✅ 已完成 | 95% |
| 权限提升检测 | ✅ 已完成 | 94% |
| 日志分析引擎 | ✅ 已完成 | 93% |
| 加密货币挖矿检测 | ✅ 已完成 | 95% |
| 系统资源 | ✅ 已完成 | 100% |
| 用户账户 | ✅ 已完成 | 100% |
| 进程 | ✅ 已完成 | 100% |
| 网络 | ✅ 已完成 | 95% |
| 计划任务 | ✅ 已完成 | 95% |
| SSH | ✅ 已完成 | 100% |
| Rootkit检测 | ✅ 已完成 | 100% |

该项目现已全部实现完成，所有13个模块已全部完成并经过全面测试。项目拥有功能完善的CI/CD流水线，使用GitHub Actions确保所有模块的代码质量和测试覆盖率。有关详细的项目状态信息，请参阅[项目状态](docs/PROJECT_STATUS_ZH.md)。

## 🎉 最新更新 (2025-05-29)

### 主要增强功能

1. **高级威胁检测模块** (`advanced_threat_detector.py`)
   - 基于机器学习的异常检测，使用 Isolation Forest 算法
   - 基于模式的威胁检测，支持 APT、勒索软件和加密挖矿检测
   - 基于图的攻击链分析和关联
   - 风险评分和自动化建议

2. **行为监控系统** (`behavior_monitor.py`)
   - 实时进程行为监控
   - 使用 pyinotify 进行文件系统活动跟踪
   - 网络行为分析，包括信标检测
   - 用户活动监控和异常检测
   - 自动基线学习和基于机器学习的检测

3. **容器安全模块** (`container_security.py`)
   - Docker 容器安全扫描
   - Kubernetes Pod 安全分析
   - 集成 Trivy/Grype 的漏洞扫描
   - 容器运行时异常检测
   - 基线比较和漂移检测

4. **企业级功能**
   - **威胁情报集成**：支持 MISP、AlienVault OTX 和 Mandiant
   - **实时告警**：Email、Slack、Webhook 和 Syslog 通道
   - **Web 仪表板**：使用 WebSocket 更新的实时监控界面
   - **增强的机器学习能力**：改进所有模块的异常检测

### 技术改进

- 标准化接口的模块化架构
- 全面的单元测试覆盖
- 大规模部署的性能优化
- 增强的中英文文档

详细的增强信息，请参阅 [深度强化更新总结](./DEEP_ENHANCEMENT_SUMMARY.md)。

## 测试覆盖度

**最新测试结果**: ✅ 106/106 测试通过 | 📊 覆盖率: 75%

- **工具模块覆盖率**: 75% (2079 语句)
- **新功能测试**: 所有企业级模块完全测试
- **测试套件**: 5个全面的测试文件
- **质量保证**: 广泛的模拟和边缘情况覆盖

详细的覆盖率信息，请参阅 [测试覆盖率报告](./TEST_COVERAGE_REPORT.md)。

## 文档

有关更详细的信息，请参阅：

### 📋 核心文档
- [用户指南](docs/user_guide_zh.md)
- [模块参考](docs/module_reference_zh.md)
- [测试指南](docs/testing_zh.md)

### 🔬 技术文档
- [机器学习分析](docs/machine_learning_analysis_zh.md)
- [项目状态](docs/PROJECT_STATUS_ZH.md)
- [SQLite线程指南](docs/SQLITE_THREADING_ZH.md)

### 🚀 增强文档
- [深度强化更新总结](./DEEP_ENHANCEMENT_SUMMARY.md) - 最新重大更新
- [测试覆盖率报告](./TEST_COVERAGE_REPORT.md) - 全面的测试指标
- [完成报告](./COMPLETION_REPORT.md) - 开发完成总结
- [增强总结](docs/ENHANCEMENT_SUMMARY_ZH.md)

### 🔧 DevOps文档
- [CI/CD状态](docs/CI_CD_STATUS_ZH.md)
- [CI/CD修复指南](docs/CI_CD_FIX_ZH.md)

## 参与贡献

欢迎贡献！请查看我们的[贡献指南](CONTRIBUTING.md)了解更多详情。

## 关于innora.ai

innora.ai专注于为现代计算环境开发高级安全解决方案。我们的团队结合了恶意软件分析、威胁情报和机器学习方面的专业知识，创建尖端安全工具，帮助组织保护其关键基础设施。

## 许可证

本项目基于MIT许可证 - 详情请参阅[LICENSE](LICENSE)文件。

## 致谢

- innora.ai研究团队
- 所有帮助改进此项目的贡献者和安全研究人员
- 启发本项目的开源安全工具