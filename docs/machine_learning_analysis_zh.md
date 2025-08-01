# SharpEye中的机器学习分析

SharpEye集成了先进的机器学习技术来增强异常检测能力。本文档提供了基于机器学习分析功能的概述，包括系统资源监控和新的全面行为异常检测系统。

## 行为异常检测

SharpEye最新更新引入了强大的行为异常检测框架，该框架对系统行为进行全面监控，以识别潜在的安全威胁。这一框架代表了SharpEye安全能力的重大提升。

### 概述

行为异常检测系统监控和分析系统行为的各个方面：

1. **进程行为** - 监控进程资源使用、关系、执行模式和生命周期
2. **用户行为** - 跟踪用户活动、登录模式、命令使用和权限变更
3. **系统资源行为** - 监控系统范围内的资源使用模式和异常
4. **文件系统行为** - 检测异常文件操作、访问模式和修改
5. **网络行为** - 识别异常连接模式、数据传输和通信

每个行为领域都使用机器学习技术建立正常行为基线并检测可能表明安全威胁的偏差。

### 关键组件

#### 1. 行为分析器

核心`BehaviorAnalyzer`类实现：

- 从原始系统数据中提取特征
- 基线建立和维护
- 使用隔离森林算法进行异常检测
- 严重性评估和报告

#### 2. 行为监控器

`BehaviorMonitor`服务提供：

- 跨所有行为领域的实时监控
- 专业监控组件之间的协调
- 定期报告和告警
- 基线管理

#### 3. 专业分析器

针对每个行为领域的专用分析器：

- `ProcessBehaviorAnalyzer` - 进程特定异常检测
- `UserBehaviorAnalyzer` - 用户活动分析
- `SystemResourceAnalyzer` - 系统范围资源监控
- `FileSystemAnalyzer` - 文件操作监控
- `NetworkBehaviorAnalyzer` - 网络通信分析

### 实现亮点

- **隔离森林算法** - 用于异常检测的高效无监督学习
- **上下文异常检测** - 在识别异常时考虑行为上下文
- **多维分析** - 同时检查多个数据点
- **时间模式识别** - 识别随时间发展的异常模式
- **跨域关联** - 连接不同行为领域的异常

### 使用方法

行为异常检测可以作为独立模块运行：

```bash
sudo sharpeye --module behavior
```

或在配置中启用为持续后台服务：

```yaml
behavior_monitor:
  continuous_monitoring: true
```

## 系统资源模式分析

系统资源模块（`SystemResourceAnalyzer`）已经增强了机器学习能力，用于检测可能表明系统被入侵或存在安全威胁的异常资源使用模式。

### 概述

传统的基于阈值的异常检测有用但有局限性：
- 固定阈值可能会遗漏微妙的异常
- 无法检测不同资源之间的相关性
- 无法识别随时间发展的模式
- 无法从系统的正常行为中学习

机器学习增强通过以下方式解决这些限制：
- 分析随时间变化的资源使用模式
- 基于与预期行为的偏差检测异常
- 识别不同资源类型之间的相关性
- 识别逐渐演变的可疑趋势和模式

### 实施技术

`ResourcePatternAnalyzer`类实现了几种机器学习和统计分析方法：

1. **无监督异常检测** - 使用隔离森林算法识别异常资源使用模式
2. **时间序列分析** - 跟踪资源指标随时间变化以检测异常变化
3. **相关性分析** - 检测不同资源类型之间的可疑相关性
4. **趋势分析** - 使用线性回归识别令人担忧的趋势

### 关键特性

#### 1. 历史数据分析

分析器维护资源指标的历史记录，使其能够建立正常行为的基线：
- 可配置的历史长度（默认：24个数据点）
- 从CPU、内存和磁盘数据自动提取特征
- 用于持续监控的滚动窗口分析

#### 2. 机器学习模型

使用三个独立的ML模型来检测不同资源类型的异常：
- CPU使用模式异常检测
- 内存使用模式异常检测
- 磁盘使用模式异常检测

模型使用scikit-learn的隔离森林算法实现，该算法：
- 不需要标记的训练数据
- 适用于高维数据
- 对实时异常检测效率高
- 可以检测特征空间中的离群点

#### 3. 跨资源相关性分析

除了单个资源异常外，分析器还检测资源之间的可疑相关性：
- CPU和内存使用模式
- 磁盘I/O和CPU模式
- 系统和用户CPU时间比率
- 异常的资源趋同模式

可检测的常见攻击模式包括：
- 高磁盘I/O但没有相应的CPU使用（潜在数据泄露）
- 完全相关的资源使用（潜在的协调攻击）
- 高CPU和逐渐减少的可用内存（资源耗尽攻击）

#### 4. 统计模式检测

即使没有训练模型，分析器也使用统计方法来识别可疑模式：
- 资源使用突然峰值
- 持续高负载
- 异常的系统到用户CPU比率
- 内存碎片增加
- 可疑进程行为

#### 5. 自我训练能力

分析器可以根据观察到的系统行为训练自己的模型：
- 收集足够的历史记录后自动训练模型
- 适应特定系统的基准行为
- 不需要预先标记的训练数据

## 高级行为异常检测功能

### 进程行为分析

进程行为分析检测异常的进程活动，包括：

- 异常的资源使用模式
- 可疑的执行路径
- 进程的异常网络活动
- 异常的进程创建模式
- 可疑的父子关系
- 加密货币挖矿和其他恶意活动

从进程提取的关键特征包括：

- CPU和内存使用模式
- I/O操作统计
- 网络连接数量和类型
- 进程生命周期和执行上下文
- 命令行参数
- 执行路径和所有权

### 用户行为分析

用户行为分析识别异常用户活动：

- 异常的登录时间或源位置
- 权限提升尝试
- 可疑的命令执行模式
- 访问敏感文件或资源
- 异常会话持续时间
- 登录失败模式

用户行为跟踪的关键特征包括：

- 登录时间分布
- 源IP地址历史
- 命令执行频率和类型
- 权限使用模式
- 文件访问模式
- 会话持续时间统计

### 文件系统行为分析

文件系统行为分析检测可疑文件活动：

- 修改关键系统文件
- 在可疑位置创建文件
- 异常的权限或所有权变更
- 对敏感文件的访问模式
- 可疑的文件扩展名或类型变更
- 异常的文件增长模式

文件行为关键特征包括：

- 操作类型（读取、写入、执行、删除）
- 路径敏感性分类
- 文件大小和增长指标
- 用户/所有者身份
- 隐藏文件指标
- 权限设置
- 时间戳模式
- 访问频率

### 网络行为分析

网络行为分析识别异常网络活动：

- 异常连接模式
- 数据泄露尝试
- 命令和控制通信
- 信标或周期性连接
- 连接到可疑目的地
- 异常数据传输量

网络行为特征包括：

- 连接协议和类型
- 远程端口和已知服务映射
- 数据传输量
- 连接持续时间
- 连接频率
- 数据包大小分布
- 加密指标
- 地理位置指标

### 配置选项

行为异常检测系统具有高度可配置性：

```yaml
behavior_monitor:
  # 核心设置
  continuous_monitoring: true
  report_interval: 300
  baseline_path: "/var/lib/sharpeye/baselines/behavior"
  auto_baseline: true
  baseline_duration: 60
  alert_threshold: 0.8
  
  # 监控设置
  process_monitor:
    enabled: true
    scan_interval: 30
  
  file_monitor:
    enabled: true
    monitored_paths:
      - "/etc"
      - "/bin"
      - "/sbin"
    excluded_paths:
      - "/var/log/sharpeye"
  
  # 行为分析器设置
  analyzer:
    history_size: 1000
    n_estimators: 100
    contamination: 0.05
```

### 与威胁情报的集成

行为异常检测系统与SharpEye的威胁情报功能集成：

1. 根据已知的恶意IP地址检查网络连接
2. 将文件操作与已知的恶意软件签名关联
3. 将进程行为与已知的攻击模式匹配
4. 分析用户行为是否有已知的入侵指标

这种集成通过为异常评估提供额外上下文来增强检测能力。

## 在其他模块中使用ML分析

SharpEye中实现的机器学习方法提供了一个全面的框架，增强了所有安全模块：

- **用户账户模块** - 通过用户行为异常检测增强
- **网络模块** - 通过网络行为模式分析丰富
- **进程模块** - 通过进程行为异常检测升级
- **SSH模块** - 通过登录模式分析和行为跟踪改进
- **Rootkit检测** - 通过复杂的基于行为的检测加强
- **加密货币挖矿检测** - 通过统计模式识别增强

行为异常检测系统提供了一种统一的方法，连接和关联所有模块的发现，显著提高了检测能力。

## 需求

机器学习功能需要以下Python包：
- numpy
- scikit-learn
- pandas
- scipy
- psutil（用于实时系统数据收集）

这些依赖项包含在SharpEye的requirements.txt文件中。

## 性能考虑

行为异常检测系统设计为高效和可扩展：

- 通过可配置的历史限制控制内存使用
- 通过使用高效算法优化CPU使用
- 存储需求最小，基线以紧凑的JSON格式存储
- 资源消耗可以通过配置参数进行微调

## 未来增强

行为异常检测系统计划的增强包括：

1. **深度学习模型** - 添加基于神经网络的检测来识别复杂模式
2. **多系统关联** - 分析多个系统间的行为
3. **对抗性分析** - 检测高级威胁使用的规避技术
4. **行为指纹** - 为已知的攻击模式开发独特签名
5. **自适应阈值** - 根据系统环境自动调整检测阈值