#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
行为监控模块 - SharpEye入侵检测系统的行为异常监控组件
该模块负责监控和分析系统行为，以检测可能的入侵和异常活动。
"""

import os
import time
import json
import logging
import threading
import psutil
import numpy as np
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
try:
    import pyinotify  # 用于文件系统监控
    HAS_PYINOTIFY = True
except ImportError:
    # pyinotify is not available on macOS
    HAS_PYINOTIFY = False
    pyinotify = None
import socket

# 导入SharpEye本地模块
from utils.behavior_analysis import BehaviorAnalyzer
from utils.behavior_analysis import ProcessBehaviorAnalyzer, UserBehaviorAnalyzer
from utils.behavior_analysis import SystemResourceAnalyzer, FileSystemAnalyzer, NetworkBehaviorAnalyzer
from utils.reporter import Reporter

# 配置日志
logger = logging.getLogger("sharpeye.behavior_monitor")

class BehaviorMonitor:
    """行为监控主类，协调各种行为的监控和分析"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化行为监控器
        
        Args:
            config: 监控配置参数
        """
        self.config = config or {}
        self.running = False
        self.threads = []
        
        # 初始化行为分析器
        analyzer_config = self.config.get('analyzer', {})
        self.analyzer = BehaviorAnalyzer(analyzer_config)
        
        # 创建专用监控器
        self.process_monitor = ProcessMonitor(self.analyzer, self.config.get('process_monitor', {}))
        self.file_monitor = FileSystemMonitor(self.analyzer, self.config.get('file_monitor', {}))
        self.network_monitor = NetworkMonitor(self.analyzer, self.config.get('network_monitor', {}))
        self.user_monitor = UserMonitor(self.analyzer, self.config.get('user_monitor', {}))
        self.system_monitor = SystemMonitor(self.analyzer, self.config.get('system_monitor', {}))
        
        # 报告器
        self.reporter = Reporter()
        
        # 警报阈值和冷却时间
        self.alert_threshold = self.config.get('alert_threshold', 0.8)
        self.alert_cooldown = self.config.get('alert_cooldown', 300)  # 秒
        self.last_alert_time = {}  # 上次警报时间
        
        # 基线设置
        self.baseline_path = self.config.get('baseline_path', '/var/lib/sharpeye/baselines')
        self.auto_baseline = self.config.get('auto_baseline', True)
        self.baseline_duration = self.config.get('baseline_duration', 60)  # 分钟
        
        logger.info("行为监控模块初始化完成")
    
    def analyze(self) -> Dict[str, Any]:
        """
        执行行为分析并返回结果
        符合 SharpEye 模块接口
        
        Returns:
            Dict: 分析结果
        """
        logger.info("开始行为分析")
        
        # 如果启用了连续监控，先启动监控
        if self.config.get('continuous_monitoring', True):
            if not self.running:
                self.start()
        
        # 收集当前系统行为数据
        results = {
            'timestamp': datetime.now().isoformat(),
            'anomalies': [],
            'statistics': {},
            'is_anomalous': False
        }
        
        # 分析各种行为
        try:
            # 进程行为分析
            process_anomalies = self._analyze_processes()
            if process_anomalies:
                results['anomalies'].extend(process_anomalies)
            
            # 文件系统行为分析
            file_anomalies = self._analyze_file_activities()
            if file_anomalies:
                results['anomalies'].extend(file_anomalies)
            
            # 网络行为分析
            network_anomalies = self._analyze_network_activities()
            if network_anomalies:
                results['anomalies'].extend(network_anomalies)
            
            # 用户行为分析
            user_anomalies = self._analyze_user_activities()
            if user_anomalies:
                results['anomalies'].extend(user_anomalies)
            
            # 系统资源分析
            system_anomalies = self._analyze_system_resources()
            if system_anomalies:
                results['anomalies'].extend(system_anomalies)
            
            # 获取综合分析报告
            comprehensive_report = self.analyzer.analyze_all()
            
            # 统计信息
            results['statistics'] = {
                'total_anomalies': len(results['anomalies']),
                'process_anomalies': len([a for a in results['anomalies'] if a['type'] == 'process']),
                'file_anomalies': len([a for a in results['anomalies'] if a['type'] == 'file']),
                'network_anomalies': len([a for a in results['anomalies'] if a['type'] == 'network']),
                'user_anomalies': len([a for a in results['anomalies'] if a['type'] == 'user']),
                'system_anomalies': len([a for a in results['anomalies'] if a['type'] == 'system']),
                'high_severity': len([a for a in results['anomalies'] if a.get('severity') == '高']),
                'critical_severity': len([a for a in results['anomalies'] if a.get('severity') == '严重'])
            }
            
            # 如果有异常，标记为异常
            if results['anomalies']:
                results['is_anomalous'] = True
            
            # 添加基线状态
            results['baseline_status'] = {
                'established': bool(self.analyzer.baselines),
                'last_updated': getattr(self, 'baseline_last_updated', None)
            }
            
            # 添加监控状态
            results['monitoring_status'] = self.get_status()
            
        except Exception as e:
            logger.error(f"行为分析过程中出错: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_processes(self) -> List[Dict[str, Any]]:
        """分析进程行为异常"""
        anomalies = []
        
        try:
            # 获取所有进程
            for proc in psutil.process_iter(['pid', 'name', 'create_time']):
                try:
                    proc_data = self.process_monitor.process_analyzer._get_full_process_info(proc)
                    if proc_data:
                        anomaly = self.process_monitor.process_analyzer.analyze_process(proc_data)
                        if anomaly:
                            anomalies.append({
                                'type': 'process',
                                'pid': proc.pid,
                                'name': proc_data.get('name'),
                                'severity': self._calculate_severity(anomaly.get('anomaly_score', 0)),
                                'details': anomaly,
                                'timestamp': datetime.now().isoformat()
                            })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.error(f"进程分析错误: {str(e)}")
        
        return anomalies
    
    def _analyze_file_activities(self) -> List[Dict[str, Any]]:
        """分析文件系统活动异常"""
        anomalies = []
        
        # 获取最近的文件活动从分析器
        recent_activities = getattr(self.analyzer.file_analyzer, 'recent_activities', [])
        
        for activity in recent_activities[-100:]:  # 最近100个活动
            anomaly = self.analyzer.file_analyzer.analyze_file_activity(activity)
            if anomaly:
                anomalies.append({
                    'type': 'file',
                    'path': activity.get('path'),
                    'operation': activity.get('operation'),
                    'severity': self._calculate_severity(anomaly.get('anomaly_score', 0)),
                    'details': anomaly,
                    'timestamp': datetime.now().isoformat()
                })
        
        return anomalies
    
    def _analyze_network_activities(self) -> List[Dict[str, Any]]:
        """分析网络活动异常"""
        anomalies = []
        
        try:
            # 获取当前网络连接
            connections = psutil.net_connections(kind='all')
            
            for conn in connections:
                if conn.raddr:  # 只分析有远程地址的连接
                    conn_data = {
                        'local_ip': conn.laddr.ip if conn.laddr else '',
                        'local_port': conn.laddr.port if conn.laddr else 0,
                        'remote_ip': conn.raddr.ip,
                        'remote_port': conn.raddr.port,
                        'protocol': 'tcp' if conn.type == socket.SOCK_STREAM else 'udp',
                        'state': conn.status if hasattr(conn, 'status') else '',
                        'pid': conn.pid
                    }
                    
                    anomaly = self.analyzer.network_analyzer.analyze_connection(conn_data)
                    if anomaly:
                        anomalies.append({
                            'type': 'network',
                            'connection': f"{conn_data['remote_ip']}:{conn_data['remote_port']}",
                            'protocol': conn_data['protocol'],
                            'severity': self._calculate_severity(anomaly.get('anomaly_score', 0)),
                            'details': anomaly,
                            'timestamp': datetime.now().isoformat()
                        })
        except Exception as e:
            logger.error(f"网络分析错误: {str(e)}")
        
        return anomalies
    
    def _analyze_user_activities(self) -> List[Dict[str, Any]]:
        """分析用户活动异常"""
        anomalies = []
        
        try:
            # 获取当前登录用户
            users = self.user_monitor._get_logged_in_users()
            
            for username, user_data in users.items():
                activity_data = {
                    'username': username,
                    'login_time': user_data.get('login_time', 0),
                    'source_ip': user_data.get('source_ip', '127.0.0.1'),
                    'is_remote': user_data.get('is_remote', False)
                }
                
                anomaly = self.analyzer.user_analyzer.analyze_user_activity(username, activity_data)
                if anomaly:
                    anomalies.append({
                        'type': 'user',
                        'username': username,
                        'source_ip': activity_data['source_ip'],
                        'severity': self._calculate_severity(anomaly.get('anomaly_score', 0)),
                        'details': anomaly,
                        'timestamp': datetime.now().isoformat()
                    })
        except Exception as e:
            logger.error(f"用户活动分析错误: {str(e)}")
        
        return anomalies
    
    def _analyze_system_resources(self) -> List[Dict[str, Any]]:
        """分析系统资源异常"""
        anomalies = []
        
        try:
            # 获取系统资源数据
            anomaly = self.analyzer.system_analyzer.analyze_system_resources()
            if anomaly:
                anomalies.append({
                    'type': 'system',
                    'resource': 'overall',
                    'severity': self._calculate_severity(anomaly.get('anomaly_score', 0)),
                    'details': anomaly,
                    'timestamp': datetime.now().isoformat()
                })
        except Exception as e:
            logger.error(f"系统资源分析错误: {str(e)}")
        
        return anomalies
    
    def _calculate_severity(self, anomaly_score: float) -> str:
        """根据异常分数计算严重程度"""
        if anomaly_score >= 0.9:
            return '严重'
        elif anomaly_score >= 0.7:
            return '高'
        elif anomaly_score >= 0.5:
            return '中'
        else:
            return '低'
    
    def start(self) -> None:
        """启动所有监控器"""
        if self.running:
            logger.warning("行为监控器已经在运行")
            return
            
        logger.info("启动行为监控")
        self.running = True
        
        # 加载或创建基线
        self._setup_baseline()
        
        # 启动各个监控器
        self._start_monitor(self.process_monitor, "进程监控")
        self._start_monitor(self.file_monitor, "文件系统监控")
        self._start_monitor(self.network_monitor, "网络监控")
        self._start_monitor(self.user_monitor, "用户活动监控")
        self._start_monitor(self.system_monitor, "系统资源监控")
        
        # 启动定期报告线程
        self._start_reporting_thread()
        
        logger.info("所有监控器已启动")
    
    def stop(self) -> None:
        """停止所有监控器"""
        if not self.running:
            logger.warning("行为监控器未在运行")
            return
            
        logger.info("停止行为监控")
        self.running = False
        
        # 等待所有线程结束
        for thread in self.threads:
            thread.join(timeout=5.0)
        
        # 保存当前基线
        self._save_baseline()
        
        logger.info("所有监控器已停止")
    
    def _start_monitor(self, monitor, name: str) -> None:
        """启动单个监控器"""
        thread = threading.Thread(target=monitor.run, name=name)
        thread.daemon = True
        thread.start()
        self.threads.append(thread)
        logger.info(f"{name}线程已启动")
    
    def _start_reporting_thread(self) -> None:
        """启动定期报告线程"""
        thread = threading.Thread(target=self._reporting_loop, name="报告线程")
        thread.daemon = True
        thread.start()
        self.threads.append(thread)
        logger.info("报告线程已启动")
    
    def _reporting_loop(self) -> None:
        """定期生成和处理异常报告"""
        report_interval = self.config.get('report_interval', 300)  # 5分钟
        
        while self.running:
            try:
                # 生成综合报告
                report = self.analyzer.analyze_all()
                
                # 处理严重和高风险异常
                self._handle_high_severity_anomalies(report)
                
                # 每日摘要报告
                self._generate_daily_summary()
                
                # 休眠到下一个报告间隔
                time.sleep(report_interval)
            except Exception as e:
                logger.error(f"报告生成过程中发生错误: {str(e)}")
                time.sleep(60)  # 错误后延迟重试
    
    def _handle_high_severity_anomalies(self, report: Dict[str, Any]) -> None:
        """处理高严重性的异常"""
        now = time.time()
        
        for behavior_type, anomalies in report.get('anomalies', {}).items():
            for anomaly in anomalies:
                severity = anomaly.get('severity', '低')
                if severity in ['严重', '高']:
                    # 检查冷却时间
                    anomaly_key = f"{behavior_type}_{anomaly.get('pid', anomaly.get('username', anomaly.get('path', '')))}"
                    last_time = self.last_alert_time.get(anomaly_key, 0)
                    
                    if now - last_time > self.alert_cooldown:
                        # 发送警报
                        self.reporter.report_security_event(
                            event_type=f"behavior_anomaly_{behavior_type}",
                            details=anomaly,
                            severity=severity
                        )
                        
                        # 更新最后警报时间
                        self.last_alert_time[anomaly_key] = now
                        
                        logger.warning(f"检测到{severity}级异常: {behavior_type} - {anomaly.get('details', {}).get('unusual_aspects', [])}")
    
    def _generate_daily_summary(self) -> None:
        """生成每日异常摘要报告"""
        now = datetime.now()
        
        # 仅在每天0:00附近生成
        if now.hour == 0 and now.minute < 5:
            try:
                # 未实现: 收集一天的统计数据并生成摘要报告
                # 这里可以添加代码，从数据库或日志中提取过去24小时的异常
                pass
            except Exception as e:
                logger.error(f"生成每日摘要时发生错误: {str(e)}")
    
    def _setup_baseline(self) -> None:
        """设置行为基线，加载现有基线或创建新基线"""
        # 确保基线目录存在
        os.makedirs(os.path.dirname(self.baseline_path), exist_ok=True)
        
        baseline_file = f"{self.baseline_path}/behavior_baseline.json"
        
        # 尝试加载现有基线
        if os.path.exists(baseline_file):
            logger.info(f"尝试加载基线文件: {baseline_file}")
            success = self.analyzer.load_baseline(baseline_file)
            
            if success:
                logger.info("成功加载现有基线")
                return
            else:
                logger.warning("加载基线失败，将创建新基线")
        
        # 需要创建新基线
        if self.auto_baseline:
            logger.info(f"开始创建新基线，持续时间: {self.baseline_duration}分钟")
            from utils.behavior_analysis import build_baseline_from_current_system
            build_baseline_from_current_system(self.analyzer, self.baseline_duration)
            logger.info("新基线创建完成")
            
            # 保存新基线
            self._save_baseline()
        else:
            logger.warning("自动基线创建已禁用，系统将使用空基线启动，这将限制异常检测能力")
    
    def _save_baseline(self) -> None:
        """保存当前基线到文件"""
        baseline_file = f"{self.baseline_path}/behavior_baseline.json"
        os.makedirs(os.path.dirname(baseline_file), exist_ok=True)
        
        success = self.analyzer.save_baseline(baseline_file)
        
        if success:
            logger.info(f"基线已保存到: {baseline_file}")
        else:
            logger.error("保存基线失败")
    
    def get_status(self) -> Dict[str, Any]:
        """获取监控器状态"""
        status = {
            'running': self.running,
            'start_time': getattr(self, 'start_time', None),
            'uptime': time.time() - getattr(self, 'start_time', time.time()) if self.running else 0,
            'monitors': {
                'process': self.process_monitor.get_status(),
                'file': self.file_monitor.get_status(),
                'network': self.network_monitor.get_status(),
                'user': self.user_monitor.get_status(),
                'system': self.system_monitor.get_status()
            },
            'anomaly_count': {
                'total': sum(len(a) for a in getattr(self.analyzer, 'recent_anomalies', {}).values()),
                'by_type': {k: len(v) for k, v in getattr(self.analyzer, 'recent_anomalies', {}).items()}
            },
            'baseline_info': {
                k: v.get('timestamp', 'N/A') if v else 'Not established' 
                for k, v in self.analyzer.baselines.items()
            }
        }
        
        return status


class ProcessMonitor:
    """进程监控器，监控系统中的进程活动"""
    
    def __init__(self, analyzer: BehaviorAnalyzer, config: Dict[str, Any] = None):
        """初始化进程监控器"""
        self.analyzer = analyzer
        self.config = config or {}
        self.running = False
        self.scan_interval = self.config.get('scan_interval', 30)  # 秒
        self.process_analyzer = analyzer.process_analyzer
        self.known_processes = {}  # 已知进程缓存
        self.last_scan_time = 0
    
    def run(self) -> None:
        """运行进程监控主循环"""
        self.running = True
        self.last_scan_time = time.time()
        
        logger.info("进程监控器启动")
        
        while self.running:
            try:
                self._scan_processes()
                time.sleep(self.scan_interval)
            except Exception as e:
                logger.error(f"进程扫描期间发生错误: {str(e)}")
                time.sleep(60)  # 错误后延迟重试
        
        logger.info("进程监控器停止")
    
    def _scan_processes(self) -> None:
        """扫描系统进程"""
        current_time = time.time()
        current_pids = set()
        
        # 对所有进程进行扫描
        for proc in psutil.process_iter(['pid', 'name', 'create_time']):
            try:
                pid = proc.pid
                current_pids.add(pid)
                
                # 如果是新进程或已存在但需要更新
                if pid not in self.known_processes or \
                   current_time - self.known_processes[pid]['last_check'] > self.scan_interval:
                    # 获取详细信息
                    proc_data = self.process_analyzer._get_full_process_info(proc)
                    
                    if proc_data:
                        # 分析这个进程
                        anomaly = self.process_analyzer.analyze_process(proc_data)
                        
                        # 如果检测到异常，记录日志
                        if anomaly:
                            logger.warning(f"检测到进程异常: PID={pid}, 名称={proc_data.get('name')}, 分数={anomaly.get('anomaly_score')}")
                        
                        # 更新已知进程缓存
                        self.known_processes[pid] = {
                            'data': proc_data,
                            'last_check': current_time,
                            'anomaly': anomaly
                        }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # 清理已终止的进程
        terminated_pids = set(self.known_processes.keys()) - current_pids
        for pid in terminated_pids:
            del self.known_processes[pid]
        
        # 更新扫描时间
        self.last_scan_time = current_time
    
    def get_status(self) -> Dict[str, Any]:
        """获取监控器状态"""
        return {
            'running': self.running,
            'last_scan': self.last_scan_time,
            'scan_interval': self.scan_interval,
            'monitored_processes': len(self.known_processes),
            'anomalies_detected': sum(1 for p in self.known_processes.values() if p.get('anomaly'))
        }


class FileSystemMonitor:
    """文件系统监控器，监控文件系统活动"""
    
    def __init__(self, analyzer: BehaviorAnalyzer, config: Dict[str, Any] = None):
        """初始化文件系统监控器"""
        self.analyzer = analyzer
        self.config = config or {}
        self.running = False
        self.file_analyzer = analyzer.file_analyzer
        
        # 监控的路径
        self.monitored_paths = self.config.get('monitored_paths', [
            '/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin', 
            '/var/www', '/var/log', '/root'
        ])
        
        # 排除的路径
        self.excluded_paths = self.config.get('excluded_paths', [
            '/var/log/sharpeye'
        ])
        
        # inotify监控设置
        self.wm = None  # pyinotify WatchManager
        self.notifier = None  # pyinotify Notifier
        
        # 统计
        self.events_processed = 0
        self.anomalies_detected = 0
        self.start_time = 0
    
    def run(self) -> None:
        """运行文件系统监控主循环"""
        self.running = True
        self.start_time = time.time()
        
        try:
            # 设置inotify监控
            self._setup_inotify()
            
            # 运行通知器
            logger.info("文件系统监控器启动")
            self.notifier.loop()
        except Exception as e:
            logger.error(f"文件系统监控期间发生错误: {str(e)}")
        finally:
            self.running = False
            logger.info("文件系统监控器停止")
    
    def _setup_inotify(self) -> None:
        """设置inotify监控"""
        if not HAS_PYINOTIFY:
            logger.warning("pyinotify not available - filesystem monitoring disabled")
            return
        try:
            from pyinotify import WatchManager, Notifier, ProcessEvent, IN_CREATE, IN_MODIFY, IN_DELETE, IN_ATTRIB, IN_MOVED_FROM, IN_MOVED_TO
            
            # 事件处理器
            class EventHandler(ProcessEvent):
                def __init__(self, monitor):
                    self.monitor = monitor
                
                def process_default(self, event):
                    self.monitor._handle_file_event(event)
            
            # 创建监控管理器
            self.wm = WatchManager()
            handler = EventHandler(self)
            self.notifier = Notifier(self.wm, handler)
            
            # 添加监控路径
            mask = IN_CREATE | IN_MODIFY | IN_DELETE | IN_ATTRIB | IN_MOVED_FROM | IN_MOVED_TO
            for path in self.monitored_paths:
                if os.path.exists(path):
                    self.wm.add_watch(path, mask, rec=True)
                    logger.debug(f"添加监控路径: {path}")
                else:
                    logger.warning(f"监控路径不存在: {path}")
            
            logger.info(f"文件系统监控已设置，监控{len(self.monitored_paths)}个路径")
        except Exception as e:
            logger.error(f"设置inotify监控时发生错误: {str(e)}")
            raise
    
    def _handle_file_event(self, event) -> None:
        """处理文件事件"""
        # 仅处理正常文件事件
        if not event.pathname:
            return
            
        # 检查是否在排除路径中
        for excluded in self.excluded_paths:
            if event.pathname.startswith(excluded):
                return
        
        # 提取事件信息
        path = event.pathname
        operation_type = 0
        
        # 确定操作类型
        if HAS_PYINOTIFY:
            if event.mask & (pyinotify.IN_CREATE | pyinotify.IN_MOVED_TO):
                operation_type = 2  # 写入
                operation = "创建"
            elif event.mask & pyinotify.IN_MODIFY:
                operation_type = 2  # 写入
                operation = "修改"
            elif event.mask & (pyinotify.IN_DELETE | pyinotify.IN_MOVED_FROM):
                operation_type = 4  # 删除
                operation = "删除"
            elif event.mask & pyinotify.IN_ATTRIB:
                operation_type = 5  # 属性变更
                operation = "属性变更"
            elif event.mask & pyinotify.IN_ACCESS:
                operation_type = 1  # 读取
                operation = "访问"
            else:
                operation_type = 0
                operation = "其他"
        else:
            # Fallback when pyinotify not available
            operation_type = 0
            operation = "未知"
        
        # 获取文件信息
        file_info = {
            'path': path,
            'operation': operation,
            'operation_type': operation_type,
            'timestamp': time.time(),
            'size': os.path.getsize(path) if os.path.exists(path) and not os.path.isdir(path) else 0,
            'permissions': os.stat(path).st_mode if os.path.exists(path) else 0,
            'uid': os.stat(path).st_uid if os.path.exists(path) else 0,
            'operation_frequency': 1  # 默认频率
        }
        
        # 增加事件计数
        self.events_processed += 1
        
        # 分析文件活动
        anomaly = self.file_analyzer.analyze_file_activity(file_info)
        
        # 如果检测到异常，记录日志
        if anomaly:
            self.anomalies_detected += 1
            logger.warning(f"检测到文件操作异常: 路径={path}, 操作={operation}, 分数={anomaly.get('anomaly_score')}")
    
    def get_status(self) -> Dict[str, Any]:
        """获取监控器状态"""
        return {
            'running': self.running,
            'start_time': self.start_time,
            'events_processed': self.events_processed,
            'anomalies_detected': self.anomalies_detected,
            'monitored_paths': len(self.monitored_paths),
            'excluded_paths': len(self.excluded_paths)
        }


class NetworkMonitor:
    """网络监控器，监控网络连接活动"""
    
    def __init__(self, analyzer: BehaviorAnalyzer, config: Dict[str, Any] = None):
        """初始化网络监控器"""
        self.analyzer = analyzer
        self.config = config or {}
        self.running = False
        self.scan_interval = self.config.get('scan_interval', 10)  # 秒
        self.network_analyzer = analyzer.network_analyzer
        self.last_scan_time = 0
        self.connections_history = {}
        self.events_processed = 0
        self.anomalies_detected = 0
    
    def run(self) -> None:
        """运行网络监控主循环"""
        self.running = True
        self.last_scan_time = time.time()
        
        logger.info("网络监控器启动")
        
        while self.running:
            try:
                self._scan_connections()
                time.sleep(self.scan_interval)
            except Exception as e:
                logger.error(f"网络连接扫描期间发生错误: {str(e)}")
                time.sleep(60)  # 错误后延迟重试
        
        logger.info("网络监控器停止")
    
    def _scan_connections(self) -> None:
        """扫描网络连接"""
        current_time = time.time()
        
        try:
            # 获取所有网络连接
            connections = psutil.net_connections(kind='all')
            
            # 处理每个连接
            current_connections = {}
            
            for conn in connections:
                # 跳过无远程地址的连接
                if not conn.raddr:
                    continue
                
                # 连接标识符: 协议-本地地址:端口-远程地址:端口
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "0.0.0.0:0"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "0.0.0.0:0"
                conn_id = f"{conn.type}-{laddr}-{raddr}"
                
                # 构建连接数据
                conn_data = {
                    'timestamp': current_time,
                    'protocol': 'tcp' if conn.type == socket.SOCK_STREAM else 'udp' if conn.type == socket.SOCK_DGRAM else 'other',
                    'local_ip': conn.laddr.ip if conn.laddr else "0.0.0.0",
                    'local_port': conn.laddr.port if conn.laddr else 0,
                    'remote_ip': conn.raddr.ip if conn.raddr else "0.0.0.0",
                    'remote_port': conn.raddr.port if conn.raddr else 0,
                    'state': conn.status if hasattr(conn, 'status') else '',
                    'pid': conn.pid if conn.pid else None,
                    'data_sent': 0,
                    'data_recv': 0,
                    'duration': 0,
                    'frequency': 1,
                    'is_beacon': False,
                    'is_encrypted': False,
                    'packet_size': 0,
                    'is_cloud_provider': False,
                    'is_known_bad': False  # 需要与威胁情报集成
                }
                
                # 如果连接以前见过，计算持续时间和更新计数器
                if conn_id in self.connections_history:
                    prev_data = self.connections_history[conn_id]
                    conn_data['duration'] = current_time - prev_data.get('first_seen', current_time)
                    
                    # 增加频率计数
                    time_diff = current_time - prev_data.get('timestamp', current_time)
                    if time_diff < 60:  # 1分钟内
                        conn_data['frequency'] = prev_data.get('frequency', 1) + 1
                    
                    # 信标检测 - 如果连接模式规律且持续时间较长
                    if conn_data['duration'] > 600:  # 10分钟以上
                        timestamps = prev_data.get('timestamps', [])
                        if len(timestamps) >= 5:
                            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
                            std_dev = np.std(intervals)
                            mean_interval = np.mean(intervals)
                            
                            # 如果间隔标准差小且平均间隔在10-600秒之间，认为是信标
                            if std_dev / mean_interval < 0.2 and 10 < mean_interval < 600:
                                conn_data['is_beacon'] = True
                else:
                    conn_data['first_seen'] = current_time
                    conn_data['timestamps'] = []
                
                # 更新时间戳列表
                timestamps = self.connections_history.get(conn_id, {}).get('timestamps', [])[-9:] + [current_time]
                conn_data['timestamps'] = timestamps
                
                # 获取网络流量统计（如果可用）
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        io_counters = proc.io_counters()
                        conn_data['data_sent'] = io_counters.write_bytes if hasattr(io_counters, 'write_bytes') else 0
                        conn_data['data_recv'] = io_counters.read_bytes if hasattr(io_counters, 'read_bytes') else 0
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                # 检查是否为云提供商IP（简单检查，可以集成威胁情报增强）
                cloud_ranges = [
                    ('52.0.0.0', '54.255.255.255'),  # AWS
                    ('34.0.0.0', '35.255.255.255'),  # Google
                    ('40.0.0.0', '40.255.255.255'),  # Azure
                    ('104.16.0.0', '104.31.255.255'),  # Cloudflare
                ]
                
                remote_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
                ip_int = int(''.join('%02x' % int(x) for x in remote_ip.split('.')), 16)
                
                for start_ip, end_ip in cloud_ranges:
                    start_int = int(''.join('%02x' % int(x) for x in start_ip.split('.')), 16)
                    end_int = int(''.join('%02x' % int(x) for x in end_ip.split('.')), 16)
                    if start_int <= ip_int <= end_int:
                        conn_data['is_cloud_provider'] = True
                        break
                
                # 加密流量检查（基于端口的简单猜测）
                if conn.raddr.port in [443, 465, 993, 995, 8443, 22]:
                    conn_data['is_encrypted'] = True
                
                # 存储连接数据
                current_connections[conn_id] = conn_data
                
                # 增加事件计数
                self.events_processed += 1
                
                # 分析网络连接
                anomaly = self.network_analyzer.analyze_connection(conn_data)
                
                # 如果检测到异常，记录日志
                if anomaly:
                    self.anomalies_detected += 1
                    logger.warning(f"检测到网络连接异常: IP={remote_ip}:{conn.raddr.port}, 分数={anomaly.get('anomaly_score')}")
            
            # 更新连接历史
            self.connections_history = current_connections
            
            # 更新扫描时间
            self.last_scan_time = current_time
        except Exception as e:
            logger.error(f"网络连接扫描错误: {str(e)}")
    
    def get_status(self) -> Dict[str, Any]:
        """获取监控器状态"""
        return {
            'running': self.running,
            'last_scan': self.last_scan_time,
            'scan_interval': self.scan_interval,
            'monitored_connections': len(self.connections_history),
            'events_processed': self.events_processed,
            'anomalies_detected': self.anomalies_detected
        }


class UserMonitor:
    """用户活动监控器，监控用户登录和活动"""
    
    def __init__(self, analyzer: BehaviorAnalyzer, config: Dict[str, Any] = None):
        """初始化用户活动监控器"""
        self.analyzer = analyzer
        self.config = config or {}
        self.running = False
        self.scan_interval = self.config.get('scan_interval', 60)  # 秒
        self.user_analyzer = analyzer.user_analyzer
        self.last_scan_time = 0
        self.user_activities = {}
        self.events_processed = 0
        self.anomalies_detected = 0
        
        # 用户IP映射
        self.user_ips = {}  # 用户名 -> 常见IP列表
    
    def run(self) -> None:
        """运行用户监控主循环"""
        self.running = True
        self.last_scan_time = time.time()
        
        logger.info("用户活动监控器启动")
        
        while self.running:
            try:
                self._scan_user_activities()
                time.sleep(self.scan_interval)
            except Exception as e:
                logger.error(f"用户活动扫描期间发生错误: {str(e)}")
                time.sleep(60)  # 错误后延迟重试
        
        logger.info("用户活动监控器停止")
    
    def _scan_user_activities(self) -> None:
        """扫描用户活动"""
        current_time = time.time()
        
        try:
            # 获取当前登录用户
            logged_in_users = self._get_logged_in_users()
            
            # 检查日志文件变化
            self._check_auth_logs()
            
            # 处理每个登录用户的活动
            for username, login_data in logged_in_users.items():
                # 构建用户活动数据
                activity_data = {
                    'username': username,
                    'login_time': login_data.get('login_time', 0),
                    'source_ip': login_data.get('source_ip', '127.0.0.1'),
                    'session_duration': current_time - login_data.get('login_time', current_time),
                    'is_remote': login_data.get('is_remote', False),
                    'terminal': login_data.get('terminal', ''),
                    'is_usual_ip': True,  # 默认为常见IP
                    'login_failures': 0,
                    'privilege_changes': 0,
                    'command_count': 0,
                    'sudo_count': 0,
                    'sensitive_file_access': 0
                }
                
                # 检查是否是常见IP
                if username in self.user_ips:
                    source_ip = login_data.get('source_ip', '127.0.0.1')
                    if source_ip not in self.user_ips[username]:
                        activity_data['is_usual_ip'] = False
                        
                        # 如果是首次见到此用户，记录IP
                        if len(self.user_ips[username]) < 5:  # 最多记录5个常见IP
                            self.user_ips[username].append(source_ip)
                else:
                    # 首次见到此用户
                    self.user_ips[username] = [login_data.get('source_ip', '127.0.0.1')]
                
                # 从日志中获取登录失败计数（这里使用模拟数据）
                activity_data['login_failures'] = 0
                
                # 增加活动计数
                self.events_processed += 1
                
                # 分析用户活动
                anomaly = self.user_analyzer.analyze_user_activity(username, activity_data)
                
                # 如果检测到异常，记录日志
                if anomaly:
                    self.anomalies_detected += 1
                    logger.warning(f"检测到用户活动异常: 用户={username}, 分数={anomaly.get('anomaly_score')}")
                
                # 存储用户活动
                self.user_activities[username] = activity_data
            
            # 更新扫描时间
            self.last_scan_time = current_time
        except Exception as e:
            logger.error(f"用户活动扫描错误: {str(e)}")
    
    def _get_logged_in_users(self) -> Dict[str, Dict[str, Any]]:
        """获取当前登录用户的信息"""
        logged_in_users = {}
        
        try:
            # 使用who命令获取登录用户
            import subprocess
            output = subprocess.check_output(['who'], universal_newlines=True)
            
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    username = parts[0]
                    terminal = parts[1]
                    
                    # 解析登录时间
                    login_time_str = ' '.join(parts[2:4])
                    try:
                        login_time = time.mktime(time.strptime(login_time_str, '%Y-%m-%d %H:%M'))
                    except ValueError:
                        try:
                            current_year = time.strftime('%Y')
                            login_time = time.mktime(time.strptime(f"{current_year} {login_time_str}", '%Y %b %d %H:%M'))
                        except ValueError:
                            login_time = time.time()
                    
                    # 解析源IP
                    source_ip = '127.0.0.1'
                    is_remote = False
                    if len(parts) >= 5 and '(' in parts[4] and ')' in parts[4]:
                        source_ip = parts[4].strip('()')
                        is_remote = source_ip != '127.0.0.1' and source_ip != 'localhost'
                    
                    logged_in_users[username] = {
                        'username': username,
                        'terminal': terminal,
                        'login_time': login_time,
                        'source_ip': source_ip,
                        'is_remote': is_remote
                    }
            
            return logged_in_users
        except Exception as e:
            logger.error(f"获取登录用户信息错误: {str(e)}")
            return {}
    
    def _check_auth_logs(self) -> None:
        """检查认证日志中的用户活动"""
        # 此函数在实际实现中应该解析/var/log/auth.log或类似文件
        # 由于文件访问权限问题和系统差异，这里仅提供框架
        auth_log_path = '/var/log/auth.log'
        
        if not os.path.exists(auth_log_path):
            return
            
        try:
            # 实际实现应该使用增量读取而不是一次性读取整个文件
            # 可以使用文件位置标记来跟踪上次读取位置
            pass
        except Exception as e:
            logger.error(f"解析认证日志错误: {str(e)}")
    
    def get_status(self) -> Dict[str, Any]:
        """获取监控器状态"""
        return {
            'running': self.running,
            'last_scan': self.last_scan_time,
            'scan_interval': self.scan_interval,
            'monitored_users': len(self.user_activities),
            'events_processed': self.events_processed,
            'anomalies_detected': self.anomalies_detected
        }


class SystemMonitor:
    """系统资源监控器，监控系统资源使用情况"""
    
    def __init__(self, analyzer: BehaviorAnalyzer, config: Dict[str, Any] = None):
        """初始化系统资源监控器"""
        self.analyzer = analyzer
        self.config = config or {}
        self.running = False
        self.scan_interval = self.config.get('scan_interval', 60)  # 秒
        self.system_analyzer = analyzer.system_analyzer
        self.last_scan_time = 0
        self.events_processed = 0
        self.anomalies_detected = 0
    
    def run(self) -> None:
        """运行系统资源监控主循环"""
        self.running = True
        self.last_scan_time = time.time()
        
        logger.info("系统资源监控器启动")
        
        while self.running:
            try:
                self._scan_system_resources()
                time.sleep(self.scan_interval)
            except Exception as e:
                logger.error(f"系统资源扫描期间发生错误: {str(e)}")
                time.sleep(60)  # 错误后延迟重试
        
        logger.info("系统资源监控器停止")
    
    def _scan_system_resources(self) -> None:
        """扫描系统资源使用情况"""
        current_time = time.time()
        
        try:
            # 获取系统资源数据
            sys_data = self.system_analyzer.get_system_data()
            
            if sys_data:
                # 增加事件计数
                self.events_processed += 1
                
                # 分析系统资源
                anomaly = self.system_analyzer.analyze_system_resources()
                
                # 如果检测到异常，记录日志
                if anomaly:
                    self.anomalies_detected += 1
                    logger.warning(f"检测到系统资源异常: 分数={anomaly.get('anomaly_score')}")
            
            # 更新扫描时间
            self.last_scan_time = current_time
        except Exception as e:
            logger.error(f"系统资源扫描错误: {str(e)}")
    
    def get_status(self) -> Dict[str, Any]:
        """获取监控器状态"""
        return {
            'running': self.running,
            'last_scan': self.last_scan_time,
            'scan_interval': self.scan_interval,
            'events_processed': self.events_processed,
            'anomalies_detected': self.anomalies_detected
        }


# 当作为脚本运行时的入口点
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, 
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # 创建监控器
    monitor = BehaviorMonitor()
    
    try:
        # 启动监控
        monitor.start()
        
        # 保持运行
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        logger.info("收到中断信号，正在停止监控...")
    finally:
        # 停止监控
        monitor.stop()