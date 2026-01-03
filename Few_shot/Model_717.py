import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Set
from torch.utils.data import DataLoader, Dataset
import random
from sklearn.metrics import f1_score, accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder
import os
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict, Counter
import json
import yaml
from dataclasses import dataclass, field
from pathlib import Path
import argparse
from sklearn.metrics import f1_score, accuracy_score, classification_report


# ===========================
# 配置类：定义协议配置
# ===========================

@dataclass
class ProtocolConfig:
    """协议配置类，定义单个协议的结构"""
    name: str  # 协议名称
    txt_file: str  # 原始数据文件路径
    csv_file: str  # 标签文件路径
    parser_func: str  # 解析函数名称
    min_length: int = 8  # 最小数据包长度
    header_patterns: List[bytes] = field(default_factory=list)  # 协议头部特征
    port: Optional[int] = None  # 协议端口号
    description: str = ""  # 协议描述


@dataclass
class TransferConfig:
    """迁移学习配置类"""
    source_protocols: List[str]  # 源协议列表
    target_protocol: str  # 目标协议
    model_params: Dict = field(default_factory=dict)  # 模型参数
    training_params: Dict = field(default_factory=dict)  # 训练参数
    data_split: Dict = field(default_factory=dict)  # 数据分割比例


# ===========================
# 扩展的协议数据加载器 - 修复版本
# ===========================

class AdvancedProtocolDataLoader:
    """高级协议数据加载器，支持更多真实协议"""

    def __init__(self, data_root: str = "../Msg2", config_file: Optional[str] = None):
        self.data_root = Path(data_root)
        self.protocols: Dict[str, ProtocolConfig] = {}
        self.parsers: Dict[str, callable] = {}

        # 注册内置解析器
        self._register_builtin_parsers()

        # 自动发现协议数据
        self._auto_discover_protocols()

        # 如果提供了配置文件，则加载
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)

        # 统一语义标签体系
        self.unified_semantic_types = [
            'PADDING', 'HEADER', 'ADDRESS', 'COMMAND', 'LENGTH',
            'DATA', 'CHECKSUM', 'CONTROL', 'FUNCTION', 'OPTION',
            'TIMESTAMP', 'VERSION', 'FLAGS', 'PAYLOAD'
        ]

        self.unified_semantic_functions = [
            'UNKNOWN', 'IDENTIFIER', 'ADDRESSING', 'CONTROL_CMD',
            'DATA_LENGTH', 'PAYLOAD', 'VALIDATION', 'RESERVED',
            'PROTOCOL_SPECIFIC', 'CONFIGURATION', 'SESSION_MGMT',
            'SECURITY', 'ROUTING', 'APPLICATION_DATA'
        ]

    def _auto_discover_protocols(self):
        """自动发现可用协议数据"""
        print("🔍 自动发现协议数据...")

        # 定义支持的协议及其默认配置
        supported_protocols = {
            'smb': {
                'parser_func': 'parse_smb',
                'min_length': 32,
                'port': 445,
                'description': 'Server Message Block协议'
            },
            'smb2': {
                'parser_func': 'parse_smb2',
                'min_length': 64,
                'port': 445,
                'description': 'Server Message Block v2协议'
            },
            'dns': {
                'parser_func': 'parse_dns',
                'min_length': 12,
                'port': 53,
                'description': 'Domain Name System协议'
            },
            's7comm': {
                'parser_func': 'parse_s7comm',
                'min_length': 8,
                'port': 102,
                'description': 'Siemens S7COMM协议'
            },
            'dnp3': {
                'parser_func': 'parse_dnp3',
                'min_length': 10,
                'port': 20000,
                'description': 'Distributed Network Protocol 3'
            },
            'modbus': {
                'parser_func': 'parse_modbus',
                'min_length': 8,
                'port': 502,
                'description': 'Modbus TCP协议'
            },
            'ftp': {
                'parser_func': 'parse_ftp',
                'min_length': 4,
                'port': 21,
                'description': 'File Transfer Protocol'
            },
            'tls': {
                'parser_func': 'parse_tls',
                'min_length': 5,
                'port': 443,
                'description': 'Transport Layer Security 1.2'
            },
            'dhcp': {
                'parser_func': 'parse_dhcp',
                'min_length': 240,
                'port': 67,
                'description': 'Dynamic Host Configuration Protocol'
            }
        }

        discovered_protocols = []

        for protocol_name, default_config in supported_protocols.items():
            # 查找TXT和CSV文件
            txt_candidates = list(self.data_root.glob(f"txt/**/*{protocol_name}*.txt"))
            csv_candidates = list(self.data_root.glob(f"csv/**/*{protocol_name}*.csv"))

            # 也尝试大写形式
            txt_candidates.extend(self.data_root.glob(f"txt/**/*{protocol_name.upper()}*.txt"))
            csv_candidates.extend(self.data_root.glob(f"csv/**/*{protocol_name.upper()}*.csv"))

            if txt_candidates and csv_candidates:
                txt_file = str(txt_candidates[0])
                csv_file = str(csv_candidates[0])

                protocol_config = ProtocolConfig(
                    name=protocol_name,
                    txt_file=txt_file,
                    csv_file=csv_file,
                    **default_config
                )

                self.protocols[protocol_name] = protocol_config
                discovered_protocols.append(protocol_name)
                print(f" 发现协议: {protocol_name}")
                print(f"     - TXT: {txt_file}")
                print(f"     - CSV: {csv_file}")

        if not discovered_protocols:
            print(" 未发现协议数据文件")
        else:
            print(f" 总共发现 {len(discovered_protocols)} 个协议: {discovered_protocols}")

    def _register_builtin_parsers(self):
        """注册内置协议解析器"""
        self.parsers.update({
            'parse_modbus': self._parse_modbus,
            'parse_dnp3': self._parse_dnp3,
            'parse_s7comm': self._parse_s7comm,
            'parse_smb': self._parse_smb,
            'parse_smb2': self._parse_smb2,
            'parse_dns': self._parse_dns,
            'parse_ftp': self._parse_ftp,
            'parse_tls': self._parse_tls,
            'parse_dhcp': self._parse_dhcp,
            'parse_generic': self._parse_generic
        })

    def get_available_protocols(self) -> List[str]:
        """获取可用协议列表"""
        return list(self.protocols.keys())

    def register_protocol(self, protocol_config: ProtocolConfig, parser_func: callable = None):
        """动态注册新协议"""
        self.protocols[protocol_config.name] = protocol_config

        if parser_func:
            self.parsers[protocol_config.parser_func] = parser_func

        print(f"协议 '{protocol_config.name}' 注册成功")

    def load_protocol_data(self, protocol_name: str) -> List[Dict]:
        """加载指定协议的数据 - 修复版本"""
        if protocol_name not in self.protocols:
            raise ValueError(f"未知协议: {protocol_name}. 可用协议: {self.get_available_protocols()}")

        config = self.protocols[protocol_name]
        parser_func = self.parsers.get(config.parser_func, self._parse_generic)

        print(f"加载 {protocol_name.upper()} 协议数据...")
        print(f"  - 数据文件: {config.txt_file}")
        print(f"  - 标签文件: {config.csv_file}")

        return parser_func(config)

    # ========== 协议解析器实现 - 修复版本 ==========

    def _parse_modbus(self, config: ProtocolConfig) -> List[Dict]:
        """Modbus协议解析器"""
        return self._parse_with_new_labels(config, self._create_modbus_ground_truth)

    def _parse_dnp3(self, config: ProtocolConfig) -> List[Dict]:
        """DNP3协议解析器"""
        return self._parse_with_new_labels(config, self._create_dnp3_ground_truth)

    def _parse_s7comm(self, config: ProtocolConfig) -> List[Dict]:
        """S7COMM协议解析器"""
        return self._parse_with_new_labels(config, self._create_s7comm_ground_truth)

    def _parse_smb(self, config: ProtocolConfig) -> List[Dict]:
        """SMB协议解析器"""
        return self._parse_with_new_labels(config, self._create_smb_ground_truth)

    def _parse_smb2(self, config: ProtocolConfig) -> List[Dict]:
        """SMB2协议解析器"""
        return self._parse_with_new_labels(config, self._create_smb2_ground_truth)

    def _parse_dns(self, config: ProtocolConfig) -> List[Dict]:
        """DNS协议解析器"""
        return self._parse_with_new_labels(config, self._create_dns_ground_truth)

    def _parse_ftp(self, config: ProtocolConfig) -> List[Dict]:
        """FTP协议解析器"""
        return self._parse_with_new_labels(config, self._create_ftp_ground_truth)

    def _parse_tls(self, config: ProtocolConfig) -> List[Dict]:
        """TLS1.2协议解析器"""
        return self._parse_with_new_labels(config, self._create_tls_ground_truth)

    def _parse_dhcp(self, config: ProtocolConfig) -> List[Dict]:
        """DHCP协议解析器"""
        return self._parse_with_new_labels(config, self._create_dhcp_ground_truth)

    def _parse_with_new_labels(self, config: ProtocolConfig, ground_truth_func) -> List[Dict]:
        """使用新的标签格式解析协议数据 - 修复版本"""
        try:
            # 读取HEX数据
            with open(config.txt_file, 'r', encoding='utf-8') as f:
                hex_packets = [line.strip() for line in f if line.strip()]

            # 读取标签数据
            df = pd.read_csv(config.csv_file)

            # 检查必要的列
            required_columns = ['HexData', 'FunctionCode', 'Boundaries', 'SemanticTypes', 'SemanticFunctions']
            missing_columns = [col for col in required_columns if col not in df.columns]

            if missing_columns:
                print(f"警告: CSV文件缺少列: {missing_columns}")
                # 使用旧的解析方式
                return self._parse_with_labels(config, ground_truth_func)

            min_len = min(len(hex_packets), len(df))
            data = []
            valid_boundary_samples = 0

            for i in range(min_len):
                try:
                    # 从DataFrame获取数据
                    row = df.iloc[i]
                    hex_data = row['HexData']
                    function_code = row['FunctionCode']

                    # 清理hex数据
                    hex_data = hex_data.replace(' ', '').replace('\t', '')
                    if len(hex_data) % 2 != 0:
                        continue

                    raw_bytes = bytes.fromhex(hex_data)
                    if len(raw_bytes) < config.min_length:
                        continue

                    # 【修复】解析边界信息 - 改进边界处理逻辑
                    boundaries_str = row.get('Boundaries', '')
                    boundaries = []
                    if boundaries_str and str(boundaries_str) != 'nan' and boundaries_str != '':
                        try:
                            # 处理逗号分隔的边界
                            boundary_parts = str(boundaries_str).split(',')
                            for part in boundary_parts:
                                part = part.strip()
                                if part and part != '-1':  # 过滤掉-1和空值
                                    boundaries.append(int(part))
                        except ValueError as e:
                            print(f"边界解析错误(行{i}): {boundaries_str} - {e}")
                            continue

                    # 【修复】过滤无效边界并排序
                    boundaries = [b for b in boundaries if 0 <= b < len(raw_bytes)]
                    boundaries = sorted(list(set(boundaries)))  # 去重并排序

                    # 【新增】验证边界质量
                    if len(boundaries) == 0:
                        # 如果没有边界，使用基于协议的默认边界
                        boundaries = self._generate_default_boundaries(raw_bytes, config.name)

                    # 解析语义信息
                    semantic_types = {}
                    semantic_functions = {}

                    try:
                        if 'SemanticTypes' in row and pd.notna(row['SemanticTypes']):
                            semantic_types = json.loads(row['SemanticTypes'])
                    except:
                        pass

                    try:
                        if 'SemanticFunctions' in row and pd.notna(row['SemanticFunctions']):
                            semantic_functions = json.loads(row['SemanticFunctions'])
                    except:
                        pass

                    # 创建ground truth
                    ground_truth = {
                        'syntax_boundaries': boundaries,
                        'semantic_types': {str(k): v for k, v in semantic_types.items()},
                        'semantic_functions': {str(k): v for k, v in semantic_functions.items()}
                    }

                    sample = {
                        'raw_data': hex_data,
                        'protocol': config.name,
                        'function_code': function_code,
                        'ground_truth': ground_truth,
                        'length': len(raw_bytes)
                    }
                    data.append(sample)

                    if len(boundaries) > 0:
                        valid_boundary_samples += 1

                except Exception as e:
                    print(f"处理第 {i} 行数据时出错: {e}")
                    continue

            print(f"成功加载 {len(data)} 条 {config.name.upper()} 数据")
            print(f"  - 有效边界样本: {valid_boundary_samples}/{len(data)}")
            return data

        except Exception as e:
            print(f"解析 {config.name} 失败: {e}")
            # 回退到旧的解析方式
            return self._parse_with_labels(config, ground_truth_func)

    def _generate_default_boundaries(self, raw_bytes: bytes, protocol_name: str) -> List[int]:
        """生成默认边界 - 基于协议特征"""
        boundaries = []

        if protocol_name == 'modbus':
            # Modbus TCP结构: MBAP头(7字节) + PDU
            if len(raw_bytes) >= 8:
                boundaries = [0, 2, 4, 6, 7]  # 主要字段边界
                if len(raw_bytes) > 8:
                    boundaries.append(8)  # 数据开始

        elif protocol_name == 'dnp3':
            # DNP3结构
            if len(raw_bytes) >= 10:
                boundaries = [0, 2, 3, 4, 6, 8, 10]  # 基于DNP3结构

        else:
            # 通用协议：按固定间隔划分
            step = max(2, len(raw_bytes) // 8)  # 最少8个段
            boundaries = list(range(0, len(raw_bytes), step))

        # 确保边界在有效范围内
        boundaries = [b for b in boundaries if 0 <= b < len(raw_bytes)]
        return sorted(boundaries)

    def _parse_with_labels(self, config: ProtocolConfig, ground_truth_func) -> List[Dict]:
        """通用的带标签解析方法 - 保留作为备用"""
        try:
            # 读取HEX数据
            with open(config.txt_file, 'r', encoding='utf-8') as f:
                hex_packets = [line.strip() for line in f if line.strip()]

            # 读取标签数据
            df = pd.read_csv(config.csv_file)

            # 确定标签列
            label_column = None
            for col in ['Label', 'label', 'Function', 'Type', 'Category', 'FunctionCode']:
                if col in df.columns:
                    label_column = col
                    break

            if label_column is None:
                label_column = df.columns[-1]  # 使用最后一列作为标签

            min_len = min(len(hex_packets), len(df))
            data = []

            for i in range(min_len):
                try:
                    hex_data = hex_packets[i]
                    label = df.iloc[i][label_column] if i < len(df) else 'UNKNOWN'

                    # 清理hex数据
                    hex_data = hex_data.replace(' ', '').replace('\t', '')
                    if len(hex_data) % 2 != 0:
                        continue

                    raw_bytes = bytes.fromhex(hex_data)
                    if len(raw_bytes) >= config.min_length:
                        sample = {
                            'raw_data': hex_data,
                            'protocol': config.name,
                            'function_code': label,
                            'ground_truth': ground_truth_func(raw_bytes, label),
                            'length': len(raw_bytes)
                        }
                        data.append(sample)
                except Exception as e:
                    continue

            print(f"成功加载 {len(data)} 条 {config.name.upper()} 数据")
            return data

        except Exception as e:
            print(f"解析 {config.name} 失败: {e}")
            return []

    def _parse_generic(self, config: ProtocolConfig) -> List[Dict]:
        """通用协议解析器"""
        return self._parse_with_new_labels(config, self._create_generic_ground_truth)

    # ========== Ground Truth 创建函数 - 修复版本 ==========

    def _create_modbus_ground_truth(self, raw_bytes: bytes, label) -> Dict:
        """创建Modbus ground truth - 修复边界逻辑"""
        annotations = {'syntax_boundaries': [], 'semantic_types': {}, 'semantic_functions': {}}

        if len(raw_bytes) < 8:
            return annotations

        # 【修复】Modbus TCP结构边界定义
        # MBAP头: [事务ID(2) | 协议ID(2) | 长度(2) | 单元ID(1) | 功能码(1) | 数据(...)]
        boundaries = [0, 2, 4, 6, 7]  # 字段起始位置

        if len(raw_bytes) > 8:
            boundaries.append(8)  # 数据部分开始

        # 语义标注
        field_mapping = [
            (0, 1, 'HEADER', 'IDENTIFIER'),  # 事务ID
            (2, 3, 'HEADER', 'PROTOCOL_SPECIFIC'),  # 协议ID
            (4, 5, 'LENGTH', 'DATA_LENGTH'),  # 长度
            (6, 6, 'ADDRESS', 'ADDRESSING'),  # 单元ID
            (7, 7, 'COMMAND', 'CONTROL_CMD'),  # 功能码
        ]

        for start, end, sem_type, sem_func in field_mapping:
            for pos in range(start, min(end + 1, len(raw_bytes))):
                annotations['semantic_types'][str(pos)] = sem_type
                annotations['semantic_functions'][str(pos)] = sem_func

        # 数据字段
        for i in range(8, len(raw_bytes)):
            annotations['semantic_types'][str(i)] = 'DATA'
            annotations['semantic_functions'][str(i)] = 'PAYLOAD'

        # 确保边界在有效范围内
        boundaries = [b for b in boundaries if b < len(raw_bytes)]
        annotations['syntax_boundaries'] = sorted(boundaries)

        return annotations

    def _create_dnp3_ground_truth(self, raw_bytes: bytes, label) -> Dict:
        """创建DNP3 ground truth - 修复边界逻辑"""
        annotations = {'syntax_boundaries': [], 'semantic_types': {}, 'semantic_functions': {}}

        if len(raw_bytes) < 10:
            return annotations

        # 【修复】DNP3数据链路层结构边界
        boundaries = []

        # DNP3数据链路层: [起始(2) | 长度(1) | 控制(1) | 目标(2) | 源(2) | CRC(2) | ...]
        if len(raw_bytes) >= 2 and raw_bytes[0] == 0x05 and raw_bytes[1] == 0x64:
            boundaries = [0, 2, 3, 4, 6, 8]  # 主要字段边界
            if len(raw_bytes) > 10:
                boundaries.append(10)  # 应用层开始

            # 语义标注
            field_mapping = [
                (0, 1, 'HEADER', 'IDENTIFIER'),  # 起始字节
                (2, 2, 'LENGTH', 'DATA_LENGTH'),  # 长度
                (3, 3, 'CONTROL', 'CONTROL_CMD'),  # 控制
                (4, 5, 'ADDRESS', 'ADDRESSING'),  # 目标地址
                (6, 7, 'ADDRESS', 'ADDRESSING'),  # 源地址
                (8, 9, 'CHECKSUM', 'VALIDATION'),  # CRC
            ]
        else:
            # 应用层格式
            boundaries = [0, 1, 2]
            if len(raw_bytes) > 4:
                boundaries.extend([4, 6, 8])

            field_mapping = [
                (0, 0, 'CONTROL', 'CONTROL_CMD'),  # 应用控制
                (1, 1, 'COMMAND', 'CONTROL_CMD'),  # 功能码
            ]

        # 应用语义标注
        for start, end, sem_type, sem_func in field_mapping:
            for pos in range(start, min(end + 1, len(raw_bytes))):
                annotations['semantic_types'][str(pos)] = sem_type
                annotations['semantic_functions'][str(pos)] = sem_func

        # 剩余数据
        data_start = max(boundaries) + 1 if boundaries else 0
        for i in range(data_start, len(raw_bytes)):
            annotations['semantic_types'][str(i)] = 'DATA'
            annotations['semantic_functions'][str(i)] = 'PAYLOAD'

        # 确保边界在有效范围内
        boundaries = [b for b in boundaries if b < len(raw_bytes)]
        annotations['syntax_boundaries'] = sorted(boundaries)

        return annotations

    def _create_s7comm_ground_truth(self, raw_bytes: bytes, label) -> Dict:
        """创建S7COMM ground truth - 修复边界逻辑"""
        annotations = {'syntax_boundaries': [], 'semantic_types': {}, 'semantic_functions': {}}

        if len(raw_bytes) < 8:
            return annotations

        # S7COMM结构: [TPKT头(4) | COTP头(3) | S7头(...)]
        boundaries = [0, 2, 4, 7]  # TPKT和COTP边界

        if len(raw_bytes) > 8:
            boundaries.append(8)  # S7头开始
        if len(raw_bytes) > 12:
            boundaries.append(12)  # S7数据开始

        field_mapping = [
            (0, 1, 'HEADER', 'VERSION'),  # TPKT版本+保留
            (2, 3, 'LENGTH', 'DATA_LENGTH'),  # TPKT长度
            (4, 6, 'HEADER', 'SESSION_MGMT'),  # COTP头
            (7, 7, 'HEADER', 'IDENTIFIER'),  # S7协议标识
        ]

        # 应用语义标注
        for start, end, sem_type, sem_func in field_mapping:
            for pos in range(start, min(end + 1, len(raw_bytes))):
                annotations['semantic_types'][str(pos)] = sem_type
                annotations['semantic_functions'][str(pos)] = sem_func

        # S7特定部分
        for i in range(8, min(12, len(raw_bytes))):
            annotations['semantic_types'][str(i)] = 'COMMAND'
            annotations['semantic_functions'][str(i)] = 'CONTROL_CMD'

        # 数据部分
        for i in range(12, len(raw_bytes)):
            annotations['semantic_types'][str(i)] = 'DATA'
            annotations['semantic_functions'][str(i)] = 'APPLICATION_DATA'

        boundaries = [b for b in boundaries if b < len(raw_bytes)]
        annotations['syntax_boundaries'] = sorted(boundaries)
        return annotations

    def _create_smb_ground_truth(self, raw_bytes: bytes, label) -> Dict:
        """创建SMB ground truth"""
        annotations = {'syntax_boundaries': [], 'semantic_types': {}, 'semantic_functions': {}}

        if len(raw_bytes) < 32:
            return annotations

        # SMB头部结构边界
        boundaries = [0, 4, 5, 9, 25]
        if len(raw_bytes) > 32:
            boundaries.append(32)

        field_mapping = [
            (0, 3, 'HEADER', 'IDENTIFIER'),  # 协议标识
            (4, 4, 'COMMAND', 'CONTROL_CMD'),  # SMB命令
            (5, 8, 'FLAGS', 'CONTROL_CMD'),  # 状态/标志
            (9, 24, 'HEADER', 'SESSION_MGMT'),  # 其他头部字段
            (25, 31, 'ADDRESS', 'ADDRESSING'),  # 树ID等
        ]

        for start, end, sem_type, sem_func in field_mapping:
            for pos in range(start, min(end + 1, len(raw_bytes))):
                annotations['semantic_types'][str(pos)] = sem_type
                annotations['semantic_functions'][str(pos)] = sem_func

        # 数据部分
        for i in range(32, len(raw_bytes)):
            annotations['semantic_types'][str(i)] = 'DATA'
            annotations['semantic_functions'][str(i)] = 'APPLICATION_DATA'

        boundaries = [b for b in boundaries if b < len(raw_bytes)]
        annotations['syntax_boundaries'] = sorted(boundaries)
        return annotations

    def _create_smb2_ground_truth(self, raw_bytes: bytes, label) -> Dict:
        """创建SMB2 ground truth"""
        annotations = {'syntax_boundaries': [], 'semantic_types': {}, 'semantic_functions': {}}

        if len(raw_bytes) < 64:
            return annotations

        # SMB2头部结构边界
        boundaries = [0, 4, 6, 8, 12, 16, 24, 64]

        field_mapping = [
            (0, 3, 'HEADER', 'IDENTIFIER'),  # 协议标识
            (4, 5, 'LENGTH', 'DATA_LENGTH'),  # 结构大小
            (6, 7, 'COMMAND', 'CONTROL_CMD'),  # 命令
            (8, 11, 'FLAGS', 'CONTROL_CMD'),  # 标志
            (12, 15, 'HEADER', 'SESSION_MGMT'),  # 状态
            (16, 23, 'ADDRESS', 'ADDRESSING'),  # 会话ID
            (24, 63, 'HEADER', 'SESSION_MGMT'),  # 其他头部
        ]

        for start, end, sem_type, sem_func in field_mapping:
            for pos in range(start, min(end + 1, len(raw_bytes))):
                annotations['semantic_types'][str(pos)] = sem_type
                annotations['semantic_functions'][str(pos)] = sem_func

        # 数据部分
        for i in range(64, len(raw_bytes)):
            annotations['semantic_types'][str(i)] = 'DATA'
            annotations['semantic_functions'][str(i)] = 'APPLICATION_DATA'

        boundaries = [b for b in boundaries if b < len(raw_bytes)]
        annotations['syntax_boundaries'] = sorted(boundaries)
        return annotations

    def _create_dns_ground_truth(self, raw_bytes: bytes, label) -> Dict:
        """创建DNS ground truth"""
        annotations = {'syntax_boundaries': [], 'semantic_types': {}, 'semantic_functions': {}}

        if len(raw_bytes) < 12:
            return annotations

        # DNS头部结构边界
        boundaries = [0, 2, 4, 6, 8, 10, 12]

        field_mapping = [
            (0, 1, 'HEADER', 'IDENTIFIER'),  # 事务ID
            (2, 3, 'FLAGS', 'CONTROL_CMD'),  # 标志
            (4, 5, 'LENGTH', 'DATA_LENGTH'),  # 问题计数
            (6, 7, 'LENGTH', 'DATA_LENGTH'),  # 回答计数
            (8, 9, 'LENGTH', 'DATA_LENGTH'),  # 权威计数
            (10, 11, 'LENGTH', 'DATA_LENGTH'),  # 附加计数
        ]

        for start, end, sem_type, sem_func in field_mapping:
            for pos in range(start, min(end + 1, len(raw_bytes))):
                annotations['semantic_types'][str(pos)] = sem_type
                annotations['semantic_functions'][str(pos)] = sem_func

        # 查询/回答部分
        for i in range(12, len(raw_bytes)):
            annotations['semantic_types'][str(i)] = 'DATA'
            annotations['semantic_functions'][str(i)] = 'APPLICATION_DATA'

        boundaries = [b for b in boundaries if b < len(raw_bytes)]
        annotations['syntax_boundaries'] = sorted(boundaries)
        return annotations

    def _create_ftp_ground_truth(self, raw_bytes: bytes, label) -> Dict:
        """创建FTP ground truth"""
        annotations = {'syntax_boundaries': [], 'semantic_types': {}, 'semantic_functions': {}}

        # FTP是文本协议，使用简单边界
        boundaries = [0]
        if len(raw_bytes) > 4:
            boundaries.append(4)

        for i in range(len(raw_bytes)):
            annotations['semantic_types'][str(i)] = 'DATA'
            annotations['semantic_functions'][str(i)] = 'APPLICATION_DATA'

        boundaries = [b for b in boundaries if b < len(raw_bytes)]
        annotations['syntax_boundaries'] = sorted(boundaries)
        return annotations

    def _create_tls_ground_truth(self, raw_bytes: bytes, label) -> Dict:
        """创建TLS ground truth"""
        annotations = {'syntax_boundaries': [], 'semantic_types': {}, 'semantic_functions': {}}

        if len(raw_bytes) < 5:
            return annotations

        # TLS记录结构边界
        boundaries = [0, 1, 3, 5]

        field_mapping = [
            (0, 0, 'HEADER', 'IDENTIFIER'),  # 内容类型
            (1, 2, 'VERSION', 'PROTOCOL_SPECIFIC'),  # 版本
            (3, 4, 'LENGTH', 'DATA_LENGTH'),  # 长度
        ]

        for start, end, sem_type, sem_func in field_mapping:
            for pos in range(start, min(end + 1, len(raw_bytes))):
                annotations['semantic_types'][str(pos)] = sem_type
                annotations['semantic_functions'][str(pos)] = sem_func

        # 加密数据
        for i in range(5, len(raw_bytes)):
            annotations['semantic_types'][str(i)] = 'DATA'
            annotations['semantic_functions'][str(i)] = 'SECURITY'

        boundaries = [b for b in boundaries if b < len(raw_bytes)]
        annotations['syntax_boundaries'] = sorted(boundaries)
        return annotations

    def _create_dhcp_ground_truth(self, raw_bytes: bytes, label) -> Dict:
        """创建DHCP ground truth"""
        annotations = {'syntax_boundaries': [], 'semantic_types': {}, 'semantic_functions': {}}

        if len(raw_bytes) < 240:
            return annotations

        # DHCP固定头部结构边界
        boundaries = [0, 1, 2, 3, 4, 8, 10, 12, 28, 44, 60, 76, 140, 236, 240]

        field_mapping = [
            (0, 0, 'HEADER', 'IDENTIFIER'),  # 消息类型
            (1, 1, 'HEADER', 'PROTOCOL_SPECIFIC'),  # 硬件类型
            (2, 2, 'LENGTH', 'DATA_LENGTH'),  # 硬件地址长度
            (3, 3, 'HEADER', 'CONTROL_CMD'),  # 跳数
            (4, 7, 'HEADER', 'IDENTIFIER'),  # 事务ID
            (8, 9, 'TIMESTAMP', 'SESSION_MGMT'),  # 秒数
            (10, 11, 'FLAGS', 'CONTROL_CMD'),  # 标志
            (12, 27, 'ADDRESS', 'ADDRESSING'),  # IP地址字段
            (28, 43, 'ADDRESS', 'ADDRESSING'),  # 服务器IP
            (44, 59, 'ADDRESS', 'ADDRESSING'),  # 网关IP
            (60, 75, 'ADDRESS', 'ADDRESSING'),  # 客户端硬件地址
            (76, 139, 'DATA', 'CONFIGURATION'),  # 服务器名
            (140, 235, 'DATA', 'CONFIGURATION'),  # 启动文件名
            (236, 239, 'HEADER', 'IDENTIFIER'),  # Magic Cookie
        ]

        for start, end, sem_type, sem_func in field_mapping:
            for pos in range(start, min(end + 1, len(raw_bytes))):
                annotations['semantic_types'][str(pos)] = sem_type
                annotations['semantic_functions'][str(pos)] = sem_func

        # 选项字段
        for i in range(240, len(raw_bytes)):
            annotations['semantic_types'][str(i)] = 'OPTION'
            annotations['semantic_functions'][str(i)] = 'CONFIGURATION'

        boundaries = [b for b in boundaries if b < len(raw_bytes)]
        annotations['syntax_boundaries'] = sorted(boundaries)
        return annotations

    def _create_generic_ground_truth(self, raw_bytes: bytes, label) -> Dict:
        """创建通用协议的ground truth"""
        annotations = {'syntax_boundaries': [], 'semantic_types': {}, 'semantic_functions': {}}

        # 简单的通用结构：固定间隔边界
        header_size = max(4, len(raw_bytes) // 4)
        boundaries = [0, header_size]

        if len(raw_bytes) > header_size * 2:
            boundaries.append(header_size * 2)

        # 头部
        for i in range(min(header_size, len(raw_bytes))):
            annotations['semantic_types'][str(i)] = 'HEADER'
            annotations['semantic_functions'][str(i)] = 'IDENTIFIER'

        # 数据
        for i in range(header_size, len(raw_bytes)):
            annotations['semantic_types'][str(i)] = 'DATA'
            annotations['semantic_functions'][str(i)] = 'PAYLOAD'

        boundaries = [b for b in boundaries if b < len(raw_bytes)]
        annotations['syntax_boundaries'] = sorted(boundaries)
        return annotations


# ===========================
# 协议无关的编码器 - 保持不变
# ===========================

class ProtocolAgnosticEncoder(nn.Module):
    """协议无关的特征编码器"""

    def __init__(self, d_model: int = 512, num_layers: int = 6, num_heads: int = 8):
        super().__init__()
        self.d_model = d_model

        # 通用特征提取层
        self.byte_embedding = nn.Embedding(256, d_model)
        self.positional_encoding = self._create_positional_encoding(512, d_model)

        # Transformer编码器
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=num_heads,
            dim_feedforward=d_model * 4,
            dropout=0.1,
            activation='gelu',
            batch_first=True
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers)

        # 协议无关的特征投影层
        self.feature_projector = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.LayerNorm(d_model),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(d_model, d_model)
        )

    def _create_positional_encoding(self, max_len: int, d_model: int):
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() *
                             (-np.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        return nn.Parameter(pe.unsqueeze(0), requires_grad=False)

    def forward(self, x: torch.Tensor, attention_mask: Optional[torch.Tensor] = None):
        batch_size, seq_len = x.size()

        # 确保输入是正确的类型
        x = x.long()  # 确保是长整型

        # Byte embedding
        embedded = self.byte_embedding(x)

        # 添加位置编码
        if seq_len <= self.positional_encoding.size(1):
            embedded += self.positional_encoding[:, :seq_len, :]

        # Transformer编码
        encoded = self.transformer_encoder(embedded, src_key_padding_mask=attention_mask)

        # 协议无关特征投影
        protocol_agnostic_features = self.feature_projector(encoded)

        return {
            'protocol_agnostic_features': protocol_agnostic_features,
            'raw_features': encoded,
            'embeddings': embedded
        }


# ===========================
# 协议特定任务头 - 保持不变
# ===========================

class ProtocolSpecificHead(nn.Module):
    """协议特定的任务头"""

    def __init__(self, d_model: int, num_semantic_types: int, num_semantic_functions: int,
                 protocol_name: str):
        super().__init__()
        self.protocol_name = protocol_name
        self.d_model = d_model

        # 协议特定的适配层
        self.protocol_adapter = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.LayerNorm(d_model),
            nn.GELU(),
            nn.Dropout(0.1)
        )

        # 边界检测头
        self.boundary_head = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(d_model // 2, 2)
        )

        # 语义类型分类头
        self.semantic_type_head = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(d_model // 2, num_semantic_types)
        )

        # 语义功能分类头
        self.semantic_function_head = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(d_model // 2, num_semantic_functions)
        )

    def forward(self, protocol_agnostic_features: torch.Tensor):
        # 协议特定适配
        adapted_features = self.protocol_adapter(protocol_agnostic_features)

        # 各任务预测
        boundary_logits = self.boundary_head(adapted_features)
        semantic_type_logits = self.semantic_type_head(adapted_features)
        semantic_function_logits = self.semantic_function_head(adapted_features)

        return {
            'boundary_logits': boundary_logits,
            'semantic_type_logits': semantic_type_logits,
            'semantic_function_logits': semantic_function_logits,
            'adapted_features': adapted_features
        }


# ===========================
# 跨协议迁移模型 - 保持不变
# ===========================

class GenericCrossProtocolTransferModel(nn.Module):
    """通用跨协议迁移学习模型，支持动态协议"""

    def __init__(self, protocol_names: List[str], d_model: int = 512, encoder_layers: int = 6,
                 num_semantic_types: int = 14, num_semantic_functions: int = 14):
        super().__init__()

        self.protocol_names = protocol_names

        # 协议无关的编码器（共享层）
        self.protocol_agnostic_encoder = ProtocolAgnosticEncoder(
            d_model=d_model,
            num_layers=encoder_layers
        )

        # 为每个协议创建特定的任务头
        self.protocol_heads = nn.ModuleDict()
        for protocol_name in protocol_names:
            self.protocol_heads[protocol_name] = ProtocolSpecificHead(
                d_model, num_semantic_types, num_semantic_functions, protocol_name
            )

        # 通用任务头（用于未知协议）
        self.protocol_heads['general'] = ProtocolSpecificHead(
            d_model, num_semantic_types, num_semantic_functions, 'general'
        )

        # 协议分类器
        self.protocol_classifier = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(d_model // 2, len(protocol_names) + 1)  # +1 for unknown
        )

    def add_protocol(self, protocol_name: str, num_semantic_types: int = 14,
                     num_semantic_functions: int = 14):
        """动态添加新协议支持"""
        if protocol_name not in self.protocol_heads:
            self.protocol_heads[protocol_name] = ProtocolSpecificHead(
                self.protocol_agnostic_encoder.d_model,
                num_semantic_types,
                num_semantic_functions,
                protocol_name
            )
            self.protocol_names.append(protocol_name)
            print(f"模型已添加对协议 '{protocol_name}' 的支持")
        else:
            print(f"协议 '{protocol_name}' 已存在")

    def forward(self, x: torch.Tensor, protocol: Optional[str] = None,
                attention_mask: Optional[torch.Tensor] = None,
                apply_boundary_postprocess: bool = False):
        """模型前向传播"""

        # 提取协议无关特征
        encoder_outputs = self.protocol_agnostic_encoder(x, attention_mask)
        protocol_agnostic_features = encoder_outputs['protocol_agnostic_features']

        # 协议分类
        protocol_probs = self.protocol_classifier(
            protocol_agnostic_features.mean(dim=1)
        )

        # 选择对应的协议头
        if protocol and protocol in self.protocol_heads:
            head_outputs = self.protocol_heads[protocol](protocol_agnostic_features)
        else:
            # 使用通用头
            head_outputs = self.protocol_heads['general'](protocol_agnostic_features)

        return {
            **head_outputs,
            'protocol_probs': protocol_probs,
            'protocol_agnostic_features': protocol_agnostic_features
        }

    def freeze_encoder(self):
        """冻结编码器参数"""
        for param in self.protocol_agnostic_encoder.parameters():
            param.requires_grad = False

    def unfreeze_encoder(self):
        """解冻编码器参数"""
        for param in self.protocol_agnostic_encoder.parameters():
            param.requires_grad = True


# ===========================
# 数据集类 - 修复边界标签生成
# ===========================

class GenericTransferLearningDataset(Dataset):
    """支持多协议的通用数据集 - 修复边界处理"""

    def __init__(self, data: List[Dict], max_length: int = 256,
                 protocol_filter: Optional[str] = None, augment: bool = False,
                 unified_semantic_types: List[str] = None,
                 unified_semantic_functions: List[str] = None):

        self.max_length = max_length
        self.augment = augment

        # 如果指定协议过滤器，只保留该协议的数据
        if protocol_filter:
            self.data = [sample for sample in data if sample['protocol'] == protocol_filter]
            print(f"过滤到{protocol_filter}协议数据: {len(self.data)}条")
        else:
            self.data = data

        # 使用提供的统一语义标签或默认标签
        self.unified_semantic_types = unified_semantic_types or [
            'PADDING', 'HEADER', 'ADDRESS', 'COMMAND', 'LENGTH',
            'DATA', 'CHECKSUM', 'CONTROL', 'FUNCTION', 'OPTION',
            'TIMESTAMP', 'VERSION', 'FLAGS', 'PAYLOAD'
        ]

        self.unified_semantic_functions = unified_semantic_functions or [
            'UNKNOWN', 'IDENTIFIER', 'ADDRESSING', 'CONTROL_CMD',
            'DATA_LENGTH', 'PAYLOAD', 'VALIDATION', 'RESERVED',
            'PROTOCOL_SPECIFIC', 'CONFIGURATION', 'SESSION_MGMT',
            'SECURITY', 'ROUTING', 'APPLICATION_DATA'
        ]

        # 创建编码器
        self.type_encoder = LabelEncoder()
        self.function_encoder = LabelEncoder()

        self.type_encoder.fit(self.unified_semantic_types)
        self.function_encoder.fit(self.unified_semantic_functions)

        # 统计协议分布
        protocol_dist = Counter([sample['protocol'] for sample in self.data])
        print(f"数据集协议分布: {dict(protocol_dist)}")

        # 【新增】边界质量统计
        self._analyze_boundary_quality()

    def _analyze_boundary_quality(self):
        """分析边界数据质量"""
        boundary_stats = {
            'valid_boundaries': 0,
            'empty_boundaries': 0,
            'avg_boundaries_per_sample': 0,
            'total_samples': len(self.data)
        }

        total_boundaries = 0
        for sample in self.data:
            boundaries = sample['ground_truth']['syntax_boundaries']
            if len(boundaries) > 0:
                boundary_stats['valid_boundaries'] += 1
                total_boundaries += len(boundaries)
            else:
                boundary_stats['empty_boundaries'] += 1

        if boundary_stats['valid_boundaries'] > 0:
            boundary_stats['avg_boundaries_per_sample'] = total_boundaries / boundary_stats['valid_boundaries']

        print(f"边界质量统计: {boundary_stats}")

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        sample = self.data[idx]

        try:
            raw_bytes = bytes.fromhex(sample['raw_data'])
        except:
            raw_bytes = b'\x00'

        # 确保数据类型为float32
        byte_sequence = np.array(list(raw_bytes), dtype=np.float32)

        # 数据增强
        if self.augment and random.random() < 0.1:
            noise = np.random.normal(0, 0.5, byte_sequence.shape).astype(np.float32)
            byte_sequence = np.clip(byte_sequence + noise, 0, 255)

        # 记录原始长度用于perfection计算
        original_length = len(byte_sequence)

        # 填充或截断
        if len(byte_sequence) > self.max_length:
            byte_sequence = byte_sequence[:self.max_length]
            actual_length = self.max_length
        else:
            actual_length = len(byte_sequence)
            byte_sequence = np.pad(byte_sequence,
                                   (0, self.max_length - len(byte_sequence)), 'constant')

        # 创建标签
        ground_truth = sample['ground_truth']

        # 【修复】边界标签生成 - 重要修复
        boundary_labels = np.zeros(self.max_length, dtype=np.int64)
        valid_boundaries = []

        for boundary in ground_truth['syntax_boundaries']:
            if 0 <= boundary < actual_length:  # 只考虑实际长度内的边界
                boundary_labels[boundary] = 1
                valid_boundaries.append(boundary)

        # 【新增】确保至少有一些边界标记
        if len(valid_boundaries) == 0 and actual_length > 0:
            # 如果没有有效边界，在序列开始处标记一个边界
            boundary_labels[0] = 1
            valid_boundaries.append(0)

        # 语义类型标签 - 确保数据类型为int64
        type_labels = np.zeros(self.max_length, dtype=np.int64)
        for pos_str, type_name in ground_truth['semantic_types'].items():
            try:
                pos = int(pos_str)
                if 0 <= pos < actual_length and type_name in self.unified_semantic_types:
                    type_idx = self.type_encoder.transform([type_name])[0]
                    type_labels[pos] = type_idx
            except:
                continue

        # 语义功能标签 - 确保数据类型为int64
        function_labels = np.zeros(self.max_length, dtype=np.int64)
        for pos_str, func_name in ground_truth['semantic_functions'].items():
            try:
                pos = int(pos_str)
                if 0 <= pos < actual_length and func_name in self.unified_semantic_functions:
                    func_idx = self.function_encoder.transform([func_name])[0]
                    function_labels[pos] = func_idx
            except:
                continue

        return {
            'sequence': torch.tensor(byte_sequence, dtype=torch.float32),
            'boundary_labels': torch.tensor(boundary_labels, dtype=torch.long),
            'semantic_type_labels': torch.tensor(type_labels, dtype=torch.long),
            'semantic_function_labels': torch.tensor(function_labels, dtype=torch.long),
            'actual_length': actual_length,  # 【修复】确保提供正确的实际长度
            'protocol': sample['protocol'],
            'valid_boundaries_count': len(valid_boundaries),  # 调试信息
            'original_length': original_length  # 【新增】原始长度信息
        }


# ===========================
# 训练器 - 修复perfection计算
# ===========================

class GenericTransferLearningTrainer:
    """通用跨协议迁移学习训练器 - 修复perfection计算"""

    def __init__(self, model: GenericCrossProtocolTransferModel, device: str = 'cpu',
                 protocol_names: List[str] = None):
        self.model = model.to(device)
        self.device = device
        self.protocol_names = protocol_names or []
        self.training_history = defaultdict(list)

        # 语义分类损失
        self.semantic_criterion = nn.CrossEntropyLoss(ignore_index=0)
        self.protocol_criterion = nn.CrossEntropyLoss()

        # 边界检测损失 - 将在训练时动态计算权重
        self.boundary_criterion = None

        # 当前阶段
        self.current_stage = 'initialization'

    def _boundaries_to_fields(self, boundaries: List[int], sequence_length: int) -> List[Tuple[int, int]]:
        """将边界位置转换为字段范围列表

        Args:
            boundaries: 边界位置列表，如 [0, 2, 4, 6, 7, 8]
            sequence_length: 序列总长度

        Returns:
            字段范围列表，如 [(0, 1), (2, 3), (4, 5), (6, 6), (7, 7), (8, sequence_length-1)]
        """
        if not boundaries:
            return [(0, sequence_length - 1)] if sequence_length > 0 else []

        fields = []
        boundaries = sorted(set(boundaries))  # 去重并排序

        for i in range(len(boundaries)):
            start = boundaries[i]

            if i < len(boundaries) - 1:
                # 不是最后一个边界
                end = boundaries[i + 1] - 1
            else:
                # 最后一个边界，字段延续到序列末尾
                end = sequence_length - 1

            if start <= end:  # 确保字段有效
                fields.append((start, end))

        return fields

    def _calculate_boundary_weights(self, data_loader: DataLoader) -> torch.Tensor:
        """动态计算边界检测的类别权重 - 改进版本"""
        print("🔄 计算边界检测权重...")

        boundary_counts = [0, 0]  # [非边界, 边界]
        total_sequences = 0
        avg_boundaries_per_seq = 0

        for batch in data_loader:
            boundary_labels = batch['boundary_labels'].numpy()
            total_sequences += boundary_labels.shape[0]

            for seq in boundary_labels:
                unique, counts = np.unique(seq, return_counts=True)
                for val, count in zip(unique, counts):
                    if val in [0, 1]:
                        boundary_counts[val] += count

                # 统计每个序列的边界数
                avg_boundaries_per_seq += np.sum(seq == 1)

        avg_boundaries_per_seq /= total_sequences if total_sequences > 0 else 1

        # 使用温和的权重策略
        if boundary_counts[1] > 0:
            raw_ratio = boundary_counts[0] / boundary_counts[1]
            # 限制最大权重，防止过度预测
            max_weight = 15.0 if avg_boundaries_per_seq < 8 else 10.0
            weight_ratio = min(max_weight, raw_ratio)
            weights = torch.tensor([1.0, weight_ratio], dtype=torch.float32, device=self.device)
        else:
            weights = torch.tensor([1.0, 10.0], dtype=torch.float32, device=self.device)

        print(f"  边界统计: 非边界={boundary_counts[0]}, 边界={boundary_counts[1]}")
        print(f"  平均每序列边界数: {avg_boundaries_per_seq:.1f}")
        print(f"  边界比例: {boundary_counts[1] / sum(boundary_counts) * 100:.2f}%")
        print(f"  计算权重: {weights.tolist()}")

        return weights

    def _compute_loss(self, outputs, batch, protocol_name, data_loader=None):
        """计算损失 - 改进版本"""

        # 如果边界损失函数未初始化，则动态计算权重
        if self.boundary_criterion is None and data_loader is not None:
            weights = self._calculate_boundary_weights(data_loader)
            self.boundary_criterion = nn.CrossEntropyLoss(weight=weights)
        elif self.boundary_criterion is None:
            # 默认更强的权重
            weights = torch.tensor([1.0, 50.0], dtype=torch.float32, device=self.device)
            self.boundary_criterion = nn.CrossEntropyLoss(weight=weights)

        # 【新增】边界密度正则化损失
        def boundary_density_loss(boundary_logits, boundary_labels, actual_lengths):
            """边界密度正则化：惩罚过度预测边界"""
            boundary_probs = torch.softmax(boundary_logits, dim=-1)[:, :, 1]  # 边界概率

            total_penalty = 0.0
            batch_size = boundary_probs.size(0)

            for i in range(batch_size):
                actual_len = actual_lengths[i] if hasattr(actual_lengths, '__len__') else actual_lengths
                actual_len = min(int(actual_len), boundary_probs.size(1))

                # 计算预测边界密度
                pred_boundary_density = torch.mean(boundary_probs[i, :actual_len])

                # 计算真实边界密度
                true_boundary_density = torch.mean(boundary_labels[i, :actual_len].float())

                # 惩罚过度预测（预测密度远高于真实密度）
                if pred_boundary_density > true_boundary_density * 2:  # 如果预测密度是真实的2倍以上
                    penalty = (pred_boundary_density - true_boundary_density) ** 2
                    total_penalty += penalty

            return total_penalty / batch_size

        # 标准边界检测损失
        boundary_loss = self.boundary_criterion(
            outputs['boundary_logits'].view(-1, 2),
            batch['boundary_labels'].view(-1)
        )

        # 【新增】边界密度正则化
        density_penalty = boundary_density_loss(
            outputs['boundary_logits'],
            batch['boundary_labels'],
            batch.get('actual_length', batch['boundary_labels'].size(1))
        )

        # 语义类型分类损失
        type_loss = self.semantic_criterion(
            outputs['semantic_type_logits'].view(-1, outputs['semantic_type_logits'].size(-1)),
            batch['semantic_type_labels'].view(-1)
        )

        # 语义功能分类损失
        func_loss = self.semantic_criterion(
            outputs['semantic_function_logits'].view(-1, outputs['semantic_function_logits'].size(-1)),
            batch['semantic_function_labels'].view(-1)
        )

        # 协议分类损失
        protocol_ids = self._get_protocol_ids(batch['protocol'])
        protocol_loss = self.protocol_criterion(outputs['protocol_probs'], protocol_ids)

        # 【修改】组合损失 - 增加密度正则化
        total_loss = (
                5.0 * boundary_loss +  # 增加边界检测权重
                2.0 * density_penalty +  # 新增：边界密度正则化
                2.0 * type_loss +  # 语义类型分类权重
                2.0 * func_loss +  # 语义功能分类权重
                0.3 * protocol_loss  # 协议分类权重较低
        )

        return total_loss

    def _evaluate_on_protocol(self, data_loader: DataLoader, protocol: str) -> Dict:
        """在特定协议上评估模型 - 修正版本，实现正确的评估指标"""
        self.model.eval()

        all_type_preds = []
        all_type_labels = []
        all_func_preds = []
        all_func_labels = []

        # 字段级别的统计
        total_true_fields = 0
        total_predicted_boundaries = 0
        total_true_positive_boundaries = 0
        perfectly_inferred_fields = 0

        # 位置级别的统计
        all_boundary_preds = []
        all_boundary_labels = []

        # 序列级别的统计（保留原有的序列完美匹配）
        total_sequences = 0
        perfect_sequences = 0
        debug_info = []

        with torch.no_grad():
            for batch_idx, batch in enumerate(data_loader):
                batch = {k: v.to(self.device) if torch.is_tensor(v) else v
                         for k, v in batch.items()}

                outputs = self.model(batch['sequence'], protocol=protocol)

                # 获取实际长度
                actual_lengths = batch.get('actual_length', torch.sum(batch['sequence'] != 0, dim=1))

                # 边界预测（原始预测，不使用后处理）
                boundary_pred = torch.argmax(outputs['boundary_logits'], dim=-1)

                # 语义预测结果
                type_pred = torch.argmax(outputs['semantic_type_logits'], dim=-1)
                func_pred = torch.argmax(outputs['semantic_function_logits'], dim=-1)

                # 收集语义预测结果
                all_type_preds.extend(type_pred.cpu().numpy().flatten())
                all_type_labels.extend(batch['semantic_type_labels'].cpu().numpy().flatten())
                all_func_preds.extend(func_pred.cpu().numpy().flatten())
                all_func_labels.extend(batch['semantic_function_labels'].cpu().numpy().flatten())

                # 处理边界检测结果
                batch_size = boundary_pred.size(0)
                seq_length = boundary_pred.size(1)

                boundary_pred_np = boundary_pred.cpu().numpy().astype(np.int64)
                boundary_labels_np = batch['boundary_labels'].cpu().numpy().astype(np.int64)

                # 获取实际序列长度
                if 'actual_length' in batch:
                    actual_lengths_np = batch['actual_length']
                    if torch.is_tensor(actual_lengths_np):
                        actual_lengths_np = actual_lengths_np.cpu().numpy()
                else:
                    actual_lengths_np = []
                    for i in range(batch_size):
                        seq_data = batch['sequence'][i].cpu().numpy()
                        non_zero_indices = np.nonzero(seq_data)[0]
                        if len(non_zero_indices) > 0:
                            actual_lengths_np.append(non_zero_indices[-1] + 1)
                        else:
                            actual_lengths_np.append(seq_length)
                    actual_lengths_np = np.array(actual_lengths_np)

                for i in range(batch_size):
                    total_sequences += 1

                    # 获取实际序列长度
                    if isinstance(actual_lengths_np, (list, np.ndarray)) and len(actual_lengths_np) > i:
                        actual_len = int(actual_lengths_np[i])
                    else:
                        actual_len = seq_length

                    actual_len = min(actual_len, seq_length)
                    actual_len = max(1, actual_len)

                    # 获取实际长度内的预测和标签
                    seq_pred = boundary_pred_np[i][:actual_len].astype(np.int64)
                    seq_label = boundary_labels_np[i][:actual_len].astype(np.int64)

                    # 位置级别统计
                    all_boundary_preds.extend(seq_pred)
                    all_boundary_labels.extend(seq_label)

                    # 序列级别完美匹配（保留原有定义）
                    is_sequence_perfect = np.array_equal(seq_pred, seq_label)
                    if is_sequence_perfect:
                        perfect_sequences += 1

                    # ==== 字段级别的perfection计算 ====

                    # 1. 从边界位置转换为字段
                    true_boundaries = np.where(seq_label == 1)[0].tolist()
                    pred_boundaries = np.where(seq_pred == 1)[0].tolist()

                    # 2. 统计预测的边界数量
                    total_predicted_boundaries += len(pred_boundaries)

                    # 3. 统计真正预测正确的边界数量（precision计算用）
                    for pred_boundary in pred_boundaries:
                        if pred_boundary in true_boundaries:
                            total_true_positive_boundaries += 1

                    # 4. 将边界转换为字段范围
                    true_fields = self._boundaries_to_fields(true_boundaries, actual_len)
                    pred_fields = self._boundaries_to_fields(pred_boundaries, actual_len)

                    # 5. 统计总的真实字段数
                    total_true_fields += len(true_fields)

                    # 6. 检查每个真实字段是否被完美推断
                    for true_field in true_fields:
                        if true_field in pred_fields:
                            perfectly_inferred_fields += 1

                    # 调试信息收集
                    if len(debug_info) < 5:
                        debug_info.append({
                            'batch_idx': batch_idx,
                            'seq_idx': i,
                            'actual_len': actual_len,
                            'true_boundaries': true_boundaries,
                            'pred_boundaries': pred_boundaries,
                            'true_fields': true_fields,
                            'pred_fields': pred_fields,
                            'is_sequence_perfect': is_sequence_perfect,
                            'field_matches': sum(1 for tf in true_fields if tf in pred_fields)
                        })

        # 计算语义分析指标
        type_mask = np.array(all_type_labels) != 0
        func_mask = np.array(all_func_labels) != 0

        type_f1 = f1_score(
            np.array(all_type_labels)[type_mask],
            np.array(all_type_preds)[type_mask],
            average='weighted', zero_division=0
        ) if type_mask.sum() > 0 else 0.0

        func_f1 = f1_score(
            np.array(all_func_labels)[func_mask],
            np.array(all_func_preds)[func_mask],
            average='weighted', zero_division=0
        ) if func_mask.sum() > 0 else 0.0

        # 计算边界检测指标
        all_boundary_labels = np.array(all_boundary_labels, dtype=np.int64)
        all_boundary_preds = np.array(all_boundary_preds, dtype=np.int64)

        # 1. accuracy: 正确推断的位置数 / 所有偏移位置数
        boundary_accuracy = accuracy_score(all_boundary_labels, all_boundary_preds)

        # 2. F1-score: 边界检测的二分类F1分数
        boundary_f1 = f1_score(
            all_boundary_labels, all_boundary_preds,
            average='binary', pos_label=1, zero_division=0
        )

        # 3. perfection: 完美推断的字段数 / 所有真实字段数
        field_perfection = (perfectly_inferred_fields / total_true_fields
                            if total_true_fields > 0 else 0.0)

        # 4. Precision (保留用于调试)
        boundary_precision = (total_true_positive_boundaries / total_predicted_boundaries
                              if total_predicted_boundaries > 0 else 0.0)

        # 5. 序列级别的完美匹配率（保留原有定义）
        sequence_perfection = perfect_sequences / total_sequences if total_sequences > 0 else 0.0

        # 统计信息
        total_boundaries_true = int(np.sum(all_boundary_labels))
        total_boundaries_pred = int(np.sum(all_boundary_preds))

        # 详细调试信息输出
        if total_sequences > 0:
            print(f"    修正评估统计:")
            print(f"      - 总序列数: {total_sequences}")
            print(f"      - 总真实字段数: {total_true_fields}")
            print(f"      - 完美推断字段数: {perfectly_inferred_fields}")
            print(f"      - 总预测边界数: {total_predicted_boundaries}")
            print(f"      - 正确预测边界数: {total_true_positive_boundaries}")
            print(f"      - 序列完美匹配数: {perfect_sequences}")
            print(f"      - 字段完美率: {field_perfection:.4f}")
            print(f"      - 边界F1分数: {boundary_f1:.4f}")

            # 输出前几个样本的详细信息
            if debug_info:
                print(f"      - 样本详细信息:")
                for info in debug_info[:3]:
                    print(f"        样本{info['seq_idx']}: 长度={info['actual_len']}")
                    print(f"          真实边界: {info['true_boundaries']} -> 字段: {info['true_fields']}")
                    print(f"          预测边界: {info['pred_boundaries']} -> 字段: {info['pred_fields']}")
                    print(f"          字段匹配: {info['field_matches']}/{len(info['true_fields'])}")

        return {
            'type_f1': type_f1,
            'func_f1': func_f1,
            # 修正的边界检测指标 - 符合论文定义
            'boundary_acc': boundary_accuracy,  # accuracy (位置级别准确率)
            'boundary_f1': boundary_f1,  # F1-score (边界检测F1分数)
            'boundary_perfection': field_perfection,  # perfection (字段级别完美率)
            # 保留用于调试
            'boundary_precision': boundary_precision,  # precision (边界预测精确率)
            'sequence_perfection': sequence_perfection,  # 序列级别完美率（保留）
            # 兼容性：使用新的字段完美率作为主要的perfection指标
            'field_perfection': field_perfection,  # 字段级别完美率
            # 统计信息
            'boundary_stats': {
                'total_boundaries_true': total_boundaries_true,
                'total_boundaries_pred': total_boundaries_pred,
                'total_sequences': total_sequences,
                'perfect_sequences': perfect_sequences,
                'total_true_fields': total_true_fields,
                'perfectly_inferred_fields': perfectly_inferred_fields,
                'total_predicted_boundaries': total_predicted_boundaries,
                'total_true_positive_boundaries': total_true_positive_boundaries,
                'debug_samples': debug_info[:5]
            }
        }

    def transfer_to_target(self, target_loader: DataLoader, val_loader: DataLoader,
                           target_protocol: str, epochs: int = 20, lr: float = 5e-5,
                           freeze_encoder: bool = True):
        """迁移到目标协议 - 使用修正的评估指标"""
        print(f"\n阶段2：迁移到 {target_protocol.upper()} 协议...")
        self.current_stage = 'target_transfer'

        # 确保模型支持目标协议
        if target_protocol not in self.model.protocol_heads:
            self.model.add_protocol(target_protocol)

        # 重置边界损失函数以重新计算权重
        self.boundary_criterion = None

        if freeze_encoder:
            print("冻结编码器，仅训练协议特定头")
            self.model.freeze_encoder()
        else:
            print("端到端微调")
            self.model.unfreeze_encoder()

        # 配置优化器
        if freeze_encoder:
            optimizer = optim.AdamW([
                {'params': self.model.protocol_heads[target_protocol].parameters(), 'lr': lr * 2},
                {'params': self.model.protocol_classifier.parameters(), 'lr': lr}
            ], weight_decay=0.01)
        else:
            optimizer = optim.AdamW([
                {'params': self.model.protocol_agnostic_encoder.parameters(), 'lr': lr * 0.1},
                {'params': self.model.protocol_heads[target_protocol].parameters(), 'lr': lr},
                {'params': self.model.protocol_classifier.parameters(), 'lr': lr}
            ], weight_decay=0.01)

        scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

        best_f1 = 0.0
        best_boundary_f1 = 0.0
        best_field_perfection = 0.0
        patience = 0
        max_patience = 8

        print(f"修正的Format Extraction指标说明:")
        print(f"  - accuracy: 位置级别的边界检测准确率 (正确预测位置数/总位置数)")
        print(f"  - F1-score: 边界检测的二分类F1分数")
        print(f"  - perfection: 字段级别完美率 (完美推断字段数/总真实字段数)")

        for epoch in range(epochs):
            self.model.train()
            total_loss = 0.0

            for batch in target_loader:
                batch = {k: v.to(self.device) if torch.is_tensor(v) else v
                         for k, v in batch.items()}

                optimizer.zero_grad()

                outputs = self.model(batch['sequence'], protocol=target_protocol)
                loss = self._compute_loss(outputs, batch, target_protocol, target_loader)

                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()

                total_loss += loss.item()

            scheduler.step()

            # 验证 - 使用修正的评估方法
            val_metrics = self._evaluate_on_protocol(val_loader, target_protocol)
            avg_f1 = (val_metrics['type_f1'] + val_metrics['func_f1']) / 2
            boundary_f1 = val_metrics['boundary_f1']
            field_perfection = val_metrics['field_perfection']

            if avg_f1 > best_f1:
                best_f1 = avg_f1
                best_boundary_f1 = boundary_f1
                best_field_perfection = field_perfection
                patience = 0
                stage_name = 'frozen' if freeze_encoder else 'finetuned'
                self._save_checkpoint(f'{target_protocol}_{stage_name}.pth', epoch, best_f1)
                print(f'新最佳结果 - Overall F1: {best_f1:.4f}')
            else:
                patience += 1

            if epoch % 3 == 0:
                print(f'  Epoch {epoch}/{epochs}: Loss={total_loss / len(target_loader):.4f}')
                print(
                    f'    Overall F1={avg_f1:.4f}, Type F1={val_metrics["type_f1"]:.4f}, Func F1={val_metrics["func_f1"]:.4f}')
                print(
                    f'    Format Extraction - accuracy={val_metrics["boundary_acc"]:.4f}, F1-score={boundary_f1:.4f}, perfection={field_perfection:.4f}')
                print(
                    f'    (Precision={val_metrics["boundary_precision"]:.4f}, Seq.Perfect={val_metrics["sequence_perfection"]:.4f})')

            if patience >= max_patience:
                print(f"早停：{max_patience}个epoch无改善")
                break

        print(f"目标协议迁移完成:")
        print(f"  - 最佳Overall F1: {best_f1:.4f}")
        print(f"  - 最佳Format Extraction指标:")
        print(f"    * F1-score: {best_boundary_f1:.4f}")
        print(f"    * perfection: {best_field_perfection:.4f}")

        return best_f1

    def train_source_protocols(self, source_loaders: Dict[str, DataLoader],
                               epochs: int = 30, lr: float = 1e-4):
        """在源协议上预训练"""
        print(f"\n阶段1：在源协议上预训练...")
        print(f"源协议: {list(source_loaders.keys())}")
        self.current_stage = 'source_pretraining'

        # 为每个源协议创建优化器
        all_params = []
        all_params.extend(self.model.protocol_agnostic_encoder.parameters())

        for protocol_name in source_loaders.keys():
            if protocol_name in self.model.protocol_heads:
                all_params.extend(self.model.protocol_heads[protocol_name].parameters())

        all_params.extend(self.model.protocol_classifier.parameters())

        optimizer = optim.AdamW(all_params, lr=lr, weight_decay=0.01)
        scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

        best_avg_f1 = 0.0
        best_boundary_f1 = 0.0
        best_field_perfection = 0.0

        for epoch in range(epochs):
            self.model.train()
            total_loss = 0.0
            batch_count = 0

            # 轮流训练每个源协议
            for protocol_name, data_loader in source_loaders.items():
                for batch in data_loader:
                    batch = {k: v.to(self.device) if torch.is_tensor(v) else v
                             for k, v in batch.items()}

                    optimizer.zero_grad()

                    outputs = self.model(batch['sequence'], protocol=protocol_name)

                    # 计算损失
                    loss = self._compute_loss(outputs, batch, protocol_name)

                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                    optimizer.step()

                    total_loss += loss.item()
                    batch_count += 1

            scheduler.step()

            # 验证
            if epoch % 5 == 0:
                eval_results = self._evaluate_multiple_protocols(source_loaders)
                avg_metrics = eval_results['averages']

                avg_f1 = avg_metrics['avg_overall_f1']
                avg_boundary_f1 = avg_metrics['avg_boundary_f1']
                avg_field_perfection = avg_metrics['avg_field_perfection']

                if avg_f1 > best_avg_f1:
                    best_avg_f1 = avg_f1
                    best_boundary_f1 = avg_boundary_f1
                    best_field_perfection = avg_field_perfection
                    self._save_checkpoint(f'source_pretrained_multi.pth', epoch, best_avg_f1)

                print(f'  Epoch {epoch}/{epochs}: Loss={total_loss / batch_count:.4f}')
                print(f'    Overall F1={avg_f1:.4f}, Boundary accuracy={avg_metrics["avg_boundary_acc"]:.4f}')
                print(f'    Boundary F1-score={avg_boundary_f1:.4f}, Field perfection={avg_field_perfection:.4f}')

        print(f"源协议预训练完成:")
        print(f"  - 最佳Overall F1: {best_avg_f1:.4f}")
        print(f"  - 最佳Boundary F1-score: {best_boundary_f1:.4f}")
        print(f"  - 最佳Field perfection: {best_field_perfection:.4f}")

        return best_avg_f1

    def _get_protocol_ids(self, protocol_names):
        """获取协议ID"""
        ids = []
        for protocol_name in protocol_names:
            if protocol_name in self.protocol_names:
                ids.append(self.protocol_names.index(protocol_name))
            else:
                ids.append(len(self.protocol_names))  # unknown protocol
        return torch.tensor(ids, dtype=torch.long, device=self.device)

    def _evaluate_multiple_protocols(self, data_loaders: Dict[str, DataLoader]) -> Dict:
        """评估多个协议的平均性能"""
        protocol_results = {}

        for protocol_name, data_loader in data_loaders.items():
            metrics = self._evaluate_on_protocol(data_loader, protocol_name)
            protocol_results[protocol_name] = metrics

        # 计算平均指标
        avg_metrics = {
            'avg_type_f1': np.mean([m['type_f1'] for m in protocol_results.values()]),
            'avg_func_f1': np.mean([m['func_f1'] for m in protocol_results.values()]),
            'avg_boundary_acc': np.mean([m['boundary_acc'] for m in protocol_results.values()]),
            'avg_boundary_precision': np.mean([m['boundary_precision'] for m in protocol_results.values()]),
            'avg_field_perfection': np.mean([m['field_perfection'] for m in protocol_results.values()]),
            'avg_boundary_f1': np.mean([m['boundary_f1'] for m in protocol_results.values()]),
            'avg_overall_f1': np.mean([(m['type_f1'] + m['func_f1']) / 2 for m in protocol_results.values()])
        }

        return {
            'individual_results': protocol_results,
            'averages': avg_metrics
        }

    def _save_checkpoint(self, path: str, epoch: int, best_f1: float):
        """保存检查点"""
        try:
            torch.save({
                'epoch': epoch,
                'model_state_dict': self.model.state_dict(),
                'best_f1': best_f1,
                'stage': self.current_stage,
                'protocol_names': self.protocol_names,
                'training_history': dict(self.training_history)
            }, path)
        except Exception as e:
            print(f"保存模型失败: {e}")


# ===========================
# 主实验运行函数 - 保持不变
# ===========================

def run_flexible_transfer_experiment(source_protocols: List[str],
                                     target_protocol: str,
                                     data_root: str = "../Msg2",
                                     model_params: Dict = None,
                                     training_params: Dict = None):
    """运行灵活的跨协议迁移学习实验"""

    print("=" * 80)
    print("跨协议迁移学习实验")
    print("=" * 80)
    print(f"源协议: {source_protocols}")
    print(f"目标协议: {target_protocol}")
    print(f"数据根目录: {data_root}")

    # 设置默认参数
    model_params = model_params or {
        'd_model': 512,
        'encoder_layers': 6
    }

    training_params = training_params or {
        'batch_size': 32,
        'source_epochs': 25,
        'transfer_epochs': 15,
        'finetune_epochs': 15
    }

    # 设置随机种子
    torch.manual_seed(42)
    np.random.seed(42)
    random.seed(42)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"使用设备: {device}")

    # 1. 初始化数据加载器
    print("\n1. 初始化数据加载器...")
    data_loader = AdvancedProtocolDataLoader(data_root)

    available_protocols = data_loader.get_available_protocols()
    print(f"可用协议: {available_protocols}")

    # 验证协议可用性
    missing_protocols = []
    for protocol in source_protocols + [target_protocol]:
        if protocol not in available_protocols:
            missing_protocols.append(protocol)

    if missing_protocols:
        print(f"缺失协议数据: {missing_protocols}")
        print(f"请检查 {data_root} 目录下的数据文件")
        return None

    # 2. 加载所有协议数据
    print("\n2. 加载协议数据...")
    all_protocols = set(source_protocols + [target_protocol])
    all_data = {}

    for protocol_name in all_protocols:
        try:
            protocol_data = data_loader.load_protocol_data(protocol_name)
            if len(protocol_data) == 0:
                print(f"  {protocol_name}: 无有效数据")
                continue
            all_data[protocol_name] = protocol_data
            print(f"{protocol_name}: {len(protocol_data)} 条数据")
        except Exception as e:
            print(f"加载 {protocol_name} 失败: {e}")
            return None

    if len(all_data) == 0:
        print("没有成功加载任何协议数据")
        return None

    # 3. 数据分割
    print("\n3. 数据分割...")
    data_splits = {}

    for protocol_name, data in all_data.items():
        random.shuffle(data)

        if protocol_name == target_protocol:
            # 目标协议：少样本学习
            train_size = min(200, int(len(data) * 0.6))
            val_size = int(len(data) * 0.2)

            data_splits[protocol_name] = {
                'train': data[:train_size],
                'val': data[train_size:train_size + val_size],
                'test': data[train_size + val_size:]
            }
            print(
                f"  {protocol_name} (目标): 训练={train_size}, 验证={val_size}, 测试={len(data_splits[protocol_name]['test'])}")
        else:
            # 源协议：充足数据
            train_size = int(len(data) * 0.8)
            val_size = int(len(data) * 0.1)

            data_splits[protocol_name] = {
                'train': data[:train_size],
                'val': data[train_size:train_size + val_size],
                'test': data[train_size + val_size:]
            }
            print(
                f"  {protocol_name} (源): 训练={train_size}, 验证={val_size}, 测试={len(data_splits[protocol_name]['test'])}")

    # 4. 创建数据集和数据加载器
    print("\n4. 创建数据集和数据加载器...")
    batch_size = training_params.get('batch_size', 32)

    # 源协议数据加载器
    source_loaders = {}
    for protocol_name in source_protocols:
        if protocol_name in data_splits and len(data_splits[protocol_name]['train']) > 0:
            dataset = GenericTransferLearningDataset(
                data_splits[protocol_name]['train'],
                protocol_filter=protocol_name,
                augment=True,
                unified_semantic_types=data_loader.unified_semantic_types,
                unified_semantic_functions=data_loader.unified_semantic_functions
            )
            source_loaders[protocol_name] = DataLoader(
                dataset, batch_size=batch_size, shuffle=True, num_workers=0
            )

    if len(source_loaders) == 0:
        print("没有有效的源协议数据")
        return None

    # 目标协议数据加载器
    if target_protocol not in data_splits:
        print(f"目标协议 {target_protocol} 数据不足")
        return None

    target_train_dataset = GenericTransferLearningDataset(
        data_splits[target_protocol]['train'],
        protocol_filter=target_protocol,
        augment=True,
        unified_semantic_types=data_loader.unified_semantic_types,
        unified_semantic_functions=data_loader.unified_semantic_functions
    )
    target_val_dataset = GenericTransferLearningDataset(
        data_splits[target_protocol]['val'],
        protocol_filter=target_protocol,
        unified_semantic_types=data_loader.unified_semantic_types,
        unified_semantic_functions=data_loader.unified_semantic_functions
    )
    target_test_dataset = GenericTransferLearningDataset(
        data_splits[target_protocol]['test'],
        protocol_filter=target_protocol,
        unified_semantic_types=data_loader.unified_semantic_types,
        unified_semantic_functions=data_loader.unified_semantic_functions
    )

    target_train_loader = DataLoader(target_train_dataset, batch_size=batch_size, shuffle=True, num_workers=0)
    target_val_loader = DataLoader(target_val_dataset, batch_size=batch_size, shuffle=False, num_workers=0)
    target_test_loader = DataLoader(target_test_dataset, batch_size=batch_size, shuffle=False, num_workers=0)

    # 5. 创建模型
    print("\n⚡ 5. 创建通用跨协议迁移学习模型...")
    all_protocol_names = list(all_protocols)

    model = GenericCrossProtocolTransferModel(
        protocol_names=all_protocol_names,
        d_model=model_params.get('d_model', 512),
        encoder_layers=model_params.get('encoder_layers', 6),
        num_semantic_types=len(data_loader.unified_semantic_types),
        num_semantic_functions=len(data_loader.unified_semantic_functions)
    )

    total_params = sum(p.numel() for p in model.parameters())
    print(f"模型总参数量: {total_params:,}")
    print(f"支持协议: {all_protocol_names}")

    # 6. 开始迁移学习实验
    print("\n6. 开始迁移学习实验...")
    trainer = GenericTransferLearningTrainer(model, device, all_protocol_names)

    # 基线实验：直接在目标协议上训练
    print(f"\n基线实验：直接在 {target_protocol.upper()} 上训练...")
    baseline_model = GenericCrossProtocolTransferModel(
        protocol_names=[target_protocol],
        d_model=model_params.get('d_model', 512),
        encoder_layers=model_params.get('encoder_layers', 6),
        num_semantic_types=len(data_loader.unified_semantic_types),
        num_semantic_functions=len(data_loader.unified_semantic_functions)
    ).to(device)

    baseline_trainer = GenericTransferLearningTrainer(baseline_model, device, [target_protocol])
    baseline_f1 = baseline_trainer.transfer_to_target(
        target_train_loader, target_val_loader,
        target_protocol, epochs=20, freeze_encoder=False
    )

    print(f"基线结果（无迁移学习）: F1 = {baseline_f1:.4f}")

    # 迁移学习实验
    print(f"\n开始完整迁移学习流程...")

    # 阶段1：源协议预训练
    source_f1 = trainer.train_source_protocols(
        source_loaders,
        epochs=training_params.get('source_epochs', 25)
    )

    # 阶段2a：冻结编码器迁移
    frozen_f1 = trainer.transfer_to_target(
        target_train_loader, target_val_loader, target_protocol,
        epochs=training_params.get('transfer_epochs', 15),
        freeze_encoder=True
    )

    # 阶段2b：端到端微调
    finetuned_f1 = trainer.transfer_to_target(
        target_train_loader, target_val_loader, target_protocol,
        epochs=training_params.get('finetune_epochs', 15),
        freeze_encoder=False
    )

    # 7. 最终测试评估
    print("\n7. 最终测试评估...")

    # 基线模型测试
    baseline_test_metrics = baseline_trainer._evaluate_on_protocol(target_test_loader, target_protocol)
    baseline_test_f1 = (baseline_test_metrics['type_f1'] + baseline_test_metrics['func_f1']) / 2

    # 迁移学习模型测试
    transfer_test_metrics = trainer._evaluate_on_protocol(target_test_loader, target_protocol)
    transfer_test_f1 = (transfer_test_metrics['type_f1'] + transfer_test_metrics['func_f1']) / 2

    # 结果对比
    print(f"\n" + "=" * 80)
    print("迁移学习效果对比")
    print("=" * 80)
    print(f"协议组合: {source_protocols} → {target_protocol}")
    print(f"基线模型 (无迁移):     {baseline_test_f1:.4f}")
    print(f"迁移学习模型:         {transfer_test_f1:.4f}")
    print(f"绝对提升:            {transfer_test_f1 - baseline_test_f1:+.4f}")

    if baseline_test_f1 > 0:
        print(f"相对提升:            {((transfer_test_f1 / baseline_test_f1) - 1) * 100:+.1f}%")

    # 【新增】Format Extraction指标对比
    print(f"\nFormat Extraction指标对比:")
    print(f"基线模型:")
    print(f"  - accuracy: {baseline_test_metrics['boundary_acc']:.4f}")
    print(f"  - F1-score: {baseline_test_metrics['boundary_f1']:.4f}")
    print(f"  - perfection: {baseline_test_metrics['field_perfection']:.4f}")
    print(f"迁移学习模型:")
    print(f"  - accuracy: {transfer_test_metrics['boundary_acc']:.4f}")
    print(f"  - F1-score: {transfer_test_metrics['boundary_f1']:.4f}")
    print(f"  - perfection: {transfer_test_metrics['field_perfection']:.4f}")

    # 详细分析
    improvement = transfer_test_f1 - baseline_test_f1
    perfection_improvement = transfer_test_metrics['field_perfection'] - baseline_test_metrics['field_perfection']
    f1_improvement = transfer_test_metrics['boundary_f1'] - baseline_test_metrics['boundary_f1']

    if improvement > 0.1:
        print(f"\n迁移学习大成功！")
        print(f"   跨协议知识迁移显著提升了 {target_protocol} 协议性能")
    elif improvement > 0.05:
        print(f"\n迁移学习有效！")
        print(f"   模型成功学到了跨协议的通用特征")
    elif improvement > 0:
        print(f"\n迁移学习有轻微提升")
    else:
        print(f"\n迁移学习效果不明显，可能需要调整策略")

    if perfection_improvement > 0.1:
        print(f"   字段完美匹配率显著提升: {perfection_improvement:+.4f}")

    if f1_improvement > 0.1:
        print(f"   边界检测F1分数显著提升: {f1_improvement:+.4f}")

    return {
        'baseline_f1': baseline_test_f1,
        'transfer_f1': transfer_test_f1,
        'improvement': improvement,
        'source_protocols': source_protocols,
        'target_protocol': target_protocol,
        'baseline_metrics': baseline_test_metrics,
        'transfer_metrics': transfer_test_metrics,
        'perfection_improvement': perfection_improvement,
        'f1_improvement': f1_improvement
    }


# ===========================
# 命令行接口 - 保持不变
# ===========================

def main():
    parser = argparse.ArgumentParser(description='跨协议迁移学习实验')

    parser.add_argument('--source-protocols', nargs='+',
                        default=['dnp3'],
                        help='源协议列表 (default: dnp3)')

    parser.add_argument('--target-protocol', type=str, default='modbus',
                        help='目标协议 (default: modbus)')

    parser.add_argument('--data-root', type=str, default='../Msg2',
                        help='数据根目录 (default: ../Msg2)')

    parser.add_argument('--d-model', type=int, default=256,
                        help='模型维度 (default: 256)')

    parser.add_argument('--encoder-layers', type=int, default=4,
                        help='编码器层数 (default: 4)')

    parser.add_argument('--batch-size', type=int, default=16,
                        help='批次大小 (default: 16)')

    parser.add_argument('--source-epochs', type=int, default=10,
                        help='源协议训练轮数 (default: 10)')

    parser.add_argument('--transfer-epochs', type=int, default=8,
                        help='迁移训练轮数 (default: 8)')

    parser.add_argument('--finetune-epochs', type=int, default=8,
                        help='微调训练轮数 (default: 8)')

    args = parser.parse_args()

    # 设置参数
    model_params = {
        'd_model': args.d_model,
        'encoder_layers': args.encoder_layers
    }

    training_params = {
        'batch_size': args.batch_size,
        'source_epochs': args.source_epochs,
        'transfer_epochs': args.transfer_epochs,
        'finetune_epochs': args.finetune_epochs
    }

    # 运行实验
    results = run_flexible_transfer_experiment(
        source_protocols=args.source_protocols,
        target_protocol=args.target_protocol,
        data_root=args.data_root,
        model_params=model_params,
        training_params=training_params
    )

    if results:
        print(f"\n实验完成！")
        print(
            f"从 {results['source_protocols']} 到 {results['target_protocol']} 的迁移效果: {results['improvement']:+.4f}")
        print(f"字段完美匹配率提升: {results['perfection_improvement']:+.4f}")
        print(f"边界检测F1分数提升: {results['f1_improvement']:+.4f}")
    else:
        print(f"\n实验失败，请检查数据和配置")


if __name__ == "__main__":
    # 测试运行
    results = run_flexible_transfer_experiment(['modbus'], 'dns')