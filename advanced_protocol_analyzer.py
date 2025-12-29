#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
1. 加载追踪数据
2. 协议预分析
3. 上下文感知字段检测 + 语义图构建
4. 高效探索 + 未知功能推断
5. 类型推断
6. 字段细化与验证
"""

import os
import json
import logging
import argparse
import struct
from pathlib import Path
from typing import List, Dict, Tuple, Set, Optional, Any
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import numpy as np

# 尝试导入scapy
try:
    from scapy.all import rdpcap, Raw, TCP, UDP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("Warning: scapy not available, using basic packet parsing")

# 导入创新模块
try:
    from semantic_graph_builder import SemanticGraphBuilder
    from unknown_function_inferencer import UnknownFunctionInferencer
    HAS_ADVANCED_MODULES = True
except ImportError:
    HAS_ADVANCED_MODULES = False
    print("Warning: Advanced modules not available, using basic analysis")


# =============================================================================
# 数据结构定义
# =============================================================================

@dataclass
class ProtocolSignature:
    """协议签名"""
    protocol_type: str  # modbus, smb2, http2, dns, unknown
    confidence: float   # 0.0 - 1.0
    variant: str        # tcp, rtu, ascii for modbus; v2, v3 for smb
    features: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FunctionCodeProfile:
    """功能码/命令类型分析"""
    code: int
    count: int
    name: str
    request_structure: List[Tuple[int, int, str]]  # [(offset, size, name), ...]
    response_structure: List[Tuple[int, int, str]]
    avg_length: float
    length_variance: float


@dataclass
class FieldCandidate:
    """字段候选"""
    start: int
    end: int
    field_type: str  # length, offset, counter, checksum, data, constant, etc.
    confidence: float
    dependencies: List[int] = field(default_factory=list)  # 依赖的其他字段
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DependencyEdge:
    """字段依赖边"""
    source_field: int  # 字段索引
    target_field: int
    dependency_type: str  # length_of, offset_to, checksum_of, etc.
    weight: float


# =============================================================================
# 步骤2: 协议预分析
# =============================================================================

class ProtocolPreAnalyzer:
    """
    协议预分析器

    功能:
    1. 协议检测 - 识别协议类型
    2. 协议变体识别 - 识别协议的具体变体
    3. 功能码分析 - 分析命令/功能码分布和结构
    """

    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)

        # 协议签名数据库
        self.protocol_signatures = {
            'modbus_tcp': {
                'magic': None,  # Modbus没有固定魔数
                'port': 502,
                'header_size': 7,
                'features': ['transaction_id', 'protocol_id', 'length', 'unit_id']
            },
            'smb2': {
                'magic': b'\xfeSMB',
                'port': 445,
                'header_size': 64,
                'features': ['protocol_id', 'structure_size', 'command', 'message_id']
            },
            'http2': {
                'magic': b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n',  # Connection preface
                'port': 443,
                'header_size': 9,
                'features': ['length', 'type', 'flags', 'stream_id']
            },
            'dns': {
                'magic': None,
                'port': 53,
                'header_size': 12,
                'features': ['transaction_id', 'flags', 'questions', 'answers']
            }
        }

        # Modbus功能码定义
        self.modbus_function_codes = {
            0x01: ('Read Coils', [(0, 2, 'start_addr'), (2, 2, 'quantity')]),
            0x02: ('Read Discrete Inputs', [(0, 2, 'start_addr'), (2, 2, 'quantity')]),
            0x03: ('Read Holding Registers', [(0, 2, 'start_addr'), (2, 2, 'quantity')]),
            0x04: ('Read Input Registers', [(0, 2, 'start_addr'), (2, 2, 'quantity')]),
            0x05: ('Write Single Coil', [(0, 2, 'output_addr'), (2, 2, 'output_value')]),
            0x06: ('Write Single Register', [(0, 2, 'register_addr'), (2, 2, 'register_value')]),
            0x0F: ('Write Multiple Coils', [(0, 2, 'start_addr'), (2, 2, 'quantity'), (4, 1, 'byte_count')]),
            0x10: ('Write Multiple Registers', [(0, 2, 'start_addr'), (2, 2, 'quantity'), (4, 1, 'byte_count')]),
        }

        # SMB2命令定义
        self.smb2_commands = {
            0x00: 'NEGOTIATE',
            0x01: 'SESSION_SETUP',
            0x02: 'LOGOFF',
            0x03: 'TREE_CONNECT',
            0x04: 'TREE_DISCONNECT',
            0x05: 'CREATE',
            0x06: 'CLOSE',
            0x07: 'FLUSH',
            0x08: 'READ',
            0x09: 'WRITE',
            0x0A: 'LOCK',
            0x0B: 'IOCTL',
            0x0C: 'CANCEL',
            0x0D: 'ECHO',
            0x0E: 'QUERY_DIRECTORY',
            0x0F: 'CHANGE_NOTIFY',
            0x10: 'QUERY_INFO',
            0x11: 'SET_INFO',
        }

    def analyze(self, messages: List[bytes]) -> Dict[str, Any]:
        """
        执行协议预分析

        Args:
            messages: 消息列表

        Returns:
            分析结果字典
        """
        self.logger.info("=" * 60)
        self.logger.info("步骤2: 协议预分析")
        self.logger.info("=" * 60)

        results = {
            'protocol_signature': None,
            'function_profiles': [],
            'message_statistics': {},
            'protocol_features': {}
        }

        if not messages:
            return results

        # 2.1 协议检测
        signature = self._detect_protocol(messages)
        results['protocol_signature'] = signature
        self.logger.info(f"检测到协议: {signature.protocol_type} (置信度: {signature.confidence:.2f})")
        self.logger.info(f"协议变体: {signature.variant}")

        # 2.2 消息统计
        stats = self._compute_message_statistics(messages)
        results['message_statistics'] = stats
        self.logger.info(f"消息统计: {stats['total_messages']}条消息, "
                        f"{stats['unique_lengths']}种长度")

        # 2.3 功能码/命令分析
        if signature.protocol_type == 'modbus':
            profiles = self._analyze_modbus_functions(messages)
        elif signature.protocol_type == 'smb2':
            profiles = self._analyze_smb2_commands(messages)
        else:
            profiles = self._analyze_generic_commands(messages)

        results['function_profiles'] = profiles
        self.logger.info(f"识别到 {len(profiles)} 种功能码/命令类型")

        # 2.4 提取协议特征
        features = self._extract_protocol_features(messages, signature)
        results['protocol_features'] = features

        return results

    def _detect_protocol(self, messages: List[bytes]) -> ProtocolSignature:
        """检测协议类型"""
        scores = {}

        # 检测SMB2
        smb2_score = self._score_smb2(messages)
        scores['smb2'] = smb2_score

        # 检测Modbus TCP
        modbus_score = self._score_modbus(messages)
        scores['modbus'] = modbus_score

        # 检测DHCP (优先级高于HTTP/2，避免误判)
        dhcp_score = self._score_dhcp(messages)
        scores['dhcp'] = dhcp_score

        # 检测HTTP/2
        http2_score = self._score_http2(messages)
        scores['http2'] = http2_score

        # 检测DNS
        dns_score = self._score_dns(messages)
        scores['dns'] = dns_score

        # 选择最高分
        best_protocol = max(scores, key=scores.get)
        best_score = scores[best_protocol]

        if best_score < 0.3:
            best_protocol = 'unknown'

        # 确定变体
        variant = self._detect_variant(messages, best_protocol)

        return ProtocolSignature(
            protocol_type=best_protocol,
            confidence=best_score,
            variant=variant,
            features=scores
        )

    def _score_smb2(self, messages: List[bytes]) -> float:
        """评估SMB2协议匹配度"""
        if not messages:
            return 0.0

        score = 0.0
        checks = 0

        for msg in messages[:min(50, len(messages))]:
            checks += 1

            # 检查SMB2魔数
            if len(msg) >= 4 and msg[0:4] == b'\xfeSMB':
                score += 1.0
            # 检查结构大小字段
            elif len(msg) >= 6:
                struct_size = struct.unpack('<H', msg[4:6])[0]
                if struct_size == 64:  # SMB2固定头部大小
                    score += 0.5

        return score / checks if checks > 0 else 0.0

    def _score_modbus(self, messages: List[bytes]) -> float:
        """评估Modbus TCP协议匹配度"""
        if not messages:
            return 0.0

        score = 0.0
        checks = 0

        for msg in messages[:min(50, len(messages))]:
            checks += 1

            if len(msg) < 8:
                continue

            # 检查协议标识符 (应该是0x0000)
            protocol_id = struct.unpack('>H', msg[2:4])[0]
            if protocol_id == 0:
                score += 0.3

            # 检查长度字段一致性
            length_field = struct.unpack('>H', msg[4:6])[0]
            actual_length = len(msg) - 6
            if length_field == actual_length:
                score += 0.5

            # 检查功能码范围
            func_code = msg[7]
            if func_code in self.modbus_function_codes or (0x80 <= func_code <= 0x90):
                score += 0.2

        return score / checks if checks > 0 else 0.0

    def _score_http2(self, messages: List[bytes]) -> float:
        """评估HTTP/2协议匹配度"""
        if not messages:
            return 0.0

        score = 0.0
        checks = 0

        for msg in messages[:min(50, len(messages))]:
            checks += 1

            if len(msg) < 9:
                continue

            # 检查帧长度字段
            frame_length = struct.unpack('>I', b'\x00' + msg[0:3])[0]
            if frame_length == len(msg) - 9:
                score += 0.5

            # 检查帧类型 (0-9是有效类型)
            frame_type = msg[3]
            if 0 <= frame_type <= 9:
                score += 0.3

            # 检查流ID的保留位
            stream_id = struct.unpack('>I', msg[5:9])[0]
            if (stream_id & 0x80000000) == 0:  # 保留位应该是0
                score += 0.2

        return score / checks if checks > 0 else 0.0

    def _score_dns(self, messages: List[bytes]) -> float:
        """评估DNS协议匹配度"""
        if not messages:
            return 0.0

        score = 0.0
        checks = 0

        for msg in messages[:min(50, len(messages))]:
            checks += 1

            if len(msg) < 12:
                continue

            # 检查问题数和回答数的合理性
            questions = struct.unpack('>H', msg[4:6])[0]
            answers = struct.unpack('>H', msg[6:8])[0]

            if 0 < questions <= 10:
                score += 0.3
            if answers <= 50:
                score += 0.2

            # 检查flags字段的合理性
            flags = struct.unpack('>H', msg[2:4])[0]
            opcode = (flags >> 11) & 0x0F
            if opcode <= 5:  # 有效的opcode
                score += 0.3

            # 检查是否有有效的域名格式
            if len(msg) > 12:
                first_label_len = msg[12]
                if 0 < first_label_len < 64:  # 有效的标签长度
                    score += 0.2

        return score / checks if checks > 0 else 0.0

    def _score_dhcp(self, messages: List[bytes]) -> float:
        """评估DHCP协议匹配度"""
        if not messages:
            return 0.0

        score = 0.0
        checks = 0

        for msg in messages[:min(50, len(messages))]:
            checks += 1

            if len(msg) < 240:  # DHCP最小长度通常为240字节
                continue

            # 检查op字段 (1=BOOTREQUEST, 2=BOOTREPLY)
            op = msg[0]
            if op in [1, 2]:
                score += 0.3

            # 检查htype字段 (1=Ethernet)
            htype = msg[1]
            if htype == 1:
                score += 0.2

            # 检查hlen字段 (6=MAC地址长度)
            hlen = msg[2]
            if hlen == 6:
                score += 0.2

            # 检查magic cookie (0x63825363)
            if len(msg) >= 240:
                magic_cookie = struct.unpack('>I', msg[236:240])[0]
                if magic_cookie == 0x63825363:
                    score += 0.4  # Magic cookie是DHCP的明确标志

        return score / checks if checks > 0 else 0.0

    def _detect_variant(self, messages: List[bytes], protocol: str) -> str:
        """检测协议变体"""
        if protocol == 'modbus':
            # 检测是TCP还是RTU
            # TCP有MBAP头部（7字节），RTU没有
            if messages and len(messages[0]) >= 7:
                protocol_id = struct.unpack('>H', messages[0][2:4])[0]
                if protocol_id == 0:
                    return 'tcp'
            return 'rtu'

        elif protocol == 'smb2':
            # 检测SMB版本
            for msg in messages[:10]:
                if len(msg) >= 4:
                    if msg[0:4] == b'\xfeSMB':
                        # 检查Dialect
                        return 'v2'
            return 'v2'

        elif protocol == 'http2':
            return 'h2'

        elif protocol == 'dns':
            return 'standard'

        elif protocol == 'dhcp':
            return 'standard'

        return 'unknown'

    def _compute_message_statistics(self, messages: List[bytes]) -> Dict[str, Any]:
        """计算消息统计信息"""
        lengths = [len(msg) for msg in messages]

        return {
            'total_messages': len(messages),
            'unique_lengths': len(set(lengths)),
            'min_length': min(lengths) if lengths else 0,
            'max_length': max(lengths) if lengths else 0,
            'avg_length': np.mean(lengths) if lengths else 0,
            'length_std': np.std(lengths) if lengths else 0,
            'length_distribution': dict(Counter(lengths).most_common(10))
        }

    def _analyze_modbus_functions(self, messages: List[bytes]) -> List[FunctionCodeProfile]:
        """分析Modbus功能码"""
        profiles = []
        func_messages = defaultdict(list)

        # 按功能码分组
        for msg in messages:
            if len(msg) > 7:
                func_code = msg[7]
                func_messages[func_code].append(msg)

        # 分析每个功能码
        for func_code, msgs in func_messages.items():
            name = self.modbus_function_codes.get(func_code, ('Unknown', []))[0]
            req_struct = self.modbus_function_codes.get(func_code, ('Unknown', []))[1]

            lengths = [len(m) for m in msgs]

            profile = FunctionCodeProfile(
                code=func_code,
                count=len(msgs),
                name=name,
                request_structure=req_struct,
                response_structure=[],  # 需要更复杂的分析
                avg_length=np.mean(lengths),
                length_variance=np.var(lengths)
            )
            profiles.append(profile)

        # 按数量排序
        profiles.sort(key=lambda x: x.count, reverse=True)

        self.logger.info("Modbus功能码分析:")
        for p in profiles:
            self.logger.info(f"  FC 0x{p.code:02X} ({p.name}): {p.count}条, "
                           f"平均长度: {p.avg_length:.1f}")

        return profiles

    def _analyze_smb2_commands(self, messages: List[bytes]) -> List[FunctionCodeProfile]:
        """分析SMB2命令"""
        profiles = []
        cmd_messages = defaultdict(list)

        # 按命令分组
        for msg in messages:
            if len(msg) >= 14:
                # SMB2命令在偏移12-13
                command = struct.unpack('<H', msg[12:14])[0]
                cmd_messages[command].append(msg)

        # 分析每个命令
        for cmd, msgs in cmd_messages.items():
            name = self.smb2_commands.get(cmd, f'Unknown(0x{cmd:02X})')
            lengths = [len(m) for m in msgs]

            profile = FunctionCodeProfile(
                code=cmd,
                count=len(msgs),
                name=name,
                request_structure=[],
                response_structure=[],
                avg_length=np.mean(lengths),
                length_variance=np.var(lengths)
            )
            profiles.append(profile)

        profiles.sort(key=lambda x: x.count, reverse=True)

        self.logger.info("SMB2命令分析:")
        for p in profiles:
            self.logger.info(f"  CMD 0x{p.code:02X} ({p.name}): {p.count}条, "
                           f"平均长度: {p.avg_length:.1f}")

        return profiles

    def _analyze_generic_commands(self, messages: List[bytes]) -> List[FunctionCodeProfile]:
        """通用命令分析"""
        # 尝试不同位置的字节作为命令标识
        profiles = []

        # 尝试前几个字节位置
        for offset in [0, 1, 2, 3, 4]:
            cmd_messages = defaultdict(list)

            for msg in messages:
                if len(msg) > offset:
                    cmd = msg[offset]
                    cmd_messages[cmd].append(msg)

            # 计算熵来评估这个位置是否是命令字段
            if len(cmd_messages) > 1:
                counts = [len(v) for v in cmd_messages.values()]
                entropy = -sum((c/len(messages)) * np.log2(c/len(messages))
                              for c in counts if c > 0)

                # 如果熵在合理范围内，可能是命令字段
                if 1.0 < entropy < 4.0:
                    for cmd, msgs in cmd_messages.items():
                        lengths = [len(m) for m in msgs]
                        profile = FunctionCodeProfile(
                            code=cmd,
                            count=len(msgs),
                            name=f'Type_{cmd}@offset{offset}',
                            request_structure=[],
                            response_structure=[],
                            avg_length=np.mean(lengths),
                            length_variance=np.var(lengths)
                        )
                        profiles.append(profile)
                    break

        profiles.sort(key=lambda x: x.count, reverse=True)
        return profiles

    def _extract_protocol_features(self, messages: List[bytes],
                                   signature: ProtocolSignature) -> Dict[str, Any]:
        """提取协议特征"""
        features = {
            'byte_patterns': {},
            'alignment': None,
            'endianness': None,
            'common_values': {}
        }

        if not messages:
            return features

        # 分析字节模式
        min_len = min(len(m) for m in messages)

        for pos in range(min(min_len, 20)):
            values = [m[pos] for m in messages]
            unique_values = set(values)

            if len(unique_values) == 1:
                features['byte_patterns'][pos] = {
                    'type': 'constant',
                    'value': values[0]
                }
            elif len(unique_values) <= 5:
                features['byte_patterns'][pos] = {
                    'type': 'enum',
                    'values': list(unique_values)
                }

        # 检测对齐模式
        if signature.protocol_type == 'smb2':
            features['alignment'] = 4
        elif signature.protocol_type == 'modbus':
            features['alignment'] = 2
        else:
            features['alignment'] = 1

        # 检测字节序
        features['endianness'] = 'big' if signature.protocol_type in ['modbus', 'dns'] else 'little'

        return features


# =============================================================================
# 步骤3: 上下文感知字段检测
# =============================================================================

class ContextAwareFieldDetector:
    """
    上下文感知字段检测器

    功能:
    1. 长度字段检测 - 检测指示其他字段长度的字段
    2. 偏移字段检测 - 检测指示数据位置的字段
    3. TLV结构检测 - 检测Type-Length-Value结构
    4. 条件字段检测 - 检测依赖其他字段值的字段
    5. 依赖图构建 - 构建字段间的依赖关系图
    """

    def __init__(self, protocol_info: Dict[str, Any], logger=None):
        self.protocol_info = protocol_info
        self.logger = logger or logging.getLogger(__name__)

        # 检测参数
        self.length_field_tolerance = 2  # 长度字段允许的误差
        self.min_confidence = 0.5

    def detect(self, messages: List[bytes]) -> Dict[str, Any]:
        """
        执行上下文感知字段检测

        Args:
            messages: 消息列表

        Returns:
            检测结果字典
        """
        self.logger.info("=" * 60)
        self.logger.info("步骤3: 上下文感知字段检测")
        self.logger.info("=" * 60)

        results = {
            'field_candidates': [],
            'length_fields': [],
            'offset_fields': [],
            'tlv_structures': [],
            'conditional_fields': [],
            'dependency_graph': []
        }

        if not messages:
            return results

        # 3.1 检测长度字段
        length_fields = self._detect_length_fields(messages)
        results['length_fields'] = length_fields
        self.logger.info(f"检测到 {len(length_fields)} 个长度字段")

        # 3.2 检测偏移字段
        offset_fields = self._detect_offset_fields(messages)
        results['offset_fields'] = offset_fields
        self.logger.info(f"检测到 {len(offset_fields)} 个偏移字段")

        # 3.3 检测TLV结构
        tlv_structures = self._detect_tlv_structures(messages)
        results['tlv_structures'] = tlv_structures
        self.logger.info(f"检测到 {len(tlv_structures)} 个TLV结构")

        # 3.4 检测条件字段
        conditional_fields = self._detect_conditional_fields(messages)
        results['conditional_fields'] = conditional_fields
        self.logger.info(f"检测到 {len(conditional_fields)} 个条件字段")

        # 3.5 构建依赖图
        dependency_graph = self._build_dependency_graph(
            length_fields, offset_fields, tlv_structures, conditional_fields
        )
        results['dependency_graph'] = dependency_graph
        self.logger.info(f"构建依赖图: {len(dependency_graph)} 条边")

        # 3.6 整合所有字段候选
        all_candidates = self._merge_field_candidates(
            length_fields, offset_fields, tlv_structures, conditional_fields
        )
        results['field_candidates'] = all_candidates

        return results

    def _detect_length_fields(self, messages: List[bytes]) -> List[FieldCandidate]:
        """
        检测长度字段

        策略:
        1. 遍历所有可能的字段位置和大小（1, 2, 4字节）
        2. 计算字段值与消息长度/剩余长度的相关性
        3. 识别指示其他字段长度的字段
        4. 针对DNS和DHCP协议进行特定字段检测
        """
        length_fields = []

        if not messages:
            return length_fields

        min_len = min(len(m) for m in messages)

        # 检测参数
        field_sizes = [1, 2, 4]  # 可能的长度字段大小
        endianness = self.protocol_info.get('protocol_features', {}).get('endianness', 'big')
        protocol_type = self.protocol_info.get('protocol_signature', ProtocolSignature('unknown', 0.0, 'unknown')).protocol_type

        # 针对DNS协议，专门检测计数字段
        if protocol_type == 'dns' and min_len >= 12:
            # DNS头部计数字段: QDCOUNT(4-5), ANCOUNT(6-7), NSCOUNT(8-9), ARCOUNT(10-11)
            dns_count_fields = [
                (4, 6, 'qdcount', 'question_count'),
                (6, 8, 'ancount', 'answer_count'),
                (8, 10, 'nscount', 'nameserver_count'),
                (10, 12, 'arcount', 'additional_count')
            ]

            for start, end, name, desc in dns_count_fields:
                if min_len >= end:
                    candidate = FieldCandidate(
                        start=start,
                        end=end,
                        field_type='length',
                        confidence=0.95,  # DNS标准字段，高置信度
                        properties={
                            'length_type': 'count',
                            'target': desc,
                            'field_size': 2,
                            'endianness': 'big',
                            'protocol_specific': 'dns_header'
                        }
                    )
                    length_fields.append(candidate)
                    self.logger.debug(f"DNS计数字段: [{start}:{end}] {name} (标准协议字段)")

        # 针对DHCP协议，检测选项长度字段
        if protocol_type == 'dhcp' and min_len >= 240:
            # DHCP固定头部之后是选项字段，采用TLV格式
            # 但这里我们标记hlen字段(位置2)为长度类型
            candidate = FieldCandidate(
                start=2,
                end=3,
                field_type='length',
                confidence=0.9,
                properties={
                    'length_type': 'hardware_address_length',
                    'target': 'chaddr_field',
                    'field_size': 1,
                    'protocol_specific': 'dhcp_header'
                }
            )
            length_fields.append(candidate)
            self.logger.debug(f"DHCP长度字段: [2:3] hlen (硬件地址长度)")

        # 通用长度字段检测
        for start_pos in range(min(min_len - 1, 20)):
            for field_size in field_sizes:
                if start_pos + field_size > min_len:
                    continue

                # 提取所有消息中该位置的值
                values = []
                msg_lengths = []
                remaining_lengths = []

                for msg in messages:
                    if len(msg) < start_pos + field_size:
                        continue

                    # 解析字段值
                    field_bytes = msg[start_pos:start_pos + field_size]
                    if field_size == 1:
                        value = field_bytes[0]
                    elif field_size == 2:
                        fmt = '>H' if endianness == 'big' else '<H'
                        value = struct.unpack(fmt, field_bytes)[0]
                    else:  # 4 bytes
                        fmt = '>I' if endianness == 'big' else '<I'
                        value = struct.unpack(fmt, field_bytes)[0]

                    values.append(value)
                    msg_lengths.append(len(msg))
                    remaining_lengths.append(len(msg) - start_pos - field_size)

                if len(values) < 3:
                    continue

                # 检查与消息总长度的关系
                total_len_score = self._check_length_relationship(
                    values, msg_lengths, 'total'
                )

                # 检查与剩余长度的关系
                remaining_len_score = self._check_length_relationship(
                    values, remaining_lengths, 'remaining'
                )

                # 检查与固定偏移后长度的关系
                fixed_offset_scores = []
                for offset in [0, 2, 4, 6, 8]:
                    offset_lengths = [l - offset for l in msg_lengths]
                    score = self._check_length_relationship(values, offset_lengths, f'offset_{offset}')
                    fixed_offset_scores.append((offset, score))

                best_offset_score = max(fixed_offset_scores, key=lambda x: x[1])

                # 选择最佳匹配
                best_score = max(total_len_score, remaining_len_score, best_offset_score[1])

                if best_score >= self.min_confidence:
                    # 确定长度类型
                    if total_len_score == best_score:
                        length_type = 'total_length'
                        target_desc = 'message'
                    elif remaining_len_score == best_score:
                        length_type = 'remaining_length'
                        target_desc = f'from_pos_{start_pos + field_size}'
                    else:
                        length_type = 'offset_length'
                        target_desc = f'from_offset_{best_offset_score[0]}'

                    candidate = FieldCandidate(
                        start=start_pos,
                        end=start_pos + field_size,
                        field_type='length',
                        confidence=best_score,
                        properties={
                            'length_type': length_type,
                            'target': target_desc,
                            'field_size': field_size,
                            'endianness': endianness
                        }
                    )
                    length_fields.append(candidate)

                    self.logger.debug(f"长度字段: [{start_pos}:{start_pos+field_size}] "
                                    f"类型={length_type}, 置信度={best_score:.2f}")

        # 去重和排序
        length_fields = self._deduplicate_candidates(length_fields)
        length_fields.sort(key=lambda x: (-x.confidence, x.start))

        return length_fields[:10]  # 返回top 10

    def _check_length_relationship(self, values: List[int],
                                   lengths: List[int],
                                   rel_type: str) -> float:
        """检查值与长度的关系"""
        if len(values) != len(lengths):
            return 0.0

        # 计算精确匹配
        exact_matches = sum(1 for v, l in zip(values, lengths) if v == l)

        # 计算近似匹配（允许小误差）
        approx_matches = sum(1 for v, l in zip(values, lengths)
                           if abs(v - l) <= self.length_field_tolerance)

        # 计算相关系数
        if len(set(values)) > 1 and len(set(lengths)) > 1:
            correlation = np.corrcoef(values, lengths)[0, 1]
            if np.isnan(correlation):
                correlation = 0
        else:
            correlation = 1.0 if values == lengths else 0.0

        # 综合评分
        exact_score = exact_matches / len(values)
        approx_score = approx_matches / len(values)

        # 精确匹配权重最高
        score = 0.5 * exact_score + 0.3 * approx_score + 0.2 * max(0, correlation)

        return score

    def _detect_offset_fields(self, messages: List[bytes]) -> List[FieldCandidate]:
        """
        检测偏移字段

        策略:
        1. 查找值指向消息内有效位置的字段
        2. 检查偏移位置是否有有意义的数据
        """
        offset_fields = []

        if not messages:
            return offset_fields

        min_len = min(len(m) for m in messages)

        for start_pos in range(min(min_len - 2, 30)):
            for field_size in [2, 4]:
                if start_pos + field_size > min_len:
                    continue

                values = []
                valid_count = 0

                for msg in messages:
                    if len(msg) < start_pos + field_size:
                        continue

                    # 解析偏移值
                    field_bytes = msg[start_pos:start_pos + field_size]
                    if field_size == 2:
                        value = struct.unpack('<H', field_bytes)[0]
                    else:
                        value = struct.unpack('<I', field_bytes)[0]

                    values.append(value)

                    # 检查偏移是否指向消息内的有效位置
                    if 0 < value < len(msg) - 1:
                        valid_count += 1

                if len(values) < 3:
                    continue

                # 计算有效偏移比例
                valid_ratio = valid_count / len(values)

                # 检查值的分布（偏移字段通常有一定变化但不会太大）
                if len(set(values)) > 1:
                    value_range = max(values) - min(values)
                    # 偏移范围应该在合理范围内
                    reasonable_range = value_range < max(len(m) for m in messages)
                else:
                    reasonable_range = True

                confidence = valid_ratio * (0.8 if reasonable_range else 0.5)

                if confidence >= self.min_confidence:
                    candidate = FieldCandidate(
                        start=start_pos,
                        end=start_pos + field_size,
                        field_type='offset',
                        confidence=confidence,
                        properties={
                            'field_size': field_size,
                            'avg_offset': np.mean(values),
                            'offset_range': (min(values), max(values))
                        }
                    )
                    offset_fields.append(candidate)

        offset_fields = self._deduplicate_candidates(offset_fields)
        return offset_fields[:5]

    def _detect_tlv_structures(self, messages: List[bytes]) -> List[Dict[str, Any]]:
        """
        检测TLV (Type-Length-Value) 结构

        策略:
        1. 在消息中寻找重复的TLV模式
        2. 验证Length字段与Value长度的一致性
        """
        tlv_structures = []

        if not messages:
            return tlv_structures

        # TLV常见格式
        tlv_formats = [
            {'type_size': 1, 'length_size': 1, 'name': 'TLV-8'},
            {'type_size': 2, 'length_size': 2, 'name': 'TLV-16'},
            {'type_size': 1, 'length_size': 2, 'name': 'TLV-8-16'},
            {'type_size': 2, 'length_size': 1, 'name': 'TLV-16-8'},
        ]

        for fmt in tlv_formats:
            type_size = fmt['type_size']
            length_size = fmt['length_size']
            header_size = type_size + length_size

            for start_pos in range(0, 30, 2):  # 尝试不同的起始位置
                valid_count = 0

                for msg in messages:
                    pos = start_pos
                    tlv_count = 0

                    while pos + header_size <= len(msg):
                        # 读取Length字段
                        length_bytes = msg[pos + type_size:pos + header_size]
                        if length_size == 1:
                            value_length = length_bytes[0]
                        else:
                            value_length = struct.unpack('<H', length_bytes)[0]

                        # 验证
                        if value_length == 0 or pos + header_size + value_length > len(msg):
                            break

                        tlv_count += 1
                        pos += header_size + value_length

                    # 如果找到了多个TLV，且覆盖了大部分消息
                    if tlv_count >= 2 and pos > len(msg) * 0.5:
                        valid_count += 1

                confidence = valid_count / len(messages)

                if confidence >= self.min_confidence:
                    tlv_structures.append({
                        'format': fmt['name'],
                        'start_position': start_pos,
                        'type_size': type_size,
                        'length_size': length_size,
                        'confidence': confidence
                    })

        return tlv_structures

    def _detect_conditional_fields(self, messages: List[bytes]) -> List[FieldCandidate]:
        """
        检测条件字段

        策略:
        1. 找出值依赖于其他字段的字段
        2. 例如：当类型=1时，字段存在；当类型=2时，字段不存在
        """
        conditional_fields = []

        if not messages or len(messages) < 10:
            return conditional_fields

        # 按某个可能的类型字段分组
        min_len = min(len(m) for m in messages)

        for type_pos in range(min(min_len, 10)):
            # 按该位置的值分组消息
            groups = defaultdict(list)
            for msg in messages:
                type_value = msg[type_pos]
                groups[type_value].append(msg)

            # 如果分组合理（2-10组），分析每组的结构差异
            if 2 <= len(groups) <= 10:
                # 比较不同组的长度分布
                group_lengths = {}
                for type_val, group_msgs in groups.items():
                    lengths = [len(m) for m in group_msgs]
                    group_lengths[type_val] = {
                        'mean': np.mean(lengths),
                        'std': np.std(lengths),
                        'count': len(group_msgs)
                    }

                # 如果不同类型有显著不同的长度分布，说明存在条件字段
                means = [v['mean'] for v in group_lengths.values()]
                if len(means) > 1 and max(means) - min(means) > 4:
                    candidate = FieldCandidate(
                        start=type_pos,
                        end=type_pos + 1,
                        field_type='type_indicator',
                        confidence=0.7,
                        properties={
                            'controls_structure': True,
                            'group_count': len(groups),
                            'length_variation': max(means) - min(means)
                        }
                    )
                    conditional_fields.append(candidate)

        return conditional_fields

    def _build_dependency_graph(self, length_fields: List[FieldCandidate],
                                offset_fields: List[FieldCandidate],
                                tlv_structures: List[Dict],
                                conditional_fields: List[FieldCandidate]) -> List[DependencyEdge]:
        """
        构建字段依赖图

        节点: 字段
        边: 依赖关系
        """
        edges = []

        # 长度字段依赖
        for i, lf in enumerate(length_fields):
            # 长度字段指向它描述的目标
            target_start = lf.end
            edge = DependencyEdge(
                source_field=i,
                target_field=-1,  # -1表示指向消息剩余部分
                dependency_type='length_of',
                weight=lf.confidence
            )
            edges.append(edge)

        # 偏移字段依赖
        for i, of in enumerate(offset_fields):
            edge = DependencyEdge(
                source_field=len(length_fields) + i,
                target_field=-2,  # -2表示指向动态位置
                dependency_type='offset_to',
                weight=of.confidence
            )
            edges.append(edge)

        # 条件字段依赖
        for i, cf in enumerate(conditional_fields):
            edge = DependencyEdge(
                source_field=len(length_fields) + len(offset_fields) + i,
                target_field=-3,  # -3表示控制结构
                dependency_type='controls_structure',
                weight=cf.confidence
            )
            edges.append(edge)

        return edges

    def _merge_field_candidates(self, *field_lists) -> List[FieldCandidate]:
        """合并所有字段候选"""
        all_candidates = []
        for field_list in field_lists:
            if isinstance(field_list, list):
                for item in field_list:
                    if isinstance(item, FieldCandidate):
                        all_candidates.append(item)

        # 按位置排序
        all_candidates.sort(key=lambda x: x.start)

        return all_candidates

    def _deduplicate_candidates(self, candidates: List[FieldCandidate]) -> List[FieldCandidate]:
        """去除重叠的候选"""
        if not candidates:
            return candidates

        # 按置信度排序
        sorted_candidates = sorted(candidates, key=lambda x: -x.confidence)

        result = []
        used_ranges = []

        for c in sorted_candidates:
            # 检查是否与已选择的候选重叠
            overlaps = False
            for start, end in used_ranges:
                if not (c.end <= start or c.start >= end):
                    overlaps = True
                    break

            if not overlaps:
                result.append(c)
                used_ranges.append((c.start, c.end))

        return result


# =============================================================================
# 步骤4: 高效探索
# =============================================================================

@dataclass
class ByteEntropyInfo:
    """字节熵信息"""
    position: int
    entropy: float
    variance: float
    unique_values: int


@dataclass
class FieldPriority:
    """字段优先级"""
    field_id: int
    field_range: Tuple[int, int]
    priority_score: float
    exploration_value: float
    information_gain: float


class EfficientExplorer:
    """
    高效探索器

    功能:
    1. 字节熵计算 - 评估每个字节位置的信息量
    2. 字段优先级排序 - 确定探索顺序
    3. 自适应探索计划 - 动态调整探索策略
    4. 状态图跟踪 - 构建协议状态机
    """

    def __init__(self, field_candidates: List[FieldCandidate], logger=None, protocol_info: Dict[str, Any] = None):
        self.field_candidates = field_candidates
        self.logger = logger or logging.getLogger(__name__)
        self.entropy_threshold = 1.0
        self.protocol_info = protocol_info or {}

    def explore(self, messages: List[bytes]) -> Dict[str, Any]:
        """执行高效探索"""
        self.logger.info("=" * 60)
        self.logger.info("步骤4: 高效探索")
        self.logger.info("=" * 60)

        results = {
            'byte_entropy': [],
            'field_priorities': [],
            'exploration_plan': {},
            'state_graph': {},
            'optimization_suggestions': []
        }

        if not messages:
            return results

        # 4.1 字节熵计算
        entropy_info = self._calculate_byte_entropy(messages)
        results['byte_entropy'] = [
            {'position': e.position, 'entropy': e.entropy, 'unique_values': e.unique_values}
            for e in entropy_info[:20]
        ]
        self.logger.info(f"计算了 {len(entropy_info)} 个位置的字节熵")

        # 4.2 字段优先级排序
        field_priorities = self._rank_field_priorities(entropy_info, messages)
        results['field_priorities'] = [
            {'field_id': p.field_id, 'field_range': p.field_range, 'priority_score': p.priority_score}
            for p in field_priorities
        ]
        self.logger.info(f"排序了 {len(field_priorities)} 个字段的优先级")

        # 4.3 自适应探索计划
        exploration_plan = self._generate_exploration_plan(field_priorities, messages)
        results['exploration_plan'] = exploration_plan
        self.logger.info(f"生成探索计划: {exploration_plan.get('total_phases', 0)} 个阶段")

        # 4.4 状态图跟踪
        state_graph = self._build_state_graph(messages)
        results['state_graph'] = state_graph
        self.logger.info(f"构建状态图: {len(state_graph.get('states', {}))} 个状态")

        # 4.5 优化建议
        suggestions = self._generate_suggestions(field_priorities, state_graph)
        results['optimization_suggestions'] = suggestions

        return results

    def _calculate_byte_entropy(self, messages: List[bytes]) -> List[ByteEntropyInfo]:
        """计算字节熵"""
        entropy_list = []
        min_len = min(len(m) for m in messages)

        for pos in range(min_len):
            values = [msg[pos] for msg in messages]
            value_counts = Counter(values)
            total = len(values)

            # 计算熵
            entropy = 0.0
            for count in value_counts.values():
                p = count / total
                if p > 0:
                    entropy -= p * np.log2(p)

            entropy_info = ByteEntropyInfo(
                position=pos,
                entropy=entropy,
                variance=float(np.var(values)),
                unique_values=len(value_counts)
            )
            entropy_list.append(entropy_info)

        entropy_list.sort(key=lambda x: -x.entropy)
        return entropy_list

    def _rank_field_priorities(self, entropy_info: List[ByteEntropyInfo],
                               messages: List[bytes]) -> List[FieldPriority]:
        """字段优先级排序"""
        priorities = []
        pos_to_entropy = {e.position: e.entropy for e in entropy_info}

        type_weights = {
            'length': 1.0, 'offset': 0.9, 'type_indicator': 0.8,
            'checksum': 0.7, 'data': 0.5, 'constant': 0.3
        }

        for i, field in enumerate(self.field_candidates):
            type_weight = type_weights.get(field.field_type, 0.5)

            # 字段平均熵
            field_entropies = [pos_to_entropy.get(p, 0.0) for p in range(field.start, field.end)]
            avg_entropy = np.mean(field_entropies) if field_entropies else 0.0
            entropy_weight = min(avg_entropy / 8.0, 1.0)

            information_gain = entropy_weight * field.confidence
            exploration_value = type_weight * information_gain

            priority_score = 0.4 * type_weight + 0.3 * entropy_weight + 0.3 * field.confidence

            priorities.append(FieldPriority(
                field_id=i,
                field_range=(field.start, field.end),
                priority_score=priority_score,
                exploration_value=exploration_value,
                information_gain=information_gain
            ))

        priorities.sort(key=lambda x: -x.priority_score)
        return priorities

    def _generate_exploration_plan(self, field_priorities: List[FieldPriority],
                                   messages: List[bytes]) -> Dict[str, Any]:
        """生成自适应探索计划"""
        plan = {'total_phases': 0, 'phases': [], 'strategy': 'adaptive'}

        if not field_priorities:
            return plan

        budget = min(1000, len(messages))
        thresholds = [(0.7, 'critical', 0.5), (0.5, 'important', 0.3), (0.0, 'optional', 0.2)]

        for phase_id, (threshold, name, ratio) in enumerate(thresholds):
            if phase_id == 0:
                fields = [p for p in field_priorities if p.priority_score >= threshold]
            else:
                prev_threshold = thresholds[phase_id - 1][0]
                fields = [p for p in field_priorities
                         if threshold <= p.priority_score < prev_threshold]

            if fields:
                plan['phases'].append({
                    'phase_id': phase_id,
                    'name': name,
                    'field_count': len(fields),
                    'budget': int(budget * ratio)
                })

        plan['total_phases'] = len(plan['phases'])
        return plan

    def _build_state_graph(self, messages: List[bytes]) -> Dict[str, Any]:
        """构建状态图 - 使用协议知识而非启发式算法"""
        graph = {'states': {}, 'transitions': []}

        if len(messages) < 2:
            return graph

        # 根据协议类型确定类型字段位置
        protocol_type = self.protocol_info.get('protocol_signature', {})
        if hasattr(protocol_type, 'protocol_type'):
            protocol_name = protocol_type.protocol_type
        else:
            protocol_name = protocol_type.get('type', 'unknown') if isinstance(protocol_type, dict) else 'unknown'

        # 使用协议知识确定类型字段位置
        type_pos, field_size = self._get_protocol_type_field_position(protocol_name, messages)

        if type_pos is None:
            self.logger.warning(f"协议 {protocol_name} 的类型字段位置未知，尝试启发式查找")
            type_pos = self._find_type_field(messages)
            field_size = 1  # 启发式查找默认1字节
            if type_pos is None:
                return graph

        self.logger.debug(f"使用类型字段位置: {type_pos}, 字段大小: {field_size} (协议: {protocol_name})")

        # 提取状态序列
        states_seq = []
        state_names = {}  # 状态ID到名称的映射

        for msg in messages:
            # 检查消息是否足够长
            if len(msg) < type_pos + field_size:
                continue  # 跳过太短的消息

            # 提取状态ID
            if field_size == 1:
                state_id = msg[type_pos]
            elif field_size == 2:
                state_id = struct.unpack('<H', msg[type_pos:type_pos+2])[0]
            else:
                state_id = struct.unpack('<I', msg[type_pos:type_pos+4])[0]

            states_seq.append(state_id)

            # 获取状态名称
            if state_id not in state_names:
                state_names[state_id] = self._get_state_name(protocol_name, state_id)

        # 如果没有有效的状态序列，返回空图
        if not states_seq:
            self.logger.warning(f"未能提取到有效的状态序列 (消息太短或字段位置错误)")
            return graph

        state_counts = Counter(states_seq)

        # 构建状态信息（包含名称）
        for state_id, count in state_counts.items():
            graph['states'][int(state_id)] = {
                'count': count,
                'frequency': count / len(messages),
                'name': state_names.get(state_id, f'Unknown(0x{state_id:02X})')
            }

        # 统计转换
        transitions = Counter()
        for i in range(len(states_seq) - 1):
            transitions[(states_seq[i], states_seq[i + 1])] += 1

        for (from_s, to_s), count in transitions.most_common(15):
            graph['transitions'].append({
                'from': int(from_s),
                'to': int(to_s),
                'count': count,
                'frequency': count / (len(states_seq) - 1) if len(states_seq) > 1 else 0
            })

        return graph

    def _get_protocol_type_field_position(self, protocol_name: str, messages: List[bytes]) -> Tuple[Optional[int], int]:
        """
        根据协议类型返回类型字段的位置和大小

        这里使用真实的协议知识，而不是启发式算法

        Returns:
            (position, field_size): 位置和字段大小（字节数）
        """
        # 协议类型字段位置映射: (位置, 字段大小)
        protocol_positions = {
            'modbus': (7, 1),      # Modbus TCP: 偏移7是功能码 (1字节)
            'smb2': (12, 2),       # SMB2: 偏移12-13是命令字段 (2字节, little-endian)
            'http2': (3, 1),       # HTTP/2: 偏移3是帧类型 (1字节)
            'dns': (2, 2),         # DNS: 偏移2-3是flags (2字节)
        }

        # 获取协议配置
        config = protocol_positions.get(protocol_name)
        if config is None:
            return None, 1

        pos, field_size = config

        # 检查是否有足够长的消息
        # 过滤掉太短的消息，只检查足够长的消息
        valid_messages = [m for m in messages if len(m) >= pos + field_size]

        if not valid_messages:
            self.logger.warning(f"协议 {protocol_name} 没有足够长的消息 (需要 >= {pos + field_size} 字节)")
            return None, 1

        self.logger.debug(f"协议 {protocol_name}: {len(valid_messages)}/{len(messages)} 条消息足够长")
        return pos, field_size

    def _get_state_name(self, protocol_name: str, state_id: int) -> str:
        """
        根据协议类型和状态ID获取状态名称
        """
        if protocol_name == 'modbus':
            # Modbus功能码名称
            modbus_function_codes = {
                0x01: 'Read Coils',
                0x02: 'Read Discrete Inputs',
                0x03: 'Read Holding Registers',
                0x04: 'Read Input Registers',
                0x05: 'Write Single Coil',
                0x06: 'Write Single Register',
                0x0F: 'Write Multiple Coils',
                0x10: 'Write Multiple Registers',
                0x17: 'Read/Write Multiple Registers',
                0x2B: 'Encapsulated Interface Transport',
            }
            return modbus_function_codes.get(state_id, f'Unknown FC(0x{state_id:02X})')

        elif protocol_name == 'smb2':
            # SMB2命令名称
            smb2_commands = {
                0x00: 'NEGOTIATE',
                0x01: 'SESSION_SETUP',
                0x02: 'LOGOFF',
                0x03: 'TREE_CONNECT',
                0x04: 'TREE_DISCONNECT',
                0x05: 'CREATE',
                0x06: 'CLOSE',
                0x07: 'FLUSH',
                0x08: 'READ',
                0x09: 'WRITE',
                0x0A: 'LOCK',
                0x0B: 'IOCTL',
                0x0C: 'CANCEL',
                0x0D: 'ECHO',
                0x0E: 'QUERY_DIRECTORY',
                0x0F: 'CHANGE_NOTIFY',
                0x10: 'QUERY_INFO',
                0x11: 'SET_INFO',
            }
            return smb2_commands.get(state_id, f'Unknown CMD(0x{state_id:02X})')

        elif protocol_name == 'http2':
            # HTTP/2帧类型
            http2_frame_types = {
                0x00: 'DATA',
                0x01: 'HEADERS',
                0x02: 'PRIORITY',
                0x03: 'RST_STREAM',
                0x04: 'SETTINGS',
                0x05: 'PUSH_PROMISE',
                0x06: 'PING',
                0x07: 'GOAWAY',
                0x08: 'WINDOW_UPDATE',
                0x09: 'CONTINUATION',
            }
            return http2_frame_types.get(state_id, f'Unknown Frame(0x{state_id:02X})')

        else:
            return f'State(0x{state_id:02X})'

    def _find_type_field(self, messages: List[bytes]) -> Optional[int]:
        """查找类型字段"""
        min_len = min(len(m) for m in messages)
        best_pos, best_score = None, 0

        for pos in range(min(min_len, 15)):
            values = [m[pos] for m in messages]
            counts = Counter(values)
            num_groups = len(counts)

            if not (2 <= num_groups <= 20):
                continue

            total = len(values)
            entropy = -sum((c/total) * np.log2(c/total) for c in counts.values())

            if 1.0 < entropy < 4.0:
                score = entropy * (1.0 - abs(num_groups - 5) / 20.0)
                if score > best_score:
                    best_score = score
                    best_pos = pos

        return best_pos

    def _generate_suggestions(self, priorities: List[FieldPriority],
                              state_graph: Dict) -> List[str]:
        """生成优化建议"""
        suggestions = []

        if priorities:
            top = priorities[0]
            if top.priority_score > 0.8:
                suggestions.append(
                    f"建议优先探索字段 [{top.field_range[0]}:{top.field_range[1]}]"
                )

        num_states = len(state_graph.get('states', {}))
        if num_states > 15:
            suggestions.append(f"检测到 {num_states} 个状态，协议较复杂")
        elif 2 <= num_states <= 10:
            suggestions.append(f"检测到 {num_states} 个主要状态，结构清晰")

        if not suggestions:
            suggestions.append("探索策略合理，建议按计划执行")

        return suggestions


# =============================================================================
# 步骤5: 类型推断
# =============================================================================

@dataclass
class FieldType:
    """字段类型信息"""
    field_id: int
    field_range: Tuple[int, int]
    inferred_type: str  # integer, string, binary, address, length, etc.
    confidence: float
    protocol_specific_type: Optional[str] = None  # Modbus-specific, SMB2-specific, etc.
    properties: Dict[str, Any] = field(default_factory=dict)


class ProtocolTypeInferencer:
    """
    协议类型推断器

    功能:
    1. 协议特定类型识别 - 识别协议规范中定义的字段类型
    2. 通用类型推断 - 推断基本数据类型（整数、字符串等）
    3. 关系优化 - 识别字段间的语义关系
    """

    def __init__(self, protocol_info: Dict[str, Any], logger=None):
        self.protocol_info = protocol_info
        self.logger = logger or logging.getLogger(__name__)

    def infer_types(self, messages: List[bytes],
                   field_candidates: List[FieldCandidate],
                   function_profiles: List[FunctionCodeProfile]) -> Dict[str, Any]:
        """
        执行类型推断

        Args:
            messages: 消息列表
            field_candidates: 字段候选列表
            function_profiles: 功能码/命令分析结果

        Returns:
            类型推断结果字典
        """
        self.logger.info("=" * 60)
        self.logger.info("步骤5: 类型推断")
        self.logger.info("=" * 60)

        results = {
            'field_types': [],
            'protocol_specific_fields': [],
            'generic_fields': [],
            'field_relationships': []
        }

        if not messages:
            return results

        # 获取协议类型
        protocol_sig = self.protocol_info.get('protocol_signature', {})
        if hasattr(protocol_sig, 'protocol_type'):
            protocol_name = protocol_sig.protocol_type
        else:
            protocol_name = protocol_sig.get('type', 'unknown') if isinstance(protocol_sig, dict) else 'unknown'

        # 5.1 协议特定类型识别
        protocol_specific = self._identify_protocol_specific_types(
            messages, field_candidates, function_profiles, protocol_name
        )
        results['protocol_specific_fields'] = protocol_specific
        self.logger.info(f"识别到 {len(protocol_specific)} 个协议特定字段")

        # 5.2 通用类型推断
        generic_types = self._infer_generic_types(messages, field_candidates)
        results['generic_fields'] = generic_types
        self.logger.info(f"推断出 {len(generic_types)} 个通用字段类型")

        # 5.3 关系优化
        relationships = self._optimize_field_relationships(
            field_candidates, protocol_specific, generic_types
        )
        results['field_relationships'] = relationships
        self.logger.info(f"识别到 {len(relationships)} 个字段关系")

        # 5.4 合并所有字段类型
        all_field_types = self._merge_field_types(
            field_candidates, protocol_specific, generic_types
        )
        results['field_types'] = all_field_types

        return results

    def _identify_protocol_specific_types(self,
                                         messages: List[bytes],
                                         field_candidates: List[FieldCandidate],
                                         function_profiles: List[FunctionCodeProfile],
                                         protocol_name: str) -> List[FieldType]:
        """识别协议特定的字段类型"""
        specific_fields = []

        if protocol_name == 'modbus':
            # Modbus特定字段
            specific_fields.extend(self._identify_modbus_fields(messages, field_candidates))
        elif protocol_name == 'smb2':
            # SMB2特定字段
            specific_fields.extend(self._identify_smb2_fields(messages, field_candidates))
        elif protocol_name == 'http2':
            # HTTP/2特定字段
            specific_fields.extend(self._identify_http2_fields(messages, field_candidates))

        return specific_fields

    def _identify_modbus_fields(self, messages: List[bytes],
                               field_candidates: List[FieldCandidate]) -> List[FieldType]:
        """识别Modbus协议特定字段"""
        modbus_fields = []

        # Modbus TCP头部结构（固定字段）
        fixed_fields = [
            (0, 2, 'transaction_id', 'Modbus事务ID', 0.99),
            (2, 4, 'protocol_id', 'Modbus协议标识符(0x0000)', 1.0),
            (4, 6, 'length', 'Modbus长度字段', 0.95),
            (6, 7, 'unit_id', 'Modbus单元ID', 0.90),
            (7, 8, 'function_code', 'Modbus功能码', 1.0),
        ]

        for start, end, field_name, description, confidence in fixed_fields:
            field_type = FieldType(
                field_id=len(modbus_fields),
                field_range=(start, end),
                inferred_type='integer' if field_name != 'protocol_id' else 'constant',
                confidence=confidence,
                protocol_specific_type=f'modbus_{field_name}',
                properties={
                    'description': description,
                    'endianness': 'big',
                    'is_header': True
                }
            )
            modbus_fields.append(field_type)

        # 根据功能码识别数据字段
        # 偏移8+的字段取决于功能码
        for msg in messages[:10]:  # 采样前10条
            if len(msg) > 8:
                func_code = msg[7]
                if func_code in [0x03, 0x04]:  # Read Holding/Input Registers
                    # 请求: 起始地址(2) + 寄存器数量(2)
                    if len(msg) >= 12:
                        modbus_fields.append(FieldType(
                            field_id=len(modbus_fields),
                            field_range=(8, 10),
                            inferred_type='address',
                            confidence=0.85,
                            protocol_specific_type='modbus_start_address',
                            properties={'description': '起始寄存器地址'}
                        ))
                        modbus_fields.append(FieldType(
                            field_id=len(modbus_fields),
                            field_range=(10, 12),
                            inferred_type='count',
                            confidence=0.85,
                            protocol_specific_type='modbus_register_count',
                            properties={'description': '寄存器数量'}
                        ))
                break  # 只分析一种模式

        return modbus_fields

    def _identify_smb2_fields(self, messages: List[bytes],
                             field_candidates: List[FieldCandidate]) -> List[FieldType]:
        """识别SMB2协议特定字段"""
        smb2_fields = []

        # SMB2头部结构
        fixed_fields = [
            (0, 4, 'protocol_id', 'SMB2协议标识(\\xfeSMB)', 1.0),
            (4, 6, 'structure_size', 'SMB2头部结构大小(64)', 1.0),
            (12, 14, 'command', 'SMB2命令', 1.0),
            (16, 24, 'message_id', 'SMB2消息ID', 0.95),
        ]

        for start, end, field_name, description, confidence in fixed_fields:
            field_type = FieldType(
                field_id=len(smb2_fields),
                field_range=(start, end),
                inferred_type='integer' if 'id' in field_name or 'command' in field_name else 'constant',
                confidence=confidence,
                protocol_specific_type=f'smb2_{field_name}',
                properties={
                    'description': description,
                    'endianness': 'little',
                    'is_header': True
                }
            )
            smb2_fields.append(field_type)

        return smb2_fields

    def _identify_http2_fields(self, messages: List[bytes],
                              field_candidates: List[FieldCandidate]) -> List[FieldType]:
        """识别HTTP/2协议特定字段"""
        http2_fields = []

        # HTTP/2帧头部
        fixed_fields = [
            (0, 3, 'length', 'HTTP/2帧长度(24位)', 0.95),
            (3, 4, 'type', 'HTTP/2帧类型', 1.0),
            (4, 5, 'flags', 'HTTP/2帧标志', 0.90),
            (5, 9, 'stream_id', 'HTTP/2流ID(31位)', 0.95),
        ]

        for start, end, field_name, description, confidence in fixed_fields:
            field_type = FieldType(
                field_id=len(http2_fields),
                field_range=(start, end),
                inferred_type='integer',
                confidence=confidence,
                protocol_specific_type=f'http2_{field_name}',
                properties={
                    'description': description,
                    'is_header': True
                }
            )
            http2_fields.append(field_type)

        return http2_fields

    def _infer_generic_types(self, messages: List[bytes],
                           field_candidates: List[FieldCandidate]) -> List[FieldType]:
        """推断通用字段类型"""
        generic_types = []

        for i, candidate in enumerate(field_candidates):
            # 提取字段值
            values = []
            for msg in messages:
                if candidate.end <= len(msg):
                    field_bytes = msg[candidate.start:candidate.end]
                    values.append(field_bytes)

            if not values:
                continue

            # 基于值特征推断类型
            inferred_type, confidence = self._classify_field_type(values, candidate)

            field_type = FieldType(
                field_id=i,
                field_range=(candidate.start, candidate.end),
                inferred_type=inferred_type,
                confidence=confidence,
                properties={
                    'candidate_type': candidate.field_type,
                    'from_context_aware': True
                }
            )
            generic_types.append(field_type)

        return generic_types

    def _classify_field_type(self, values: List[bytes],
                           candidate: FieldCandidate) -> Tuple[str, float]:
        """基于值特征分类字段类型"""
        field_len = candidate.end - candidate.start

        # 已知的字段类型
        if candidate.field_type == 'length':
            return 'length_field', candidate.confidence
        elif candidate.field_type == 'offset':
            return 'offset_field', candidate.confidence
        elif candidate.field_type == 'type_indicator':
            return 'type_field', candidate.confidence

        # 检查是否为常量
        unique_values = set(values)
        if len(unique_values) == 1:
            return 'constant', 1.0

        # 检查是否为小整数（枚举/标志）
        if field_len <= 2:
            if len(unique_values) <= 20:
                return 'enum', 0.8

        # 检查是否为字符串
        printable_ratio = sum(1 for v in values if self._is_printable(v)) / len(values)
        if printable_ratio > 0.7:
            return 'string', 0.7 * printable_ratio

        # 默认为二进制数据
        return 'binary_data', 0.5

    def _is_printable(self, data: bytes) -> bool:
        """检查字节序列是否为可打印字符"""
        try:
            data.decode('ascii')
            return all(32 <= b < 127 or b in [9, 10, 13] for b in data)
        except:
            return False

    def _optimize_field_relationships(self,
                                     field_candidates: List[FieldCandidate],
                                     protocol_specific: List[FieldType],
                                     generic_types: List[FieldType]) -> List[Dict[str, Any]]:
        """优化字段间的关系"""
        relationships = []

        # 查找长度字段与数据字段的关系
        length_fields = [f for f in field_candidates if f.field_type == 'length']

        for lf in length_fields:
            # 长度字段控制后续数据
            relationships.append({
                'type': 'length_control',
                'source_field': (lf.start, lf.end),
                'target_field': (lf.end, 'variable'),
                'description': f'偏移{lf.start}的长度字段控制后续数据'
            })

        # 查找类型字段与条件字段的关系
        type_fields = [f for f in field_candidates if f.field_type == 'type_indicator']

        for tf in type_fields:
            relationships.append({
                'type': 'conditional_structure',
                'source_field': (tf.start, tf.end),
                'target_field': 'message_structure',
                'description': f'偏移{tf.start}的类型字段决定消息结构'
            })

        return relationships

    def _merge_field_types(self,
                          field_candidates: List[FieldCandidate],
                          protocol_specific: List[FieldType],
                          generic_types: List[FieldType]) -> List[FieldType]:
        """合并所有字段类型信息"""
        # 协议特定字段优先
        merged = list(protocol_specific)

        # 添加未被协议特定覆盖的通用字段
        covered_ranges = set()
        for pf in protocol_specific:
            for pos in range(pf.field_range[0], pf.field_range[1]):
                covered_ranges.add(pos)

        for gf in generic_types:
            # 检查是否与协议特定字段重叠
            overlaps = any(
                pos in covered_ranges
                for pos in range(gf.field_range[0], gf.field_range[1])
            )

            if not overlaps:
                merged.append(gf)

        # 按位置排序
        merged.sort(key=lambda x: x.field_range[0])

        return merged


# =============================================================================
# 步骤6: 字段细化与验证
# =============================================================================

@dataclass
class FieldStatistics:
    """字段统计信息"""
    field_range: Tuple[int, int]
    field_type: str
    occurrence_count: int
    value_entropy: float
    value_range: Tuple[Any, Any]
    confidence_score: float
    validation_status: str  # passed, warning, failed


class FieldRefinementValidator:
    """
    字段细化与验证器

    功能:
    1. 字段分类统计 - 统计各类字段的分布和特征
    2. 置信度评估 - 评估字段识别的可靠性
    3. 边界验证 - 验证字段边界是否正确
    4. 类型验证 - 验证推断的类型是否合理
    """

    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)

    def refine_and_validate(self,
                           messages: List[bytes],
                           field_types: List[FieldType],
                           field_candidates: List[FieldCandidate]) -> Dict[str, Any]:
        """
        执行字段细化与验证

        Args:
            messages: 消息列表
            field_types: 类型推断结果
            field_candidates: 字段候选列表

        Returns:
            验证结果字典
        """
        self.logger.info("=" * 60)
        self.logger.info("步骤6: 字段细化与验证")
        self.logger.info("=" * 60)

        results = {
            'field_statistics': [],
            'confidence_scores': {},
            'validation_results': {},
            'refinement_suggestions': []
        }

        if not messages or not field_types:
            return results

        # 6.1 字段分类统计
        field_stats = self._compute_field_statistics(messages, field_types)
        results['field_statistics'] = field_stats
        self.logger.info(f"统计了 {len(field_stats)} 个字段")

        # 6.2 置信度评估
        confidence_scores = self._evaluate_confidence(messages, field_types, field_candidates)
        results['confidence_scores'] = confidence_scores

        high_conf = sum(1 for s in confidence_scores.values() if s >= 0.8)
        med_conf = sum(1 for s in confidence_scores.values() if 0.5 <= s < 0.8)
        low_conf = sum(1 for s in confidence_scores.values() if s < 0.5)
        self.logger.info(f"置信度评估: 高={high_conf}, 中={med_conf}, 低={low_conf}")

        # 6.3 字段验证
        validation_results = self._validate_fields(messages, field_types)
        results['validation_results'] = validation_results

        passed = sum(1 for v in validation_results.values() if v['status'] == 'passed')
        warned = sum(1 for v in validation_results.values() if v['status'] == 'warning')
        failed = sum(1 for v in validation_results.values() if v['status'] == 'failed')
        self.logger.info(f"验证结果: 通过={passed}, 警告={warned}, 失败={failed}")

        # 6.4 生成细化建议
        suggestions = self._generate_refinement_suggestions(
            field_stats, confidence_scores, validation_results
        )
        results['refinement_suggestions'] = suggestions
        self.logger.info(f"生成了 {len(suggestions)} 条细化建议")

        return results

    def _compute_field_statistics(self,
                                  messages: List[bytes],
                                  field_types: List[FieldType]) -> List[FieldStatistics]:
        """计算字段统计信息"""
        statistics = []

        for ft in field_types:
            # 提取字段值
            values = []
            for msg in messages:
                if ft.field_range[1] <= len(msg):
                    field_bytes = msg[ft.field_range[0]:ft.field_range[1]]
                    values.append(field_bytes)

            if not values:
                continue

            # 计算熵
            value_counts = Counter(values)
            total = len(values)
            entropy = 0.0
            for count in value_counts.values():
                p = count / total
                if p > 0:
                    entropy -= p * np.log2(p)

            # 值范围
            if ft.inferred_type in ['integer', 'length_field', 'offset_field']:
                try:
                    int_values = [int.from_bytes(v, 'big') for v in values]
                    value_range = (min(int_values), max(int_values))
                except:
                    value_range = (None, None)
            else:
                value_range = (None, None)

            stat = FieldStatistics(
                field_range=ft.field_range,
                field_type=ft.inferred_type,
                occurrence_count=len(values),
                value_entropy=entropy,
                value_range=value_range,
                confidence_score=ft.confidence,
                validation_status='pending'
            )
            statistics.append(stat)

        return statistics

    def _evaluate_confidence(self,
                            messages: List[bytes],
                            field_types: List[FieldType],
                            field_candidates: List[FieldCandidate]) -> Dict[str, float]:
        """评估每个字段的置信度"""
        confidence_scores = {}

        for ft in field_types:
            field_key = f"{ft.field_range[0]}:{ft.field_range[1]}"

            # 基础置信度
            base_confidence = ft.confidence

            # 协议特定字段置信度更高
            if ft.protocol_specific_type:
                base_confidence = min(1.0, base_confidence * 1.2)

            # 根据出现频率调整
            occurrence_count = sum(
                1 for msg in messages
                if ft.field_range[1] <= len(msg)
            )
            occurrence_ratio = occurrence_count / len(messages)

            # 高出现率提升置信度
            if occurrence_ratio > 0.9:
                base_confidence = min(1.0, base_confidence * 1.1)
            elif occurrence_ratio < 0.5:
                base_confidence *= 0.8

            confidence_scores[field_key] = base_confidence

        return confidence_scores

    def _validate_fields(self,
                        messages: List[bytes],
                        field_types: List[FieldType]) -> Dict[str, Dict[str, Any]]:
        """验证字段定义"""
        validation_results = {}

        for ft in field_types:
            field_key = f"{ft.field_range[0]}:{ft.field_range[1]}"

            # 验证字段边界
            boundary_valid = self._validate_boundary(messages, ft)

            # 验证字段类型
            type_valid = self._validate_type(messages, ft)

            # 验证字段一致性
            consistency_valid = self._validate_consistency(messages, ft)

            # 综合验证结果
            all_checks = [boundary_valid, type_valid, consistency_valid]

            if all(all_checks):
                status = 'passed'
            elif any(all_checks):
                status = 'warning'
            else:
                status = 'failed'

            validation_results[field_key] = {
                'status': status,
                'boundary_check': boundary_valid,
                'type_check': type_valid,
                'consistency_check': consistency_valid
            }

        return validation_results

    def _validate_boundary(self, messages: List[bytes], field_type: FieldType) -> bool:
        """验证字段边界是否合理"""
        # 检查字段范围
        start, end = field_type.field_range

        if start < 0 or end <= start:
            return False

        # 检查是否在大多数消息中有效
        valid_count = sum(
            1 for msg in messages
            if end <= len(msg)
        )

        return valid_count / len(messages) >= 0.5

    def _validate_type(self, messages: List[bytes], field_type: FieldType) -> bool:
        """验证推断的类型是否合理"""
        # 常量字段应该只有一个值
        if field_type.inferred_type == 'constant':
            values = set()
            for msg in messages:
                if field_type.field_range[1] <= len(msg):
                    value = msg[field_type.field_range[0]:field_type.field_range[1]]
                    values.add(value)

            return len(values) <= 2  # 允许少量变化

        # 长度字段值应该合理
        if field_type.inferred_type in ['length_field', 'length']:
            try:
                for msg in messages[:20]:  # 采样检查
                    if field_type.field_range[1] <= len(msg):
                        field_bytes = msg[field_type.field_range[0]:field_type.field_range[1]]
                        value = int.from_bytes(field_bytes, 'big')

                        # 长度不应超过消息长度的10倍
                        if value > len(msg) * 10:
                            return False

                return True
            except:
                return False

        # 默认通过
        return True

    def _validate_consistency(self, messages: List[bytes], field_type: FieldType) -> bool:
        """验证字段值的一致性"""
        values = []

        for msg in messages[:50]:  # 采样检查
            if field_type.field_range[1] <= len(msg):
                value = msg[field_type.field_range[0]:field_type.field_range[1]]
                values.append(value)

        if not values:
            return False

        # 检查值的多样性
        unique_ratio = len(set(values)) / len(values)

        # 常量字段应该多样性低
        if field_type.inferred_type == 'constant':
            return unique_ratio < 0.1

        # 数据字段应该有一定多样性
        if field_type.inferred_type in ['binary_data', 'string']:
            return unique_ratio > 0.1

        return True

    def _generate_refinement_suggestions(self,
                                        field_stats: List[FieldStatistics],
                                        confidence_scores: Dict[str, float],
                                        validation_results: Dict[str, Dict]) -> List[str]:
        """生成字段细化建议"""
        suggestions = []

        # 检查低置信度字段
        low_confidence_fields = [
            field_key for field_key, score in confidence_scores.items()
            if score < 0.6
        ]

        if low_confidence_fields:
            suggestions.append(
                f"发现 {len(low_confidence_fields)} 个低置信度字段，建议进一步验证"
            )

        # 检查验证失败的字段
        failed_fields = [
            field_key for field_key, result in validation_results.items()
            if result['status'] == 'failed'
        ]

        if failed_fields:
            suggestions.append(
                f"发现 {len(failed_fields)} 个验证失败的字段，需要重新分析"
            )

        # 检查高熵字段（可能是数据字段）
        high_entropy_fields = [
            stat for stat in field_stats
            if stat.value_entropy > 6.0
        ]

        if high_entropy_fields:
            suggestions.append(
                f"发现 {len(high_entropy_fields)} 个高熵字段，可能包含随机数据或加密内容"
            )

        if not suggestions:
            suggestions.append("所有字段通过验证，字段识别结果可靠")

        return suggestions


# =============================================================================
# 主Pipeline集成
# =============================================================================

class AdvancedProtocolPipeline:
    """
    HierPRE - 层次化协议逆向工程框架

    集成步骤1-6的完整流程:
    - 步骤1: 加载追踪数据
    - 步骤2: 协议预分析
    - 步骤3: 上下文感知字段检测 + 语义图构建 (创新)
    - 步骤4: 高效探索 + 未知功能推断 (创新)
    - 步骤5: 类型推断
    - 步骤6: 字段细化与验证

    创新特性：
    - 跨消息依赖挖掘 (Request-Response配对)
    - 算术/逻辑约束发现 (Field A = Field B * 2 + 4)
    - 未知功能码零样本推断 (不依赖硬编码字典)
    - Bit-level语义分析
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = self._setup_logger()

        self.pre_analyzer = ProtocolPreAnalyzer(self.logger)
        self.field_detector = None  # 在分析后初始化
        self.type_inferencer = None  # 在分析后初始化
        self.refinement_validator = FieldRefinementValidator(self.logger)

        # 创新模块
        if HAS_ADVANCED_MODULES:
            self.semantic_graph_builder = SemanticGraphBuilder(self.logger)
            self.unknown_function_inferencer = UnknownFunctionInferencer(self.logger)
        else:
            self.semantic_graph_builder = None
            self.unknown_function_inferencer = None

    def _setup_logger(self):
        """设置日志"""
        logger = logging.getLogger('AdvancedPipeline')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))
            logger.addHandler(handler)

        return logger

    def run(self, input_path: str, output_path: str):
        """
        运行完整分析流程
        """
        self.logger.info("=" * 60)
        self.logger.info("高级协议分析Pipeline")
        self.logger.info(f"输入: {input_path}")
        self.logger.info(f"输出: {output_path}")
        self.logger.info("=" * 60)

        # 创建输出目录
        os.makedirs(output_path, exist_ok=True)

        # 步骤1: 加载数据
        messages = self._load_messages(input_path)
        self.logger.info(f"步骤1: 加载 {len(messages)} 条消息")

        if not messages:
            self.logger.error("没有加载到消息")
            return

        # 步骤2: 协议预分析
        pre_analysis = self.pre_analyzer.analyze(messages)

        # 步骤3: 上下文感知字段检测 + 语义图构建 (创新)
        self.field_detector = ContextAwareFieldDetector(pre_analysis, self.logger)
        field_detection = self.field_detector.detect(messages)

        # 步骤3.5: 构建语义感知图 (创新功能)
        semantic_graph_results = None
        if self.semantic_graph_builder:
            protocol_info = {'protocol_signature': pre_analysis['protocol_signature']}
            semantic_graph_results = self.semantic_graph_builder.build_session_graph(
                messages,
                field_detection['field_candidates'],
                protocol_info
            )

        # 步骤4: 高效探索
        # 传递协议信息给探索器，以便使用真实的协议知识
        protocol_info = {
            'protocol_signature': pre_analysis['protocol_signature']
        }
        explorer = EfficientExplorer(
            field_detection['field_candidates'],
            self.logger,
            protocol_info=protocol_info
        )
        exploration_results = explorer.explore(messages)

        # 步骤4.5: 未知功能码推断 (创新功能)
        unknown_function_results = None
        if self.unknown_function_inferencer:
            protocol_name = pre_analysis['protocol_signature'].protocol_type
            unknown_function_results = self.unknown_function_inferencer.infer_unknown_functions(
                messages,
                pre_analysis['function_profiles'],
                protocol_name
            )

            # 将推断结果添加到function_profiles中
            if unknown_function_results:
                self.logger.info(f"成功推断 {len(unknown_function_results)} 个未知功能码")

        # 步骤5: 类型推断
        self.type_inferencer = ProtocolTypeInferencer(protocol_info, self.logger)
        type_inference_results = self.type_inferencer.infer_types(
            messages,
            field_detection['field_candidates'],
            pre_analysis['function_profiles']
        )

        # 步骤6: 字段细化与验证
        refinement_results = self.refinement_validator.refine_and_validate(
            messages,
            type_inference_results['field_types'],
            field_detection['field_candidates']
        )

        # 整合结果
        results = {
            'step1_loading': {
                'message_count': len(messages),
                'source': input_path
            },
            'step2_pre_analysis': {
                'protocol': pre_analysis['protocol_signature'].protocol_type,
                'confidence': pre_analysis['protocol_signature'].confidence,
                'variant': pre_analysis['protocol_signature'].variant,
                'function_count': len(pre_analysis['function_profiles']),
                'statistics': pre_analysis['message_statistics']
            },
            'step3_field_detection': {
                'length_fields': len(field_detection['length_fields']),
                'offset_fields': len(field_detection['offset_fields']),
                'tlv_structures': len(field_detection['tlv_structures']),
                'conditional_fields': len(field_detection['conditional_fields']),
                'dependency_edges': len(field_detection['dependency_graph']),
                'total_candidates': len(field_detection['field_candidates'])
            },
            'step3_5_semantic_graph': {
                'enabled': semantic_graph_results is not None,
                'total_nodes': len(semantic_graph_results['nodes']) if semantic_graph_results else 0,
                'total_edges': len(semantic_graph_results['edges']) if semantic_graph_results else 0,
                'cross_message_dependencies': len(semantic_graph_results['cross_message_dependencies']) if semantic_graph_results else 0,
                'bit_level_patterns': len(semantic_graph_results['bit_level_patterns']) if semantic_graph_results else 0,
                'arithmetic_constraints': sum(1 for e in (semantic_graph_results['edges'] if semantic_graph_results else [])
                                             if 'arithmetic' in e.edge_type or 'linear' in e.edge_type) if semantic_graph_results else 0
            },
            'step4_exploration': {
                'byte_entropy_positions': len(exploration_results['byte_entropy']),
                'field_priorities': len(exploration_results['field_priorities']),
                'exploration_phases': exploration_results['exploration_plan'].get('total_phases', 0),
                'state_count': len(exploration_results['state_graph'].get('states', {})),
                'transition_count': len(exploration_results['state_graph'].get('transitions', [])),
                'suggestions': exploration_results['optimization_suggestions']
            },
            'step4_5_unknown_function_inference': {
                'enabled': unknown_function_results is not None,
                'inferred_count': len(unknown_function_results) if unknown_function_results else 0,
                'high_confidence_inferences': sum(1 for s in (unknown_function_results or []) if s.confidence > 0.85),
                'function_types_discovered': dict(Counter([s.signature_type for s in (unknown_function_results or [])])) if unknown_function_results else {}
            },
            'step5_type_inference': {
                'total_field_types': len(type_inference_results['field_types']),
                'protocol_specific_fields': len(type_inference_results['protocol_specific_fields']),
                'generic_fields': len(type_inference_results['generic_fields']),
                'field_relationships': len(type_inference_results['field_relationships'])
            },
            'step6_refinement': {
                'field_statistics_count': len(refinement_results['field_statistics']),
                'high_confidence_fields': sum(1 for s in refinement_results['confidence_scores'].values() if s >= 0.8),
                'medium_confidence_fields': sum(1 for s in refinement_results['confidence_scores'].values() if 0.5 <= s < 0.8),
                'low_confidence_fields': sum(1 for s in refinement_results['confidence_scores'].values() if s < 0.5),
                'passed_validation': sum(1 for v in refinement_results['validation_results'].values() if v['status'] == 'passed'),
                'warned_validation': sum(1 for v in refinement_results['validation_results'].values() if v['status'] == 'warning'),
                'failed_validation': sum(1 for v in refinement_results['validation_results'].values() if v['status'] == 'failed'),
                'refinement_suggestions': refinement_results['refinement_suggestions']
            }
        }

        # 保存详细结果
        detailed_results = {
            'pre_analysis': self._serialize_pre_analysis(pre_analysis),
            'field_detection': self._serialize_field_detection(field_detection),
            'semantic_graph': self._serialize_semantic_graph(semantic_graph_results) if semantic_graph_results else None,
            'exploration': exploration_results,
            'unknown_function_inference': self._serialize_unknown_functions(unknown_function_results) if unknown_function_results else None,
            'type_inference': self._serialize_type_inference(type_inference_results),
            'refinement': self._serialize_refinement(refinement_results)
        }

        # 保存结果
        output_file = os.path.join(output_path, 'advanced_analysis_report.json')
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'summary': results,
                'details': detailed_results
            }, f, indent=2, ensure_ascii=False)

        self.logger.info(f"结果已保存: {output_file}")

        # 打印摘要
        self._print_summary(results)

        return results

    def _load_messages(self, input_path: str) -> List[bytes]:
        """加载消息"""
        messages = []
        path = Path(input_path)

        if path.is_file():
            files = [path]
        else:
            files = list(path.glob('*.pcap')) + list(path.glob('*.pcapng'))

        for pcap_file in files:
            try:
                if HAS_SCAPY:
                    packets = rdpcap(str(pcap_file))
                    for pkt in packets:
                        if pkt.haslayer(Raw):
                            payload = bytes(pkt[Raw].load)
                            if len(payload) > 0:
                                messages.append(payload)
                        elif pkt.haslayer(TCP):
                            tcp_layer = pkt[TCP]
                            if hasattr(tcp_layer, 'payload'):
                                payload_bytes = bytes(tcp_layer.payload)
                                if len(payload_bytes) > 4:
                                    # 跳过可能的NetBIOS头部
                                    if payload_bytes[0] == 0x00:
                                        payload_bytes = payload_bytes[4:]
                                    if len(payload_bytes) > 0:
                                        messages.append(payload_bytes)
            except Exception as e:
                self.logger.warning(f"加载 {pcap_file} 失败: {e}")

        return messages

    def _serialize_pre_analysis(self, pre_analysis: Dict) -> Dict:
        """序列化预分析结果"""
        result = {
            'protocol_signature': {
                'type': pre_analysis['protocol_signature'].protocol_type,
                'confidence': pre_analysis['protocol_signature'].confidence,
                'variant': pre_analysis['protocol_signature'].variant
            },
            'function_profiles': [
                {
                    'code': p.code,
                    'name': p.name,
                    'count': p.count,
                    'avg_length': p.avg_length
                }
                for p in pre_analysis['function_profiles']
            ],
            'message_statistics': pre_analysis['message_statistics'],
            'protocol_features': pre_analysis['protocol_features']
        }
        return result

    def _serialize_field_detection(self, field_detection: Dict) -> Dict:
        """序列化字段检测结果"""
        result = {
            'length_fields': [
                {
                    'start': f.start,
                    'end': f.end,
                    'confidence': f.confidence,
                    'properties': f.properties
                }
                for f in field_detection['length_fields']
            ],
            'offset_fields': [
                {
                    'start': f.start,
                    'end': f.end,
                    'confidence': f.confidence,
                    'properties': f.properties
                }
                for f in field_detection['offset_fields']
            ],
            'tlv_structures': field_detection['tlv_structures'],
            'conditional_fields': [
                {
                    'start': f.start,
                    'end': f.end,
                    'confidence': f.confidence,
                    'properties': f.properties
                }
                for f in field_detection['conditional_fields']
            ],
            'dependency_graph': [
                {
                    'source': e.source_field,
                    'target': e.target_field,
                    'type': e.dependency_type,
                    'weight': e.weight
                }
                for e in field_detection['dependency_graph']
            ]
        }
        return result

    def _serialize_type_inference(self, type_inference: Dict) -> Dict:
        """序列化类型推断结果"""
        result = {
            'field_types': [
                {
                    'field_range': ft.field_range,
                    'inferred_type': ft.inferred_type,
                    'confidence': ft.confidence,
                    'protocol_specific_type': ft.protocol_specific_type,
                    'properties': ft.properties
                }
                for ft in type_inference['field_types']
            ],
            'protocol_specific_fields': [
                {
                    'field_range': ft.field_range,
                    'inferred_type': ft.inferred_type,
                    'protocol_specific_type': ft.protocol_specific_type,
                    'confidence': ft.confidence
                }
                for ft in type_inference['protocol_specific_fields']
            ],
            'field_relationships': type_inference['field_relationships']
        }
        return result

    def _serialize_refinement(self, refinement: Dict) -> Dict:
        """序列化字段细化与验证结果"""
        result = {
            'field_statistics': [
                {
                    'field_range': fs.field_range,
                    'field_type': fs.field_type,
                    'occurrence_count': fs.occurrence_count,
                    'value_entropy': fs.value_entropy,
                    'value_range': fs.value_range,
                    'confidence_score': fs.confidence_score,
                    'validation_status': fs.validation_status
                }
                for fs in refinement['field_statistics']
            ],
            'confidence_scores': refinement['confidence_scores'],
            'validation_results': refinement['validation_results'],
            'refinement_suggestions': refinement['refinement_suggestions']
        }
        return result

    def _serialize_semantic_graph(self, semantic_graph: Dict) -> Dict:
        """序列化语义图结果"""
        return {
            'statistics': semantic_graph.get('statistics', {}),
            'cross_message_dependencies': [
                {
                    'request_msg': dep.request_msg_idx,
                    'response_msg': dep.response_msg_idx,
                    'type': dep.dependency_type,
                    'confidence': dep.confidence
                }
                for dep in semantic_graph.get('cross_message_dependencies', [])
            ],
            'bit_level_patterns': semantic_graph.get('bit_level_patterns', []),
            'arithmetic_constraints': [
                {
                    'source_field': e.source,
                    'target_field': e.target,
                    'constraint': e.constraint,
                    'type': e.edge_type,
                    'weight': e.weight
                }
                for e in semantic_graph.get('edges', [])
                if e.constraint and ('arithmetic' in e.edge_type or 'linear' in e.edge_type or 'xor' in e.edge_type)
            ]
        }

    def _serialize_unknown_functions(self, unknown_functions: List) -> Dict:
        """序列化未知功能推断结果"""
        return {
            'inferred_functions': [
                {
                    'function_code': f'0x{func.func_code:02X}',
                    'inferred_name': func.inferred_name,
                    'signature_type': func.signature_type,
                    'confidence': func.confidence,
                    'structure_fingerprint': func.structure_fingerprint,
                    'evidence': func.evidence,
                    'similar_to_known': func.similar_to
                }
                for func in unknown_functions
            ]
        }

    def _print_summary(self, results: Dict):
        """打印摘要"""
        self.logger.info("=" * 60)
        self.logger.info("HierPRE 分析摘要")
        self.logger.info("=" * 60)

        s2 = results['step2_pre_analysis']
        self.logger.info(f"协议: {s2['protocol']} ({s2['variant']})")
        self.logger.info(f"置信度: {s2['confidence']:.2f}")
        self.logger.info(f"功能码/命令数: {s2['function_count']}")

        s3 = results['step3_field_detection']
        self.logger.info(f"长度字段: {s3['length_fields']}个")
        self.logger.info(f"偏移字段: {s3['offset_fields']}个")
        self.logger.info(f"TLV结构: {s3['tlv_structures']}个")
        self.logger.info(f"条件字段: {s3['conditional_fields']}个")
        self.logger.info(f"依赖关系: {s3['dependency_edges']}条")

        # 创新功能输出
        s3_5 = results.get('step3_5_semantic_graph', {})
        if s3_5.get('enabled'):
            self.logger.info("")
            self.logger.info("[创新] 语义感知图:")
            self.logger.info(f"  - 语义节点: {s3_5['total_nodes']}个")
            self.logger.info(f"  - 语义边: {s3_5['total_edges']}条")
            self.logger.info(f"  - 跨消息依赖: {s3_5['cross_message_dependencies']}个 (Request-Response配对)")
            self.logger.info(f"  - 算术约束: {s3_5['arithmetic_constraints']}个 (如: B = A × 2 + 4)")
            self.logger.info(f"  - Bit级模式: {s3_5['bit_level_patterns']}个")

        s4 = results['step4_exploration']
        self.logger.info(f"\n字节熵位置: {s4['byte_entropy_positions']}个")
        self.logger.info(f"字段优先级: {s4['field_priorities']}个")
        self.logger.info(f"探索阶段: {s4['exploration_phases']}个")
        self.logger.info(f"状态数: {s4['state_count']}个")
        self.logger.info(f"状态转换: {s4['transition_count']}条")

        if s4['suggestions']:
            self.logger.info("优化建议:")
            for suggestion in s4['suggestions']:
                self.logger.info(f"  - {suggestion}")

        # 未知功能推断输出
        s4_5 = results.get('step4_5_unknown_function_inference', {})
        if s4_5.get('enabled') and s4_5.get('inferred_count', 0) > 0:
            self.logger.info("")
            self.logger.info("[创新] 未知功能码零样本推断:")
            self.logger.info(f"  - 成功推断: {s4_5['inferred_count']}个未知功能码")
            self.logger.info(f"  - 高置信度推断: {s4_5['high_confidence_inferences']}个 (置信度>0.85)")
            if s4_5.get('function_types_discovered'):
                self.logger.info(f"  - 发现的功能类型: {s4_5['function_types_discovered']}")

        # 步骤5和6的摘要
        s5 = results['step5_type_inference']
        self.logger.info(f"\n字段类型总数: {s5['total_field_types']}个")
        self.logger.info(f"协议特定字段: {s5['protocol_specific_fields']}个")
        self.logger.info(f"通用字段: {s5['generic_fields']}个")
        self.logger.info(f"字段关系: {s5['field_relationships']}个")

        s6 = results['step6_refinement']
        self.logger.info(f"高置信度字段: {s6['high_confidence_fields']}个")
        self.logger.info(f"中置信度字段: {s6['medium_confidence_fields']}个")
        self.logger.info(f"低置信度字段: {s6['low_confidence_fields']}个")
        self.logger.info(f"验证通过: {s6['passed_validation']}个")
        self.logger.info(f"验证警告: {s6['warned_validation']}个")
        self.logger.info(f"验证失败: {s6['failed_validation']}个")

        if s6['refinement_suggestions']:
            self.logger.info("细化建议:")
            for suggestion in s6['refinement_suggestions']:
                self.logger.info(f"  - {suggestion}")

        self.logger.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(description='高级协议分析Pipeline')
    parser.add_argument('-i', '--input', required=True, help='输入PCAP文件或目录')
    parser.add_argument('-o', '--output', required=True, help='输出目录')

    args = parser.parse_args()

    pipeline = AdvancedProtocolPipeline()
    pipeline.run(args.input, args.output)


if __name__ == '__main__':
    main()
