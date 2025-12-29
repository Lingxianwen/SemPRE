#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SemPRE: Zero-Shot Function Semantic Inferencer
零样本功能语义推断器

论文贡献2: 零样本功能语义推理
- 不依赖硬编码字典
- 基于结构指纹（地址/计数/有效载荷模式）
- 标准化输出标签: READ, WRITE, Filesystem_Op, Session_Setup, Unknown
- 人类可读的推理过程

Author: SemPRE Research Team
For CCF-A Conference Submission
"""

import numpy as np
from typing import List, Dict, Tuple, Set, Any, Optional
from dataclasses import dataclass, field
from collections import Counter
import logging


# 标准化的功能类型标签（符合论文）
FUNCTION_LABELS = {
    'READ': 'READ',
    'WRITE': 'WRITE',
    'FILESYSTEM_OP': 'Filesystem_Op',
    'SESSION_SETUP': 'Session_Setup',
    'CONTROL': 'Control',
    'QUERY': 'Query',
    'UNKNOWN': 'Unknown'
}


@dataclass
class StructuralFingerprint:
    """
    结构指纹（论文核心概念）

    用于零样本推理的结构特征
    """
    # 地址字段特征
    has_address_field: bool
    num_address_fields: int = 0

    # 计数字段特征
    has_count_field: bool = False
    num_count_fields: int = 0

    # 数据载荷特征
    has_data_payload: bool = False
    payload_size_pattern: str = 'unknown'  # 'fixed', 'variable', 'count_dependent'
    avg_payload_size: float = 0.0

    # 结构复杂度
    field_count: int = 0
    avg_message_size: float = 0.0

    # 数据流特征
    request_response_ratio: float = 0.0  # >1: more requests, <1: more responses

    def to_readable_string(self) -> str:
        """
        转换为人类可读的指纹字符串（符合论文可解释性要求）
        """
        features = []

        if self.has_address_field:
            features.append(f"ADDRESS_FIELDS({self.num_address_fields})")

        if self.has_count_field:
            features.append(f"COUNT_FIELDS({self.num_count_fields})")

        if self.has_data_payload:
            features.append(f"PAYLOAD({self.payload_size_pattern},{self.avg_payload_size:.0f}B)")

        features.append(f"FIELDS({self.field_count})")
        features.append(f"SIZE({self.avg_message_size:.0f}B)")

        if self.request_response_ratio > 0:
            features.append(f"REQ_RESP_RATIO({self.request_response_ratio:.2f})")

        return " | ".join(features)


@dataclass
class FunctionSignature:
    """
    功能签名（零样本推理结果）
    """
    func_code: int
    inferred_label: str  # 标准化标签（FUNCTION_LABELS中的一个）
    confidence: float
    fingerprint: StructuralFingerprint
    fingerprint_str: str  # 人类可读的指纹
    evidence: List[str] = field(default_factory=list)  # 推理证据链

    def __str__(self):
        return (f"FC 0x{self.func_code:02X} -> {self.inferred_label} "
                f"(conf={self.confidence:.2f})")


class ZeroShotFunctionInferencer:
    """
    零样本功能推断器

    论文核心贡献：
    1. 不依赖硬编码字典
    2. 基于结构指纹的语义推理
    3. 可解释的推理过程
    4. 标准化输出标签
    """

    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)

        # 推理规则（基于结构模式，而非硬编码字典）
        self.inference_rules = self._initialize_inference_rules()

    def _initialize_inference_rules(self) -> List[Dict[str, Any]]:
        """
        初始化推理规则

        这些规则基于协议设计的一般原则，而非特定协议
        """
        return [
            {
                'label': FUNCTION_LABELS['READ'],
                'patterns': {
                    'address': True,
                    'count': True,
                    'payload': False,
                    'size_range': (8, 30)
                },
                'weight': 0.8,
                'description': 'READ: Has address+count, no/small payload'
            },
            {
                'label': FUNCTION_LABELS['WRITE'],
                'patterns': {
                    'address': True,
                    'count': True,
                    'payload': True,
                    'size_range': (20, 500)
                },
                'weight': 0.8,
                'description': 'WRITE: Has address+count+payload'
            },
            {
                'label': FUNCTION_LABELS['FILESYSTEM_OP'],
                'patterns': {
                    'address': False,
                    'payload': True,
                    'size_range': (50, 1000),
                    'variable_size': True
                },
                'weight': 0.7,
                'description': 'Filesystem: Large variable payload, no address'
            },
            {
                'label': FUNCTION_LABELS['SESSION_SETUP'],
                'patterns': {
                    'size_range': (50, 500),
                    'field_count': (5, 20),
                    'req_resp_ratio': (0.8, 1.2)
                },
                'weight': 0.7,
                'description': 'Session: Medium complexity, balanced req/resp'
            },
            {
                'label': FUNCTION_LABELS['CONTROL'],
                'patterns': {
                    'size_range': (4, 20),
                    'payload': False
                },
                'weight': 0.6,
                'description': 'Control: Small, no payload'
            }
        ]

    def infer_unknown_functions(self, messages: List[bytes],
                                function_profiles: List[Any],
                                protocol_name: str = 'unknown') -> List[FunctionSignature]:
        """
        推断未知功能码的语义

        Args:
            messages: 原始消息列表
            function_profiles: 功能码统计信息
            protocol_name: 协议名称（用于日志）

        Returns:
            功能签名列表
        """
        self.logger.info("=" * 70)
        self.logger.info("SemPRE: Zero-Shot Function Semantic Inference")
        self.logger.info("=" * 70)

        signatures = []

        for profile in function_profiles:
            # 检查是否是未知功能码
            if self._is_unknown_function(profile):
                signature = self._infer_single_function(profile, messages)

                if signature:
                    signatures.append(signature)
                    self.logger.info(f"✓ {signature}")
                    self.logger.info(f"  Fingerprint: {signature.fingerprint_str}")
                    if signature.evidence:
                        self.logger.info(f"  Evidence: {'; '.join(signature.evidence[:3])}")

        self.logger.info(f"\nInferred {len(signatures)} unknown function codes")
        return signatures

    def _is_unknown_function(self, profile: Any) -> bool:
        """判断是否是未知功能码"""
        if hasattr(profile, 'name'):
            name = profile.name.lower()
            return 'unknown' in name or name.startswith('type_') or name.startswith('fc_')
        return False

    def _infer_single_function(self, profile: Any,
                               messages: List[bytes]) -> Optional[FunctionSignature]:
        """
        推断单个功能码

        核心算法：基于结构指纹匹配推理规则
        """
        # 1. 提取结构指纹
        fingerprint = self._extract_structural_fingerprint(profile, messages)

        # 2. 匹配推理规则
        scores = []
        for rule in self.inference_rules:
            score, evidence = self._match_rule(fingerprint, rule)
            scores.append((rule['label'], score, evidence))

        # 3. 选择最佳匹配
        scores.sort(key=lambda x: x[1], reverse=True)
        best_label, best_score, best_evidence = scores[0]

        # 4. 如果置信度太低，标记为Unknown
        if best_score < 0.3:
            best_label = FUNCTION_LABELS['UNKNOWN']
            best_evidence = ['Low confidence in all rules']

        # 5. 创建签名
        signature = FunctionSignature(
            func_code=getattr(profile, 'code', 0),
            inferred_label=best_label,
            confidence=best_score,
            fingerprint=fingerprint,
            fingerprint_str=fingerprint.to_readable_string(),
            evidence=best_evidence
        )

        return signature

    def _extract_structural_fingerprint(self, profile: Any,
                                        messages: List[bytes]) -> StructuralFingerprint:
        """
        提取结构指纹（协议无关）

        这是零样本推理的核心：从消息结构中提取特征
        不假设任何字段的固定位置
        """
        # 收集该功能码的所有消息
        func_code = getattr(profile, 'code', 0)
        byte_position = getattr(profile, 'byte_position', 0)  # 从profile获取类型字段位置

        func_messages = [msg for msg in messages
                        if len(msg) > byte_position and msg[byte_position] == func_code]

        if not func_messages:
            return StructuralFingerprint(
                has_address_field=False,
                has_count_field=False,
                has_data_payload=False
            )

        # 分析消息特征
        sizes = [len(msg) for msg in func_messages]
        avg_size = np.mean(sizes)
        size_std = np.std(sizes)

        # 检测地址字段（在消息中搜索，不假设位置）
        has_address, num_address = self._detect_address_fields_generic(func_messages)

        # 检测计数字段
        has_count, num_count = self._detect_count_fields_generic(func_messages)

        # 检测数据载荷
        has_payload, payload_pattern, avg_payload = self._detect_payload_generic(func_messages)

        # 估计字段数量（简化：每4字节一个字段）
        estimated_fields = int(avg_size / 4)

        fingerprint = StructuralFingerprint(
            has_address_field=has_address,
            num_address_fields=num_address,
            has_count_field=has_count,
            num_count_fields=num_count,
            has_data_payload=has_payload,
            payload_size_pattern=payload_pattern,
            avg_payload_size=avg_payload,
            field_count=estimated_fields,
            avg_message_size=avg_size
        )

        return fingerprint

    def _detect_address_fields_generic(self, messages: List[bytes]) -> Tuple[bool, int]:
        """
        检测地址字段（协议无关）

        特征：2-4字节整数，值在合理范围，跨消息有变化
        搜索整个消息，不假设固定位置
        """
        if not messages or len(messages[0]) < 4:
            return False, 0

        # 尝试多个可能的位置
        for offset in range(min(20, len(messages[0]) - 2)):
            values = []
            for msg in messages[:min(50, len(messages))]:
                if offset + 2 <= len(msg):
                    val = int.from_bytes(msg[offset:offset+2], 'big')
                    values.append(val)

            if not values:
                continue

            # 检查是否符合地址字段特征
            unique_vals = len(set(values))
            if unique_vals > 1 and unique_vals < len(values) * 0.9:  # 有变化但不是完全随机
                if max(values) < 65536:  # 合理范围
                    return True, 1

        return False, 0

    def _detect_count_fields_generic(self, messages: List[bytes]) -> Tuple[bool, int]:
        """
        检测计数字段（协议无关）

        特征：1-2字节，值较小（<256），可能与payload大小相关
        """
        if not messages or len(messages[0]) < 4:
            return False, 0

        # 尝试多个位置
        for offset in range(min(20, len(messages[0]) - 1)):
            values = []
            for msg in messages[:min(50, len(messages))]:
                if offset < len(msg):
                    val = msg[offset]
                    values.append(val)

            if not values:
                continue

            # 计数字段特征：值较小，有变化
            if max(values) < 256 and len(set(values)) > 1:
                return True, 1

        return False, 0

    def _detect_payload_generic(self, messages: List[bytes]) -> Tuple[bool, str, float]:
        """
        检测数据载荷（协议无关）

        策略：假设消息后半部分可能是payload
        """
        if not messages:
            return False, 'none', 0.0

        # 估计头部大小：使用消息的前1/4或前16字节（取较小值）
        avg_len = np.mean([len(msg) for msg in messages])
        estimated_header = min(16, int(avg_len * 0.25))

        payload_sizes = []

        for msg in messages:
            if len(msg) > estimated_header:
                payload_size = len(msg) - estimated_header
                payload_sizes.append(payload_size)

        if not payload_sizes:
            return False, 'none', 0.0

        avg_payload = np.mean(payload_sizes)
        std_payload = np.std(payload_sizes)

        # 判断载荷模式
        if avg_payload < 5:
            return False, 'none', 0.0
        elif std_payload < 5:
            return True, 'fixed', avg_payload
        elif std_payload / avg_payload < 0.3:
            return True, 'count_dependent', avg_payload
        else:
            return True, 'variable', avg_payload

    def _match_rule(self, fingerprint: StructuralFingerprint,
                   rule: Dict[str, Any]) -> Tuple[float, List[str]]:
        """
        匹配推理规则

        返回: (匹配分数, 证据列表)
        """
        patterns = rule['patterns']
        evidence = []
        score = 0.0
        matched = 0
        total = 0

        # 检查地址字段
        if 'address' in patterns:
            total += 1
            if patterns['address'] == fingerprint.has_address_field:
                matched += 1
                if fingerprint.has_address_field:
                    evidence.append(f"Has address field(s): {fingerprint.num_address_fields}")

        # 检查计数字段
        if 'count' in patterns:
            total += 1
            if patterns['count'] == fingerprint.has_count_field:
                matched += 1
                if fingerprint.has_count_field:
                    evidence.append(f"Has count field(s): {fingerprint.num_count_fields}")

        # 检查载荷
        if 'payload' in patterns:
            total += 1
            if patterns['payload'] == fingerprint.has_data_payload:
                matched += 1
                if fingerprint.has_data_payload:
                    evidence.append(f"Has payload: {fingerprint.payload_size_pattern}, "
                                  f"{fingerprint.avg_payload_size:.0f}B")

        # 检查大小范围
        if 'size_range' in patterns:
            total += 1
            min_size, max_size = patterns['size_range']
            if min_size <= fingerprint.avg_message_size <= max_size:
                matched += 1
                evidence.append(f"Size in range [{min_size}, {max_size}]: "
                              f"{fingerprint.avg_message_size:.0f}B")

        # 检查字段数量
        if 'field_count' in patterns:
            total += 1
            min_fields, max_fields = patterns['field_count']
            if min_fields <= fingerprint.field_count <= max_fields:
                matched += 1
                evidence.append(f"Field count in range [{min_fields}, {max_fields}]: "
                              f"{fingerprint.field_count}")

        # 计算匹配分数
        if total > 0:
            score = (matched / total) * rule['weight']

        # 添加规则描述
        if score > 0.3:
            evidence.insert(0, rule['description'])

        return score, evidence

    def export_confusion_matrix(self, signatures: List[FunctionSignature],
                               ground_truth: Dict[int, str]) -> Dict[str, Any]:
        """
        导出混淆矩阵（实验3需要）

        Args:
            signatures: 推断的签名列表
            ground_truth: 真实标签 {func_code: label}

        Returns:
            混淆矩阵统计
        """
        # 收集预测和真实标签
        y_true = []
        y_pred = []

        for sig in signatures:
            if sig.func_code in ground_truth:
                y_true.append(ground_truth[sig.func_code])
                y_pred.append(sig.inferred_label)

        if not y_true:
            return {'error': 'No ground truth available'}

        # 构建混淆矩阵
        labels = sorted(set(y_true + y_pred))
        matrix = {true_label: {pred_label: 0 for pred_label in labels}
                 for true_label in labels}

        for true, pred in zip(y_true, y_pred):
            matrix[true][pred] += 1

        # 计算准确率
        correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
        accuracy = correct / len(y_true) if y_true else 0.0

        return {
            'confusion_matrix': matrix,
            'accuracy': accuracy,
            'total_samples': len(y_true),
            'labels': labels
        }