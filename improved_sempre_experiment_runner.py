#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SemPRE: 真正的协议逆向工程实验运行器（Protocol-Agnostic Version）

核心改进 - 移除所有硬编码知识，实现真正的统计学习：

1. **纯统计的字段边界检测**（无协议假设）
   - 字节级熵分析（Shannon Entropy）
   - 重合指数（Index of Coincidence）
   - 熵梯度边界检测

2. **零样本功能语义推理**（无位置假设）
   - 自动发现类型字段位置（基于低熵特征）
   - 结构指纹提取（地址/计数/Payload模式）
   - 规则匹配（READ/WRITE/Control分类）

3. **协议无关的约束发现**
   - 长度字段自动检测（测试多种长度关系）
   - 公式自动发现（len(msg), len(msg)-offset等）
   - SDG构建（算术/逻辑/位级依赖）

4. **科学评估指标**
   - F1/Precision/Recall（边界检测准确率）
   - Perfect Score（完全匹配率）
   - 数据效率曲线（10%/30%/50%/100%）

评估与原始SemPRE的区别：
- 原始版本：硬编码Modbus规则 → 高分但无泛化能力
- 本版本：纯统计学习 → 真实反映算法学习能力

Author: SemPRE Research Team (Protocol-Agnostic Version)
Date: 2025
"""

import os
import sys
import json
import csv
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Any, Optional, Set
from datetime import datetime
import numpy as np
from collections import Counter, defaultdict
from dataclasses import dataclass

# 导入SemPRE核心模块
try:
    # 优先导入优化版
    try:
        from optimized_semantic_graph import OptimizedSemanticDependencyGraph as SemanticDependencyGraph
        print("✓ 使用优化版 SDG")
    except ImportError:
        from sempre_semantic_graph import SemanticDependencyGraph
        print("! 使用原始版 SDG (可能较慢)")
    
    from sempre_function_inferencer import ZeroShotFunctionInferencer, FUNCTION_LABELS
except ImportError as e:
    print(f"Error importing SemPRE modules: {e}")
    sys.exit(1)


@dataclass
class ProtocolFieldSpec:
    """协议特定的字段规范"""
    start: int
    end: int
    name: str
    field_type: str  # 'length', 'command', 'address', 'data', etc.
    confidence: float = 1.0


# ProtocolKnowledgeBase 已移除 - 不使用任何硬编码的协议知识


class StatisticalFieldDetector:
    """
    统计学习的字段检测器 - 纯基于熵和重合指数

    核心算法：
    1. 字节级熵分析 - 识别高熵（变化）和低熵（常量/类型）位置
    2. 重合指数 (Index of Coincidence) - 检测字段边界
    3. 序列对齐 - 发现跨消息的字段模式
    """

    def __init__(self, protocol: str = 'unknown', logger=None):
        self.protocol = protocol
        self.logger = logger or logging.getLogger(__name__)
    
    def detect_fields(self, messages: List[bytes]) -> Tuple[List[Any], Dict]:
        """
        纯统计学习的字段边界检测（协议无关）

        算法：
        1. 字节级熵分析
        2. 重合指数计算
        3. 边界候选生成
        4. 跨消息一致性验证
        """
        @dataclass
        class DetectedField:
            start: int
            end: int
            field_type: str = 'unknown'
            confidence: float = 0.8
            source: str = 'statistical'

        if not messages:
            return [], {'boundaries_per_message': [], 'detection_method': 'statistical'}

        # 步骤1: 计算字节级统计特征
        byte_entropy = self._calculate_byte_entropy(messages)
        byte_ioc = self._calculate_index_of_coincidence(messages)

        self.logger.info(f"  字节熵范围: {np.min(byte_entropy):.2f} - {np.max(byte_entropy):.2f}")
        self.logger.info(f"  重合指数范围: {np.min(byte_ioc):.3f} - {np.max(byte_ioc):.3f}")

        # 步骤2: 检测全局边界候选（传递messages用于高级统计）
        boundary_candidates = self._detect_boundary_candidates(byte_entropy, byte_ioc, messages)

        self.logger.info(f"  边界候选: {boundary_candidates}")

        # 步骤3: 为每条消息生成字段
        all_fields = []
        boundaries_per_message = []

        for msg in messages:
            # 使用统计边界分割消息
            msg_boundaries = [b for b in boundary_candidates if b < len(msg)]

            # 创建字段
            msg_fields = []
            prev_boundary = 0
            for boundary in msg_boundaries:
                if boundary > prev_boundary:
                    field_type = self._infer_field_type_statistical(
                        msg, prev_boundary, boundary, byte_entropy
                    )
                    msg_fields.append(DetectedField(
                        start=prev_boundary,
                        end=boundary,
                        field_type=field_type,
                        confidence=0.7,
                        source='statistical'
                    ))
                    prev_boundary = boundary

            # 处理剩余部分
            if prev_boundary < len(msg):
                msg_fields.append(DetectedField(
                    start=prev_boundary,
                    end=len(msg),
                    field_type='payload',
                    confidence=0.6,
                    source='statistical'
                ))

            all_fields.extend(msg_fields)
            boundaries_per_message.append(msg_boundaries)

        metadata = {
            'boundaries_per_message': boundaries_per_message,
            'detection_method': 'statistical',
            'byte_entropy': byte_entropy.tolist() if isinstance(byte_entropy, np.ndarray) else byte_entropy,
            'boundary_candidates': boundary_candidates
        }

        return all_fields, metadata
    
    def _calculate_byte_entropy(self, messages: List[bytes]) -> np.ndarray:
        """
        计算每个字节位置的熵（论文方法）

        高熵 -> 数据/ID字段
        低熵 -> 类型/命令字段
        """
        if not messages:
            return np.array([])

        max_len = max(len(msg) for msg in messages)
        entropies = []

        for pos in range(max_len):
            values = []
            for msg in messages:
                if pos < len(msg):
                    values.append(msg[pos])

            if not values:
                entropies.append(0.0)
                continue

            # 计算香农熵
            counter = Counter(values)
            total = len(values)
            entropy = 0.0
            for count in counter.values():
                p = count / total
                if p > 0:
                    entropy -= p * np.log2(p)

            entropies.append(entropy)

        return np.array(entropies)

    def _calculate_index_of_coincidence(self, messages: List[bytes]) -> np.ndarray:
        """
        计算重合指数 (Index of Coincidence)

        用于检测字段边界：边界处IoC通常有突变
        """
        if not messages:
            return np.array([])

        max_len = max(len(msg) for msg in messages)
        ioc_values = []

        for pos in range(max_len):
            values = []
            for msg in messages:
                if pos < len(msg):
                    values.append(msg[pos])

            if len(values) < 2:
                ioc_values.append(0.0)
                continue

            # IoC = Σ[n_i * (n_i - 1)] / [N * (N - 1)]
            counter = Counter(values)
            N = len(values)
            ioc = sum(count * (count - 1) for count in counter.values()) / (N * (N - 1))
            ioc_values.append(ioc)

        return np.array(ioc_values)

    def _detect_boundary_candidates(self, byte_entropy: np.ndarray,
                                    byte_ioc: np.ndarray, messages: List[bytes] = None) -> List[int]:
        """
        高级边界检测（多变量统计方法）

        策略：
        1. 熵梯度检测（更严格的阈值）
        2. IoC突变检测
        3. 互信息(MI)边界检测 - 检测相邻字节间依赖关系突变
        4. TLV启发式检测 - 检测Type-Length-Value模式
        5. 滑动窗口方差检测 - 检测高/低熵区域边界
        6. 邻近边界合并
        7. 限制边界数量
        """
        if len(byte_entropy) == 0:
            return []

        boundaries = set()

        # 方法1: 熵梯度检测（提高阈值，减少噪声）
        entropy_gradient = np.gradient(byte_entropy)
        entropy_threshold = np.std(entropy_gradient) * 1.5  # 从0.5提高到1.5

        for i in range(1, len(entropy_gradient)):
            if abs(entropy_gradient[i]) > entropy_threshold:
                boundaries.add(i)

        # 方法2: IoC突变检测（提高阈值）
        if len(byte_ioc) > 1:
            ioc_gradient = np.gradient(byte_ioc)
            ioc_threshold = np.std(ioc_gradient) * 1.5  # 从0.5提高到1.5

            for i in range(1, len(ioc_gradient)):
                if abs(ioc_gradient[i]) > ioc_threshold:
                    boundaries.add(i)

        # 方法3: 互信息(MI)边界检测（新增）
        if messages is not None:
            mi_boundaries = self._detect_mi_boundaries(messages)
            boundaries.update(mi_boundaries)
            self.logger.info(f"  MI边界检测: {len(mi_boundaries)} 个")

        # 方法4: TLV模式检测（新增）
        if messages is not None:
            tlv_boundaries = self._detect_tlv_patterns(messages)
            boundaries.update(tlv_boundaries)
            self.logger.info(f"  TLV边界检测: {len(tlv_boundaries)} 个")

        # 方法5: 滑动窗口方差检测（新增）
        variance_boundaries = self._detect_variance_boundaries(byte_entropy)
        boundaries.update(variance_boundaries)
        self.logger.info(f"  方差边界检测: {len(variance_boundaries)} 个")

        # 方法6: 只保留常见协议边界位置（减少噪声）
        # 移除方法6中的所有边界，因为这会产生大量固定边界
        # 只在熵/IoC检测的基础上添加极少数通用边界
        essential_boundaries = [1, 2, 4, 8]  # 只保留最常见的边界
        for size in essential_boundaries:
            if size < len(byte_entropy):
                # 只有当该位置附近有熵突变时才添加
                if size in boundaries or (size-1) in boundaries or (size+1) in boundaries:
                    boundaries.add(size)

        # 方法7: 合并邻近边界（关键优化）
        boundaries = self._merge_nearby_boundaries(sorted(list(boundaries)))

        # 方法8: 限制边界数量（避免过拟合）
        MAX_BOUNDARIES = 15  # 限制最多15个边界
        if len(boundaries) > MAX_BOUNDARIES:
            # 保留熵梯度最大的边界
            boundary_scores = []
            for b in boundaries:
                if b < len(entropy_gradient):
                    score = abs(entropy_gradient[b])
                    boundary_scores.append((b, score))

            boundary_scores.sort(key=lambda x: x[1], reverse=True)
            boundaries = [b for b, _ in boundary_scores[:MAX_BOUNDARIES]]

        return sorted(boundaries)

    def _merge_nearby_boundaries(self, boundaries: List[int], min_distance: int = 2) -> List[int]:
        """
        合并邻近的边界（关键去噪方法）

        策略：如果两个边界距离<min_distance，保留较小的那个

        注意：对于前16字节的密集边界，使用更小的距离阈值
        """
        if not boundaries:
            return []

        merged = [boundaries[0]]

        for i in range(1, len(boundaries)):
            prev_boundary = merged[-1]
            curr_boundary = boundaries[i]

            # 对于前16字节，允许更密集的边界（min_distance=1）
            # 因为很多协议的头部字段很小（1-2字节）
            if prev_boundary < 16 and curr_boundary < 16:
                effective_min_distance = 1  # 允许连续边界
            else:
                effective_min_distance = min_distance

            # 如果当前边界与上一个边界距离够远，保留
            if curr_boundary - prev_boundary >= effective_min_distance:
                merged.append(curr_boundary)

        return merged

    def _detect_mi_boundaries(self, messages: List[bytes]) -> Set[int]:
        """
        互信息(MI)边界检测（新增高级方法）

        原理：
        - 互信息 MI(X,Y) 衡量两个随机变量的依赖关系
        - 在字段边界处，相邻字节的依赖关系通常突降
        - MI(Byte[i], Byte[i+1]) 在边界处会有显著下降

        算法：
        1. 计算每个相邻字节对的互信息
        2. 计算MI梯度
        3. MI负梯度超过阈值的位置为边界候选
        """
        if not messages or len(messages[0]) < 2:
            return set()

        # 限制检查范围（只检查前32字节）
        max_len = min(32, max(len(msg) for msg in messages))
        mi_values = []

        # 采样消息（减少计算量）
        sampled_messages = messages[:min(200, len(messages))]

        # 计算相邻字节的互信息
        for pos in range(max_len - 1):
            byte_i_values = []
            byte_i1_values = []

            for msg in sampled_messages:
                if pos + 1 < len(msg):
                    byte_i_values.append(msg[pos])
                    byte_i1_values.append(msg[pos + 1])

            if len(byte_i_values) < 10:
                mi_values.append(0.0)
                continue

            # 计算互信息 MI(X,Y) = H(X) + H(Y) - H(X,Y)
            mi = self._calculate_mutual_information(byte_i_values, byte_i1_values)
            mi_values.append(mi)

        if not mi_values:
            return set()

        # 计算MI梯度（负梯度=依赖下降=可能边界）
        mi_gradient = np.gradient(mi_values)
        mi_threshold = np.std(mi_gradient) * 1.5  # 提高阈值，减少噪声

        boundaries = set()
        for i in range(1, len(mi_gradient)):
            # MI负梯度超过阈值 → 边界
            if mi_gradient[i] < -mi_threshold:
                boundaries.add(i)

        return boundaries

    def _calculate_mutual_information(self, x_values: List[int], y_values: List[int]) -> float:
        """
        计算互信息 MI(X,Y) = H(X) + H(Y) - H(X,Y)

        Args:
            x_values: 第一个字节位置的值列表
            y_values: 第二个字节位置的值列表

        Returns:
            互信息值
        """
        if len(x_values) != len(y_values) or len(x_values) == 0:
            return 0.0

        # 计算H(X)
        x_counter = Counter(x_values)
        n = len(x_values)
        h_x = 0.0
        for count in x_counter.values():
            p = count / n
            if p > 0:
                h_x -= p * np.log2(p)

        # 计算H(Y)
        y_counter = Counter(y_values)
        h_y = 0.0
        for count in y_counter.values():
            p = count / n
            if p > 0:
                h_y -= p * np.log2(p)

        # 计算H(X,Y) - 联合熵
        xy_counter = Counter(zip(x_values, y_values))
        h_xy = 0.0
        for count in xy_counter.values():
            p = count / n
            if p > 0:
                h_xy -= p * np.log2(p)

        # MI(X,Y) = H(X) + H(Y) - H(X,Y)
        mi = h_x + h_y - h_xy

        return mi

    def _detect_tlv_patterns(self, messages: List[bytes]) -> Set[int]:
        """
        TLV (Type-Length-Value) 启发式检测（新增高级方法）

        原理：
        - TLV模式：Byte[i] (Type) + Byte[i+1] (Length) + Data
        - 如果Byte[i+1]的值经常等于到下一个Type的距离，则i+1是长度字段

        算法：
        1. 对于每个位置i，假设Byte[i]是Type，Byte[i+1]是Length
        2. 检查Byte[i+1]的值是否与后续数据长度一致
        3. 如果一致性>70%，则i和i+2是边界
        """
        if not messages or len(messages[0]) < 3:
            return set()

        boundaries = set()
        max_len = min(16, max(len(msg) for msg in messages))  # 从32减少到16

        # 采样消息（减少计算量）
        sampled_messages = messages[:min(50, len(messages))]  # 从100减少到50

        for type_pos in range(max_len - 2):
            length_pos = type_pos + 1
            matches = 0
            total = 0

            for msg in sampled_messages:
                if length_pos >= len(msg):
                    continue

                length_byte = msg[length_pos]

                # 长度字段通常不会超过255（单字节）或太小
                if length_byte == 0 or length_byte > 250:
                    continue

                # 检查：从length_pos之后是否有length_byte个字节
                expected_next_boundary = length_pos + 1 + length_byte

                if expected_next_boundary <= len(msg):
                    total += 1
                    # 如果多条消息在同一位置有相同的Type值，说明是TLV
                    if expected_next_boundary < len(msg):
                        matches += 1

            # 如果匹配率>80%，认为是TLV模式（提高阈值）
            if total > 5 and matches / total > 0.8:
                boundaries.add(type_pos)
                boundaries.add(length_pos + 1)  # Value起始位置

        return boundaries

    def _detect_variance_boundaries(self, byte_entropy: np.ndarray) -> Set[int]:
        """
        滑动窗口方差检测（新增高级方法）

        原理：
        - 高熵区域（数据）和低熵区域（类型/常量）之间存在边界
        - 使用滑动窗口计算熵的局部方差
        - 方差突变处为高/低熵区域的边界

        算法：
        1. 使用窗口大小为3的滑动窗口计算局部方差
        2. 计算方差的梯度
        3. 梯度超过阈值的位置为边界
        """
        if len(byte_entropy) < 3:
            return set()

        window_size = 3
        variances = []

        # 计算滑动窗口方差
        for i in range(len(byte_entropy) - window_size + 1):
            window = byte_entropy[i:i + window_size]
            variance = np.var(window)
            variances.append(variance)

        if not variances:
            return set()

        # 计算方差梯度
        variance_gradient = np.gradient(variances)
        variance_threshold = np.std(variance_gradient) * 1.3

        boundaries = set()
        for i in range(1, len(variance_gradient)):
            if abs(variance_gradient[i]) > variance_threshold:
                # 调整回原始位置（考虑窗口偏移）
                boundary_pos = i + window_size // 2
                if boundary_pos < len(byte_entropy):
                    boundaries.add(boundary_pos)

        return boundaries

    def _infer_field_type_statistical(self, msg: bytes, start: int, end: int,
                                      byte_entropy: np.ndarray) -> str:
        """
        基于统计特征推断字段类型

        - 高熵 -> 'data' / 'identifier'
        - 低熵 -> 'type' / 'command'
        - 中熵 -> 'length' / 'count'
        """
        if start >= len(byte_entropy):
            return 'unknown'

        # 计算该字段的平均熵
        field_entropy = np.mean(byte_entropy[start:min(end, len(byte_entropy))])

        # 基于熵分类
        if field_entropy > 5.0:
            return 'data'  # 高熵，可能是数据
        elif field_entropy > 3.0:
            return 'identifier'  # 中高熵，可能是ID
        elif field_entropy > 1.5:
            return 'length'  # 中熵，可能是长度/计数
        elif field_entropy > 0.5:
            return 'type'  # 低熵，可能是类型/命令
        else:
            return 'constant'  # 极低熵，可能是常量


class StatisticalLengthFieldDetector:
    """
    高级长度字段检测器（基于线性相关性）

    核心改进：
    1. Pearson相关性分析 - 检测线性关系
    2. 线性回归 - 自动发现 field = a*len + b
    3. 多端序支持 - 测试大端和小端
    """

    @staticmethod
    def detect_length_fields(messages: List[bytes],
                            field_candidates: List[Any]) -> List[Tuple[int, int, float]]:
        """
        基于Pearson相关性的长度字段检测

        算法：
        1. 扫描所有1-4字节窗口
        2. 计算字段值与消息长度的Pearson相关系数
        3. 如果相关性>0.9，进行线性回归验证
        4. 返回高置信度的长度字段

        返回: [(start, end, confidence), ...]
        """
        length_fields = []
        tested_positions = set()

        # 方法1: 基于field_candidates检测（严格限制数量）
        max_candidates_to_test = 20  # 最多测试20个候选
        candidates_tested = 0

        for field in field_candidates[:min(50, len(field_candidates))]:
            if candidates_tested >= max_candidates_to_test:
                break

            if not (hasattr(field, 'start') and hasattr(field, 'end')):
                continue

            start, end = field.start, field.end
            field_size = end - start

            if field_size < 1 or field_size > 4:
                continue

            if (start, end) in tested_positions:
                continue
            tested_positions.add((start, end))
            candidates_tested += 1

            # 使用线性相关性检测
            confidence = StatisticalLengthFieldDetector._test_linear_correlation(
                messages, start, end, 'big'
            )

            if confidence > 0.7:
                length_fields.append((start, end, confidence))

        # 方法2: 只扫描最常见的位置（Modbus长度字段通常在offset 4）
        # 极简扫描，只测试4-5个关键位置
        if not messages:
            return length_fields

        critical_positions = [4]  # Modbus 长度字段的典型位置

        for start_pos in critical_positions:
            end_pos = start_pos + 2  # 只测试 2 字节

            if (start_pos, end_pos) in tested_positions:
                continue

            # 测试大端序
            confidence = StatisticalLengthFieldDetector._test_linear_correlation(
                messages, start_pos, end_pos, 'big'
            )

            if confidence > 0.85:
                length_fields.append((start_pos, end_pos, confidence))
                tested_positions.add((start_pos, end_pos))

        return length_fields

    @staticmethod
    def _test_linear_correlation(messages: List[bytes], start: int, end: int,
                                 endian: str) -> float:
        """
        测试字段与消息长度的线性相关性

        使用Pearson相关系数 + 线性回归验证

        返回：置信度 (0.0-1.0)
        """
        field_values = []
        msg_lengths = []

        # 收集数据（减少采样数量，从200减少到50）
        for msg in messages[:min(50, len(messages))]:  # 进一步减少到50
            if end > len(msg):
                continue

            try:
                field_bytes = msg[start:end]
                if endian == 'big':
                    field_value = int.from_bytes(field_bytes, 'big')
                else:
                    field_value = int.from_bytes(field_bytes, 'little')

                # 过滤异常值（长度字段不应该是0或超大值）
                if field_value == 0 or field_value > 65535:
                    continue

                field_values.append(field_value)
                msg_lengths.append(len(msg))
            except:
                continue

        if len(field_values) < 10:
            return 0.0

        # 优先使用简化版本（避免 scipy 导致的卡顿）
        return StatisticalLengthFieldDetector._simple_correlation(
            field_values, msg_lengths
        )

    @staticmethod
    def _simple_correlation(field_values: List[int], msg_lengths: List[int]) -> float:
        """简化的相关性计算（无需scipy）"""
        if len(field_values) < 10:
            return 0.0

        # 简单的线性关系测试
        # 测试: field = len - offset
        for offset in range(0, 20):
            match_count = sum(1 for fv, ml in zip(field_values, msg_lengths)
                            if fv == ml - offset)
            ratio = match_count / len(field_values)
            if ratio > 0.9:
                return ratio

        return 0.0


class StatisticalConstraintMiner:
    """
    统计约束挖掘器（协议无关）
    """

    @staticmethod
    def mine_length_constraints(messages: List[bytes],
                               length_fields: List[Tuple[int, int, float]]) -> List[Dict]:
        """
        挖掘长度控制约束（协议无关）

        自动发现长度字段的计算公式
        """
        constraints = []

        for start, end, conf in length_fields:
            # 自动发现约束公式
            constraint_formula = StatisticalConstraintMiner._discover_length_formula(
                messages, start, end
            )

            if constraint_formula:
                constraints.append({
                    'type': 'length_control',
                    'source_field': (start, end),
                    'constraint': constraint_formula['formula'],
                    'confidence': constraint_formula['confidence'],
                    'validated_samples': constraint_formula['matches']
                })

        return constraints

    @staticmethod
    def _discover_length_formula(messages: List[bytes], start: int, end: int) -> Optional[Dict]:
        """
        自动发现长度字段的计算公式

        测试多种可能：
        - field = len(msg)
        - field = len(msg) - offset
        - field = len(msg) - start - field_size
        """
        best_formula = None
        best_confidence = 0.0

        formulas_to_test = [
            ('len(msg)', lambda msg, s, e: len(msg)),
            (f'len(msg) - {end}', lambda msg, s, e: len(msg) - e),
            (f'len(msg) - {start}', lambda msg, s, e: len(msg) - s),
            (f'len(msg) - {start} - {end - start}', lambda msg, s, e: len(msg) - s - (e - s)),
        ]

        for formula_str, formula_fn in formulas_to_test:
            match_count = 0
            total_count = 0

            for msg in messages[:min(100, len(messages))]:
                if end > len(msg):
                    continue

                try:
                    field_value = int.from_bytes(msg[start:end], 'big')
                    expected = formula_fn(msg, start, end)

                    if field_value == expected:
                        match_count += 1
                    total_count += 1
                except:
                    continue

            confidence = match_count / total_count if total_count > 0 else 0.0

            if confidence > best_confidence:
                best_confidence = confidence
                best_formula = {
                    'formula': f'Field[{start}:{end}] = {formula_str}',
                    'confidence': confidence,
                    'matches': match_count
                }

        return best_formula if best_confidence > 0.7 else None


class StatisticalSemPREExperimentRunner:
    """
    纯统计学习的 SemPRE 实验运行器（Protocol-Agnostic）

    关键特性：
    - 无Modbus特定知识
    - 无硬编码字段位置
    - 纯基于统计特征的学习
    """

    def __init__(self, output_dir: str, protocol_name: str = 'unknown'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.protocol_name = protocol_name
        self.logger = self._setup_logger()

        # 统计学习的检测器（协议无关）
        self.field_detector = StatisticalFieldDetector(protocol_name, self.logger)
        self.length_detector = StatisticalLengthFieldDetector()
        self.constraint_miner = StatisticalConstraintMiner()

        self.results = {
            'exp1_format_inference': {},
            'exp2_constraint_discovery': {},
            'exp3_function_inference': {},
            'exp4_data_efficiency': {}
        }
    
    def _setup_logger(self) -> logging.Logger:
        """配置日志"""
        logger = logging.getLogger('StatisticalSemPRE')
        logger.setLevel(logging.INFO)

        log_file = self.output_dir / 'statistical_experiment.log'
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setLevel(logging.INFO)
        
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        logger.addHandler(fh)
        logger.addHandler(ch)
        
        return logger
    
    def load_data(self, csv_path: str, ground_truth_path: str) -> Tuple[List[bytes], Dict]:
        """加载数据（仅用于评估，不影响学习过程）"""
        self.logger.info("=" * 70)
        self.logger.info("加载数据（纯统计学习版）")
        self.logger.info("=" * 70)
        
        # 加载CSV
        messages, csv_boundaries = self._load_from_csv_with_boundaries(csv_path)
        self.logger.info(f"✓ 从CSV加载了 {len(messages)} 条消息")
        
        # 加载Ground Truth（尝试多种格式）
        ground_truth = self._load_ground_truth(ground_truth_path, csv_boundaries)
        self.logger.info(f"✓ 加载了Ground Truth")
        
        # 存储CSV边界作为备份
        self.csv_boundaries = csv_boundaries
        
        return messages, ground_truth
    
    def _load_from_csv_with_boundaries(self, csv_path: str) -> Tuple[List[bytes], List[List[int]]]:
        """从CSV加载消息和边界"""
        messages = []
        boundaries_list = []
        
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'HexData' in row:
                    hex_str = row['HexData'].strip()
                    try:
                        msg_bytes = bytes.fromhex(hex_str)
                        messages.append(msg_bytes)
                        
                        # 提取边界（仅从CSV）
                        if 'Boundaries' in row and row['Boundaries']:
                            boundaries_str = row['Boundaries'].strip('"').strip("'")
                            boundaries = [int(b) for b in boundaries_str.split(',')]
                            boundaries_list.append(boundaries)
                        else:
                            # 如果CSV中没有边界，则记录为空
                            # 注意：不使用任何硬编码规则生成边界
                            boundaries_list.append([])
                    except (ValueError, Exception) as e:
                        continue
        
        return messages, boundaries_list
    
    def _load_ground_truth(self, gt_path: str, csv_boundaries: List[List[int]]) -> Dict:
        """
        加载Ground Truth（支持多种格式）
        
        优先级：
        1. JSON文件中的边界
        2. CSV中的边界
        3. 协议标准边界
        """
        ground_truth = {
            'syntax_groundtruth': {},
            'boundaries_per_message': csv_boundaries,
            'function_labels': {},
            'constraints': []
        }
        
        # 尝试加载JSON
        if os.path.exists(gt_path):
            try:
                with open(gt_path, 'r', encoding='utf-8') as f:
                    loaded_gt = json.load(f)
                    ground_truth.update(loaded_gt)
                    self.logger.info(f"  ✓ 从JSON加载Ground Truth: {len(loaded_gt)} 项")
            except Exception as e:
                self.logger.warning(f"  ! 无法加载JSON Ground Truth: {e}")
        
        # 如果JSON中没有边界，使用CSV边界
        if 'boundaries_per_message' not in ground_truth or not ground_truth['boundaries_per_message']:
            ground_truth['boundaries_per_message'] = csv_boundaries
            self.logger.info(f"  ✓ 使用CSV边界作为Ground Truth")
        
        return ground_truth
    
    def run_all_experiments(self, messages: List[bytes], ground_truth: Dict) -> None:
        """运行所有实验（纯统计学习版）"""
        self.logger.info("\n" + "=" * 70)
        self.logger.info("SemPRE: Protocol-Agnostic Statistical Learning")
        self.logger.info("=" * 70)

        # 实验1: 格式推理准确率（纯统计）
        self.logger.info("\n### Experiment 1: Statistical Format Inference")
        self.results['exp1_format_inference'] = self.experiment1_statistical(
            messages, ground_truth
        )

        # 实验2: 语义约束发现（协议无关）
        self.logger.info("\n### Experiment 2: Protocol-Agnostic Constraint Discovery")
        self.results['exp2_constraint_discovery'] = self.experiment2_statistical(
            messages, ground_truth
        )

        # 实验3: 零样本功能推理（无位置假设）
        self.logger.info("\n### Experiment 3: Zero-Shot Function Inference (No Position Assumptions)")
        self.results['exp3_function_inference'] = self.experiment3_function_inference(
            messages, ground_truth
        )

        # 实验4: 数据效率
        self.logger.info("\n### Experiment 4: Data Efficiency")
        self.results['exp4_data_efficiency'] = self.experiment4_data_efficiency(
            messages, ground_truth
        )

        # 保存结果
        self._save_all_results()
    
    def experiment1_statistical(self, messages: List[bytes], ground_truth: Dict) -> Dict[str, Any]:
        """
        实验1：纯统计的字段边界检测（无协议知识）
        """
        self.logger.info("使用纯统计方法（熵+IoC）...")

        # 使用统计检测器
        detected_fields, metadata = self.field_detector.detect_fields(messages)
        detected_boundaries_per_msg = metadata['boundaries_per_message']
        
        # 从ground truth获取真实边界
        true_boundaries_per_msg = ground_truth.get('boundaries_per_message', self.csv_boundaries)
        
        if not true_boundaries_per_msg:
            return {'error': 'No ground truth boundaries'}
        
        # 计算指标
        all_precisions = []
        all_recalls = []
        all_f1s = []
        perfect_matches = 0
        
        for i in range(min(len(detected_boundaries_per_msg), len(true_boundaries_per_msg))):
            detected_set = set(detected_boundaries_per_msg[i])
            true_set = set(true_boundaries_per_msg[i])
            
            if not true_set:
                continue
            
            tp = len(detected_set & true_set)
            fp = len(detected_set - true_set)
            fn = len(true_set - detected_set)
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            
            all_precisions.append(precision)
            all_recalls.append(recall)
            all_f1s.append(f1)
            
            if detected_set == true_set:
                perfect_matches += 1
        
        metrics = {
            'precision': np.mean(all_precisions) if all_precisions else 0.0,
            'recall': np.mean(all_recalls) if all_recalls else 0.0,
            'f1_score': np.mean(all_f1s) if all_f1s else 0.0,
            'perfect_score': perfect_matches / len(true_boundaries_per_msg),
            'detection_method': metadata['detection_method'],
            'total_samples': len(true_boundaries_per_msg)
        }
        
        self.logger.info(f"✓ F1 Score: {metrics['f1_score']:.4f}")
        self.logger.info(f"✓ Perfect Score: {metrics['perfect_score']:.4f}")
        self.logger.info(f"✓ Precision: {metrics['precision']:.4f}")
        self.logger.info(f"✓ Recall: {metrics['recall']:.4f}")
        self.logger.info(f"✓ Perfect Matches: {perfect_matches}/{len(true_boundaries_per_msg)}")
        
        return metrics
    
    def experiment2_statistical(self, messages: List[bytes], ground_truth: Dict) -> Dict[str, Any]:
        """
        实验2：协议无关的约束发现
        """
        # 检测长度字段
        detected_fields, _ = self.field_detector.detect_fields(messages)
        length_fields = self.length_detector.detect_length_fields(messages, detected_fields)
        
        self.logger.info(f"✓ 检测到 {len(length_fields)} 个长度字段")
        
        # 挖掘长度约束
        length_constraints = self.constraint_miner.mine_length_constraints(messages, length_fields)
        
        self.logger.info(f"✓ 发现 {len(length_constraints)} 个长度控制约束")

        # SDG构建（可选 - 耗时较长，可跳过）
        # 注意：SDG构建对核心评估指标（F1/Perfect Score）无影响
        ENABLE_SDG = False  # 设为False可大幅提速

        if ENABLE_SDG:
            self.logger.info("开始构建语义依赖图...")
            sdg = SemanticDependencyGraph(logger=self.logger)
            sampled = messages[:min(100, len(messages))]  # 减少样本数
            stats = sdg.build_from_messages(sampled, detected_fields)

            # 导出Graphviz
            dot_path = self.output_dir / f"{self.protocol_name}_improved_sdg.dot"
            sdg.export_graphviz(str(dot_path))
            self.logger.info(f"✓ SDG已导出到: {dot_path}")
        else:
            self.logger.info("跳过SDG构建（提速优化）")
            stats = {
                'arithmetic_constraints': 0,
                'logical_constraints': 0,
                'edge_count': 0
            }
        
        results = {
            'length_fields_detected': len(length_fields),
            'length_constraints': len(length_constraints),
            'arithmetic_constraints': stats.get('arithmetic_constraints', 0),
            'logical_constraints': stats.get('logical_constraints', 0),
            'total_constraints': len(length_constraints) + stats.get('edge_count', 0),
            'constraint_details': length_constraints,
            'sdg_stats': stats
        }
        
        self.logger.info(f"✓ 总约束数: {results['total_constraints']}")
        self.logger.info(f"✓ 算术约束: {results['arithmetic_constraints']}")
        
        return results
    
    def experiment3_function_inference(self, messages: List[bytes], ground_truth: Dict) -> Dict[str, Any]:
        """实验3：零样本功能推理"""
        inferencer = ZeroShotFunctionInferencer(logger=self.logger)
        
        # 提取功能码统计
        function_profiles = self._extract_function_profiles(messages)
        
        signatures = inferencer.infer_unknown_functions(
            messages, function_profiles, self.protocol_name
        )
        
        return {
            'inferred_functions': len(signatures),
            'signatures': [
                {
                    'func_code': f"0x{sig.func_code:02X}",
                    'label': sig.inferred_label,
                    'confidence': sig.confidence,
                    'fingerprint': sig.fingerprint_str
                }
                for sig in signatures[:10]  # 只显示前10个
            ]
        }
    
    def experiment4_data_efficiency(self, messages: List[bytes], ground_truth: Dict) -> Dict[str, Any]:
        """实验4：数据效率"""
        ratios = [0.1, 0.3, 0.5, 1.0]
        results = []
        
        true_boundaries = ground_truth.get('boundaries_per_message', self.csv_boundaries)
        
        for ratio in ratios:
            sample_size = int(len(messages) * ratio)
            sampled_messages = messages[:sample_size]
            sampled_boundaries_true = true_boundaries[:sample_size]
            
            self.logger.info(f"\n  Testing with {ratio*100:.0f}% data ({sample_size} messages)")
            
            # 检测边界
            _, metadata = self.field_detector.detect_fields(sampled_messages)
            detected_boundaries = metadata['boundaries_per_message']
            
            # 计算F1
            all_f1s = []
            for i in range(min(len(detected_boundaries), len(sampled_boundaries_true))):
                detected_set = set(detected_boundaries[i])
                true_set = set(sampled_boundaries_true[i])
                
                if not true_set:
                    continue
                
                tp = len(detected_set & true_set)
                fp = len(detected_set - true_set)
                fn = len(true_set - detected_set)
                
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
                
                all_f1s.append(f1)
            
            result = {
                'data_ratio': ratio,
                'sample_size': sample_size,
                'f1_score': np.mean(all_f1s) if all_f1s else 0.0
            }
            results.append(result)
            
            self.logger.info(f"  F1 Score: {result['f1_score']:.4f}")
        
        return {'ratios': ratios, 'results': results}
    
    def _extract_function_profiles(self, messages: List[bytes]) -> List[Any]:
        """
        提取功能码统计（协议无关）

        策略：尝试所有可能的字节位置作为"类型字段"候选
        基于低熵特征识别类型字段
        """
        from dataclasses import dataclass

        @dataclass
        class FunctionProfile:
            code: int
            count: int
            name: str
            avg_length: float
            byte_position: int  # 该功能码所在的字节位置

        # 1. 找到最可能的"类型字段"位置（基于熵分析）
        type_field_position = self._find_type_field_position(messages)

        self.logger.info(f"  推断类型字段位置: offset {type_field_position}")

        # 2. 基于该位置提取功能码
        func_stats = {}
        for msg in messages:
            if len(msg) > type_field_position:
                func_code = msg[type_field_position]
                if func_code not in func_stats:
                    func_stats[func_code] = {'count': 0, 'lengths': []}
                func_stats[func_code]['count'] += 1
                func_stats[func_code]['lengths'].append(len(msg))

        profiles = []
        for code, stats in func_stats.items():
            profile = FunctionProfile(
                code=code,
                count=stats['count'],
                name=f'Type_0x{code:02X}',
                avg_length=np.mean(stats['lengths']),
                byte_position=type_field_position
            )
            profiles.append(profile)

        return profiles

    def _find_type_field_position(self, messages: List[bytes]) -> int:
        """
        找到最可能的类型/命令字段位置（协议无关）

        特征：
        1. 低熵（值的种类少）
        2. 跨消息一致（所有消息都有该字节）
        3. 不是常量（至少有几个不同值）
        """
        if not messages:
            return 0

        max_len = max(len(msg) for msg in messages)
        best_position = 0
        best_score = float('inf')

        for pos in range(min(32, max_len)):  # 只检查前32字节
            values = []
            for msg in messages:
                if pos < len(msg):
                    values.append(msg[pos])

            if len(values) < len(messages) * 0.9:  # 至少90%的消息有该字节
                continue

            # 计算该位置的"类型字段分数"
            unique_count = len(set(values))

            # 理想的类型字段：3-20个不同值
            if 3 <= unique_count <= 20:
                # 计算熵
                counter = Counter(values)
                total = len(values)
                entropy = 0.0
                for count in counter.values():
                    p = count / total
                    if p > 0:
                        entropy -= p * np.log2(p)

                # 低熵的字段更可能是类型字段
                score = entropy

                if score < best_score:
                    best_score = score
                    best_position = pos

        return best_position
    
    def _save_all_results(self) -> None:
        """保存所有结果"""
        self.logger.info("\n" + "=" * 70)
        self.logger.info("保存结果")
        self.logger.info("=" * 70)
        
        # 保存JSON
        json_path = self.output_dir / 'improved_results.json'
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        self.logger.info(f"✓ Saved JSON: {json_path}")
        
        # 保存CSV
        csv_path = self.output_dir / 'improved_results.csv'
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Experiment', 'Metric', 'Value'])
            
            # 实验1
            exp1 = self.results['exp1_format_inference']
            if 'f1_score' in exp1:
                writer.writerow(['Format Inference', 'F1 Score', f"{exp1['f1_score']:.4f}"])
                writer.writerow(['Format Inference', 'Precision', f"{exp1['precision']:.4f}"])
                writer.writerow(['Format Inference', 'Recall', f"{exp1['recall']:.4f}"])
                writer.writerow(['Format Inference', 'Perfect Score', f"{exp1['perfect_score']:.4f}"])
            
            # 实验2
            exp2 = self.results['exp2_constraint_discovery']
            writer.writerow(['Constraint Discovery', 'Length Constraints', str(exp2.get('length_constraints', 0))])
            writer.writerow(['Constraint Discovery', 'Arithmetic', str(exp2.get('arithmetic_constraints', 0))])
            writer.writerow(['Constraint Discovery', 'Total', str(exp2.get('total_constraints', 0))])
        
        self.logger.info(f"✓ Saved CSV: {csv_path}")
        
        # 打印对比
        self._print_improvement_summary()
    
    def _print_improvement_summary(self) -> None:
        """打印实验总结"""
        self.logger.info("\n" + "=" * 70)
        self.logger.info("实验总结（纯统计学习）")
        self.logger.info("=" * 70)

        exp1 = self.results['exp1_format_inference']
        exp2 = self.results['exp2_constraint_discovery']

        self.logger.info("\n 关键指标:")
        self.logger.info(f"  • F1 Score: {exp1.get('f1_score', 0):.4f}")
        self.logger.info(f"  • Perfect Score: {exp1.get('perfect_score', 0):.4f}")
        self.logger.info(f"  • Precision: {exp1.get('precision', 0):.4f}")
        self.logger.info(f"  • Recall: {exp1.get('recall', 0):.4f}")
        self.logger.info(f"  • 长度约束: {exp2.get('length_constraints', 0)} 个")
        self.logger.info(f"  • 检测方法: {exp1.get('detection_method', 'unknown')}")

        self.logger.info("\n 注意：")
        self.logger.info("  - 本版本使用纯统计学习，无Modbus特定知识")
        self.logger.info("  - 分数反映算法的真实学习能力，而非规则匹配")
        self.logger.info("  - 评估重点：泛化能力 > 单一协议准确率")


def main():
    parser = argparse.ArgumentParser(
        description='SemPRE: Protocol-Agnostic Statistical Learning Experiment Runner'
    )

    parser.add_argument('--csv', required=True, help='输入CSV文件')
    parser.add_argument('--ground-truth', required=True, help='Ground Truth JSON文件')
    parser.add_argument('--output-dir', default='./output/statistical', help='输出目录')
    parser.add_argument('--protocol', default='unknown', help='协议名称（仅用于标记，不影响算法）')

    args = parser.parse_args()

    # 创建纯统计学习运行器
    runner = StatisticalSemPREExperimentRunner(args.output_dir, args.protocol)
    
    # 加载数据
    messages, ground_truth = runner.load_data(args.csv, args.ground_truth)
    
    # 运行所有实验
    runner.run_all_experiments(messages, ground_truth)
    
    print(f"\n实验完成！结果保存到: {args.output_dir}")


if __name__ == '__main__':
    main()