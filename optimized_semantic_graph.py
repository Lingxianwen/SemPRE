#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SemPRE: Optimized Semantic Dependency Graph (SDG) Builder
优化版语义依赖图构建器

性能优化：
1. 智能字段过滤 - 只检测有意义的字段对
2. 去重字段节点 - 合并相同位置的字段
3. 早期终止 - 快速跳过不相关的字段对
4. 采样策略 - 减少需要检查的样本数

Author: SemPRE Research Team (Optimized)
"""

import numpy as np
from typing import List, Dict, Tuple, Set, Any, Optional
from dataclasses import dataclass, field, asdict
from collections import defaultdict, Counter
from scipy import stats
import logging


@dataclass
class SDGNode:
    """语义依赖图节点"""
    node_id: int
    node_type: str
    field_range: Optional[Tuple[int, int]] = None
    message_index: Optional[int] = None
    semantic_label: Optional[str] = None
    entropy: float = 0.0
    properties: Dict[str, Any] = field(default_factory=dict)

    def __str__(self):
        if self.node_type == 'field':
            return f"Field_{self.node_id}[{self.field_range[0]}:{self.field_range[1]}]"
        return f"{self.node_type}_{self.node_id}"


@dataclass
class SDGEdge:
    """语义依赖图边"""
    source: int
    target: int
    edge_type: str
    weight: float
    constraint: Optional[str] = None
    linear_params: Optional[Dict[str, float]] = None
    properties: Dict[str, Any] = field(default_factory=dict)

    def __str__(self):
        if self.constraint:
            return f"{self.source} -> {self.target}: {self.constraint} (conf={self.weight:.2f})"
        return f"{self.source} -> {self.target}: {self.edge_type} (conf={self.weight:.2f})"


class OptimizedSemanticDependencyGraph:
    """
    优化版语义依赖图 (SDG)
    
    性能改进：
    1. 字段去重 - 合并相同位置的字段
    2. 智能过滤 - 只检测可能有约束的字段对
    3. 早期终止 - 快速跳过无关字段对
    """

    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.nodes: Dict[int, SDGNode] = {}
        self.edges: List[SDGEdge] = []
        self.node_counter = 0

    def add_node(self, node_type: str, **kwargs) -> int:
        """添加节点"""
        node_id = self.node_counter
        self.node_counter += 1
        node = SDGNode(node_id=node_id, node_type=node_type, **kwargs)
        self.nodes[node_id] = node
        return node_id

    def add_edge(self, source: int, target: int, edge_type: str,
                 weight: float = 1.0, **kwargs) -> None:
        """添加边"""
        edge = SDGEdge(source=source, target=target, edge_type=edge_type,
                      weight=weight, **kwargs)
        self.edges.append(edge)

    def build_from_messages(self, messages: List[bytes],
                           field_candidates: List[Any]) -> Dict[str, Any]:
        """
        从消息构建SDG（优化版）
        """
        self.logger.info("=" * 70)
        self.logger.info("优化版 SDG 构建")
        self.logger.info("=" * 70)

        # 1. 创建去重的字段节点
        unique_fields = self._deduplicate_fields(field_candidates)
        field_nodes = self._create_field_nodes_optimized(messages, unique_fields)
        self.logger.info(f"✓ 创建 {len(field_nodes)} 个去重字段节点")

        # 2. 优化的算术约束挖掘
        arith_edges = self._mine_arithmetic_constraints_optimized(
            messages, unique_fields
        )
        self.logger.info(f"✓ 发现 {len(arith_edges)} 个算术约束")

        # 3. 逻辑约束挖掘
        logic_edges = self._mine_logical_constraints(messages, unique_fields)
        self.logger.info(f"✓ 发现 {len(logic_edges)} 个逻辑约束")

        # 4. 位级依赖
        bitlevel_deps = self._analyze_bitlevel_dependencies(messages)
        self.logger.info(f"✓ 发现 {bitlevel_deps} 个位级依赖")

        return {
            'node_count': len(self.nodes),
            'edge_count': len(self.edges),
            'arithmetic_constraints': len(arith_edges),
            'logical_constraints': len(logic_edges),
            'bitlevel_dependencies': bitlevel_deps
        }

    def _deduplicate_fields(self, field_candidates: List[Any]) -> List[Any]:
        """
        字段去重 - 合并相同位置的字段
        
        关键优化：减少字段节点数量
        """
        unique_fields_dict = {}
        
        for field in field_candidates:
            if hasattr(field, 'start') and hasattr(field, 'end'):
                key = (field.start, field.end)
                
                # 保留置信度最高的字段
                if key not in unique_fields_dict:
                    unique_fields_dict[key] = field
                else:
                    existing = unique_fields_dict[key]
                    if hasattr(field, 'confidence') and hasattr(existing, 'confidence'):
                        if field.confidence > existing.confidence:
                            unique_fields_dict[key] = field
        
        unique_fields = list(unique_fields_dict.values())
        self.logger.info(f"  字段去重: {len(field_candidates)} → {len(unique_fields)}")
        
        return unique_fields

    def _create_field_nodes_optimized(self, messages: List[bytes],
                                     field_candidates: List[Any]) -> List[int]:
        """创建优化的字段节点（不为每条消息重复创建）"""
        field_nodes = []
        
        # 只为唯一的字段位置创建节点
        for field in field_candidates:
            if hasattr(field, 'start') and hasattr(field, 'end'):
                entropy = self._calculate_field_entropy(messages, field.start, field.end)
                
                node_id = self.add_node(
                    node_type='field',
                    field_range=(field.start, field.end),
                    semantic_label=getattr(field, 'field_type', 'unknown'),
                    entropy=entropy,
                    properties={
                        'confidence': getattr(field, 'confidence', 0.0),
                        'type': getattr(field, 'field_type', 'unknown')
                    }
                )
                field_nodes.append(node_id)
        
        return field_nodes

    def _mine_arithmetic_constraints_optimized(self, messages: List[bytes],
                                              field_candidates: List[Any]) -> List[SDGEdge]:
        """
        优化的算术约束挖掘
        
        性能优化策略：
        1. 智能过滤 - 只检测数值字段对
        2. 大小限制 - 只检测小字段（1-4字节）
        3. 熵过滤 - 跳过低熵（常量）字段
        4. 早期终止 - 快速相关性检查
        """
        edges = []
        
        # 步骤1: 过滤出候选字段（只保留可能参与算术关系的字段）
        numeric_fields = []
        for field in field_candidates:
            if not (hasattr(field, 'start') and hasattr(field, 'end')):
                continue
            
            field_size = field.end - field.start
            
            # 只检测1-4字节的字段（可能的数值字段）
            if 1 <= field_size <= 4:
                # 计算熵
                entropy = self._calculate_field_entropy(messages, field.start, field.end)
                
                # 跳过低熵字段（可能是常量）
                if entropy > 0.5:  # 阈值：至少有一些变化
                    numeric_fields.append(field)
        
        self.logger.info(f"  算术约束候选字段: {len(numeric_fields)} / {len(field_candidates)}")
        
        # 步骤2: 采样消息（减少计算量）
        sampled_messages = messages[:min(100, len(messages))]
        
        # 步骤3: 智能配对检测（只检测可能相关的字段对）
        checked_pairs = 0
        max_pairs = min(1000, len(numeric_fields) * 10)  # 限制最大检查数
        
        for i, field_a in enumerate(numeric_fields):
            for j, field_b in enumerate(numeric_fields):
                if i >= j:
                    continue
                
                checked_pairs += 1
                if checked_pairs > max_pairs:
                    self.logger.info(f"  达到最大检查对数限制: {max_pairs}")
                    break
                
                # 快速相关性检查
                correlation = self._quick_correlation_check(
                    sampled_messages, field_a, field_b
                )
                
                # 只对高相关性的字段对进行详细分析
                if correlation > 0.7:
                    edge = self._analyze_field_pair(
                        sampled_messages, field_a, field_b, i, j
                    )
                    if edge:
                        edges.append(edge)
            
            if checked_pairs > max_pairs:
                break
        
        self.logger.info(f"  检查了 {checked_pairs} 个字段对")
        
        return edges

    def _quick_correlation_check(self, messages: List[bytes],
                                 field_a: Any, field_b: Any) -> float:
        """
        快速相关性检查（早期终止策略）
        
        返回皮尔逊相关系数的绝对值
        """
        values_a = []
        values_b = []
        
        for msg in messages[:50]:  # 只检查前50条
            try:
                if field_a.end <= len(msg) and field_b.end <= len(msg):
                    val_a = self._extract_numeric_value(msg, field_a.start, field_a.end)
                    val_b = self._extract_numeric_value(msg, field_b.start, field_b.end)
                    
                    if val_a is not None and val_b is not None:
                        values_a.append(val_a)
                        values_b.append(val_b)
            except:
                continue
        
        if len(values_a) < 5:
            return 0.0
        
        # 快速相关性计算
        try:
            correlation = np.corrcoef(values_a, values_b)[0, 1]
            if np.isnan(correlation):
                return 0.0
            return abs(correlation)
        except:
            return 0.0

    def _analyze_field_pair(self, messages: List[bytes],
                           field_a: Any, field_b: Any,
                           idx_a: int, idx_b: int) -> Optional[SDGEdge]:
        """
        详细分析字段对的线性关系
        """
        values_a = []
        values_b = []
        
        for msg in messages:
            try:
                if field_a.end <= len(msg) and field_b.end <= len(msg):
                    val_a = self._extract_numeric_value(msg, field_a.start, field_a.end)
                    val_b = self._extract_numeric_value(msg, field_b.start, field_b.end)
                    
                    if val_a is not None and val_b is not None:
                        values_a.append(val_a)
                        values_b.append(val_b)
            except:
                continue
        
        if len(values_a) < 10:
            return None
        
        # 线性回归
        try:
            slope, intercept, r_value, p_value, std_err = stats.linregress(values_a, values_b)
            r_squared = r_value ** 2
            
            # 高置信度线性关系
            if r_squared > 0.85 and p_value < 0.01:
                constraint_str = self._format_linear_constraint(slope, intercept, idx_a, idx_b)
                
                # 查找节点ID
                source_id = self._find_node_by_field_index(idx_a)
                target_id = self._find_node_by_field_index(idx_b)
                
                if source_id is not None and target_id is not None:
                    self.add_edge(
                        source=source_id,
                        target=target_id,
                        edge_type='arithmetic',
                        weight=r_squared,
                        constraint=constraint_str,
                        linear_params={'k': slope, 'b': intercept, 'r2': r_squared}
                    )
                    return self.edges[-1]
        except:
            pass
        
        return None

    def _mine_logical_constraints(self, messages: List[bytes],
                                  field_candidates: List[Any]) -> List[SDGEdge]:
        """挖掘逻辑约束（长度控制等）"""
        edges = []
        
        # 检测长度控制关系
        for i, field in enumerate(field_candidates):
            if not hasattr(field, 'field_type'):
                continue
            
            if field.field_type == 'length':
                # 查找被控制的字段
                for j, target_field in enumerate(field_candidates):
                    if i == j:
                        continue
                    
                    is_control = self._check_length_control(messages, field, target_field)
                    
                    if is_control:
                        source_id = self._find_node_by_field_index(i)
                        target_id = self._find_node_by_field_index(j)
                        
                        if source_id is not None and target_id is not None:
                            self.add_edge(
                                source=source_id,
                                target=target_id,
                                edge_type='length_control',
                                weight=0.9,
                                constraint=f"Field_{i} controls length of Field_{j}"
                            )
                            edges.append(self.edges[-1])
        
        return edges

    def _analyze_bitlevel_dependencies(self, messages: List[bytes]) -> int:
        """位级依赖分析"""
        bitlevel_count = 0
        
        if len(messages) < 10:
            return 0
        
        for byte_offset in range(min(8, len(messages[0]))):
            byte_values = []
            for msg in messages[:100]:  # 采样
                if byte_offset < len(msg):
                    byte_values.append(msg[byte_offset])
            
            if len(byte_values) < 10:
                continue
            
            unique_values = set(byte_values)
            if len(unique_values) <= 16:
                bitlevel_count += 1
        
        return bitlevel_count

    def _calculate_field_entropy(self, messages: List[bytes],
                                 start: int, end: int) -> float:
        """计算字段熵"""
        values = []
        for msg in messages[:100]:  # 采样
            if end <= len(msg):
                field_bytes = msg[start:end]
                values.append(field_bytes)
        
        if not values:
            return 0.0
        
        counter = Counter(values)
        total = len(values)
        entropy = 0.0
        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy

    def _extract_numeric_value(self, msg: bytes, start: int, end: int) -> Optional[int]:
        """提取数值"""
        if end > len(msg):
            return None
        
        field_bytes = msg[start:end]
        length = end - start
        
        try:
            if length == 1:
                return field_bytes[0]
            elif length == 2:
                return int.from_bytes(field_bytes, 'big')
            elif length == 4:
                return int.from_bytes(field_bytes, 'big')
            else:
                return int.from_bytes(field_bytes, 'big')
        except:
            return None

    def _format_linear_constraint(self, slope: float, intercept: float,
                                  source_idx: int, target_idx: int) -> str:
        """格式化线性约束"""
        if abs(intercept) < 0.1:
            if abs(slope - round(slope)) < 0.1:
                k = int(round(slope))
                return f"Field_{target_idx} = Field_{source_idx} * {k}"
            else:
                return f"Field_{target_idx} = Field_{source_idx} * {slope:.2f}"
        else:
            if abs(slope - round(slope)) < 0.1 and abs(intercept - round(intercept)) < 0.1:
                k = int(round(slope))
                b = int(round(intercept))
                sign = '+' if b >= 0 else ''
                return f"Field_{target_idx} = Field_{source_idx} * {k} {sign}{b}"
            else:
                sign = '+' if intercept >= 0 else ''
                return f"Field_{target_idx} = Field_{source_idx} * {slope:.2f} {sign}{intercept:.2f}"

    def _check_length_control(self, messages: List[bytes],
                              length_field: Any, target_field: Any) -> bool:
        """检查长度控制关系"""
        matches = 0
        total = 0
        
        for msg in messages[:50]:  # 采样
            try:
                if length_field.end <= len(msg) and target_field.end <= len(msg):
                    length_val = self._extract_numeric_value(
                        msg, length_field.start, length_field.end
                    )
                    target_len = target_field.end - target_field.start
                    
                    if length_val == target_len or length_val == target_len + length_field.end:
                        matches += 1
                    total += 1
            except:
                continue
        
        return matches / total > 0.7 if total > 0 else False

    def _find_node_by_field_index(self, field_idx: int) -> Optional[int]:
        """根据字段索引查找节点ID"""
        field_count = 0
        for node_id, node in self.nodes.items():
            if node.node_type == 'field':
                if field_count == field_idx:
                    return node_id
                field_count += 1
        return None

    def export_graphviz(self, output_path: str) -> None:
        """导出为Graphviz DOT格式"""
        self.logger.info(f"导出SDG到: {output_path}")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("digraph SDG {\n")
            f.write("  rankdir=TB;\n")
            f.write("  node [shape=box, style=filled];\n\n")
            
            # 节点
            for node_id, node in self.nodes.items():
                if node.node_type == 'field':
                    color = 'lightblue'
                    label = f"{node}\\nEntropy: {node.entropy:.2f}"
                    if node.semantic_label:
                        label += f"\\nType: {node.semantic_label}"
                else:
                    color = 'lightgreen'
                    label = f"{node.node_type}_{node_id}"
                
                f.write(f'  {node_id} [label="{label}", fillcolor={color}];\n')
            
            f.write("\n")
            
            # 边
            for edge in self.edges:
                if edge.edge_type == 'arithmetic':
                    style = 'solid'
                    color = 'red'
                elif edge.edge_type == 'length_control':
                    style = 'dashed'
                    color = 'blue'
                else:
                    style = 'dotted'
                    color = 'black'
                
                label = edge.constraint if edge.constraint else edge.edge_type
                f.write(f'  {edge.source} -> {edge.target} '
                       f'[label="{label}", style={style}, color={color}];\n')
            
            f.write("}\n")
        
        self.logger.info(f"✓ Graphviz文件已保存")

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        edge_types = Counter([e.edge_type for e in self.edges])
        
        return {
            'total_nodes': len(self.nodes),
            'field_nodes': sum(1 for n in self.nodes.values() if n.node_type == 'field'),
            'total_edges': len(self.edges),
            'edge_types': dict(edge_types),
            'avg_node_degree': len(self.edges) * 2 / len(self.nodes) if self.nodes else 0
        }

    def to_json(self) -> Dict[str, Any]:
        """导出为JSON"""
        return {
            'nodes': [asdict(node) for node in self.nodes.values()],
            'edges': [asdict(edge) for edge in self.edges],
            'statistics': self.get_statistics()
        }


# 向后兼容别名
SemanticDependencyGraph = OptimizedSemanticDependencyGraph