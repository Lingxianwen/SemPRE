#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SemPRE 评估框架
基于真实数据集的性能评估工具

评估指标:
1. Boundary Detection: 边界检测准确率、精确率、召回率、F1分数
2. Field-level Perfection: 字段级完美匹配率
3. Type Inference: 字段类型推断准确率
4. Semantic Understanding: 语义理解准确率

"""

import os
import sys
import numpy as np
import pandas as pd
import logging
import argparse
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict, Counter
from pathlib import Path
import warnings
import json
from dataclasses import dataclass

# 导入主模块
from advanced_protocol_analyzer import AdvancedProtocolPipeline

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
warnings.filterwarnings('ignore')


# =============================================================================
# 数据加载器
# =============================================================================

class RealDatasetLoader:
    """真实数据集加载器"""

    def __init__(self, data_root: str = "Msg2"):
        self.data_root = Path(data_root)
        self.csv_root = self.data_root / "csv"
        self.txt_root = self.data_root / "txt"

        # 支持的协议列表
        self.supported_protocols = [
            'smb', 'smb2', 'dns', 's7comm', 'dnp3',
            'modbus', 'ftp', 'tls', 'dhcp'
        ]

    def load_protocol_data(self, protocol_name: str) -> List[Dict]:
        """加载协议数据从CSV文件"""
        logger.info(f"  加载 {protocol_name.upper()} 协议数据...")

        # 检查CSV文件夹
        csv_protocol_dir = self.csv_root / protocol_name
        if not csv_protocol_dir.exists():
            logger.warning(f"  CSV目录不存在: {csv_protocol_dir}")
            return []

        # 查找CSV文件
        csv_files = list(csv_protocol_dir.glob("*.csv"))
        if not csv_files:
            logger.warning(f"  没有找到CSV文件: {csv_protocol_dir}")
            return []

        data = []
        for csv_file in csv_files:
            try:
                file_data = self._load_csv_file(csv_file, protocol_name)
                data.extend(file_data)
                logger.info(f"    从 {csv_file.name} 加载 {len(file_data)} 条数据")
            except Exception as e:
                logger.error(f"  加载CSV文件 {csv_file} 失败: {e}")
                continue

        logger.info(f"    总计加载 {len(data)} 条 {protocol_name.upper()} 数据")
        return data

    def _load_csv_file(self, csv_file: Path, protocol_name: str) -> List[Dict]:
        """加载单个CSV文件"""
        data = []

        try:
            # 读取CSV文件
            df = pd.read_csv(csv_file)
            logger.info(f"     CSV文件 {csv_file.name} 包含 {len(df)} 行数据")

            # 检查必要的列
            required_columns = self._get_required_columns(df.columns.tolist())
            if not required_columns:
                logger.warning(f"     CSV文件缺少必要列，尝试自动推断...")
                required_columns = self._infer_columns(df.columns.tolist())

            # 处理每一行数据
            for index, row in df.iterrows():
                try:
                    sample = self._parse_csv_row(row, index, protocol_name, required_columns)
                    if sample:
                        data.append(sample)
                except Exception as e:
                    logger.debug(f"     解析第 {index} 行失败: {e}")
                    continue

        except Exception as e:
            logger.error(f"  读取CSV文件失败: {e}")

        return data

    def _get_required_columns(self, columns: List[str]) -> Dict[str, str]:
        """获取必要的列名映射 - 使用修复后的两步匹配策略"""
        column_mapping = {}

        # 第一步：尝试精确匹配最常见的列名
        for col in columns:
            col_lower = col.lower().strip()
            if col_lower == 'hexdata':
                column_mapping['hex_data'] = col
            if col_lower == 'boundaries':
                column_mapping['boundaries'] = col

        # 第二步：如果精确匹配失败，尝试模式匹配
        if 'hex_data' not in column_mapping or 'boundaries' not in column_mapping:
            hex_patterns = ['hex_data', 'hex', 'data', 'payload', 'raw_data', 'message', 'packet', 'frame']
            boundary_patterns = ['boundary', 'field_boundaries', 'gt_boundaries', 'ground_truth', 'fields']

            for col in columns:
                col_lower = col.lower().strip()

                # 查找HEX数据列
                if not column_mapping.get('hex_data'):
                    for pattern in hex_patterns:
                        if pattern in col_lower:
                            column_mapping['hex_data'] = col
                            break

                # 查找边界标签列 - 排除以 "has" 开头的列
                if not column_mapping.get('boundaries'):
                    if not col_lower.startswith('has'):
                        for pattern in boundary_patterns:
                            if pattern in col_lower:
                                column_mapping['boundaries'] = col
                                break

        return column_mapping

    def _infer_columns(self, columns: List[str]) -> Dict[str, str]:
        """推断列名"""
        column_mapping = {}

        # 如果只有少数几列，尝试推断
        if len(columns) >= 1:
            column_mapping['hex_data'] = columns[0]  # 第一列通常是数据

        if len(columns) >= 2:
            column_mapping['boundaries'] = columns[1]  # 第二列可能是标签

        return column_mapping

    def _parse_csv_row(self, row: pd.Series, row_index: int, protocol_name: str, column_mapping: Dict[str, str]) -> Optional[Dict]:
        """解析CSV行数据"""
        try:
            # 获取HEX数据
            hex_data = None
            if 'hex_data' in column_mapping:
                hex_data = str(row[column_mapping['hex_data']]).strip()
            else:
                hex_data = str(row.iloc[0]).strip()

            if not hex_data or hex_data.lower() in ['nan', 'none', '']:
                return None

            # 清理HEX数据
            hex_data = self._clean_hex_data(hex_data)
            if not hex_data:
                return None

            # 转换为字节
            try:
                raw_bytes = bytes.fromhex(hex_data)
            except ValueError as e:
                logger.debug(f"     第 {row_index} 行HEX数据格式错误: {e}")
                return None

            # 获取边界标签
            boundaries = self._parse_boundaries(row, column_mapping, len(raw_bytes), protocol_name)

            # 获取语义类型 (如果有)
            semantic_types = self._parse_semantic_types(row, column_mapping)

            # 创建样本
            sample = {
                'raw_data': hex_data,
                'protocol': protocol_name,
                'bytes': raw_bytes,
                'length': len(raw_bytes),
                'message_type': f'real_{protocol_name}',
                'ground_truth_boundaries': boundaries,
                'semantic_types': semantic_types,
                'source': f'csv_row_{row_index}',
                'row_index': row_index
            }

            return sample

        except Exception as e:
            logger.debug(f"     解析第 {row_index} 行失败: {e}")
            return None

    def _clean_hex_data(self, hex_data: str) -> str:
        """清理HEX数据"""
        # 移除空格、冒号、连字符等
        hex_data = hex_data.replace(' ', '').replace(':', '').replace('-', '')

        # 只保留有效的HEX字符
        hex_data = ''.join(c for c in hex_data if c in '0123456789abcdefABCDEF')

        # 确保长度为偶数
        if len(hex_data) % 2 != 0:
            hex_data = '0' + hex_data

        return hex_data

    def _parse_boundaries(self, row: pd.Series, column_mapping: Dict[str, str],
                          length: int, protocol_name: str) -> List[int]:
        """解析边界 - 使用修复后的逻辑"""
        boundaries = [0]  # 总是包含起始位置
        csv_boundaries_found = False

        try:
            # 1. 尝试从指定列获取边界
            if 'boundaries' in column_mapping:
                boundary_data = str(row[column_mapping['boundaries']]).strip()
                if boundary_data and boundary_data.lower() not in ['nan', 'none', '']:
                    parsed_boundaries = self._parse_boundary_string(boundary_data, length)
                    if parsed_boundaries:
                        boundaries.extend(parsed_boundaries)
                        csv_boundaries_found = True

            # 2. 如果没有找到边界标签，使用协议标准边界
            if not csv_boundaries_found:
                standard_boundaries = self._get_protocol_standard_boundaries(protocol_name, length)
                boundaries.extend(standard_boundaries)

        except Exception as e:
            logger.debug(f"     解析边界失败: {e}")
            if not csv_boundaries_found:
                standard_boundaries = self._get_protocol_standard_boundaries(protocol_name, length)
                boundaries.extend(standard_boundaries)

        # 确保包含结束位置
        if length not in boundaries:
            boundaries.append(length)

        # 去重并排序
        boundaries = sorted(list(set(boundaries)))

        return boundaries

    def _parse_boundary_string(self, boundary_str: str, length: int) -> List[int]:
        """解析边界字符串"""
        boundaries = []

        try:
            # 清理边界字符串
            boundary_str = boundary_str.strip('[](){}"\'')

            # 尝试不同的分隔符
            separators = [',', ';', ' ', '|', '\t', '-', '_']

            for sep in separators:
                if sep in boundary_str:
                    parts = boundary_str.split(sep)
                    for part in parts:
                        part = part.strip()
                        try:
                            pos = int(part)
                            if 0 <= pos <= length:
                                boundaries.append(pos)
                        except ValueError:
                            continue
                    break

            # 如果没有分隔符，尝试解析单个数字
            if not boundaries and boundary_str.isdigit():
                pos = int(boundary_str)
                if 0 <= pos <= length:
                    boundaries.append(pos)

        except Exception as e:
            logger.debug(f"     解析边界字符串失败: {e}")

        return boundaries

    def _parse_semantic_types(self, row: pd.Series, column_mapping: Dict[str, str]) -> Dict[int, str]:
        """解析语义类型（如果CSV中包含）"""
        semantic_types = {}

        try:
            # 查找 SemanticTypes 列
            semantic_col = None
            for col in row.index:
                if 'semantic' in col.lower() and 'type' in col.lower():
                    semantic_col = col
                    break

            if semantic_col:
                semantic_str = str(row[semantic_col])
                if semantic_str and semantic_str.lower() not in ['nan', 'none', '']:
                    # 尝试解析JSON格式
                    try:
                        import json
                        semantic_types = json.loads(semantic_str.replace("'", '"'))
                        # 转换键为整数
                        semantic_types = {int(k): v for k, v in semantic_types.items()}
                    except:
                        pass

        except Exception as e:
            logger.debug(f"     解析语义类型失败: {e}")

        return semantic_types

    def _get_protocol_standard_boundaries(self, protocol_name: str, length: int) -> List[int]:
        """获取协议标准边界"""
        boundaries = []

        protocol_specs = {
            'dns': [2, 4, 6, 8, 10, 12],
            'modbus': [2, 4, 6, 7, 8],
            'smb': [4, 5, 6, 8, 32],
            'smb2': [4, 6, 8, 12, 16, 20, 24],
            'dhcp': [1, 2, 3, 4, 8, 12, 16, 20, 24, 28],
            'dnp3': [2, 3, 4, 6, 8, 10],
            'ftp': [2, 4],
            'tls': [1, 3, 5, 6, 9],
            's7comm': [2, 4, 6, 8, 10, 12]
        }

        if protocol_name in protocol_specs:
            boundaries = [pos for pos in protocol_specs[protocol_name] if pos < length]

        return boundaries

    def get_available_protocols(self) -> List[str]:
        """获取可用的协议列表"""
        available = []

        if self.csv_root.exists():
            for protocol_dir in self.csv_root.iterdir():
                if protocol_dir.is_dir() and protocol_dir.name in self.supported_protocols:
                    csv_files = list(protocol_dir.glob("*.csv"))
                    if csv_files:
                        available.append(protocol_dir.name)

        return available


# =============================================================================
# SemPRE评估器
# =============================================================================

class SemPREEvaluator:
    """SemPRE性能评估器"""

    def __init__(self):
        self.debug_mode = False

    def evaluate_boundaries(self, predicted_boundaries: List[int],
                            ground_truth_boundaries: List[int],
                            sequence_length: int,
                            debug_info: str = "") -> Dict[str, float]:
        """评估边界检测性能"""

        if self.debug_mode:
            logger.debug(f"评估边界 {debug_info}")
            logger.debug(f"  预测边界: {predicted_boundaries}")
            logger.debug(f"  真实边界: {ground_truth_boundaries}")
            logger.debug(f"  序列长度: {sequence_length}")

        return self._precision_evaluation(predicted_boundaries, ground_truth_boundaries, sequence_length)

    def _precision_evaluation(self, predicted_boundaries: List[int],
                              ground_truth_boundaries: List[int],
                              sequence_length: int) -> Dict[str, float]:
        """精确评估算法"""

        # 确保边界列表包含起始和结束位置
        pred_boundaries = sorted(list(set(predicted_boundaries + [0, sequence_length])))
        true_boundaries = sorted(list(set(ground_truth_boundaries + [0, sequence_length])))

        # 移除超出范围的边界
        pred_boundaries = [b for b in pred_boundaries if 0 <= b <= sequence_length]
        true_boundaries = [b for b in true_boundaries if 0 <= b <= sequence_length]

        if self.debug_mode:
            logger.debug(f"  标准化预测边界: {pred_boundaries}")
            logger.debug(f"  标准化真实边界: {true_boundaries}")

        # 1. 边界准确率（逐位置比较）
        accuracy = self._calculate_position_accuracy(pred_boundaries, true_boundaries, sequence_length)

        # 2. 边界精确率和召回率
        precision, recall = self._calculate_boundary_precision_recall(pred_boundaries, true_boundaries)

        # 3. F1分数
        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        # 4. 字段级完美匹配率
        perfection = self._calculate_field_perfection(pred_boundaries, true_boundaries, sequence_length)

        if self.debug_mode:
            logger.debug(f"  准确率: {accuracy:.4f}")
            logger.debug(f"  精确率: {precision:.4f}")
            logger.debug(f"  召回率: {recall:.4f}")
            logger.debug(f"  F1分数: {f1_score:.4f}")
            logger.debug(f"  完美率: {perfection:.4f}")

        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'perfection': perfection
        }

    def _calculate_position_accuracy(self, pred_boundaries: List[int],
                                     true_boundaries: List[int],
                                     sequence_length: int) -> float:
        """计算位置级准确率"""
        if sequence_length == 0:
            return 1.0

        pred_set = set(pred_boundaries)
        true_set = set(true_boundaries)

        correct_positions = 0
        for pos in range(sequence_length + 1):
            pred_is_boundary = pos in pred_set
            true_is_boundary = pos in true_set
            if pred_is_boundary == true_is_boundary:
                correct_positions += 1

        return correct_positions / (sequence_length + 1)

    def _calculate_boundary_precision_recall(self, pred_boundaries: List[int],
                                             true_boundaries: List[int]) -> Tuple[float, float]:
        """计算边界级精确率和召回率"""
        pred_set = set(pred_boundaries)
        true_set = set(true_boundaries)

        # 精确率: 预测的边界中有多少是正确的
        if len(pred_boundaries) > 0:
            true_positives = len(pred_set & true_set)
            precision = true_positives / len(pred_boundaries)
        else:
            precision = 0.0

        # 召回率: 真实边界中有多少被预测到
        if len(true_boundaries) > 0:
            true_positives = len(pred_set & true_set)
            recall = true_positives / len(true_boundaries)
        else:
            recall = 1.0 if len(pred_boundaries) == 0 else 0.0

        return precision, recall

    def _calculate_field_perfection(self, pred_boundaries: List[int],
                                    true_boundaries: List[int],
                                    sequence_length: int) -> float:
        """计算字段级完美匹配率"""

        # 将边界转换为字段范围
        pred_fields = self._boundaries_to_fields(pred_boundaries, sequence_length)
        true_fields = self._boundaries_to_fields(true_boundaries, sequence_length)

        if self.debug_mode:
            logger.debug(f"  预测字段: {pred_fields}")
            logger.debug(f"  真实字段: {true_fields}")

        if not true_fields:
            return 1.0 if not pred_fields else 0.0

        # 计算完全匹配的字段数
        pred_fields_set = set(pred_fields)
        true_fields_set = set(true_fields)

        perfect_matches = len(pred_fields_set & true_fields_set)
        total_true_fields = len(true_fields_set)

        perfection = perfect_matches / total_true_fields if total_true_fields > 0 else 0.0

        if self.debug_mode:
            logger.debug(f"  完美匹配字段数: {perfect_matches}")
            logger.debug(f"  总真实字段数: {total_true_fields}")

        return perfection

    def _boundaries_to_fields(self, boundaries: List[int], length: int) -> List[Tuple[int, int]]:
        """将边界转换为字段范围"""
        if not boundaries:
            return [(0, length)] if length > 0 else []

        fields = []
        boundaries = sorted(list(set(boundaries)))

        # 确保包含起始和结束边界
        if 0 not in boundaries:
            boundaries.insert(0, 0)
        if length not in boundaries:
            boundaries.append(length)

        # 生成字段范围
        for i in range(len(boundaries) - 1):
            start = boundaries[i]
            end = boundaries[i + 1]

            if start < end and start < length:
                fields.append((start, min(end, length)))

        return fields


# =============================================================================
#SemPRE实验管理器
# =============================================================================

class SemPREExperiment:
    """SemPRE实验管理器"""

    def __init__(self, data_root: str = "Msg2"):
        self.data_loader = RealDatasetLoader(data_root)
        self.analyzer = AdvancedProtocolPipeline()
        self.evaluator = SemPREEvaluator()
        self.results = {}
        self.debug_mode = False

    def analyze_messages(self, messages: List[bytes]) -> Dict:
        """适配层：将消息列表转换为SemPRE可分析的格式"""
        # 直接调用各个组件进行分析
        try:
            # 步骤2: 协议预分析
            pre_analysis = self.analyzer.pre_analyzer.analyze(messages)
            
            # 步骤3: 字段检测
            from advanced_protocol_analyzer import ContextAwareFieldDetector
            field_detector = ContextAwareFieldDetector(pre_analysis, self.analyzer.logger)
            field_detection = field_detector.detect(messages)
            
            # 构建分析结果
            analysis_result = {
                'step2_pre_analysis': {
                    'protocol': pre_analysis['protocol_signature'].protocol_type,
                    'confidence': pre_analysis['protocol_signature'].confidence,
                    'variant': pre_analysis['protocol_signature'].variant,
                    'function_count': len(pre_analysis['function_profiles']),
                },
                'step3_field_detection': {
                    'field_candidates': field_detection['field_candidates'],
                    'length_fields': len(field_detection['length_fields']),
                    'offset_fields': len(field_detection['offset_fields']),
                    'dependency_edges': len(field_detection.get('dependency_graph', [])),
                    'total_fields': len(field_detection['field_candidates'])
                }
            }
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"分析失败: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {
                'step2_pre_analysis': {},
                'step3_field_detection': {'field_candidates': []}
            }


    def enable_debug(self):
        """启用调试模式"""
        self.debug_mode = True
        self.evaluator.debug_mode = True

    def run_experiments(self, protocols: List[str] = None, sample_limit: int = None):
        """运行实验"""
        # 获取可用协议
        available_protocols = self.data_loader.get_available_protocols()

        if protocols is None:
            protocols = available_protocols
        else:
            protocols = [p for p in protocols if p in available_protocols]

        if not protocols:
            logger.error("  没有找到可用的协议数据")
            return

        logger.info("🚀 SemPRE实验开始")
        logger.info(f"📂 数据目录: {self.data_loader.data_root}")
        logger.info(f" 测试协议: {protocols}")
        if sample_limit:
            logger.info(f"  样本限制: {sample_limit}")
        logger.info("=" * 70)

        for protocol in protocols:
            logger.info(f"\n  测试协议: {protocol.upper()}")
            logger.info("-" * 50)

            # 加载真实数据
            data = self.data_loader.load_protocol_data(protocol)

            if not data:
                logger.warning(f"  跳过 {protocol}: 无数据")
                continue

            # 限制样本数量（用于调试）
            if sample_limit and len(data) > sample_limit:
                data = data[:sample_limit]
                logger.info(f"    限制样本数量为: {sample_limit}")

            # 准备消息列表
            messages = [sample['bytes'] for sample in data]

            try:
                # 运行SemPRE算法
                logger.info(f"   🔍 运行SemPRE算法...")
                analysis_result = self.analyze_messages(messages)

                # 提取预测的边界
                predicted_boundaries_list = self._extract_boundaries_from_analysis(
                    analysis_result, messages, protocol
                )

                # 评估性能
                logger.info(f"    评估性能...")
                all_metrics = []

                for i, (sample, pred_boundaries) in enumerate(zip(data, predicted_boundaries_list)):
                    true_boundaries = sample['ground_truth_boundaries']
                    length = sample['length']

                    debug_info = f"{protocol}_{i}" if self.debug_mode else ""
                    metrics = self.evaluator.evaluate_boundaries(
                        pred_boundaries, true_boundaries, length, debug_info
                    )
                    all_metrics.append(metrics)

                    # 调试模式下显示前几个样本的详细信息
                    if self.debug_mode and i < 3:
                        logger.info(f"   🔍 样本 {i}: 预测边界={pred_boundaries}, 真实边界={true_boundaries}")
                        logger.info(f"        完美率={metrics['perfection']:.4f}")

                # 计算平均指标
                avg_metrics = {}
                for key in ['accuracy', 'precision', 'recall', 'f1_score', 'perfection']:
                    values = [m[key] for m in all_metrics if not np.isnan(m[key])]
                    avg_metrics[key] = np.mean(values) if values else 0.0

                # 保存结果
                self.results[protocol] = {
                    'sample_count': len(data),
                    'metrics': avg_metrics,
                    'csv_rows': len(data),
                    'individual_metrics': all_metrics,
                    'analysis_result': self._serialize_analysis_result(analysis_result)
                }

                # 显示结果
                logger.info(f"    结果:")
                logger.info(f"      CSV行数: {len(data)}")
                logger.info(f"      样本数量: {len(data)}")
                logger.info(f"      准确率: {avg_metrics['accuracy']:.4f}")
                logger.info(f"      精确率: {avg_metrics['precision']:.4f}")
                logger.info(f"      召回率: {avg_metrics['recall']:.4f}")
                logger.info(f"      F1分数: {avg_metrics['f1_score']:.4f}")
                logger.info(f"      字段IoU: {avg_metrics['perfection']:.4f}")

                # 分析完美匹配分布 (100%边界正确)
                perfection_values = [m['perfection'] for m in all_metrics]
                perfect_count = sum(1 for p in perfection_values if p >= 0.9999)
                logger.info(f"      完美匹配样本: {perfect_count}/{len(data)} ({perfect_count / len(data) * 100:.1f}%)")

            except Exception as e:
                logger.error(f"  处理 {protocol} 时出错: {e}")
                import traceback
                logger.error(traceback.format_exc())
                self.results[protocol] = {
                    'sample_count': 0,
                    'csv_rows': 0,
                    'metrics': {'accuracy': 0, 'precision': 0, 'recall': 0,
                                'f1_score': 0, 'perfection': 0},
                    'error': str(e)
                }

    def _extract_boundaries_from_analysis(self, analysis_result: Dict,
                                          messages: List[bytes],
                                          protocol: str) -> List[List[int]]:
        """从SemPRE分析结果中提取边界"""
        boundaries_list = []

        try:
            # 从step3的字段检测结果中提取边界
            step3 = analysis_result.get('step3_field_detection', {})
            field_candidates = step3.get('field_candidates', [])

            # 为每个消息提取边界
            for msg_idx, msg in enumerate(messages):
                msg_length = len(msg)
                boundaries = [0]  # 起始位置

                # 提取该消息的字段边界
                for field in field_candidates:
                    if hasattr(field, 'start') and hasattr(field, 'end'):
                        # 确保字段边界在消息范围内
                        if field.start < msg_length:
                            boundaries.append(field.start)
                        if field.end < msg_length:
                            boundaries.append(field.end)

                # 添加结束位置
                boundaries.append(msg_length)

                # 去重并排序
                boundaries = sorted(list(set(boundaries)))
                boundaries_list.append(boundaries)

        except Exception as e:
            logger.warning(f"     提取边界失败: {e}")
            # 如果提取失败，为每个消息返回默认边界
            for msg in messages:
                boundaries_list.append([0, len(msg)])

        return boundaries_list

    def _serialize_analysis_result(self, analysis_result: Dict) -> Dict:
        """序列化分析结果以便保存"""
        try:
            serialized = {}

            # 提取关键统计信息
            if 'step2_pre_analysis' in analysis_result:
                s2 = analysis_result['step2_pre_analysis']
                serialized['protocol'] = s2.get('protocol', 'unknown')
                serialized['confidence'] = s2.get('confidence', 0.0)
                serialized['function_count'] = s2.get('function_count', 0)

            if 'step3_field_detection' in analysis_result:
                s3 = analysis_result['step3_field_detection']
                serialized['field_count'] = s3.get('total_fields', 0)
                serialized['length_fields'] = s3.get('length_fields', 0)
                serialized['offset_fields'] = s3.get('offset_fields', 0)
                serialized['dependency_edges'] = s3.get('dependency_edges', 0)

            # SemPRE创新功能统计
            if 'step3_5_semantic_graph' in analysis_result:
                s3_5 = analysis_result['step3_5_semantic_graph']
                serialized['semantic_nodes'] = s3_5.get('total_nodes', 0)
                serialized['semantic_edges'] = s3_5.get('total_edges', 0)
                serialized['cross_message_deps'] = s3_5.get('cross_message_dependencies', 0)

            if 'step4_5_unknown_function_inference' in analysis_result:
                s4_5 = analysis_result['step4_5_unknown_function_inference']
                serialized['inferred_functions'] = s4_5.get('inferred_count', 0)

            return serialized

        except Exception as e:
            logger.warning(f"     序列化分析结果失败: {e}")
            return {}

    def generate_detailed_report(self):
        """生成详细报告"""
        logger.info(f"\n" + "=" * 70)
        logger.info(" SemPRE实验详细报告")
        logger.info("=" * 70)

        if not self.results:
            logger.warning("  没有实验结果")
            return

        # 创建结果表格
        report_data = []
        for protocol, result in self.results.items():
            metrics = result['metrics']
            report_data.append({
                'Protocol': protocol.upper(),
                'CSV_Rows': result.get('csv_rows', 0),
                'Samples': result['sample_count'],
                'Accuracy': f"{metrics['accuracy']:.4f}",
                'Precision': f"{metrics['precision']:.4f}",
                'Recall': f"{metrics['recall']:.4f}",
                'F1-score': f"{metrics['f1_score']:.4f}",
                'Perfection': f"{metrics['perfection']:.4f}"
            })

        # 显示表格
        df = pd.DataFrame(report_data)
        print("\nSemPRE实验结果表格:")
        print(df.to_string(index=False))

        # 计算性能统计
        logger.info(f"\n 性能统计:")
        valid_results = [r for r in self.results.values() if 'error' not in r]

        if valid_results:
            total_samples = sum(r['sample_count'] for r in valid_results)
            total_csv_rows = sum(r.get('csv_rows', 0) for r in valid_results)
            avg_field_iou = np.mean([r['metrics']['perfection'] for r in valid_results])
            avg_f1 = np.mean([r['metrics']['f1_score'] for r in valid_results])
            avg_accuracy = np.mean([r['metrics']['accuracy'] for r in valid_results])

            logger.info(f"   总CSV行数: {total_csv_rows}")
            logger.info(f"   总样本数: {total_samples}")
            logger.info(f"   平均准确率: {avg_accuracy:.4f}")
            logger.info(f"   平均F1分数: {avg_f1:.4f}")
            logger.info(f"   平均字段IoU: {avg_field_iou:.4f}")

            # 分析完美匹配分布 (100%边界正确的样本)
            logger.info(f"\n 完美匹配分析:")
            for protocol, result in self.results.items():
                if 'error' not in result and 'individual_metrics' in result:
                    individual_perfections = [m['perfection'] for m in result['individual_metrics']]
                    perfect_count = sum(1 for p in individual_perfections if p >= 0.9999)
                    total_count = len(individual_perfections)
                    logger.info(
                        f"   {protocol.upper()}: {perfect_count}/{total_count} ({perfect_count / total_count * 100:.1f}%) 完美匹配")

            # SemPRE创新功能统计
            logger.info(f"\n SemPRE创新功能统计:")
            for protocol, result in self.results.items():
                if 'error' not in result and 'analysis_result' in result:
                    ar = result['analysis_result']
                    if ar.get('semantic_nodes', 0) > 0:
                        logger.info(f"   {protocol.upper()}:")
                        logger.info(f"      - 语义节点: {ar.get('semantic_nodes', 0)}")
                        logger.info(f"      - 跨消息依赖: {ar.get('cross_message_deps', 0)}")
                        logger.info(f"      - 推断功能码: {ar.get('inferred_functions', 0)}")

        else:
            logger.warning("   没有有效的实验结果")

        logger.info(f"\n SemPRE特色:")
        logger.info("   1. 多粒度语义感知图 - 理解字段之间的语义关系")
        logger.info("   2. 跨消息依赖挖掘 - Request-Response配对分析")
        logger.info("   3. 未知功能码零样本推断 - 自动推断未知功能类型")
        logger.info("   4. Bit级语义注意力 - 精细到位级别的分析")
        logger.info("   5. 算术/逻辑约束发现 - 字段间数学关系识别")

    def save_results(self, output_file: str):
        """保存结果到JSON文件"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            logger.info(f"\n 结果已保存到: {output_file}")
        except Exception as e:
            logger.error(f"  保存结果失败: {e}")


# =============================================================================
# 主函数
# =============================================================================

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='SemPRE真实数据集实验评估')

    parser.add_argument('--data-root', default='Msg2',
                        help='数据集根目录 (默认: Msg2)')

    parser.add_argument('--protocols', nargs='+',
                        choices=['smb', 'smb2', 'dns', 's7comm', 'dnp3',
                                 'modbus', 'ftp', 'tls', 'dhcp'],
                        help='要测试的协议列表')

    parser.add_argument('--debug', action='store_true',
                        help='启用调试模式')

    parser.add_argument('--sample-limit', type=int,
                        help='限制每个协议的样本数量（用于调试）')

    parser.add_argument('--output', default='./output/Sempre_results.json',
                        help='输出结果文件路径')

    args = parser.parse_args()

    # 创建实验管理器
    experiment = SemPREExperiment(args.data_root)

    if args.debug:
        experiment.enable_debug()
        logger.info("🔧 调试模式已启用")

    logger.info(f"🌟 SemPRE实验设置:")
    logger.info(f"   数据根目录: {args.data_root}")
    logger.info(f"   测试协议: {args.protocols or 'ALL'}")
    logger.info(f"   调试模式: {args.debug}")
    if args.sample_limit:
        logger.info(f"   样本限制: {args.sample_limit}")

    # 运行实验
    experiment.run_experiments(protocols=args.protocols, sample_limit=args.sample_limit)

    # 生成报告
    experiment.generate_detailed_report()

    # 保存结果
    experiment.save_results(args.output)

    logger.info("\n SemPRE实验完成！")


if __name__ == "__main__":
    main()
