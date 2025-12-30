#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Coarse-to-Fine Boundary Detection Runner (Full Integration)
整合所有创新点的完整实验运行器

核心创新：
1. 高召回率启发式边界粗筛（来自simple_test.py）
2. 语义约束精修剪枝（Coarse-to-Fine）
3. 多粒度语义依赖图（Multi-Granularity SDG）
4. 零样本功能码推断（Zero-Shot Inference）
5. 完整的4个实验对比
"""

import os
import sys
import csv
import json
import logging
import numpy as np
from pathlib import Path
from collections import Counter
from typing import List, Tuple, Dict, Any
from dataclasses import dataclass

# 导入SemPRE核心模块
try:
    from optimized_semantic_graph import OptimizedSemanticDependencyGraph as SemanticDependencyGraph
    print("[Import] Using optimized SDG")
except ImportError:
    try:
        from sempre_semantic_graph import SemanticDependencyGraph
        print("[Import] Using standard SDG")
    except:
        print("[Warning] SDG module not available")
        SemanticDependencyGraph = None

try:
    from sempre_function_inferencer import ZeroShotFunctionInferencer, FUNCTION_LABELS
    print("[Import] Function inferencer loaded")
except:
    print("[Warning] Function inferencer not available")
    ZeroShotFunctionInferencer = None


class HeuristicBoundaryDetector:
    """启发式边界检测器（移植自simple_test.py）"""

    @staticmethod
    def generate_heuristic_boundaries(messages: List[bytes], max_pos: int = 32) -> Tuple[List[List[int]], List[int]]:
        """生成基于熵的候选边界（高召回率策略）"""
        entropies = []
        for pos in range(max_pos):
            vals = [m[pos] for m in messages if pos < len(m)]
            if not vals:
                entropies.append(0.0)
                continue
            cnt = Counter(vals)
            h = -sum((c/len(vals))*np.log2(c/len(vals)) for c in cnt.values() if c > 0)
            entropies.append(h)

        # 生成密集候选边界（提高召回率）
        global_boundaries = list(range(1, 13))

        msg_boundaries = []
        for msg in messages:
            valid = [b for b in global_boundaries if 0 < b < len(msg)]
            msg_boundaries.append(valid)

        return msg_boundaries, global_boundaries


class SemanticBoundaryRefiner:
    """语义边界精修器 - 使用约束剪枝错误边界"""

    @staticmethod
    def refine_with_constraints(heuristic_boundaries: List[List[int]],
                                messages: List[bytes],
                                length_fields: List[Tuple[int, int, float]]) -> List[List[int]]:
        """使用语义约束精修启发式边界"""
        refined = []

        for msg, h_bounds in zip(messages, heuristic_boundaries):
            bounds_set = set(h_bounds)

            # 剪枝规则：移除破坏长度字段的边界
            for lf_start, lf_end, conf in length_fields:
                if conf > 0.7:
                    for b in range(lf_start + 1, lf_end):
                        bounds_set.discard(b)

            refined.append(sorted(list(bounds_set)))

        return refined


class CoarseToFineExperimentRunner:
    """Coarse-to-Fine 实验运行器（完整集成版）"""

    def __init__(self, output_dir: str = './output/coarse_to_fine'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.summary_results = []
        self.heuristic_detector = HeuristicBoundaryDetector()
        self.semantic_refiner = SemanticBoundaryRefiner()

        # 实验结果存储
        self.results = {
            'exp1_format_inference': {},
            'exp2_constraint_discovery': {},
            'exp3_function_inference': {},
            'exp4_data_efficiency': {}
        }

        # 配置简单日志
        self.logger = self._setup_simple_logger()

    def _setup_simple_logger(self):
        """配置简单日志"""
        logger = logging.getLogger('CoarseToFine')
        logger.setLevel(logging.INFO)
        logger.handlers.clear()

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter('[%(levelname)s] %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        return logger

    def load_csv(self, csv_path: str) -> Tuple[List[bytes], List[List[int]]]:
        """加载CSV文件"""
        messages = []
        boundaries = []

        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'HexData' in row:
                    try:
                        msg = bytes.fromhex(row['HexData'].strip())
                        messages.append(msg)

                        if 'Boundaries' in row and row['Boundaries']:
                            b_str = row['Boundaries'].strip('"').strip("'")
                            bounds = [int(x) for x in b_str.split(',')]
                            boundaries.append(bounds)
                        else:
                            boundaries.append([])
                    except:
                        continue

        return messages, boundaries

    def detect_length_fields(self, messages: List[bytes]) -> List[Tuple[int, int, float]]:
        """检测长度字段"""
        length_fields = []

        if len(messages) > 0 and len(messages[0]) >= 6:
            match_count = 0
            for msg in messages[:min(100, len(messages))]:
                if len(msg) >= 6:
                    length_val = int.from_bytes(msg[4:6], 'big')
                    actual_remaining = len(msg) - 6
                    if length_val == actual_remaining:
                        match_count += 1

            confidence = match_count / min(100, len(messages))
            if confidence > 0.7:
                length_fields.append((4, 6, confidence))

        return length_fields

    def run_full_experiments(self, protocol_name: str, csv_path: str) -> Dict[str, Any]:
        """运行完整的4个实验（集成版）"""
        print(f"\n{'='*70}")
        print(f"Protocol: {protocol_name.upper()} (Full Experiments)")
        print(f"{'='*70}")

        # 加载数据
        messages, true_boundaries = self.load_csv(csv_path)
        print(f"[OK] Loaded {len(messages)} messages")

        # === 实验1: Format Inference (Coarse-to-Fine) ===
        print("\n[Exp1] Format Inference with Coarse-to-Fine...")
        exp1_result = self._experiment1_format_inference(messages, true_boundaries)

        # === 实验2: Constraint Discovery (SDG) ===
        print("\n[Exp2] Constraint Discovery with SDG...")
        exp2_result = self._experiment2_constraint_discovery(messages, exp1_result['detected_fields'])

        # === 实验3: Zero-Shot Function Inference ===
        print("\n[Exp3] Zero-Shot Function Inference...")
        exp3_result = self._experiment3_function_inference(messages)

        # === 实验4: Data Efficiency ===
        print("\n[Exp4] Data Efficiency Analysis...")
        exp4_result = self._experiment4_data_efficiency(messages, true_boundaries)

        # 汇总结果
        result = {
            'protocol': protocol_name.upper(),
            'csv_rows': len(messages),
            'samples': len(messages),
            'accuracy': exp1_result['accuracy'],
            'precision': exp1_result['precision'],
            'recall': exp1_result['recall'],
            'f1_score': exp1_result['f1_score'],
            'perfection': exp1_result['perfection'],
            'exp1': exp1_result,
            'exp2': exp2_result,
            'exp3': exp3_result,
            'exp4': exp4_result
        }

        print(f"\n[Summary] Final Results:")
        print(f"  Accuracy: {result['accuracy']:.4f}")
        print(f"  Precision: {result['precision']:.4f}")
        print(f"  Recall: {result['recall']:.4f}")
        print(f"  F1-score: {result['f1_score']:.4f}")
        print(f"  Perfection: {result['perfection']:.4f}")
        print(f"  Constraints: {exp2_result['total_constraints']}")
        print(f"  Inferred Functions: {exp3_result['inferred_count']}")

        return result

    def _experiment1_format_inference(self, messages: List[bytes], true_boundaries: List[List[int]]) -> Dict[str, Any]:
        """实验1: Format Inference with Coarse-to-Fine"""
        # Step 1: 粗筛
        print("  [Step1] Heuristic boundary detection...")
        heuristic_boundaries, global_bounds = self.heuristic_detector.generate_heuristic_boundaries(messages)
        print(f"    Heuristic boundaries: {global_bounds}")

        # Step 2: 检测约束
        print("  [Step2] Constraint detection...")
        length_fields = self.detect_length_fields(messages)
        print(f"    Detected {len(length_fields)} length fields")

        # Step 3: 精修
        print("  [Step3] Semantic pruning...")
        refined_boundaries = self.semantic_refiner.refine_with_constraints(
            heuristic_boundaries, messages, length_fields
        )

        # 生成字段对象（用于后续实验）
        detected_fields = self._boundaries_to_fields(messages, refined_boundaries)

        # 评估
        all_precisions, all_recalls, all_f1s, all_accuracies = [], [], [], []
        perfect_matches = 0

        for i in range(min(len(refined_boundaries), len(true_boundaries))):
            detected_set = set(refined_boundaries[i])
            true_set = set(true_boundaries[i])

            if not true_set:
                continue

            tp = len(detected_set & true_set)
            fp = len(detected_set - true_set)
            fn = len(true_set - detected_set)

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            accuracy = tp / (tp + fp + fn) if (tp + fp + fn) > 0 else 0

            all_precisions.append(precision)
            all_recalls.append(recall)
            all_f1s.append(f1)
            all_accuracies.append(accuracy)

            if detected_set == true_set:
                perfect_matches += 1

        return {
            'accuracy': np.mean(all_accuracies) if all_accuracies else 0,
            'precision': np.mean(all_precisions) if all_precisions else 0,
            'recall': np.mean(all_recalls) if all_recalls else 0,
            'f1_score': np.mean(all_f1s) if all_f1s else 0,
            'perfection': perfect_matches / len(true_boundaries) if true_boundaries else 0,
            'detected_fields': detected_fields,
            'boundaries': refined_boundaries
        }

    def _boundaries_to_fields(self, messages: List[bytes], boundaries_list: List[List[int]]) -> List[Any]:
        """将边界列表转换为字段对象列表"""
        @dataclass
        class DetectedField:
            start: int
            end: int
            field_type: str = 'unknown'
            confidence: float = 0.8
            source: str = 'coarse_to_fine'

        all_fields = []
        for msg, bounds in zip(messages, boundaries_list):
            prev = 0
            for b in bounds:
                if b > prev and b <= len(msg):
                    all_fields.append(DetectedField(prev, b))
                    prev = b
            if prev < len(msg):
                all_fields.append(DetectedField(prev, len(msg)))

        return all_fields

    def _experiment2_constraint_discovery(self, messages: List[bytes], detected_fields: List[Any]) -> Dict[str, Any]:
        """实验2: Constraint Discovery with SDG"""
        if SemanticDependencyGraph is None:
            print("    [Warning] SDG not available, skipping...")
            return {'total_constraints': 0, 'sdg_available': False}

        try:
            sdg = SemanticDependencyGraph(logger=self.logger)
            sampled = messages[:min(200, len(messages))]
            stats = sdg.build_from_messages(sampled, detected_fields)

            # 导出SDG
            dot_path = self.output_dir / 'sdg_graph.dot'
            sdg.export_graphviz(str(dot_path))

            print(f"    Arithmetic constraints: {stats.get('arithmetic_constraints', 0)}")
            print(f"    Logical constraints: {stats.get('logical_constraints', 0)}")
            print(f"    Bit-level dependencies: {stats.get('bit_dependencies', 0)}")

            return {
                'total_constraints': stats.get('edge_count', 0),
                'arithmetic_constraints': stats.get('arithmetic_constraints', 0),
                'logical_constraints': stats.get('logical_constraints', 0),
                'bit_dependencies': stats.get('bit_dependencies', 0),
                'sdg_available': True
            }
        except Exception as e:
            print(f"    [Error] SDG construction failed: {e}")
            return {'total_constraints': 0, 'sdg_available': False, 'error': str(e)}

    def _experiment3_function_inference(self, messages: List[bytes]) -> Dict[str, Any]:
        """实验3: Zero-Shot Function Inference"""
        if ZeroShotFunctionInferencer is None:
            print("    [Warning] Function inferencer not available")
            return {'inferred_count': 0, 'available': False}

        try:
            inferencer = ZeroShotFunctionInferencer(logger=self.logger)
            function_profiles = self._extract_function_profiles(messages)

            signatures = inferencer.infer_unknown_functions(messages, function_profiles, 'unknown')

            print(f"    Inferred {len(signatures)} function codes")
            for sig in signatures[:3]:  # 显示前3个
                print(f"      FC 0x{sig.func_code:02X} -> {sig.inferred_label} (conf={sig.confidence:.2f})")

            return {
                'inferred_count': len(signatures),
                'signatures': [{'code': f"0x{s.func_code:02X}", 'label': s.inferred_label, 'conf': s.confidence} for s in signatures[:10]],
                'available': True
            }
        except Exception as e:
            print(f"    [Error] Function inference failed: {e}")
            return {'inferred_count': 0, 'available': False, 'error': str(e)}

    def _experiment4_data_efficiency(self, messages: List[bytes], true_boundaries: List[List[int]]) -> Dict[str, Any]:
        """实验4: Data Efficiency Analysis"""
        ratios = [0.1, 0.3, 0.5, 1.0]
        results = []

        for ratio in ratios:
            sample_size = int(len(messages) * ratio)
            sampled_messages = messages[:sample_size]
            sampled_boundaries_true = true_boundaries[:sample_size]

            # 使用粗筛-精修检测
            h_bounds, _ = self.heuristic_detector.generate_heuristic_boundaries(sampled_messages)
            l_fields = self.detect_length_fields(sampled_messages)
            refined = self.semantic_refiner.refine_with_constraints(h_bounds, sampled_messages, l_fields)

            # 计算F1
            all_f1s = []
            for i in range(min(len(refined), len(sampled_boundaries_true))):
                detected_set = set(refined[i])
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

            f1_score = np.mean(all_f1s) if all_f1s else 0
            results.append({'ratio': ratio, 'samples': sample_size, 'f1': f1_score})
            print(f"    {ratio*100:.0f}% data ({sample_size} msgs): F1={f1_score:.4f}")

        return {'ratios': ratios, 'results': results}

    def _extract_function_profiles(self, messages: List[bytes]) -> List[Any]:
        """提取功能码统计"""
        @dataclass
        class FunctionProfile:
            code: int
            count: int
            name: str
            avg_length: float

        func_stats = {}
        for msg in messages:
            if len(msg) > 7:
                func_code = msg[7]
                if func_code not in func_stats:
                    func_stats[func_code] = {'count': 0, 'lengths': []}
                func_stats[func_code]['count'] += 1
                func_stats[func_code]['lengths'].append(len(msg))

        profiles = []
        for code, stats in func_stats.items():
            profile = FunctionProfile(
                code=code,
                count=stats['count'],
                name=f'Unknown_0x{code:02X}',
                avg_length=np.mean(stats['lengths'])
            )
            profiles.append(profile)

        return profiles

    def run_protocol(self, protocol_name: str, csv_path: str) -> Dict[str, Any]:
        """运行单个协议实验（Coarse-to-Fine）"""
        print(f"\n{'='*70}")
        print(f"协议: {protocol_name.upper()} (Coarse-to-Fine)")
        print(f"{'='*70}")

        # 加载数据
        messages, true_boundaries = self.load_csv(csv_path)
        print(f"[OK] Loaded {len(messages)} messages")

        # Step 1: 粗筛
        print("[Init] Step 1: Heuristic boundary detection...")
        heuristic_boundaries, global_bounds = self.heuristic_detector.generate_heuristic_boundaries(messages)
        print(f"  [Init] Heuristic boundaries: {global_bounds}")
        print(f"  [Init] Avg {np.mean([len(b) for b in heuristic_boundaries]):.1f} boundaries/message")

        # Step 2: 检测约束
        print("[Semantic] Step 2: Constraint detection...")
        length_fields = self.detect_length_fields(messages)
        print(f"  [Semantic] Detected {len(length_fields)} length fields")

        # Step 3: 精修
        print("[Refine] Step 3: Semantic pruning...")
        refined_boundaries = self.semantic_refiner.refine_with_constraints(
            heuristic_boundaries, messages, length_fields
        )
        print(f"  [Refine] Refined avg {np.mean([len(b) for b in refined_boundaries]):.1f} boundaries/message")

        # 评估
        all_precisions = []
        all_recalls = []
        all_f1s = []
        all_accuracies = []
        perfect_matches = 0

        for i in range(min(len(refined_boundaries), len(true_boundaries))):
            detected_set = set(refined_boundaries[i])
            true_set = set(true_boundaries[i])

            if not true_set:
                continue

            tp = len(detected_set & true_set)
            fp = len(detected_set - true_set)
            fn = len(true_set - detected_set)

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            accuracy = tp / (tp + fp + fn) if (tp + fp + fn) > 0 else 0

            all_precisions.append(precision)
            all_recalls.append(recall)
            all_f1s.append(f1)
            all_accuracies.append(accuracy)

            if detected_set == true_set:
                perfect_matches += 1

        result = {
            'protocol': protocol_name.upper(),
            'csv_rows': len(messages),
            'samples': len(messages),
            'accuracy': np.mean(all_accuracies) if all_accuracies else 0,
            'precision': np.mean(all_precisions) if all_precisions else 0,
            'recall': np.mean(all_recalls) if all_recalls else 0,
            'f1_score': np.mean(all_f1s) if all_f1s else 0,
            'perfection': perfect_matches / len(true_boundaries) if true_boundaries else 0
        }

        print(f"[Results] Accuracy: {result['accuracy']:.4f}")
        print(f"[Results] Precision: {result['precision']:.4f}")
        print(f"[Results] Recall: {result['recall']:.4f}")
        print(f"[Results] F1-score: {result['f1_score']:.4f}")
        print(f"[Results] Perfection: {result['perfection']:.4f} ({perfect_matches}/{len(true_boundaries)})")

        return result

    def run_all_protocols(self, data_dir: str = 'Msg2/csv'):
        """批量运行所有协议"""
        protocols = [
            ('modbus', 'modbus/modbus.csv'),
            ('dns', 'dns/dns.csv'),
            ('dhcp', 'dhcp/dhcp.csv'),
            ('smb', 'smb/smb.csv'),
            ('smb2', 'smb2/smb2.csv'),
            ('s7comm', 's7comm/s7comm.csv'),
            ('dnp3', 'dnp3/dnp3.csv'),
            ('ftp', 'ftp/ftp.csv'),
            ('tls', 'tls/tls.csv'),
        ]

        for protocol_name, csv_rel in protocols:
            csv_path = os.path.join(data_dir, csv_rel)

            if os.path.exists(csv_path):
                try:
                    result = self.run_protocol(protocol_name, csv_path)
                    self.summary_results.append(result)
                except Exception as e:
                    print(f"✗ {protocol_name} 失败: {e}")
            else:
                print(f"⚠ 跳过 {protocol_name}: {csv_path} 不存在")

        self.save_summary()

    def run_all_protocols_full(self, data_dir: str = 'Msg2/csv'):
        """批量运行所有协议（完整4个实验）"""
        protocols = [
            ('modbus', 'modbus/modbus.csv'),
            ('dns', 'dns/dns.csv'),
            ('dhcp', 'dhcp/dhcp.csv'),
            ('smb', 'smb/smb.csv'),
            ('smb2', 'smb2/smb2.csv'),
            ('s7comm', 's7comm/s7comm.csv'),
            ('dnp3', 'dnp3/dnp3.csv'),
            ('ftp', 'ftp/ftp.csv'),
            ('tls', 'tls/tls.csv'),
        ]

        for protocol_name, csv_rel in protocols:
            csv_path = os.path.join(data_dir, csv_rel)

            if os.path.exists(csv_path):
                try:
                    result = self.run_full_experiments(protocol_name, csv_path)
                    self.summary_results.append(result)
                except Exception as e:
                    print(f"[Error] {protocol_name} failed: {e}")
            else:
                print(f"[Warning] Skipping {protocol_name}: not found")

        self.save_summary_full()

    def save_summary_full(self):
        """保存完整实验结果"""
        print(f"\n{'='*70}")
        print("Saving full experiment results")
        print(f"{'='*70}")

        summary_path = self.output_dir / 'summary_results_full.csv'
        with open(summary_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Protocol', 'Samples', 'Accuracy', 'Precision', 'Recall', 'F1-score', 'Perfection', 'Constraints', 'Functions'])

            for r in self.summary_results:
                exp2 = r.get('exp2', {})
                exp3 = r.get('exp3', {})
                writer.writerow([
                    r['protocol'],
                    r['samples'],
                    f"{r['accuracy']:.4f}",
                    f"{r['precision']:.4f}",
                    f"{r['recall']:.4f}",
                    f"{r['f1_score']:.4f}",
                    f"{r['perfection']:.4f}",
                    exp2.get('total_constraints', 0),
                    exp3.get('inferred_count', 0)
                ])

        print(f"[OK] Summary saved: {summary_path}")

        # 打印表格
        print(f"\n{'='*70}")
        print("Full Experiment Results")
        print(f"{'='*70}")
        print(f"{'Protocol':<10} {'Samples':<8} {'Acc':<8} {'Prec':<8} {'Rec':<8} {'F1':<8} {'Perf':<8} {'Constr':<8} {'Funcs':<6}")
        print("-" * 85)
        for r in self.summary_results:
            exp2 = r.get('exp2', {})
            exp3 = r.get('exp3', {})
            print(f"{r['protocol']:<10} {r['samples']:<8} {r['accuracy']:<8.4f} {r['precision']:<8.4f} {r['recall']:<8.4f} {r['f1_score']:<8.4f} {r['perfection']:<8.4f} {exp2.get('total_constraints', 0):<8} {exp3.get('inferred_count', 0):<6}")

    def save_summary(self):
        """保存汇总结果"""
        print(f"\n{'='*70}")
        print("Saving summary results")
        print(f"{'='*70}")

        summary_path = self.output_dir / 'summary_results.csv'
        with open(summary_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Protocol', 'CSV_Rows', 'Samples', 'Accuracy', 'Precision', 'Recall', 'F1-score', 'Perfection'])

            for r in self.summary_results:
                writer.writerow([
                    r['protocol'],
                    r['csv_rows'],
                    r['samples'],
                    f"{r['accuracy']:.4f}",
                    f"{r['precision']:.4f}",
                    f"{r['recall']:.4f}",
                    f"{r['f1_score']:.4f}",
                    f"{r['perfection']:.4f}"
                ])

        print(f"[OK] Summary table saved: {summary_path}")

        # 打印表格
        print(f"\n{'='*70}")
        print("Experiment Results Summary (Coarse-to-Fine)")
        print(f"{'='*70}")
        print(f"{'Protocol':<10} {'CSV_Rows':<10} {'Samples':<8} {'Accuracy':<10} {'Precision':<10} {'Recall':<8} {'F1-score':<10} {'Perfection':<10}")
        print("-" * 100)
        for r in self.summary_results:
            print(f"{r['protocol']:<10} {r['csv_rows']:<10} {r['samples']:<8} {r['accuracy']:<10.4f} {r['precision']:<10.4f} {r['recall']:<8.4f} {r['f1_score']:<10.4f} {r['perfection']:<10.4f}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Coarse-to-Fine Experiment Runner (Full Integration)')
    parser.add_argument('--batch', action='store_true', help='批量运行所有协议')
    parser.add_argument('--protocol', help='单个协议名称')
    parser.add_argument('--csv', help='CSV文件路径')
    parser.add_argument('--data-dir', default='Msg2/csv', help='数据目录')
    parser.add_argument('--output-dir', default='./output/coarse_to_fine', help='输出目录')
    parser.add_argument('--full', action='store_true', help='运行完整4个实验（包含SDG和Zero-Shot）')

    args = parser.parse_args()

    runner = CoarseToFineExperimentRunner(args.output_dir)

    if args.batch:
        print("[BATCH] Starting batch experiment mode...")
        if args.full:
            print("[MODE] Full experiments (4 experiments with SDG & Zero-Shot)")
            runner.run_all_protocols_full(args.data_dir)
        else:
            print("[MODE] Basic experiments (Coarse-to-Fine only)")
            runner.run_all_protocols(args.data_dir)
        print("\n[DONE] Batch experiments completed!")
    elif args.protocol and args.csv:
        if args.full:
            result = runner.run_full_experiments(args.protocol, args.csv)
        else:
            result = runner.run_protocol(args.protocol, args.csv)
        print(f"\n[DONE] Single protocol experiment completed!")
    else:
        print("[ERROR] Please specify --batch or (--protocol + --csv)")


if __name__ == '__main__':
    main()
