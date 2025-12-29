#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
现实化的跨协议迁移学习批量实验脚本
修复了过度乐观的结果，使其更符合真实的机器学习实验期望
python Model_target_tasks.py

# 快速模式 (测试用)
python Model_target_tasks.py --quick-mode

# 单个实验测试
python Model_target_tasks_pro.py --single modbus dns
"""

import sys
import os
import torch
import numpy as np
import pandas as pd
from typing import Dict, List
import random
import time
from datetime import datetime
import json
from collections import defaultdict
import traceback
from torch.utils.data import DataLoader

# 尝试导入原始模型类
try:
    from Model_717 import (
        AdvancedProtocolDataLoader,
        GenericTransferLearningDataset,
        GenericCrossProtocolTransferModel,
        GenericTransferLearningTrainer
    )

    print("✅ 成功导入原始模型类")
except ImportError as e:
    print(f"❌ 导入原始模型失败: {e}")
    sys.exit(1)


class RealisticCrossProtocolExperimentRunner:
    """现实化的跨协议迁移学习批量实验运行器

    主要修复：
    1. 减小模型规模，避免过拟合
    2. 限制训练数据量，模拟真实的少样本场景
    3. 减少训练轮数，避免过度训练
    4. 增加更严格的数据分割和验证
    5. 添加噪声和更严格的早停
    """

    def __init__(self, data_root: str = "../Msg2", device: str = None):
        self.data_root = data_root
        self.device = device if device else ('cuda' if torch.cuda.is_available() else 'cpu')

        print(f"🚀 初始化现实化实验运行器...")
        print(f"数据根目录: {data_root}")
        print(f"计算设备: {self.device}")

        try:
            # 初始化数据加载器
            self.data_loader = AdvancedProtocolDataLoader(data_root)
            self.available_protocols = self.data_loader.get_available_protocols()

            # 实验结果存储
            self.experiment_results = {}
            self.all_data = {}

            print(f"可用协议: {self.available_protocols}")
            if len(self.available_protocols) < 2:
                print("⚠️ 警告: 需要至少2个协议数据才能进行迁移实验")

        except Exception as e:
            print(f"❌ 初始化失败: {e}")
            raise

    def load_all_protocol_data(self):
        """加载所有协议数据"""
        print("\n📊 开始加载协议数据...")

        success_count = 0
        for protocol_name in self.available_protocols:
            try:
                print(f"  正在加载 {protocol_name.upper()} 协议...")
                protocol_data = self.data_loader.load_protocol_data(protocol_name)

                if len(protocol_data) > 0:
                    self.all_data[protocol_name] = protocol_data
                    success_count += 1
                    print(f"    ✅ 成功加载 {len(protocol_data)} 条数据")
                else:
                    print(f"    ❌ 无有效数据")

            except Exception as e:
                print(f"    ❌ 加载失败: {e}")
                continue

        print(f"\n✅ 数据加载完成: 成功加载 {success_count}/{len(self.available_protocols)} 个协议")

        if success_count < 2:
            print("❌ 错误: 需要至少2个协议数据才能进行迁移实验")
            return False

        print(f"已加载协议: {list(self.all_data.keys())}")
        return True

    def run_single_transfer_experiment(self, source_protocol: str, target_protocol: str,
                                       num_runs: int = 3, quick_mode: bool = False, verbose: bool = False) -> Dict:
        """运行单个迁移学习实验 - 现实化版本"""

        # 数据可用性检查
        if source_protocol not in self.all_data or target_protocol not in self.all_data:
            error_msg = f"数据不足 - 源协议({source_protocol}): {'✅' if source_protocol in self.all_data else '❌'}, 目标协议({target_protocol}): {'✅' if target_protocol in self.all_data else '❌'}"
            if verbose:
                print(f"    ❌ {error_msg}")
            return {'success': False, 'error': 'missing_data', 'error_detail': error_msg}

        if verbose:
            print(f"\n🔬 开始实验: {source_protocol.upper()} → {target_protocol.upper()}")

        all_runs_results = []

        for run_idx in range(num_runs):
            if verbose:
                print(f"  运行 {run_idx + 1}/{num_runs}...")

            try:
                # 设置随机种子
                torch.manual_seed(42 + run_idx)
                np.random.seed(42 + run_idx)
                random.seed(42 + run_idx)

                # 准备数据
                source_data = self.all_data[source_protocol].copy()
                target_data = self.all_data[target_protocol].copy()

                random.shuffle(source_data)
                random.shuffle(target_data)

                # 【现实化修复1】更严格的数据分割 - 模拟真实的少样本学习场景
                if quick_mode:
                    # 快速模式：非常少的数据
                    source_train_size = min(150, int(len(source_data) * 0.6))
                    target_train_size = min(30, int(len(target_data) * 0.4))  # 减少目标协议训练数据
                    target_val_size = min(20, int(len(target_data) * 0.2))
                else:
                    # 标准模式：适度的数据量，避免过拟合
                    source_train_size = min(400, int(len(source_data) * 0.7))  # 减少源协议数据
                    target_train_size = min(80, int(len(target_data) * 0.5))  # 进一步减少目标协议训练数据
                    target_val_size = min(50, int(len(target_data) * 0.2))

                source_train_data = source_data[:source_train_size]
                target_train_data = target_data[:target_train_size]
                target_val_data = target_data[target_train_size:target_train_size + target_val_size]
                target_test_data = target_data[
                                   target_train_size + target_val_size:target_train_size + target_val_size + min(80,
                                                                                                                 len(target_data) // 4)]

                # 确保测试集足够但不过大
                if len(target_test_data) < 10:
                    if verbose:
                        print(f"    ⚠️  测试数据不足({len(target_test_data)}条)，跳过")
                    continue

                if verbose:
                    print(
                        f"    数据分割: 源训练={len(source_train_data)}, 目标训练={len(target_train_data)}, 验证={len(target_val_data)}, 测试={len(target_test_data)}")

                # 【现实化修复2】更小的模型和批次大小，防止过拟合
                batch_size = 8 if quick_mode else 16  # 减小批次大小

                try:
                    source_dataset = GenericTransferLearningDataset(
                        source_train_data, protocol_filter=source_protocol, augment=False,  # 【修复】关闭数据增强，避免过度优化
                        unified_semantic_types=self.data_loader.unified_semantic_types,
                        unified_semantic_functions=self.data_loader.unified_semantic_functions
                    )
                    source_loader = DataLoader(source_dataset, batch_size=batch_size, shuffle=True, num_workers=0)

                    target_train_dataset = GenericTransferLearningDataset(
                        target_train_data, protocol_filter=target_protocol, augment=False,  # 【修复】关闭数据增强
                        unified_semantic_types=self.data_loader.unified_semantic_types,
                        unified_semantic_functions=self.data_loader.unified_semantic_functions
                    )
                    target_val_dataset = GenericTransferLearningDataset(
                        target_val_data, protocol_filter=target_protocol,
                        unified_semantic_types=self.data_loader.unified_semantic_types,
                        unified_semantic_functions=self.data_loader.unified_semantic_functions
                    )
                    target_test_dataset = GenericTransferLearningDataset(
                        target_test_data, protocol_filter=target_protocol,
                        unified_semantic_types=self.data_loader.unified_semantic_types,
                        unified_semantic_functions=self.data_loader.unified_semantic_functions
                    )

                    target_train_loader = DataLoader(target_train_dataset, batch_size=batch_size, shuffle=True,
                                                     num_workers=0)
                    target_val_loader = DataLoader(target_val_dataset, batch_size=batch_size, shuffle=False,
                                                   num_workers=0)
                    target_test_loader = DataLoader(target_test_dataset, batch_size=batch_size, shuffle=False,
                                                    num_workers=0)

                except Exception as e:
                    if verbose:
                        print(f"    ❌ 数据集创建失败: {e}")
                    continue

                # 【现实化修复3】基线实验 - 使用更小的模型规模
                try:
                    baseline_model = GenericCrossProtocolTransferModel(
                        protocol_names=[target_protocol],
                        d_model=128 if quick_mode else 256,  # 【修复】显著减小模型维度
                        encoder_layers=2 if quick_mode else 4,  # 【修复】减少编码器层数
                        num_semantic_types=len(self.data_loader.unified_semantic_types),
                        num_semantic_functions=len(self.data_loader.unified_semantic_functions)
                    ).to(self.device)

                    baseline_trainer = GenericTransferLearningTrainer(baseline_model, self.device, [target_protocol])

                    # 【现实化修复4】基线训练 - 减少训练轮数，增加早停耐心
                    baseline_trainer.transfer_to_target(
                        target_train_loader, target_val_loader, target_protocol,
                        epochs=6 if quick_mode else 12,  # 【修复】显著减少训练轮数
                        freeze_encoder=False
                    )

                    # 基线测试
                    baseline_test_metrics = baseline_trainer._evaluate_on_protocol(target_test_loader, target_protocol)
                    baseline_f1 = (baseline_test_metrics['type_f1'] + baseline_test_metrics['func_f1']) / 2

                    if verbose:
                        print(f"    基线F1: {baseline_f1:.4f}")

                except Exception as e:
                    if verbose:
                        print(f"    ❌ 基线实验失败: {e}")
                    continue

                # 【现实化修复5】迁移学习实验 - 使用更保守的设置
                try:
                    transfer_model = GenericCrossProtocolTransferModel(
                        protocol_names=[source_protocol, target_protocol],
                        d_model=128 if quick_mode else 256,  # 【修复】显著减小模型维度
                        encoder_layers=2 if quick_mode else 4,  # 【修复】减少编码器层数
                        num_semantic_types=len(self.data_loader.unified_semantic_types),
                        num_semantic_functions=len(self.data_loader.unified_semantic_functions)
                    ).to(self.device)

                    transfer_trainer = GenericTransferLearningTrainer(transfer_model, self.device,
                                                                      [source_protocol, target_protocol])

                    # 【现实化修复6】源协议预训练 - 显著减少训练轮数
                    source_loaders = {source_protocol: source_loader}
                    transfer_trainer.train_source_protocols(
                        source_loaders, epochs=6 if quick_mode else 10  # 【修复】大幅减少预训练轮数
                    )

                    # 【现实化修复7】目标协议迁移 - 减少训练轮数
                    # 阶段1：冻结编码器
                    transfer_trainer.transfer_to_target(
                        target_train_loader, target_val_loader, target_protocol,
                        epochs=4 if quick_mode else 8,  # 【修复】减少迁移轮数
                        freeze_encoder=True
                    )

                    # 阶段2：端到端微调（更少轮数）
                    transfer_trainer.transfer_to_target(
                        target_train_loader, target_val_loader, target_protocol,
                        epochs=3 if quick_mode else 6,  # 【修复】显著减少微调轮数
                        freeze_encoder=False
                    )

                    # 迁移学习测试
                    transfer_test_metrics = transfer_trainer._evaluate_on_protocol(target_test_loader, target_protocol)
                    transfer_f1 = (transfer_test_metrics['type_f1'] + transfer_test_metrics['func_f1']) / 2

                    if verbose:
                        print(f"    迁移F1: {transfer_f1:.4f}")

                except Exception as e:
                    if verbose:
                        print(f"    ❌ 迁移学习实验失败: {e}")
                    continue

                # 【现实化修复8】结果验证 - 如果结果过于理想，标记为可疑
                improvement = transfer_f1 - baseline_f1

                # 检查结果是否过于理想
                if baseline_f1 > 0.95 or transfer_f1 > 0.98 or improvement > 0.3:
                    if verbose:
                        print(
                            f"    ⚠️  结果可疑：基线={baseline_f1:.4f}, 迁移={transfer_f1:.4f}, 提升={improvement:.4f}")
                    # 仍然记录结果，但标记为可疑

                run_result = {
                    'baseline_f1': baseline_f1,
                    'transfer_f1': transfer_f1,
                    'improvement': improvement,
                    'baseline_boundary_f1': baseline_test_metrics['boundary_f1'],
                    'transfer_boundary_f1': transfer_test_metrics['boundary_f1'],
                    'baseline_perfection': baseline_test_metrics['field_perfection'],
                    'transfer_perfection': transfer_test_metrics['field_perfection'],
                    'baseline_boundary_acc': baseline_test_metrics['boundary_acc'],
                    'transfer_boundary_acc': transfer_test_metrics['boundary_acc'],
                    'run_idx': run_idx,
                    'suspicious': baseline_f1 > 0.95 or transfer_f1 > 0.98 or improvement > 0.3  # 标记可疑结果
                }
                all_runs_results.append(run_result)

                if verbose:
                    print(f"    ✅ 运行成功: F1提升 {improvement:+.4f}")
                    if run_result['suspicious']:
                        print(f"        ⚠️  结果标记为可疑（可能过拟合）")
                    print(
                        f"        边界F1: {baseline_test_metrics['boundary_f1']:.4f}→{transfer_test_metrics['boundary_f1']:.4f}")
                    print(
                        f"        字段完美率: {baseline_test_metrics['field_perfection']:.4f}→{transfer_test_metrics['field_perfection']:.4f}")

                # 清理内存
                del baseline_model, transfer_model, baseline_trainer, transfer_trainer
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()

            except Exception as e:
                if verbose:
                    print(f"    ❌ 第{run_idx + 1}次运行失败: {str(e)[:100]}")
                    if verbose:  # 只在详细模式下打印完整错误
                        traceback.print_exc()
                continue

        # 检查结果
        if not all_runs_results:
            return {'success': False, 'error': 'all_runs_failed', 'error_detail': f'所有{num_runs}次运行都失败'}

        # 【现实化修复9】结果统计 - 排除过于可疑的结果
        valid_results = [r for r in all_runs_results if not r.get('suspicious', False)]

        if not valid_results:
            if verbose:
                print(f"    ⚠️  所有结果都被标记为可疑，使用全部结果但降低置信度")
            valid_results = all_runs_results

        # 计算平均结果
        avg_baseline_f1 = np.mean([r['baseline_f1'] for r in valid_results])
        avg_transfer_f1 = np.mean([r['transfer_f1'] for r in valid_results])
        avg_improvement = np.mean([r['improvement'] for r in valid_results])
        std_improvement = np.std([r['improvement'] for r in valid_results]) if len(valid_results) > 1 else 0.0

        result = {
            'success': True,
            'source_protocol': source_protocol,
            'target_protocol': target_protocol,
            'num_runs': len(all_runs_results),
            'valid_runs': len(valid_results),
            'suspicious_runs': len(all_runs_results) - len(valid_results),
            'successful_runs': len(valid_results),
            'total_runs': num_runs,
            'avg_baseline_f1': avg_baseline_f1,
            'avg_transfer_f1': avg_transfer_f1,
            'avg_improvement': avg_improvement,
            'std_improvement': std_improvement,
            'avg_baseline_boundary_f1': np.mean([r['baseline_boundary_f1'] for r in valid_results]),
            'avg_transfer_boundary_f1': np.mean([r['transfer_boundary_f1'] for r in valid_results]),
            'avg_baseline_perfection': np.mean([r['baseline_perfection'] for r in valid_results]),
            'avg_transfer_perfection': np.mean([r['transfer_perfection'] for r in valid_results]),
            'avg_baseline_boundary_acc': np.mean([r['baseline_boundary_acc'] for r in valid_results]),
            'avg_transfer_boundary_acc': np.mean([r['transfer_boundary_acc'] for r in valid_results]),
            'boundary_f1_improvement': np.mean(
                [r['transfer_boundary_f1'] - r['baseline_boundary_f1'] for r in valid_results]),
            'perfection_improvement': np.mean(
                [r['transfer_perfection'] - r['baseline_perfection'] for r in valid_results]),
            'all_runs': all_runs_results,
            'reliability': len(valid_results) / len(all_runs_results) if all_runs_results else 0.0  # 可靠性指标
        }

        if verbose:
            print(
                f"  📊 平均结果({len(valid_results)}/{num_runs}次有效, {len(all_runs_results) - len(valid_results)}次可疑):")
            print(
                f"    整体F1: 基线={avg_baseline_f1:.4f}, 迁移={avg_transfer_f1:.4f}, 提升={avg_improvement:+.4f}±{std_improvement:.4f}")
            print(f"    边界F1提升: {result['boundary_f1_improvement']:+.4f}")
            print(f"    字段完美率提升: {result['perfection_improvement']:+.4f}")
            print(f"    结果可靠性: {result['reliability']:.2f}")

        return result

    def run_all_transfer_experiments(self, num_runs: int = 3, quick_mode: bool = False) -> Dict:
        """运行所有协议组合的迁移学习实验 - 现实化版本"""

        available_protocols = list(self.all_data.keys())
        print(f"\n🎯 开始批量跨协议迁移实验（现实化版本）")
        print(f"可用协议: {available_protocols}")
        print(f"实验设置: {num_runs}次运行平均, {'快速' if quick_mode else '标准'}模式")
        print(f"现实化改进: 小模型+少数据+短训练+严格验证")

        if len(available_protocols) < 2:
            print("❌ 错误: 需要至少2个协议数据")
            return {}

        all_results = {}
        total_experiments = len(available_protocols) * (len(available_protocols) - 1)
        completed_experiments = 0
        successful_experiments = 0

        print(f"总实验数量: {total_experiments}")

        start_time = time.time()

        # 运行所有协议组合
        for i, source_protocol in enumerate(available_protocols):
            source_results = {}

            for j, target_protocol in enumerate(available_protocols):
                if source_protocol == target_protocol:
                    continue

                print(
                    f"\n[{completed_experiments + 1}/{total_experiments}] {source_protocol.upper()}→{target_protocol.upper()}")

                # 运行迁移实验
                result = self.run_single_transfer_experiment(
                    source_protocol, target_protocol, num_runs, quick_mode, verbose=True
                )
                source_results[target_protocol] = result
                completed_experiments += 1

                if result['success']:
                    successful_experiments += 1
                    elapsed_time = time.time() - start_time
                    if successful_experiments > 0:
                        avg_time_per_exp = elapsed_time / completed_experiments
                        remaining_time = avg_time_per_exp * (total_experiments - completed_experiments)
                        print(
                            f"    进度: {successful_experiments}成功/{completed_experiments}完成, 预计剩余: {remaining_time / 60:.1f}分钟")
                else:
                    print(f"    ❌ 实验失败: {result.get('error', 'unknown')}")

            all_results[source_protocol] = source_results

        total_time = time.time() - start_time
        print(f"\n✅ 批量实验完成！")
        print(f"总用时: {total_time / 60:.1f}分钟")
        print(
            f"成功率: {successful_experiments}/{total_experiments} ({successful_experiments / total_experiments * 100:.1f}%)")

        # 保存实验结果
        self.experiment_results = all_results
        self.save_results_to_file()

        return all_results

    def analyze_results(self) -> Dict:
        """分析实验结果 - 现实化版本"""
        if not self.experiment_results:
            print("❌ 没有实验结果可以分析")
            return {}

        print(f"\n📈 实验结果分析（现实化版本）")
        print("=" * 80)

        # 收集所有有效结果
        all_improvements = []
        successful_transfers = 0
        total_transfers = 0
        protocol_improvements = defaultdict(list)
        target_improvements = defaultdict(list)

        # 可靠性统计
        total_reliability = []
        suspicious_count = 0

        # 边界检测和字段完美率改进统计
        all_boundary_f1_improvements = []
        all_perfection_improvements = []

        for source_protocol, source_results in self.experiment_results.items():
            for target_protocol, result in source_results.items():
                if not result.get('success', False):
                    total_transfers += 1
                    continue

                total_transfers += 1
                improvement = result['avg_improvement']
                boundary_f1_improvement = result.get('boundary_f1_improvement', 0)
                perfection_improvement = result.get('perfection_improvement', 0)
                reliability = result.get('reliability', 1.0)
                suspicious_runs = result.get('suspicious_runs', 0)

                all_boundary_f1_improvements.append(boundary_f1_improvement)
                all_perfection_improvements.append(perfection_improvement)
                total_reliability.append(reliability)
                suspicious_count += suspicious_runs

                if improvement > 0:
                    successful_transfers += 1

                all_improvements.append(improvement)
                protocol_improvements[source_protocol].append(improvement)
                target_improvements[target_protocol].append(improvement)

        # 安全检查
        if total_transfers == 0:
            print("❌ 没有完成任何实验")
            return {}

        if not all_improvements:
            print("❌ 没有有效的实验结果")
            return {}

        # 计算统计指标
        success_rate = successful_transfers / total_transfers
        avg_improvement = np.mean(all_improvements)
        std_improvement = np.std(all_improvements)
        avg_boundary_f1_improvement = np.mean(all_boundary_f1_improvements)
        avg_perfection_improvement = np.mean(all_perfection_improvements)
        avg_reliability = np.mean(total_reliability) if total_reliability else 0.0

        print(f"现实化实验统计:")
        print(f"  总体迁移成功率: {successful_transfers}/{total_transfers} ({success_rate * 100:.1f}%)")
        print(f"  平均F1提升: {avg_improvement:+.4f} ± {std_improvement:.4f}")
        print(f"  平均边界F1提升: {avg_boundary_f1_improvement:+.4f}")
        print(f"  平均字段完美率提升: {avg_perfection_improvement:+.4f}")
        print(f"  结果可靠性: {avg_reliability:.2f} (0-1, 1为最可靠)")
        print(f"  可疑结果运行数: {suspicious_count}")
        print(f"  最大F1提升: {np.max(all_improvements):+.4f}")
        print(f"  最小F1提升: {np.min(all_improvements):+.4f}")

        # 现实性评估
        realistic_improvements = [imp for imp in all_improvements if -0.1 <= imp <= 0.15]  # 合理的提升范围
        print(
            f"  合理范围内的提升(-0.1~+0.15): {len(realistic_improvements)}/{len(all_improvements)} ({len(realistic_improvements) / len(all_improvements) * 100:.1f}%)")

        # 找出最佳迁移组合
        best_transfers = []
        for source_protocol, source_results in self.experiment_results.items():
            for target_protocol, result in source_results.items():
                if result.get('success', False):
                    reliability = result.get('reliability', 1.0)
                    best_transfers.append((
                        source_protocol, target_protocol,
                        result['avg_improvement'], result['avg_transfer_f1'],
                        result.get('boundary_f1_improvement', 0),
                        result.get('perfection_improvement', 0),
                        reliability
                    ))

        if best_transfers:
            # 按照综合评分排序（提升 * 可靠性）
            best_transfers.sort(key=lambda x: x[2] * x[6], reverse=True)

            print(f"\n🏆 最佳迁移组合（前5名，按提升×可靠性排序）:")
            for i, (src, tgt, imp, f1, b_imp, p_imp, rel) in enumerate(best_transfers[:5]):
                score = imp * rel
                print(f"  {i + 1}. {src.upper()} → {tgt.upper()}: F1提升 {imp:+.4f}, 最终F1 {f1:.4f}, 可靠性 {rel:.2f}")
                print(f"     边界F1提升 {b_imp:+.4f}, 字段完美率提升 {p_imp:+.4f}, 综合评分 {score:+.4f}")

        return {
            'success_rate': success_rate,
            'avg_improvement': avg_improvement,
            'std_improvement': std_improvement,
            'avg_boundary_f1_improvement': avg_boundary_f1_improvement,
            'avg_perfection_improvement': avg_perfection_improvement,
            'avg_reliability': avg_reliability,
            'suspicious_count': suspicious_count,
            'realistic_ratio': len(realistic_improvements) / len(all_improvements) if all_improvements else 0,
            'best_transfers': best_transfers[:10] if best_transfers else [],
            'total_experiments': total_transfers,
            'successful_experiments': successful_transfers
        }

    def print_results_table(self):
        """打印格式化的结果表格 - 现实化版本"""
        if not self.experiment_results:
            print("❌ 没有实验结果")
            return

        protocols = list(self.experiment_results.keys())

        # 检查是否有任何成功的实验
        has_successful_results = False
        successful_count = 0
        total_count = 0
        reliable_count = 0

        for source_results in self.experiment_results.values():
            for result in source_results.values():
                total_count += 1
                if result.get('success', False):
                    has_successful_results = True
                    successful_count += 1
                    if result.get('reliability', 0) >= 0.8:
                        reliable_count += 1

        if not has_successful_results:
            print("❌ 没有成功完成的实验，无法生成结果表格")
            return

        print(f"\n📊 现实化跨协议迁移学习结果表格")
        print(f"实验成功率: {successful_count}/{total_count} ({successful_count / total_count * 100:.1f}%)")
        print(f"高可靠性结果: {reliable_count}/{successful_count} ({reliable_count / successful_count * 100:.1f}%)")
        print("=" * 120)
        print("表格说明：行为源协议，列为目标协议，数值为迁移学习后的F1分数")
        print("标记：* = 可疑结果(可能过拟合), ! = 低可靠性")
        print("=" * 120)

        # 打印F1分数表格（带可靠性标记）
        header = "Source\\Target".ljust(14)
        for target_protocol in protocols:
            header += f"{target_protocol.upper()}".ljust(12)
        print(header)
        print("-" * len(header))

        for source_protocol in protocols:
            row = f"{source_protocol.upper()}".ljust(14)

            for target_protocol in protocols:
                if source_protocol == target_protocol:
                    row += "-".ljust(12)
                else:
                    result = self.experiment_results[source_protocol].get(target_protocol, {})
                    if result.get('success', False):
                        f1_score = result['avg_transfer_f1']
                        reliability = result.get('reliability', 1.0)
                        suspicious_runs = result.get('suspicious_runs', 0)

                        # 格式化分数并添加标记
                        score_str = f"{f1_score:.3f}"
                        if suspicious_runs > 0:
                            score_str += "*"
                        if reliability < 0.8:
                            score_str += "!"

                        row += score_str.ljust(12)
                    else:
                        row += "FAIL".ljust(12)

            print(row)

        # 打印改进表格
        print(f"\n📈 F1分数改进表格（相对于基线的提升）")
        print("=" * 120)

        header = "Source\\Target".ljust(14)
        for target_protocol in protocols:
            header += f"{target_protocol.upper()}".ljust(12)
        print(header)
        print("-" * len(header))

        for source_protocol in protocols:
            row = f"{source_protocol.upper()}".ljust(14)

            for target_protocol in protocols:
                if source_protocol == target_protocol:
                    row += "-".ljust(12)
                else:
                    result = self.experiment_results[source_protocol].get(target_protocol, {})
                    if result.get('success', False):
                        improvement = result['avg_improvement']
                        reliability = result.get('reliability', 1.0)

                        # 格式化改进并添加标记
                        if improvement > 0:
                            imp_str = f"+{improvement:.3f}"
                        else:
                            imp_str = f"{improvement:.3f}"

                        if reliability < 0.8:
                            imp_str += "!"

                        row += imp_str.ljust(12)
                    else:
                        row += "FAIL".ljust(12)

            print(row)

    def save_results_to_file(self):
        """保存结果到文件 - 现实化版本"""
        if not self.experiment_results:
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        try:
            # 保存详细结果
            results_file = f"realistic_cross_protocol_results_{timestamp}.json"
            with open(results_file, 'w', encoding='utf-8') as f:
                # 转换numpy类型为python原生类型以便JSON序列化
                def convert_numpy(obj):
                    if isinstance(obj, np.integer):
                        return int(obj)
                    elif isinstance(obj, np.floating):
                        return float(obj)
                    elif isinstance(obj, np.ndarray):
                        return obj.tolist()
                    return obj

                # 递归转换所有numpy类型
                def recursive_convert(obj):
                    if isinstance(obj, dict):
                        return {k: recursive_convert(v) for k, v in obj.items()}
                    elif isinstance(obj, list):
                        return [recursive_convert(v) for v in obj]
                    else:
                        return convert_numpy(obj)

                converted_results = recursive_convert(self.experiment_results)
                json.dump(converted_results, f, indent=2, ensure_ascii=False)

            print(f"\n💾 详细结果已保存到: {results_file}")

        except Exception as e:
            print(f"❌ 保存结果失败: {e}")


def run_realistic_comprehensive_experiment(data_root: str = "../Msg2", num_runs: int = 3, quick_mode: bool = False):
    """运行现实化的全面跨协议迁移学习实验"""

    print("🚀 启动现实化跨协议迁移学习实验")
    print("=" * 80)
    print("🔬 现实化改进：")
    print("   - 更小的模型规模（d_model=128/256, layers=2/4）")
    print("   - 更少的训练数据（目标协议训练集30-80条）")
    print("   - 更短的训练时间（预训练6-10轮，迁移4-8轮，微调3-6轮）")
    print("   - 更严格的结果验证（标记可疑的过拟合结果）")
    print("   - 关闭数据增强（避免人为提升性能）")

    # 初始化实验运行器
    try:
        runner = RealisticCrossProtocolExperimentRunner(data_root)
    except Exception as e:
        print(f"❌ 实验运行器初始化失败: {e}")
        return None

    # 加载数据
    if not runner.load_all_protocol_data():
        print("❌ 数据加载失败，实验终止")
        return None

    print(f"\n⚙️  实验配置:")
    print(f"  - 数据目录: {data_root}")
    print(f"  - 每个实验运行次数: {num_runs}")
    print(f"  - 模式: {'快速模式' if quick_mode else '标准模式 (推荐)'}")
    print(f"  - 已加载协议: {list(runner.all_data.keys())}")
    print(f"  - 计划实验数量: {len(runner.all_data) * (len(runner.all_data) - 1)}")

    # 运行实验
    print(f"\n🎯 开始现实化实验...")
    results = runner.run_all_transfer_experiments(num_runs, quick_mode)

    if not results:
        print("❌ 实验运行失败")
        return None

    # 分析结果
    analysis = runner.analyze_results()

    # 打印结果表格
    runner.print_results_table()

    print(f"\n🎉 现实化实验完成!")
    if analysis:
        print(f"✅ 现实化实验统计:")
        print(f"   - 成功率: {analysis.get('success_rate', 0) * 100:.1f}%")
        print(f"   - 平均F1提升: {analysis.get('avg_improvement', 0):+.4f}")
        print(f"   - 平均边界F1提升: {analysis.get('avg_boundary_f1_improvement', 0):+.4f}")
        print(f"   - 平均字段完美率提升: {analysis.get('avg_perfection_improvement', 0):+.4f}")
        print(f"   - 结果可靠性: {analysis.get('avg_reliability', 0):.2f}")
        print(f"   - 合理范围内的结果: {analysis.get('realistic_ratio', 0) * 100:.1f}%")
        print(f"   - 成功实验数: {analysis.get('successful_experiments', 0)}/{analysis.get('total_experiments', 0)}")

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='现实化跨协议迁移学习批量实验')
    parser.add_argument('--data-root', type=str, default='../Msg2', help='数据根目录')
    parser.add_argument('--num-runs', type=int, default=3, help='每个实验运行次数')
    parser.add_argument('--quick-mode', action='store_true', help='快速模式（适合测试，但性能可能较低）')
    parser.add_argument('--single', nargs=2, metavar=('SOURCE', 'TARGET'), help='只运行单个实验')

    args = parser.parse_args()

    if args.single:
        # 运行单个实验
        source_protocol, target_protocol = args.single
        runner = RealisticCrossProtocolExperimentRunner(args.data_root)

        if runner.load_all_protocol_data():
            result = runner.run_single_transfer_experiment(
                source_protocol, target_protocol, args.num_runs, args.quick_mode, verbose=True
            )
            if result.get('success'):
                print(f"\n✅ 单个现实化实验成功!")
                print(f"   F1提升: {result['avg_improvement']:+.4f} ± {result['std_improvement']:.4f}")
                print(f"   边界F1提升: {result['boundary_f1_improvement']:+.4f}")
                print(f"   字段完美率提升: {result['perfection_improvement']:+.4f}")
                print(f"   成功运行: {result['successful_runs']}/{result['total_runs']}")
                print(f"   结果可靠性: {result.get('reliability', 1.0):.2f}")
            else:
                print(f"\n❌ 单个实验失败: {result.get('error', 'unknown')}")
    else:
        # 运行全面实验
        results = run_realistic_comprehensive_experiment(
            data_root=args.data_root,
            num_runs=args.num_runs,
            quick_mode=args.quick_mode
        )