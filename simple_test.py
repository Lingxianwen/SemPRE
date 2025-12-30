#!/usr/bin/env python3
"""最简化测试脚本 - 测试边界检测"""
import sys
import csv
import json
import numpy as np
from collections import Counter

def load_csv(csv_path):
    """加载CSV"""
    messages, boundaries = [], []
    with open(csv_path, 'r') as f:
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

def detect_boundaries(messages):
    """简单边界检测"""
    # 计算前32字节的熵
    entropies = []
    for pos in range(32):
        vals = [m[pos] for m in messages if pos < len(m)]
        if not vals:
            entropies.append(0.0)
            continue
        cnt = Counter(vals)
        h = -sum((c/len(vals))*np.log2(c/len(vals)) for c in cnt.values() if c > 0)
        entropies.append(h)
    
    # 生成边界：密集候选[1-12]
    boundaries = list(range(1, 13))
    
    print(f"全局边界候选: {boundaries}")
    
    # 为每条消息生成边界
    msg_boundaries = []
    for msg in messages:
        valid = [b for b in boundaries if 0 < b < len(msg)]
        msg_boundaries.append(valid)
    
    return msg_boundaries

def evaluate(detected, truth):
    """评估"""
    precisions, recalls, f1s = [], [], []
    perfect = 0
    
    for i in range(min(len(detected), len(truth))):
        det_set = set(detected[i])
        true_set = set(truth[i])
        
        if not true_set:
            continue
        
        tp = len(det_set & true_set)
        fp = len(det_set - true_set)
        fn = len(true_set - det_set)
        
        p = tp/(tp+fp) if tp+fp > 0 else 0
        r = tp/(tp+fn) if tp+fn > 0 else 0
        f1 = 2*p*r/(p+r) if p+r > 0 else 0
        
        precisions.append(p)
        recalls.append(r)
        f1s.append(f1)
        
        if det_set == true_set:
            perfect += 1
    
    return {
        'precision': np.mean(precisions) if precisions else 0,
        'recall': np.mean(recalls) if recalls else 0,
        'f1': np.mean(f1s) if f1s else 0,
        'perfect': perfect / len(truth) if truth else 0,
        'perfect_count': perfect
    }

def main():
    if len(sys.argv) < 2:
        print("用法: python simple_test.py <csv文件>")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    
    print("=" * 60)
    print("简单测试：边界检测")
    print("=" * 60)
    
    # 加载数据
    print("\n1. 加载数据...")
    messages, truth = load_csv(csv_path)
    print(f"   ✓ 加载 {len(messages)} 条消息")
    
    # 检测边界
    print("\n2. 检测边界...")
    detected = detect_boundaries(messages)
    
    # 显示前5个样本
    print("\n3. 前5个样本对比:")
    for i in range(min(5, len(detected), len(truth))):
        det = detected[i]
        true = truth[i]
        match = "✓" if set(det) == set(true) else "✗"
        print(f"   [{i}] 检测={det}")
        print(f"       真实={true} {match}")
    
    # 评估
    print("\n4. 评估结果:")
    results = evaluate(detected, truth)
    print(f"   F1 Score:      {results['f1']:.4f}")
    print(f"   Precision:     {results['precision']:.4f}")
    print(f"   Recall:        {results['recall']:.4f}")
    print(f"   Perfect Score: {results['perfect']:.4f} ({results['perfect_count']}/{len(truth)})")
    
    print("\n" + "=" * 60)
    print("完成!")
    print("=" * 60)

if __name__ == '__main__':
    main()