# 边界检测算法改进说明

## 问题诊断

### 原始结果（有问题）
```
边界候选: [1, 2, 4, 6, 7, 8, 9, 11, 12, 13, 16, 18, 24, ...] (91个边界)
真实边界: [1, 3, 5, 6, 7] (5个边界)

结果:
- F1 Score: 0.5575
- Perfect Score: 0.0000  ← 问题！
- Precision: 0.4927     ← 太多假阳性
- Recall: 0.6846        ← Recall还可以
```

### 根本原因
1. **熵梯度阈值过低**（0.5 × std）→ 产生大量噪声边界
2. **固定边界太多**（[1, 2, 4, 8, 12, 16]全部添加）
3. **邻近边界未合并**（6, 7, 8, 9都被检测为边界）
4. **无边界数量限制**（91个边界过多）

---

## 改进策略（参考CrossPRE）

### 1. **提高梯度阈值**（减少假阳性）
```python
# 原版本
entropy_threshold = np.std(entropy_gradient) * 0.5  # 太宽松

# 改进版本
entropy_threshold = np.std(entropy_gradient) * 1.5  # 更严格（3倍提升）
ioc_threshold = np.std(ioc_gradient) * 1.5
```

**效果**：将熵突变检测的灵敏度降低，只保留最显著的边界

---

### 2. **移除固定边界添加**（避免协议偏见）
```python
# 原版本：无条件添加常见边界
common_header_sizes = [1, 2, 4, 8, 12, 16]
for size in common_header_sizes:
    boundaries.add(size)  # 直接添加，产生噪声

# 改进版本：只在有熵突变支持时才添加
essential_boundaries = [1, 2, 4, 8]  # 减少数量
for size in essential_boundaries:
    # 只有当该位置附近有熵突变时才添加
    if size in boundaries or (size-1) in boundaries or (size+1) in boundaries:
        boundaries.add(size)
```

**效果**：避免在无证据的情况下添加边界

---

### 3. **邻近边界合并**（关键去噪）
```python
def _merge_nearby_boundaries(boundaries: List[int], min_distance: int = 2):
    """
    如果两个边界距离 < min_distance，保留较小的那个

    示例：
    输入: [6, 7, 8, 9, 11, 12]
    输出: [6, 8, 11]  # 合并后边界数大幅减少
    """
    merged = [boundaries[0]]

    for i in range(1, len(boundaries)):
        if boundaries[i] - merged[-1] >= min_distance:
            merged.append(boundaries[i])

    return merged
```

**效果**：
- 原始：[6, 7, 8, 9] → 4个边界（噪声）
- 合并后：[6, 8] → 2个边界（清晰）

---

### 4. **限制边界数量**（避免过拟合）
```python
MAX_BOUNDARIES = 15  # Modbus实际只需5-8个边界

if len(boundaries) > MAX_BOUNDARIES:
    # 保留熵梯度最大的边界
    boundary_scores = [(b, abs(entropy_gradient[b])) for b in boundaries]
    boundary_scores.sort(key=lambda x: x[1], reverse=True)
    boundaries = [b for b, _ in boundary_scores[:MAX_BOUNDARIES]]
```

**效果**：强制限制边界数量，优先保留最显著的边界

---

## 预期改进效果

### 改进前
```
边界候选: 91个
Perfect Score: 0.0000
Precision: 0.4927
```

### 改进后（预期）
```
边界候选: 8-12个  ← 大幅减少
Perfect Score: 0.05-0.15  ← 从0提升
Precision: 0.65-0.75  ← 提升20-30%
F1 Score: 0.60-0.70  ← 整体提升
```

**注意**：
- Perfect Score仍然不会很高（0.05-0.15），因为统计方法难以完美匹配
- 这是正常的——真实反映了算法在未知协议上的性能
- 重点是**消除明显的噪声**，让结果更可信

---

## 技术细节

### 为什么Perfect Score=0是问题？

**原因**：边界候选过多导致Precision低
```
真实边界: {1, 3, 5, 6, 7}
检测边界: {1, 2, 4, 6, 7, 8, 9, 11, 12, ...}

交集: {1, 6, 7}  ← 只匹配了3个
假阳性: {2, 4, 8, 9, 11, ...}  ← 大量噪声

结果: 没有一条消息的边界集合完全相等
```

### 改进后的预期

```
真实边界: {1, 3, 5, 6, 7}
检测边界: {1, 4, 6, 8}  ← 减少到合理数量

匹配情况:
- 消息1: {1, 6, 7} vs {1, 4, 6, 8} → 部分匹配
- 消息2: {1, 3, 5} vs {1, 4, 6} → 部分匹配
- ...
- 可能有5-15%的消息完全匹配（对于统计方法已经不错）
```

---

## 与CrossPRE的对比

| 特性 | CrossPRE | 改进后的SemPRE |
|------|----------|---------------|
| 边界检测方法 | 熵分析 + 序列对齐 | 熵梯度 + IoC突变 |
| 邻近合并 | ✓ | ✓（新增） |
| 边界数量限制 | ✓ | ✓（新增） |
| 跨消息验证 | ✓ | 部分（通过合并实现） |
| 协议无关性 | ✓ | ✓ |

---

## 运行建议

### 快速验证
```bash
python improved_sempre_experiment_runner.py \
    --csv Msg2/csv/modbus/modbus.csv \
    --ground-truth Msg2/csv/modbus/modbus_groundtruth.json \
    --output-dir ./output/statistical \
    --protocol unknown
```

### 预期日志输出
```
边界候选: [1, 4, 6, 8, 11]  ← 应该在5-12个之间
✓ F1 Score: 0.62-0.70
✓ Perfect Score: 0.08-0.15  ← 不再是0
✓ Precision: 0.65-0.75
✓ Recall: 0.60-0.70
```

---

## 进一步优化方向

如果结果仍不理想，可以尝试：

1. **消息长度聚类**
   ```python
   # 将消息按长度分组，分别检测边界
   groups = group_by_length(messages)
   for group in groups:
       boundaries = detect_boundaries(group)
   ```

2. **序列对齐**（CrossPRE方法）
   ```python
   # 使用序列对齐算法找共同模式
   aligned_positions = sequence_alignment(messages)
   ```

3. **基于频率的边界验证**
   ```python
   # 只保留在>80%消息中出现的边界
   boundary_frequency = count_boundary_frequency(boundaries, messages)
   final_boundaries = [b for b in boundaries if frequency[b] > 0.8]
   ```

---

**改进日期**: 2025-12-29
**状态**: 已实现，待测试
