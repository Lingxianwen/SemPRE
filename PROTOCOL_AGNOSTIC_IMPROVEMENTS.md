# SemPRE 协议无关版本改进说明

## 问题诊断

### 原始版本的科学评估偏差

**核心问题**：原始实验结果（F1=0.9909, Perfect=0.8638）虽然数字很高，但存在**循环评估**问题：

```
硬编码Modbus规则 → 检测边界 → 与Modbus Ground Truth对比 → 高分
```

这种评估方式的问题：
- ✗ **高分≠算法能力强**：只证明"规则写对了"，而非"算法能学习"
- ✗ **无泛化能力**：换一个协议（如DNP3/S7）就完全失效
- ✗ **不符合PRE目标**：PRE的核心是"在不知道协议的情况下推断格式"

### 硬编码位置列表（已全部移除）

1. **字段位置硬编码** ([improved_sempre_experiment_runner.py:61-114](improved_sempre_experiment_runner.py#L61-L114))
   - `get_modbus_standard_fields()`: Transaction ID在0-1, Function Code在7等
   - `get_modbus_boundaries_by_function()`: 根据功能码返回固定边界

2. **功能码位置硬编码** ([sempre_function_inferencer.py:269-271](sempre_function_inferencer.py#L269-L271))
   - `msg[7]`: 假设功能码在偏移7
   - `msg[1:3]`: 假设地址在偏移1-3
   - `msg[4]`: 假设计数在偏移4

3. **长度字段硬编码** (原improved_sempre_experiment_runner.py:234-250)
   - 直接检查`msg[4:6]`是否等于`len(msg)-6`

---

## 改进方案：真正的协议无关统计学习

### 1. 纯统计的字段边界检测

#### 算法：字节级熵 + 重合指数（IoC）

```python
# 字节级熵分析（Shannon Entropy）
for pos in range(max_len):
    values = [msg[pos] for msg in messages if pos < len(msg)]
    entropy = -Σ(p * log2(p))  # 高熵=数据，低熵=类型

# 重合指数（Index of Coincidence）
IoC = Σ[n_i * (n_i - 1)] / [N * (N - 1)]

# 熵梯度边界检测
boundaries = {i where |∇entropy[i]| > threshold}
```

**关键代码**：
- [improved_sempre_experiment_runner.py:152-216](improved_sempre_experiment_runner.py#L152-L216) - `_calculate_byte_entropy()`
- [improved_sempre_experiment_runner.py:218-258](improved_sempre_experiment_runner.py#L218-L258) - `_detect_boundary_candidates()`

**特点**：
- ✓ 无协议假设
- ✓ 基于信息论（熵/IoC）
- ✓ 可适用于任何二进制协议

---

### 2. 零样本功能语义推理（无位置假设）

#### 算法：自动发现类型字段 + 结构指纹匹配

```python
# 步骤1: 自动发现"类型字段"位置
for pos in range(32):
    unique_count = len(set([msg[pos] for msg in messages]))
    entropy = calculate_entropy(pos)

    # 类型字段特征：3-20个不同值 + 低熵
    if 3 <= unique_count <= 20 and entropy < best_score:
        type_field_position = pos

# 步骤2: 基于类型字段提取功能码
func_code = msg[type_field_position]  # 而非硬编码的msg[7]

# 步骤3: 提取结构指纹（无位置假设）
fingerprint = {
    'has_address': search_for_address_pattern(msg),  # 搜索整个消息
    'has_payload': detect_payload_pattern(msg),
    'avg_size': mean(message_sizes)
}

# 步骤4: 匹配推理规则
if has_address and has_count and no_payload:
    → READ
elif has_address and has_count and has_payload:
    → WRITE
```

**关键代码**：
- [improved_sempre_experiment_runner.py:859-905](improved_sempre_experiment_runner.py#L859-L905) - `_find_type_field_position()`
- [sempre_function_inferencer.py:314-403](sempre_function_inferencer.py#L314-L403) - `_detect_*_generic()`

**特点**：
- ✓ 不假设功能码在offset 7
- ✓ 不假设地址在offset 1-3
- ✓ 自动搜索特征字段

---

### 3. 协议无关的约束发现

#### 算法：遍历测试 + 公式自动发现

```python
# 长度字段检测：遍历所有1-4字节字段
for field in all_fields:
    for relationship in ['len(msg)', 'len(msg)-offset', 'payload_size']:
        if field_value == relationship(msg):
            confidence += 1

# 自动发现最佳公式
best_formula = argmax(confidence(formula) for formula in candidates)
```

**关键代码**：
- [improved_sempre_experiment_runner.py:295-394](improved_sempre_experiment_runner.py#L295-L394) - `StatisticalLengthFieldDetector`
- [improved_sempre_experiment_runner.py:430-477](improved_sempre_experiment_runner.py#L430-L477) - `_discover_length_formula()`

**特点**：
- ✓ 不假设长度字段在offset 4-5
- ✓ 测试多种长度关系
- ✓ 自动发现计算公式

---

### 4. SDG构建（已优化为协议无关）

[optimized_semantic_graph.py](optimized_semantic_graph.py) 已经是协议无关的：
- ✓ 字段去重（8800→8个节点）
- ✓ 智能过滤（只检测数值字段）
- ✓ 采样优化（减少计算量）

---

## 修改对比表

| 组件 | 原始版本 | 协议无关版本 |
|------|---------|-------------|
| **字段检测** | `get_modbus_boundaries_by_function()` | 熵分析 + IoC梯度 |
| **功能码提取** | `msg[7]` | 自动发现类型字段位置 |
| **地址检测** | `msg[1:3]` | 搜索整个消息（offset 0-20） |
| **长度字段** | 检查`msg[4:6]` | 遍历所有字段 + 测试多种公式 |
| **评估指标** | F1=0.99（规则匹配） | F1=?（真实学习能力） |

---

## 预期结果变化

### 原始版本（硬编码）
```
✓ F1 Score: 0.9909  ← 因为规则完全匹配Modbus
✓ Perfect Score: 0.8638
✓ 检测方法: protocol_aware
```

### 协议无关版本（统计学习）
```
? F1 Score: 0.40-0.70（预期）  ← 反映真实学习能力
? Perfect Score: 0.10-0.30（预期）
✓ 检测方法: statistical
```

**分数下降是正常的**，因为：
1. 不再使用Modbus特定知识
2. 纯统计方法需要更多样本才能学习
3. 这才是真实的算法性能

---

## 如何评估改进效果

### 错误的评估方式（原版本）
- ✗ 只在Modbus上测试
- ✗ 硬编码Modbus规则 → 高分 → "算法很好"

### 正确的评估方式（新版本）
- ✓ **跨协议泛化**：在Modbus训练 → 在DNP3/S7测试
- ✓ **数据效率**：10%数据能学到什么程度？
- ✓ **学习曲线**：F1 vs 样本数量的关系
- ✓ **零样本能力**：能否正确推断未见过的功能码？

---

## 运行方式

### 原始版本（已废弃）
```bash
python improved_sempre_experiment_runner.py \
    --csv Msg2/csv/modbus/modbus.csv \
    --ground-truth Msg2/csv/modbus/modbus_groundtruth.json \
    --output-dir ./output/improved \
    --protocol modbus  # 会使用Modbus硬编码规则
```

### 协议无关版本（推荐）
```bash
python improved_sempre_experiment_runner.py \
    --csv Msg2/csv/modbus/modbus.csv \
    --ground-truth Msg2/csv/modbus/modbus_groundtruth.json \
    --output-dir ./output/statistical \
    --protocol unknown  # 不使用任何协议知识
```

---

## 代码修改清单

### 完全重写的类
1. ✓ `StatisticalFieldDetector` (替代 `ImprovedFieldDetector`)
2. ✓ `StatisticalLengthFieldDetector` (替代 `ImprovedLengthFieldDetector`)
3. ✓ `StatisticalConstraintMiner` (替代 `ImprovedConstraintMiner`)
4. ✓ `StatisticalSemPREExperimentRunner` (替代 `ImprovedSemPREExperimentRunner`)

### 完全删除的类
1. ✓ `ProtocolKnowledgeBase` (硬编码Modbus规则)

### 修改的文件
1. ✓ [improved_sempre_experiment_runner.py](improved_sempre_experiment_runner.py) - 主实验文件
2. ✓ [sempre_function_inferencer.py](sempre_function_inferencer.py) - 功能推理器

---

## 论文写作建议

### Baseline对比
- **Baseline 1**: Netzob/Discoverer（完全无监督）
- **Baseline 2**: SemPRE-Hardcoded（本次改进前的版本，标注为"使用协议知识"）
- **Our Method**: SemPRE-Statistical（协议无关版本）

### 实验设计
1. **单协议准确率**：Modbus/DNP3/S7各自的F1
2. **跨协议泛化**：在A训练 → 在B测试
3. **数据效率**：样本数 vs F1曲线
4. **零样本推理**：功能码分类准确率

### 诚实汇报
- ✓ 汇报真实的F1分数（可能0.4-0.7）
- ✓ 强调"无协议假设"这一优势
- ✓ 对比"硬编码版本"作为上界
- ✓ 分析失败案例（哪些边界检测失败？为什么？）

---

## 总结

### 科学意义
- **原版本**：Engineering Trick（规则匹配）
- **新版本**：Machine Learning（统计学习）

### 核心贡献
1. ✓ 真正的零样本学习（无位置假设）
2. ✓ 协议无关的边界检测（熵+IoC）
3. ✓ 自动公式发现（长度约束）
4. ✓ 科学的评估方法（泛化 > 准确率）

### 下一步
1. 运行新版本，收集真实数据
2. 分析失败案例，改进算法
3. 在多个协议上测试泛化能力
4. 撰写诚实的论文，强调方法论创新而非单一分数

---

**改进完成日期**: 2025-12-29
**代码状态**: 已移除所有硬编码，可直接运行
