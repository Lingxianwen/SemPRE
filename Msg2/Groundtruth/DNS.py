# DNS (Domain Name System) 协议 Groundtruth 定义 - 修复版本
# 基于RFC 1035和实际DNS消息分析

semantic_Types = ['Static', 'Group', 'String', 'Bit Field', 'Bytes']
semantic_Functions = ['Command', 'Length', 'Delim', 'CheckSum', 'Aligned', 'Filename']

dns_Syntax_Groundtruth = {}

# DNS Header固定结构: 12 bytes
# Transaction ID(2) + Flags(2) + Questions(2) + Answer RRs(2) + Authority RRs(2) + Additional RRs(2)

# ===== 修复：使用字节形式的Flags字段作为键 =====

# DNS Standard Query (Flags = 0x0100: QR=0, Opcode=0, RD=1)
dns_Syntax_Groundtruth[b'\x01\x00'] = [2, 4, 6, 8, 10, 12]  # 基本DNS头部边界

# DNS Standard Response (Flags = 0x8180: QR=1, Opcode=0, RD=1, RA=1)
dns_Syntax_Groundtruth[b'\x81\x80'] = [2, 4, 6, 8, 10, 12]  # 基本DNS头部边界

# DNS Non-recursive Query (Flags = 0x0000)
dns_Syntax_Groundtruth[b'\x00\x00'] = [2, 4, 6, 8, 10, 12]

# DNS Authoritative Response (Flags = 0x8400: QR=1, AA=1)
dns_Syntax_Groundtruth[b'\x84\x00'] = [2, 4, 6, 8, 10, 12]

# DNS Error Response (Flags = 0x8183: QR=1, RD=1, RA=1, RCODE=3)
dns_Syntax_Groundtruth[b'\x81\x83'] = [2, 4, 6, 8, 10, 12]

# 通用DNS消息边界（适用于大多数情况）
dns_Syntax_Groundtruth['default'] = [2, 4, 6, 8, 10, 12]

# 同时支持字符串键（为了兼容性）
dns_Syntax_Groundtruth['0100'] = [2, 4, 6, 8, 10, 12]
dns_Syntax_Groundtruth['8180'] = [2, 4, 6, 8, 10, 12]
dns_Syntax_Groundtruth['0000'] = [2, 4, 6, 8, 10, 12]
dns_Syntax_Groundtruth['8400'] = [2, 4, 6, 8, 10, 12]
dns_Syntax_Groundtruth['8183'] = [2, 4, 6, 8, 10, 12]

# DNS协议特定偏移量定义
dns_lengthOffset = None  # DNS over UDP没有长度字段
dns_commandOffset = '2,3'  # DNS Flags字段位置
dns_checksumOffset = None  # DNS依赖于底层传输协议的校验

dns_Semantic_Groundtruth = {}
dns_Semantic_Functions_Groundtruth = {}

''' Semantic-Type Groundtruth - 修复版本 '''


# DNS消息通用语义类型定义（基于Flags字段）
def create_dns_semantic_groundtruth(flags_key):
    return {
        '0,1': semantic_Types[3],  # Transaction ID (Bit Field)
        '2,3': semantic_Types[3],  # Flags (Bit Field)
        '4,5': semantic_Types[3],  # Questions count (Bit Field)
        '6,7': semantic_Types[3],  # Answer RRs count (Bit Field)
        '8,9': semantic_Types[3],  # Authority RRs count (Bit Field)
        '10,11': semantic_Types[3],  # Additional RRs count (Bit Field)
        '12,+': semantic_Types[4]  # Variable data (Bytes)
    }


# DNS标准查询 (Flags = 0x0100) - 字节键
dns_Semantic_Groundtruth[b'\x01\x00'] = create_dns_semantic_groundtruth('0100')

# DNS标准响应 (Flags = 0x8180) - 字节键
dns_Semantic_Groundtruth[b'\x81\x80'] = create_dns_semantic_groundtruth('8180')

# DNS其他查询类型 - 字节键
dns_Semantic_Groundtruth[b'\x00\x00'] = create_dns_semantic_groundtruth('0000')
dns_Semantic_Groundtruth[b'\x84\x00'] = create_dns_semantic_groundtruth('8400')
dns_Semantic_Groundtruth[b'\x81\x83'] = create_dns_semantic_groundtruth('8183')

# 同时支持字符串键（为了兼容性）
dns_Semantic_Groundtruth['0100'] = create_dns_semantic_groundtruth('0100')
dns_Semantic_Groundtruth['8180'] = create_dns_semantic_groundtruth('8180')
dns_Semantic_Groundtruth['0000'] = create_dns_semantic_groundtruth('0000')
dns_Semantic_Groundtruth['8400'] = create_dns_semantic_groundtruth('8400')
dns_Semantic_Groundtruth['8183'] = create_dns_semantic_groundtruth('8183')

# 默认语义类型
dns_Semantic_Groundtruth['default'] = create_dns_semantic_groundtruth('default')

''' Semantic-Function Groundtruth - 修复版本 '''


def create_dns_semantic_functions(flags_key):
    return {
        '2,3': semantic_Functions[0],  # Flags (Command)
        '4,5': semantic_Functions[1],  # Questions count (Length)
        '6,7': semantic_Functions[1],  # Answer count (Length)
        '8,9': semantic_Functions[1],  # Authority count (Length)
        '10,11': semantic_Functions[1],  # Additional count (Length)
    }


# DNS标准查询功能定义 - 字节键
dns_Semantic_Functions_Groundtruth[b'\x01\x00'] = create_dns_semantic_functions('0100')

# DNS标准响应功能定义 - 字节键
dns_Semantic_Functions_Groundtruth[b'\x81\x80'] = create_dns_semantic_functions('8180')

# DNS其他类型功能定义 - 字节键
dns_Semantic_Functions_Groundtruth[b'\x00\x00'] = create_dns_semantic_functions('0000')
dns_Semantic_Functions_Groundtruth[b'\x84\x00'] = create_dns_semantic_functions('8400')
dns_Semantic_Functions_Groundtruth[b'\x81\x83'] = create_dns_semantic_functions('8183')

# 同时支持字符串键（为了兼容性）
dns_Semantic_Functions_Groundtruth['0100'] = create_dns_semantic_functions('0100')
dns_Semantic_Functions_Groundtruth['8180'] = create_dns_semantic_functions('8180')
dns_Semantic_Functions_Groundtruth['0000'] = create_dns_semantic_functions('0000')
dns_Semantic_Functions_Groundtruth['8400'] = create_dns_semantic_functions('8400')
dns_Semantic_Functions_Groundtruth['8183'] = create_dns_semantic_functions('8183')

# 默认功能定义
dns_Semantic_Functions_Groundtruth['default'] = create_dns_semantic_functions('default')


# ===== 新增：基于实际数据的解析函数 =====

def extract_dns_key(hex_data):
    """
    从DNS十六进制数据中提取用于匹配groundtruth的键

    Args:
        hex_data (str): DNS消息的十六进制字符串

    Returns:
        bytes: 用于匹配groundtruth的键（Flags字段的字节形式）
    """
    if len(hex_data) < 8:
        return 'default'

    # 提取Flags字段 (位置2-3, 即第4-7个字符)
    flags_hex = hex_data[4:8]

    try:
        # 转换为字节形式
        flags_bytes = bytes.fromhex(flags_hex)

        # 如果在groundtruth中找到对应键，返回该键
        if flags_bytes in dns_Syntax_Groundtruth:
            return flags_bytes
        elif flags_hex.upper() in dns_Syntax_Groundtruth:
            return flags_bytes  # 返回字节形式，但知道字符串键存在
        else:
            return 'default'
    except ValueError:
        return 'default'


def get_dns_boundaries(hex_data):
    """
    获取DNS消息的字段边界

    Args:
        hex_data (str): DNS消息的十六进制字符串

    Returns:
        list: 字段边界位置列表
    """
    key = extract_dns_key(hex_data)

    # 处理字节形式的键
    if isinstance(key, bytes):
        if key in dns_Syntax_Groundtruth:
            return dns_Syntax_Groundtruth[key]
        else:
            # 尝试字符串形式
            hex_key = key.hex().upper()
            if hex_key in dns_Syntax_Groundtruth:
                return dns_Syntax_Groundtruth[hex_key]

    # 使用字符串键或默认值
    return dns_Syntax_Groundtruth.get(key, dns_Syntax_Groundtruth['default'])


def get_dns_semantic_types(hex_data):
    """
    获取DNS消息的语义类型

    Args:
        hex_data (str): DNS消息的十六进制字符串

    Returns:
        dict: 字段位置到语义类型的映射
    """
    key = extract_dns_key(hex_data)

    # 处理字节形式的键
    if isinstance(key, bytes):
        if key in dns_Semantic_Groundtruth:
            return dns_Semantic_Groundtruth[key]
        else:
            # 尝试字符串形式
            hex_key = key.hex().upper()
            if hex_key in dns_Semantic_Groundtruth:
                return dns_Semantic_Groundtruth[hex_key]

    # 使用字符串键或默认值
    return dns_Semantic_Groundtruth.get(key, dns_Semantic_Groundtruth['default'])


def get_dns_semantic_functions(hex_data):
    """
    获取DNS消息的语义功能

    Args:
        hex_data (str): DNS消息的十六进制字符串

    Returns:
        dict: 字段位置到语义功能的映射
    """
    key = extract_dns_key(hex_data)

    # 处理字节形式的键
    if isinstance(key, bytes):
        if key in dns_Semantic_Functions_Groundtruth:
            return dns_Semantic_Functions_Groundtruth[key]
        else:
            # 尝试字符串形式
            hex_key = key.hex().upper()
            if hex_key in dns_Semantic_Functions_Groundtruth:
                return dns_Semantic_Functions_Groundtruth[hex_key]

    # 使用字符串键或默认值
    return dns_Semantic_Functions_Groundtruth.get(key, dns_Semantic_Functions_Groundtruth['default'])


# ===== 测试函数 =====
def test_dns_groundtruth():
    """测试修复后的DNS groundtruth"""

    test_data = [
        "60d5010000010000000000000b6476672d67657374616c740264650000010001",  # Query
        "60d5818000010001000000000b6476672d67657374616c740264650000010001c00c0001000100001c1f000458c61c28",  # Response
        "0a7c01000001000000000000037777770b6476672d67657374616c740264650000010001",  # Query
        "0a7c81800001000100000000037777770b6476672d67657374616c740264650000010001c00c0001000100001c1f000458c61c28"
        # Response
    ]

    print("=== DNS Groundtruth测试结果 ===")
    for i, data in enumerate(test_data):
        print(f"\n测试数据 {i + 1}:")
        print(f"  原始数据: {data[:32]}...")
        print(f"  数据长度: {len(data) // 2} 字节")

        # 提取关键信息
        transaction_id = data[0:4]
        flags = data[4:8]
        key = extract_dns_key(data)

        print(f"  Transaction ID: 0x{transaction_id}")
        print(f"  Flags: 0x{flags}")
        print(f"  匹配键: {key}")

        # 获取边界
        boundaries = get_dns_boundaries(data)
        print(f"  边界数量: {len(boundaries)}")
        print(f"  边界位置: {boundaries}")

        # 获取语义类型数量
        semantic_types = get_dns_semantic_types(data)
        print(f"  语义类型数量: {len(semantic_types)}")

        # 获取语义功能数量
        semantic_functions = get_dns_semantic_functions(data)
        print(f"  语义功能数量: {len(semantic_functions)}")


if __name__ == "__main__":
    test_dns_groundtruth()