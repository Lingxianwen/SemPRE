# SMB (Server Message Block) 协议 Groundtruth 定义 - 修复版本
# 基于SMB/CIFS协议规范和实际消息分析

semantic_Types = ['Static', 'Group', 'String', 'Bit Field', 'Bytes']
semantic_Functions = ['Command', 'Length', 'Delim', 'CheckSum', 'Aligned', 'Filename']

smb_Syntax_Groundtruth = {}

# ===== 修复：调整SMB头部结构定义 =====
# 实际SMB数据结构：SMB Protocol ID(4) + Command(1) + Status(4) + Flags(1) + Flags2(2) + ...
# 不包含NetBIOS Session Service Header，直接是SMB头部

# SMB Negotiate Protocol Request (Command 0x72)
smb_Syntax_Groundtruth[b'\x72'] = [4, 5, 9, 10, 12, 14, 22, 24, 26, 28, 30, 32, 33, 35]

# SMB Session Setup AndX Request (Command 0x73)
smb_Syntax_Groundtruth[b'\x73'] = [4, 5, 9, 10, 12, 14, 22, 24, 26, 28, 30, 32, 33, 34, 35, 37, 39, 41]

# SMB Tree Connect AndX Request (Command 0x75)
smb_Syntax_Groundtruth[b'\x75'] = [4, 5, 9, 10, 12, 14, 22, 24, 26, 28, 30, 32, 33, 35]

# SMB NT Create AndX Request (Command 0xa2) - 这是第一条数据的命令
smb_Syntax_Groundtruth[b'\xa2'] = [4, 5, 9, 10, 12, 14, 22, 24, 26, 28, 30, 32, 33, 35, 39, 43, 47, 51, 55, 59]

# SMB Read AndX Request (Command 0x2e)
smb_Syntax_Groundtruth[b'\x2e'] = [4, 5, 9, 10, 12, 14, 22, 24, 26, 28, 30, 32, 33, 35, 37, 39, 41]

# SMB Write AndX Request (Command 0x2f)
smb_Syntax_Groundtruth[b'\x2f'] = [4, 5, 9, 10, 12, 14, 22, 24, 26, 28, 30, 32, 33, 35, 37, 39, 41, 43]

# SMB Close Request (Command 0x04)
smb_Syntax_Groundtruth[b'\x04'] = [4, 5, 9, 10, 12, 14, 22, 24, 26, 28, 30, 32, 33]

# SMB Tree Disconnect Request (Command 0x71)
smb_Syntax_Groundtruth[b'\x71'] = [4, 5, 9, 10, 12, 14, 22, 24, 26, 28, 30, 32, 33]

# SMB Logoff AndX Request (Command 0x74)
smb_Syntax_Groundtruth[b'\x74'] = [4, 5, 9, 10, 12, 14, 22, 24, 26, 28, 30, 32, 33, 34, 35]

# SMB Transaction Request (Command 0x25)
smb_Syntax_Groundtruth[b'\x25'] = [4, 5, 9, 10, 12, 14, 22, 24, 26, 28, 30, 32, 33, 35, 37, 39, 41, 43, 45, 47, 49, 51,
                                   53, 55, 57, 59, 61]

# SMB Echo Request (Command 0x2b)
smb_Syntax_Groundtruth[b'\x2b'] = [4, 5, 9, 10, 12, 14, 22, 24, 26, 28, 30, 32, 33, 35]

# SMB Find Close Request (Command 0x34)
smb_Syntax_Groundtruth[b'\x34'] = [4, 5, 9, 10, 12, 14, 22, 24, 26, 28, 30, 32, 33, 35]

# 通用SMB边界（用于未知命令）
smb_Syntax_Groundtruth['default'] = [4, 5, 9, 10, 12, 14, 22, 24, 26, 28, 30, 32]

# SMB协议特定偏移量定义 - 修复
smb_lengthOffset = None  # SMB本身没有长度字段，长度由底层传输层提供
smb_commandOffset = '4'  # SMB Command在第4字节（修复：原来是8）
smb_checksumOffset = None  # SMB没有简单的校验和字段

smb_Semantic_Groundtruth = {}
smb_Semantic_Functions_Groundtruth = {}

''' Semantic-Type Groundtruth - 修复版本 '''


def create_smb_semantic_types():
    """创建SMB通用语义类型定义"""
    return {
        '0,3': semantic_Types[0],  # SMB Protocol Identifier (\xffSMB)
        '4': semantic_Types[1],  # SMB Command
        '5,8': semantic_Types[3],  # NT Status
        '9': semantic_Types[3],  # Flags
        '10,11': semantic_Types[3],  # Flags2
        '12,13': semantic_Types[3],  # Process ID High
        '14,21': semantic_Types[3],  # Signature
        '22,23': semantic_Types[0],  # Reserved
        '24,25': semantic_Types[3],  # Tree ID
        '26,27': semantic_Types[3],  # Process ID
        '28,29': semantic_Types[3],  # User ID
        '30,31': semantic_Types[3],  # Multiplex ID
        '32': semantic_Types[3],  # Word Count
        '33,+': semantic_Types[4]  # Parameters and Data
    }


# SMB NT Create AndX Request (0xa2) - 详细定义
smb_Semantic_Groundtruth[b'\xa2'] = {
    '0,3': semantic_Types[0],  # SMB Protocol Identifier
    '4': semantic_Types[1],  # SMB Command
    '5,8': semantic_Types[3],  # NT Status
    '9': semantic_Types[3],  # Flags
    '10,11': semantic_Types[3],  # Flags2
    '12,13': semantic_Types[3],  # Process ID High
    '14,21': semantic_Types[3],  # Signature
    '22,23': semantic_Types[0],  # Reserved
    '24,25': semantic_Types[3],  # Tree ID
    '26,27': semantic_Types[3],  # Process ID
    '28,29': semantic_Types[3],  # User ID
    '30,31': semantic_Types[3],  # Multiplex ID
    '32': semantic_Types[3],  # Word Count
    '33': semantic_Types[3],  # AndX Command
    '34': semantic_Types[0],  # AndX Reserved
    '35,36': semantic_Types[3],  # AndX Offset
    '37': semantic_Types[0],  # Reserved
    '38,39': semantic_Types[3],  # File Name Length
    '40,43': semantic_Types[3],  # Create Flags
    '44,47': semantic_Types[3],  # Root Directory FID
    '48,51': semantic_Types[3],  # Desired Access
    '52,59': semantic_Types[3],  # Allocation Size
    '60,63': semantic_Types[3],  # File Attributes
    '64,67': semantic_Types[3],  # Share Access
    '68,71': semantic_Types[3],  # Create Disposition
    '72,75': semantic_Types[3],  # Create Options
    '76,77': semantic_Types[3],  # Impersonation Level
    '78': semantic_Types[3],  # Security Flags
    '79,80': semantic_Types[3],  # Byte Count
    '81,+': semantic_Types[2]  # File Name (String)
}

# 其他常见SMB命令的语义类型
for cmd in [b'\x72', b'\x73', b'\x75', b'\x2e', b'\x2f', b'\x04', b'\x71', b'\x74', b'\x25', b'\x2b', b'\x34']:
    smb_Semantic_Groundtruth[cmd] = create_smb_semantic_types()

# 默认语义类型
smb_Semantic_Groundtruth['default'] = create_smb_semantic_types()

''' Semantic-Function Groundtruth - 修复版本 '''


def create_smb_semantic_functions():
    """创建SMB通用语义功能定义"""
    return {
        '4': semantic_Functions[0],  # Command
        '32': semantic_Functions[1],  # Word Count (类似长度)
    }


# 为所有SMB命令定义语义功能
for cmd in [b'\xa2', b'\x72', b'\x73', b'\x75', b'\x2e', b'\x2f', b'\x04', b'\x71', b'\x74', b'\x25', b'\x2b', b'\x34']:
    smb_Semantic_Functions_Groundtruth[cmd] = create_smb_semantic_functions()

# 默认语义功能
smb_Semantic_Functions_Groundtruth['default'] = create_smb_semantic_functions()


# ===== 新增：SMB协议辅助函数 =====

def extract_smb_command(hex_data):
    """
    从SMB十六进制数据中提取命令字节

    Args:
        hex_data (str): SMB消息的十六进制字符串

    Returns:
        bytes: SMB命令字节，如果无效则返回None
    """
    if len(hex_data) < 10:  # 至少需要5字节（Protocol ID + Command）
        return None

    # 检查SMB协议标识符
    protocol_id = hex_data[0:8].upper()
    if protocol_id != 'FF534D42':  # \xFF\x53\x4D\x42
        return None

    # 提取命令字节（第4字节，索引8-9）
    try:
        command_hex = hex_data[8:10]
        return bytes.fromhex(command_hex)
    except ValueError:
        return None


def get_smb_boundaries(hex_data):
    """
    获取SMB消息的字段边界

    Args:
        hex_data (str): SMB消息的十六进制字符串

    Returns:
        list: 字段边界位置列表
    """
    command = extract_smb_command(hex_data)
    if command and command in smb_Syntax_Groundtruth:
        return smb_Syntax_Groundtruth[command]
    else:
        return smb_Syntax_Groundtruth['default']


def get_smb_semantic_types(hex_data):
    """
    获取SMB消息的语义类型

    Args:
        hex_data (str): SMB消息的十六进制字符串

    Returns:
        dict: 字段位置到语义类型的映射
    """
    command = extract_smb_command(hex_data)
    if command and command in smb_Semantic_Groundtruth:
        return smb_Semantic_Groundtruth[command]
    else:
        return smb_Semantic_Groundtruth['default']


def get_smb_semantic_functions(hex_data):
    """
    获取SMB消息的语义功能

    Args:
        hex_data (str): SMB消息的十六进制字符串

    Returns:
        dict: 字段位置到语义功能的映射
    """
    command = extract_smb_command(hex_data)
    if command and command in smb_Semantic_Functions_Groundtruth:
        return smb_Semantic_Functions_Groundtruth[command]
    else:
        return smb_Semantic_Functions_Groundtruth['default']


# ===== 测试函数 =====
def test_smb_groundtruth():
    """测试修复后的SMB groundtruth"""

    test_data = [
        "ff534d42a2000000009803c8000000000000000000000000000872fc0008002c2aff008700000d4001000000000000000000000000000000000000000000000000000000000000000000000080000000001000000000000000000000000000000200ff0500000000000000000000000000000000000000",
        "ff534d4274000000009807c80000000000000000000000000000fffe0008400102ff0027000000",
        "ff534d4225000000009803c8000000000000000000000000000872fc0008c0060a000000020000000038000000000238000000000001020005000203100000000002000012000000e80100000000000070a20a0015000000000000000000000000000000000000000000000000000000ffffffffffffff7f0000000000000000ffffffffffffff7f0a000a0018150d000000000058580a000000000040a30d0000000000c0ae0d000000000060ae0d000000000098540a007000700058c60b0000000000b0c80b000000000010740b000000000000900c000000000000000000000000000000000000000000000000000000000000000000f50100000102000015020000ffffff00a8000000b0180d000000000000000000000000000500000000000000050000004700750065007300740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003800000000000000380000004200750069006c0074002d0069006e0020006100630063006f0075006e007400200066006f0072002000670075006500730074002000610063006300650073007300200074006f002000740068006500200063006f006d00700075007400650072002f0064006f006d00610069006e00000000000000000000000000000000000000000000000000000000000000000000000000ec0400000000000015000000ffffffffffffffffffffffffffffffffffffffffff00000000000000"
    ]

    print("=== SMB Groundtruth测试结果 ===")
    for i, data in enumerate(test_data):
        print(f"\n测试数据 {i + 1}:")
        print(f"  原始数据: {data[:32]}...")
        print(f"  数据长度: {len(data) // 2} 字节")

        # 提取SMB命令
        command = extract_smb_command(data)
        print(f"  SMB命令: {command.hex().upper() if command else 'None'}")

        if command:
            # 获取边界
            boundaries = get_smb_boundaries(data)
            print(f"  边界数量: {len(boundaries)}")
            print(f"  边界位置: {boundaries[:10]}{'...' if len(boundaries) > 10 else ''}")

            # 获取语义类型数量
            semantic_types = get_smb_semantic_types(data)
            print(f"  语义类型数量: {len(semantic_types)}")

            # 获取语义功能数量
            semantic_functions = get_smb_semantic_functions(data)
            print(f"  语义功能数量: {len(semantic_functions)}")

            # 命令描述
            cmd_hex = command.hex().upper()
            cmd_descriptions = {
                'A2': 'NT_CREATE_ANDX',
                '74': 'LOGOFF_ANDX',
                '25': 'TRANSACTION',
                '72': 'NEGOTIATE',
                '73': 'SESSION_SETUP_ANDX',
                '75': 'TREE_CONNECT_ANDX',
                '2E': 'READ_ANDX',
                '2F': 'WRITE_ANDX',
                '04': 'CLOSE'
            }
            print(f"  命令描述: {cmd_descriptions.get(cmd_hex, 'UNKNOWN')}")
        else:
            print(f"  ✗ 无法识别SMB命令")


if __name__ == "__main__":
    test_smb_groundtruth()