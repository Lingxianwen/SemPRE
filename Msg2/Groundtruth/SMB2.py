# SMB2 (Server Message Block version 2) 协议 Groundtruth 定义 - 修复版本
# 基于SMB2协议规范和实际消息分析，移除NetBIOS Session Service Header假设

semantic_Types = ['Static', 'Group', 'String', 'Bit Field', 'Bytes']
semantic_Functions = ['Command', 'Length', 'Delim', 'CheckSum', 'Aligned', 'Filename']

smb2_Syntax_Groundtruth = {}

# SMB2 Header结构（64字节）：
# Protocol(4) + StructureSize(2) + CreditCharge(2) + Status(4) + Command(2) + Credit(2) +
# Flags(4) + NextCommand(4) + MessageId(8) + ProcessId(4) + TreeId(4) + SessionId(8) + Signature(16)

# SMB2 Negotiate Request (Command 0x0000)
smb2_Syntax_Groundtruth[b'\x00\x00'] = [4, 6, 8, 12, 14, 16, 20, 24, 32, 36, 40, 48, 64, 66, 68]

# SMB2 Session Setup Request (Command 0x0001)
smb2_Syntax_Groundtruth[b'\x00\x01'] = [4, 6, 8, 12, 14, 16, 20, 24, 32, 36, 40, 48, 64, 66, 67, 68, 72, 76]

# SMB2 Tree Connect Request (Command 0x0003)
smb2_Syntax_Groundtruth[b'\x00\x03'] = [4, 6, 8, 12, 14, 16, 20, 24, 32, 36, 40, 48, 64, 66, 68, 70]

# SMB2 Create Request (Command 0x0005)
smb2_Syntax_Groundtruth[b'\x00\x05'] = [4, 6, 8, 12, 14, 16, 20, 24, 32, 36, 40, 48, 64, 66, 67, 68, 72, 80, 88, 92, 96, 100, 104, 108, 112, 114, 116, 120, 124]

# SMB2 Close Request (Command 0x0006)
smb2_Syntax_Groundtruth[b'\x00\x06'] = [4, 6, 8, 12, 14, 16, 20, 24, 32, 36, 40, 48, 64, 66, 68, 84]

# SMB2 Read Request (Command 0x0008)
smb2_Syntax_Groundtruth[b'\x00\x08'] = [4, 6, 8, 12, 14, 16, 20, 24, 32, 36, 40, 48, 64, 66, 68, 72, 76, 80, 84, 88, 104]

# SMB2 Write Request (Command 0x0009)
smb2_Syntax_Groundtruth[b'\x00\x09'] = [4, 6, 8, 12, 14, 16, 20, 24, 32, 36, 40, 48, 64, 66, 68, 72, 76, 80, 84, 88, 104]

# SMB2协议特定偏移量定义 - 修复版本
smb2_lengthOffset = None  # SMB2本身没有单独的长度字段
smb2_commandOffset = '12,13'  # SMB2 Command (2 bytes) - 修复：从16,17改为12,13
smb2_checksumOffset = '48,63'  # SMB2 Signature (16 bytes) - 修复：从52,67改为48,63

smb2_Semantic_Groundtruth = {}
smb2_Semantic_Functions_Groundtruth = {}

''' Semantic-Type Groundtruth - 修复版本 '''

def create_smb2_base_semantic_types():
    """创建SMB2基础语义类型定义"""
    return {
        '0,3': semantic_Types[0],     # SMB2 Protocol Identifier (\xfeSMB)
        '4,5': semantic_Types[0],     # Structure Size
        '6,7': semantic_Types[3],     # Credit Charge
        '8,11': semantic_Types[3],    # Status
        '12,13': semantic_Types[1],   # Command
        '14,15': semantic_Types[3],   # Credit Request/Response
        '16,19': semantic_Types[3],   # Flags
        '20,23': semantic_Types[3],   # Next Command
        '24,31': semantic_Types[3],   # Message ID
        '32,35': semantic_Types[3],   # Process ID
        '36,39': semantic_Types[3],   # Tree ID
        '40,47': semantic_Types[3],   # Session ID
        '48,63': semantic_Types[3],   # Signature
    }

# SMB2 Negotiate Request (0x0000)
smb2_Semantic_Groundtruth[b'\x00\x00'] = {
    **create_smb2_base_semantic_types(),
    '64,65': semantic_Types[0],   # Structure Size
    '66,67': semantic_Types[3],   # Dialect Count
    '68,+': semantic_Types[4]     # Dialects
}

# SMB2 Session Setup Request (0x0001)
smb2_Semantic_Groundtruth[b'\x00\x01'] = {
    **create_smb2_base_semantic_types(),
    '64,65': semantic_Types[0],   # Structure Size
    '66': semantic_Types[3],      # Flags
    '67': semantic_Types[3],      # Security Mode
    '68,71': semantic_Types[3],   # Capabilities
    '72,75': semantic_Types[3],   # Channel
    '76,+': semantic_Types[4]     # Security Buffer
}

# SMB2 Tree Connect Request (0x0003)
smb2_Semantic_Groundtruth[b'\x00\x03'] = {
    **create_smb2_base_semantic_types(),
    '64,65': semantic_Types[0],   # Structure Size
    '66,67': semantic_Types[0],   # Reserved
    '68,69': semantic_Types[3],   # Path Offset
    '70,+': semantic_Types[2]     # Path (String)
}

# SMB2 Create Request (0x0005)
smb2_Semantic_Groundtruth[b'\x00\x05'] = {
    **create_smb2_base_semantic_types(),
    '64,65': semantic_Types[0],   # Structure Size
    '66': semantic_Types[3],      # Security Flags
    '67': semantic_Types[3],      # Requested Oplock Level
    '68,71': semantic_Types[3],   # Impersonation Level
    '72,79': semantic_Types[3],   # SMB Create Flags
    '80,87': semantic_Types[0],   # Reserved
    '88,91': semantic_Types[3],   # Desired Access
    '92,95': semantic_Types[3],   # File Attributes
    '96,99': semantic_Types[3],   # Share Access
    '100,103': semantic_Types[3], # Create Disposition
    '104,107': semantic_Types[3], # Create Options
    '108,109': semantic_Types[3], # Name Offset
    '110,111': semantic_Types[3], # Name Length
    '112,115': semantic_Types[3], # Create Contexts Offset
    '116,119': semantic_Types[3], # Create Contexts Length
    '120,+': semantic_Types[2]    # Filename (String)
}

# SMB2 Close Request (0x0006)
smb2_Semantic_Groundtruth[b'\x00\x06'] = {
    **create_smb2_base_semantic_types(),
    '64,65': semantic_Types[0],   # Structure Size
    '66,67': semantic_Types[3],   # Flags
    '68,83': semantic_Types[3],   # File ID
}

# SMB2 Read Request (0x0008)
smb2_Semantic_Groundtruth[b'\x00\x08'] = {
    **create_smb2_base_semantic_types(),
    '64,65': semantic_Types[0],   # Structure Size
    '66': semantic_Types[3],      # Padding
    '67': semantic_Types[3],      # Flags
    '68,71': semantic_Types[3],   # Length
    '72,79': semantic_Types[3],   # Offset
    '80,95': semantic_Types[3],   # File ID
    '96,99': semantic_Types[3],   # Minimum Count
    '100,103': semantic_Types[3], # Channel
}

# SMB2 Write Request (0x0009)
smb2_Semantic_Groundtruth[b'\x00\x09'] = {
    **create_smb2_base_semantic_types(),
    '64,65': semantic_Types[0],   # Structure Size
    '66,67': semantic_Types[3],   # Data Offset
    '68,71': semantic_Types[3],   # Length
    '72,79': semantic_Types[3],   # Offset
    '80,95': semantic_Types[3],   # File ID
    '96,99': semantic_Types[3],   # Channel
    '100,103': semantic_Types[3], # Remaining Bytes
    '104,+': semantic_Types[4]    # Data
}

# 默认语义类型
smb2_Semantic_Groundtruth['default'] = create_smb2_base_semantic_types()

''' Semantic-Function Groundtruth - 修复版本 '''

def create_smb2_base_semantic_functions():
    """创建SMB2基础语义功能定义"""
    return {
        '12,13': semantic_Functions[0],  # Command
        '48,63': semantic_Functions[3],  # Signature (CheckSum equivalent)
    }

# SMB2 Negotiate Request (0x0000)
smb2_Semantic_Functions_Groundtruth[b'\x00\x00'] = {
    **create_smb2_base_semantic_functions(),
    '66,67': semantic_Functions[1],  # Dialect Count (Length equivalent)
}

# SMB2 Session Setup Request (0x0001)
smb2_Semantic_Functions_Groundtruth[b'\x00\x01'] = create_smb2_base_semantic_functions()

# SMB2 Tree Connect Request (0x0003)
smb2_Semantic_Functions_Groundtruth[b'\x00\x03'] = {
    **create_smb2_base_semantic_functions(),
    '68,69': semantic_Functions[1],  # Path Offset (Length equivalent)
    '70,+': semantic_Functions[5],   # Path (Filename equivalent)
}

# SMB2 Create Request (0x0005)
smb2_Semantic_Functions_Groundtruth[b'\x00\x05'] = {
    **create_smb2_base_semantic_functions(),
    '108,109': semantic_Functions[1], # Name Offset (Length equivalent)
    '110,111': semantic_Functions[1], # Name Length
    '120,+': semantic_Functions[5],   # Filename
}

# SMB2 Close Request (0x0006)
smb2_Semantic_Functions_Groundtruth[b'\x00\x06'] = create_smb2_base_semantic_functions()

# SMB2 Read Request (0x0008)
smb2_Semantic_Functions_Groundtruth[b'\x00\x08'] = {
    **create_smb2_base_semantic_functions(),
    '68,71': semantic_Functions[1],   # Length
    '96,99': semantic_Functions[1],   # Minimum Count (Length equivalent)
}

# SMB2 Write Request (0x0009)
smb2_Semantic_Functions_Groundtruth[b'\x00\x09'] = {
    **create_smb2_base_semantic_functions(),
    '66,67': semantic_Functions[1],   # Data Offset (Length equivalent)
    '68,71': semantic_Functions[1],   # Length
}

# 默认语义功能
smb2_Semantic_Functions_Groundtruth['default'] = create_smb2_base_semantic_functions()


# ===== 新增：SMB2协议辅助函数 =====

def extract_smb2_command(hex_data):
    """
    从SMB2十六进制数据中提取命令字节

    Args:
        hex_data (str): SMB2消息的十六进制字符串

    Returns:
        bytes: SMB2命令字节，如果无效则返回None
    """
    if len(hex_data) < 28:  # 至少需要14字节（Protocol ID + 到Command的偏移）
        return None

    # 检查SMB2协议标识符
    protocol_id = hex_data[0:8].upper()
    if protocol_id != 'FE534D42':  # \xfe\x53\x4d\x42
        return None

    # 提取命令字节（第12-13字节，索引24-27）
    try:
        command_hex = hex_data[24:28]
        return bytes.fromhex(command_hex)
    except ValueError:
        return None


def get_smb2_boundaries(hex_data):
    """
    获取SMB2消息的字段边界

    Args:
        hex_data (str): SMB2消息的十六进制字符串

    Returns:
        list: 字段边界位置列表
    """
    command = extract_smb2_command(hex_data)
    if command and command in smb2_Syntax_Groundtruth:
        return smb2_Syntax_Groundtruth[command]
    else:
        return smb2_Syntax_Groundtruth.get('default', [4, 6, 8, 12, 14, 16, 20, 24, 32, 36, 40, 48, 64])


def get_smb2_semantic_types(hex_data):
    """
    获取SMB2消息的语义类型

    Args:
        hex_data (str): SMB2消息的十六进制字符串

    Returns:
        dict: 字段位置到语义类型的映射
    """
    command = extract_smb2_command(hex_data)
    if command and command in smb2_Semantic_Groundtruth:
        return smb2_Semantic_Groundtruth[command]
    else:
        return smb2_Semantic_Groundtruth['default']


def get_smb2_semantic_functions(hex_data):
    """
    获取SMB2消息的语义功能

    Args:
        hex_data (str): SMB2消息的十六进制字符串

    Returns:
        dict: 字段位置到语义功能的映射
    """
    command = extract_smb2_command(hex_data)
    if command and command in smb2_Semantic_Functions_Groundtruth:
        return smb2_Semantic_Functions_Groundtruth[command]
    else:
        return smb2_Semantic_Functions_Groundtruth['default']


# ===== 测试函数 =====
def test_smb2_groundtruth():
    """测试修复后的SMB2 groundtruth"""

    test_data = [
        "fe534d4240000000000000000000000000000000000000000100000000000000fffe00000000000000000000000000000000000000000000000000000000000024000500010000007f00000082d99567646fef119fbe000c29c37feb700000000400000002021002000302031103000001002600000000000100200001008ff21e7dcb4dacadf2796b25a7c0cbef91bf51da779a198654f4153ecbaeff9700000200060000000000020002000100000003001000000000000400000001000000040002000300010005003c000000000076006d00330039002d006100640032003000320034002e006100640032003000320034002e00770065006200650072006c00610062002e006400650000000000",
        "fe534d4240000100000000000100210010000000000000000200000000000000fffe00000000000000000000000000000000000000000000000000000000000019000002010000000000000058004a000000000000000000604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000978208e2000000000000000000000000000000000a00614a0000000f",
        "fe534d4240000100000000000000210010000000000000000000000000000000fffe00000000000000000000000000000000000000000000000000000000000024000500010000007f00000082d99567646fef119fbe000c29c37feb7000000005000000020210020003020311030000010026000000000001002000010065c5c2a0a013903dbce5399811e2bcc430a6e8e4fbcab5cc94bd03ad951d2fcd00000200060000000000020002000100000003001000000000000400000001000000040002000300010005003c000000000076006d00330039002d006100640032003000320034002e006100640032003000320034002e00770065006200650072006c00610062002e006400650000000000060004000000000000000000"
    ]

    print("=== SMB2 Groundtruth测试结果 ===")
    for i, data in enumerate(test_data):
        print(f"\n测试数据 {i + 1}:")
        print(f"  原始数据: {data[:32]}...")
        print(f"  数据长度: {len(data) // 2} 字节")

        # 提取SMB2命令
        command = extract_smb2_command(data)
        print(f"  SMB2命令: {command.hex().upper() if command else 'None'}")

        if command:
            # 获取边界
            boundaries = get_smb2_boundaries(data)
            print(f"  边界数量: {len(boundaries)}")
            print(f"  边界位置: {boundaries[:10]}{'...' if len(boundaries) > 10 else ''}")

            # 获取语义类型数量
            semantic_types = get_smb2_semantic_types(data)
            print(f"  语义类型数量: {len(semantic_types)}")

            # 获取语义功能数量
            semantic_functions = get_smb2_semantic_functions(data)
            print(f"  语义功能数量: {len(semantic_functions)}")

            # 命令描述
            cmd_hex = command.hex().upper()
            cmd_descriptions = {
                '0000': 'NEGOTIATE',
                '0001': 'SESSION_SETUP',
                '0002': 'LOGOFF',
                '0003': 'TREE_CONNECT',
                '0004': 'TREE_DISCONNECT',
                '0005': 'CREATE',
                '0006': 'CLOSE',
                '0008': 'READ',
                '0009': 'WRITE'
            }
            print(f"  命令描述: {cmd_descriptions.get(cmd_hex, 'UNKNOWN')}")
        else:
            print(f"  ✗ 无法识别SMB2命令")


if __name__ == "__main__":
    test_smb2_groundtruth()