# S7Comm (Siemens S7 Communication) 协议 Groundtruth 定义 - 修复版本
# 基于Siemens S7协议规范和Wireshark分析

semantic_Types = ['Static', 'Group', 'String', 'Bit Field', 'Bytes']
semantic_Functions = ['Command', 'Length', 'Delim', 'CheckSum', 'Aligned', 'Filename']

s7comm_Syntax_Groundtruth = {}

# S7Comm结构：TPKT Header (4 bytes) + COTP Header (3 bytes常见) + S7Comm Header (10+ bytes)
# TPKT: Version(1) + Reserved(1) + Length(2)
# COTP: Length(1) + PDU_Type(1) + Others(1)
# S7Comm Header: Protocol_ID(1) + ROSCTR(1) + Reserved(2) + PDU_Reference(2) + Parameter_Length(2) + Data_Length(2) + [Error_Class(1) + Error_Code(1)]

# S7Comm Job Request (ROSCTR = 0x01)
s7comm_Syntax_Groundtruth[b'\x01'] = [0, 2, 4, 7, 8, 10, 12, 14, 16, 18, 20]

# S7Comm Ack (ROSCTR = 0x02)
s7comm_Syntax_Groundtruth[b'\x02'] = [0, 2, 4, 7, 8, 10, 12, 14, 16, 18, 19]

# S7Comm Ack_Data (ROSCTR = 0x03)
s7comm_Syntax_Groundtruth[b'\x03'] = [0, 2, 4, 7, 8, 10, 12, 14, 16, 18, 19, 20]

# S7Comm Userdata (ROSCTR = 0x07)
s7comm_Syntax_Groundtruth[b'\x07'] = [0, 2, 4, 7, 8, 10, 12, 14, 16, 18, 20]

# S7Comm Setup Communication Request (Function = 0xF0)
s7comm_Syntax_Groundtruth[b'\xf0'] = [0, 2, 4, 7, 8, 10, 12, 14, 16, 18, 20, 22, 24]

# S7Comm Read Var Request (Function = 0x04)
s7comm_Syntax_Groundtruth[b'\x04'] = [0, 2, 4, 7, 8, 10, 12, 14, 16, 18, 20, 21, 22, 23, 24, 26]

# S7Comm Write Var Request (Function = 0x05)
s7comm_Syntax_Groundtruth[b'\x05'] = [0, 2, 4, 7, 8, 10, 12, 14, 16, 18, 20, 21, 22, 23, 24, 26, 28]

# 默认边界（用于未识别的S7Comm消息）
s7comm_Syntax_Groundtruth['default'] = [0, 2, 4, 7, 8, 10, 12, 14, 16]

# S7协议特定偏移量定义 - 修复版本
s7comm_lengthOffset = '2,3'  # TPKT Length
s7comm_commandOffset = '7'   # S7Comm ROSCTR - 修复：基于常见COTP长度3的情况
s7comm_checksumOffset = None # S7Comm依赖TPKT/COTP的完整性检查

s7comm_Semantic_Groundtruth = {}
s7comm_Semantic_Functions_Groundtruth = {}

''' Semantic-Type Groundtruth - 修复版本 '''

def create_s7comm_base_semantic_types():
    """创建S7Comm基础语义类型定义"""
    return {
        '0': semantic_Types[0],       # TPKT Version
        '1': semantic_Types[0],       # TPKT Reserved
        '2,3': semantic_Types[3],     # TPKT Length
        '4': semantic_Types[3],       # COTP Length
        '5': semantic_Types[3],       # COTP PDU Type
        '6': semantic_Types[3],       # COTP Others
        '7': semantic_Types[0],       # S7Comm Protocol ID (0x32)
        '8': semantic_Types[1],       # S7Comm ROSCTR
        '9,10': semantic_Types[0],    # S7Comm Reserved
        '11,12': semantic_Types[3],   # S7Comm PDU Reference
        '13,14': semantic_Types[3],   # S7Comm Parameter Length
        '15,16': semantic_Types[3],   # S7Comm Data Length
    }

# S7Comm Job Request (ROSCTR = 0x01)
s7comm_Semantic_Groundtruth[b'\x01'] = {
    **create_s7comm_base_semantic_types(),
    '17': semantic_Types[1],      # S7Comm Function Code
    '18': semantic_Types[3],      # S7Comm Item Count
    '19,+': semantic_Types[4]     # S7Comm Parameters/Data
}

# S7Comm Ack (ROSCTR = 0x02)
s7comm_Semantic_Groundtruth[b'\x02'] = {
    **create_s7comm_base_semantic_types(),
    '17': semantic_Types[3],      # Error Class
    '18': semantic_Types[3],      # Error Code
    '19,+': semantic_Types[4]     # Data
}

# S7Comm Ack_Data (ROSCTR = 0x03)
s7comm_Semantic_Groundtruth[b'\x03'] = {
    **create_s7comm_base_semantic_types(),
    '17': semantic_Types[3],      # Error Class
    '18': semantic_Types[3],      # Error Code
    '19': semantic_Types[1],      # Function Code
    '20': semantic_Types[3],      # Item Count
    '21,+': semantic_Types[4]     # Response Data
}

# S7Comm Userdata (ROSCTR = 0x07)
s7comm_Semantic_Groundtruth[b'\x07'] = {
    **create_s7comm_base_semantic_types(),
    '17': semantic_Types[1],      # Function Code
    '18': semantic_Types[3],      # Subfunction
    '19': semantic_Types[3],      # Sequence Number
    '20,+': semantic_Types[4]     # Userdata
}

# S7Comm Setup Communication (Function = 0xF0)
s7comm_Semantic_Groundtruth[b'\xf0'] = {
    **create_s7comm_base_semantic_types(),
    '17': semantic_Types[1],      # Function Code (0xF0)
    '18': semantic_Types[0],      # Reserved
    '19,20': semantic_Types[3],   # Max AMQ Calling
    '21,22': semantic_Types[3],   # Max AMQ Called
    '23,24': semantic_Types[3],   # PDU Length
    '25,+': semantic_Types[4]     # Additional Parameters
}

# S7Comm Read Var (Function = 0x04)
s7comm_Semantic_Groundtruth[b'\x04'] = {
    **create_s7comm_base_semantic_types(),
    '17': semantic_Types[1],      # Function Code (0x04)
    '18': semantic_Types[3],      # Item Count
    '19': semantic_Types[3],      # Variable Specification
    '20': semantic_Types[3],      # Length of address specification
    '21': semantic_Types[3],      # Syntax ID
    '22': semantic_Types[3],      # Transport Size
    '23,24': semantic_Types[3],   # Length
    '25,26': semantic_Types[3],   # DB Number
    '27,+': semantic_Types[4]     # Area/Address
}

# S7Comm Write Var (Function = 0x05)
s7comm_Semantic_Groundtruth[b'\x05'] = {
    **create_s7comm_base_semantic_types(),
    '17': semantic_Types[1],      # Function Code (0x05)
    '18': semantic_Types[3],      # Item Count
    '19': semantic_Types[3],      # Variable Specification
    '20': semantic_Types[3],      # Length of address specification
    '21': semantic_Types[3],      # Syntax ID
    '22': semantic_Types[3],      # Transport Size
    '23,24': semantic_Types[3],   # Length
    '25,26': semantic_Types[3],   # DB Number
    '27,28': semantic_Types[4],   # Area/Address
    '29,+': semantic_Types[4]     # Data to write
}

# 默认语义类型
s7comm_Semantic_Groundtruth['default'] = create_s7comm_base_semantic_types()

''' Semantic-Function Groundtruth - 修复版本 '''

def create_s7comm_base_semantic_functions():
    """创建S7Comm基础语义功能定义"""
    return {
        '2,3': semantic_Functions[1],    # TPKT Length
        '8': semantic_Functions[0],      # ROSCTR (Command type)
        '13,14': semantic_Functions[1],  # Parameter Length
        '15,16': semantic_Functions[1],  # Data Length
    }

s7comm_Semantic_Functions_Groundtruth[b'\x01'] = {
    **create_s7comm_base_semantic_functions(),
    '17': semantic_Functions[0],     # Function Code
}

s7comm_Semantic_Functions_Groundtruth[b'\x02'] = create_s7comm_base_semantic_functions()

s7comm_Semantic_Functions_Groundtruth[b'\x03'] = {
    **create_s7comm_base_semantic_functions(),
    '19': semantic_Functions[0],     # Function Code
}

s7comm_Semantic_Functions_Groundtruth[b'\x07'] = {
    **create_s7comm_base_semantic_functions(),
    '17': semantic_Functions[0],     # Function Code
}

s7comm_Semantic_Functions_Groundtruth[b'\xf0'] = {
    **create_s7comm_base_semantic_functions(),
    '17': semantic_Functions[0],     # Function Code
    '23,24': semantic_Functions[1],  # PDU Length
}

s7comm_Semantic_Functions_Groundtruth[b'\x04'] = {
    **create_s7comm_base_semantic_functions(),
    '17': semantic_Functions[0],     # Function Code
    '20': semantic_Functions[1],     # Address specification length
    '23,24': semantic_Functions[1],  # Data length
}

s7comm_Semantic_Functions_Groundtruth[b'\x05'] = {
    **create_s7comm_base_semantic_functions(),
    '17': semantic_Functions[0],     # Function Code
    '20': semantic_Functions[1],     # Address specification length
    '23,24': semantic_Functions[1],  # Data length
}

# 默认语义功能
s7comm_Semantic_Functions_Groundtruth['default'] = create_s7comm_base_semantic_functions()


# ===== 新增：S7Comm协议辅助函数 =====

def extract_s7comm_rosctr(hex_data):
    """
    从S7Comm十六进制数据中提取ROSCTR字节

    Args:
        hex_data (str): S7Comm消息的十六进制字符串

    Returns:
        bytes: ROSCTR字节，如果无效则返回None
    """
    if len(hex_data) < 24:  # 至少需要12字节到达ROSCTR位置
        return None

    # 检查TPKT协议标识符（版本应该是0x03）
    if not hex_data.startswith('03'):
        return None

    # 提取ROSCTR字节（第11字节，索引22-23）
    try:
        rosctr_hex = hex_data[22:24]
        return bytes.fromhex(rosctr_hex)
    except ValueError:
        return None


def extract_s7comm_function(hex_data):
    """
    从S7Comm十六进制数据中提取功能码

    Args:
        hex_data (str): S7Comm消息的十六进制字符串

    Returns:
        bytes: 功能码字节，如果无效则返回None
    """
    if len(hex_data) < 44:  # 至少需要22字节到达功能码位置
        return None

    # 提取功能码字节（第21字节，索引42-43）
    try:
        function_hex = hex_data[42:44]
        return bytes.fromhex(function_hex)
    except ValueError:
        return None