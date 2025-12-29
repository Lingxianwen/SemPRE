# 该代码通过结构化数据定义了DNP3协议不同功能码的消息格式（字段边界）和语义（类型与功能），
# 作为评估逆向工具准确性的基准。Groundtruth 在此是人工标注的正确答案，用于计算工具输出的精确率（Precision）、召回率（Recall）等指标。
# 语法边界定义 (dnp3_Syntax_Groundtruth) - 定义了不同DNP3功能码的字段边界
# 语义类型标注 (dnp3_Semantic_Groundtruth) - 标注每个字段的语义类型
# 语义功能标注 (dnp3_Semantic_Functions_Groundtruth) - 标注关键字段的功能

semantic_Types = ['Static', 'Group', 'String', 'Bit Field', 'Bytes']
semantic_Functions = ['Command', 'Length', 'Delim', 'CheckSum', 'Aligned', 'Filename']

dnp3_Syntax_Groundtruth = {}

# DNP3 Data Link Layer (常见帧格式) - 基于实际消息分析
# Format 1: 基本数据链路层帧 (0x05 0x64)
dnp3_Syntax_Groundtruth[b'\x05\x64'] = [-1, 2, 3, 5, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28]

# 基于实际消息中的功能码定义格式
# Format 2: Function Code 0x00 (Confirm/Null Data)
dnp3_Syntax_Groundtruth[b'\x00'] = [-1, 1, 2, 3, 4]

# Format 3: Function Code 0x01 (READ请求)
dnp3_Syntax_Groundtruth[b'\x01'] = [-1, 1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24]

# Format 4: Function Code 0x02 (WRITE请求)
dnp3_Syntax_Groundtruth[b'\x02'] = [-1, 1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24]

# Format 5: Function Code 0x03 (SELECT请求)
dnp3_Syntax_Groundtruth[b'\x03'] = [-1, 1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38]

# Format 6: Function Code 0x0D (Unsolicited Response Disable)
dnp3_Syntax_Groundtruth[b'\x0d'] = [-1, 1, 2, 3, 4]

# Format 7: Function Code 0x12 (Delay Measurement)
dnp3_Syntax_Groundtruth[b'\x12'] = [-1, 1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22]

# Format 8: Function Code 0x14 (Record Current Time)
dnp3_Syntax_Groundtruth[b'\x14'] = [-1, 1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22]

# Format 9: Function Code 0x15 (File Transport)
dnp3_Syntax_Groundtruth[b'\x15'] = [-1, 1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22]

# DNP3协议特定偏移量定义
dnp3_lengthOffset = '2'  # Data Link Layer长度字段
dnp3_commandOffset = '12'  # Application Layer功能码字段 (修正为实际位置)
dnp3_checksumOffset = '8,9'  # Data Link Layer校验和字段

# Groundtruth: 基于实际消息分析

dnp3_Semantic_Groundtruth = {}
dnp3_Semantic_Functions_Groundtruth = {}

''' Semantic-Type Groundtruth '''

# DNP3 Data Link Layer Frame (基于实际消息结构)
dnp3_Semantic_Groundtruth[b'\x05\x64'] = {
    '0,1': semantic_Types[0],    # Start bytes (0x0564)
    '2': semantic_Types[1],      # Length
    '3': semantic_Types[3],      # Control field
    '4,5': semantic_Types[3],    # Destination address
    '6,7': semantic_Types[3],    # Source address
    '8,9': semantic_Types[3],    # CRC
    '10': semantic_Types[0],     # Transport header
    '11': semantic_Types[0],     # Application header - Control
    '12': semantic_Types[1],     # Application header - Function code
    '13,+': semantic_Types[4]    # Application data
}

# Function Code 0x00 (Confirm/Null Data)
dnp3_Semantic_Groundtruth[b'\x00'] = {
    '0': semantic_Types[0],      # Application Control
    '1': semantic_Types[1],      # Function Code
    '2,+': semantic_Types[4]     # Data
}

# Function Code 0x01 (READ Request)
dnp3_Semantic_Groundtruth[b'\x01'] = {
    '0': semantic_Types[0],      # Application Control
    '1': semantic_Types[1],      # Function Code
    '2,3': semantic_Types[3],    # Object Group/Variation
    '4': semantic_Types[3],      # Qualifier Code
    '5,6': semantic_Types[3],    # Range Start
    '7,8': semantic_Types[3],    # Range Stop
    '9,+': semantic_Types[4]     # Additional data
}

# Function Code 0x02 (WRITE Request)
dnp3_Semantic_Groundtruth[b'\x02'] = {
    '0': semantic_Types[0],      # Application Control
    '1': semantic_Types[1],      # Function Code
    '2,3': semantic_Types[3],    # Object Group/Variation
    '4': semantic_Types[3],      # Qualifier Code
    '5,6': semantic_Types[3],    # Range/Count
    '7,8': semantic_Types[3],    # Index/Additional info
    '9,+': semantic_Types[4]     # Object data
}

# Function Code 0x03 (SELECT Request)
dnp3_Semantic_Groundtruth[b'\x03'] = {
    '0': semantic_Types[0],      # Application Control
    '1': semantic_Types[1],      # Function Code
    '2,3': semantic_Types[3],    # Object Group/Variation
    '4': semantic_Types[3],      # Qualifier Code
    '5,6': semantic_Types[3],    # Index/Range
    '7,8': semantic_Types[3],    # Control block
    '9,+': semantic_Types[4]     # Control data
}

# Function Code 0x0D (Unsolicited Response Disable)
dnp3_Semantic_Groundtruth[b'\x0d'] = {
    '0': semantic_Types[0],      # Application Control
    '1': semantic_Types[1],      # Function Code
    '2,+': semantic_Types[4]     # Data
}

# Function Code 0x12 (Delay Measurement)
dnp3_Semantic_Groundtruth[b'\x12'] = {
    '0': semantic_Types[0],      # Application Control
    '1': semantic_Types[1],      # Function Code
    '2,3': semantic_Types[3],    # Object Group/Variation
    '4': semantic_Types[3],      # Qualifier Code
    '5,6': semantic_Types[3],    # Index/Range
    '7,8': semantic_Types[3],    # Control block
    '9,+': semantic_Types[4]     # Control data
}

# Function Code 0x14 (Record Current Time)
dnp3_Semantic_Groundtruth[b'\x14'] = {
    '0': semantic_Types[0],      # Application Control
    '1': semantic_Types[1],      # Function Code
    '2,3': semantic_Types[3],    # Object Group/Variation
    '4': semantic_Types[3],      # Qualifier Code
    '5,6': semantic_Types[3],    # Index/Range
    '7,8': semantic_Types[3],    # Control block
    '9,+': semantic_Types[4]     # Control data
}

# Function Code 0x15 (File Transport)
dnp3_Semantic_Groundtruth[b'\x15'] = {
    '0': semantic_Types[0],      # Application Control
    '1': semantic_Types[1],      # Function Code
    '2,3': semantic_Types[3],    # Object Group/Variation
    '4': semantic_Types[3],      # Qualifier Code
    '5,6': semantic_Types[3],    # Index/Range
    '7,8': semantic_Types[3],    # Control block
    '9,+': semantic_Types[4]     # Control data
}

''' Semantic-Function Groundtruth '''

# Function Code 0x00 functions
dnp3_Semantic_Functions_Groundtruth[b'\x00'] = {
    '1': semantic_Functions[0],   # Function Code (Command)
}

# Function Code 0x01 functions
dnp3_Semantic_Functions_Groundtruth[b'\x01'] = {
    '1': semantic_Functions[0],   # Function Code (Command)
    '4': semantic_Functions[1],   # Qualifier (Length related)
}

# Function Code 0x02 functions
dnp3_Semantic_Functions_Groundtruth[b'\x02'] = {
    '1': semantic_Functions[0],   # Function Code (Command)
    '4': semantic_Functions[1],   # Qualifier (Length related)
}

# Function Code 0x03 functions
dnp3_Semantic_Functions_Groundtruth[b'\x03'] = {
    '1': semantic_Functions[0],   # Function Code (Command)
    '4': semantic_Functions[1],   # Qualifier (Length related)
}

# Function Code 0x0D functions
dnp3_Semantic_Functions_Groundtruth[b'\x0d'] = {
    '1': semantic_Functions[0],   # Function Code (Command)
}

# Function Code 0x12 functions
dnp3_Semantic_Functions_Groundtruth[b'\x12'] = {
    '1': semantic_Functions[0],   # Function Code (Command)
    '4': semantic_Functions[1],   # Qualifier (Length related)
}

# Function Code 0x14 functions
dnp3_Semantic_Functions_Groundtruth[b'\x14'] = {
    '1': semantic_Functions[0],   # Function Code (Command)
    '4': semantic_Functions[1],   # Qualifier (Length related)
}

# Function Code 0x15 functions
dnp3_Semantic_Functions_Groundtruth[b'\x15'] = {
    '1': semantic_Functions[0],   # Function Code (Command)
    '4': semantic_Functions[1],   # Qualifier (Length related)
}

# DNP3特有的CRC校验和定义
dnp3_Semantic_Functions_Groundtruth[b'\x05\x64'] = {
    '2': semantic_Functions[1],   # Length field
    '8,9': semantic_Functions[3], # CRC checksum
    '12': semantic_Functions[0],  # Application Function Code
}