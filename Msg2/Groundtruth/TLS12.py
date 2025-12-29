# TLS1.2 (Transport Layer Security version 1.2) 协议 Groundtruth 定义
# 基于RFC 5246和实际TLS握手分析

semantic_Types = ['Static', 'Group', 'String', 'Bit Field', 'Bytes']
semantic_Functions = ['Command', 'Length', 'Delim', 'CheckSum', 'Aligned', 'Filename']

tls12_Syntax_Groundtruth = {}

# TLS Record Layer Header (5 bytes): ContentType(1) + Version(2) + Length(2)
# 然后是具体的消息内容

# TLS Handshake Record (ContentType = 0x16)
# Handshake Header: Type(1) + Length(3)

# Client Hello (HandshakeType = 0x01)
tls12_Syntax_Groundtruth[b'\x16\x03\x01'] = [-1, 1, 3, 5, 6, 9, 11, 43, 44, 45, 47, 49, 51]

# Server Hello (HandshakeType = 0x02)
tls12_Syntax_Groundtruth[b'\x16\x03\x02'] = [-1, 1, 3, 5, 6, 9, 11, 43, 44, 45, 47, 48, 49, 51]

# Certificate (HandshakeType = 0x0b)
tls12_Syntax_Groundtruth[b'\x16\x03\x0b'] = [-1, 1, 3, 5, 6, 9, 12, 15, 18]

# Server Key Exchange (HandshakeType = 0x0c)
tls12_Syntax_Groundtruth[b'\x16\x03\x0c'] = [-1, 1, 3, 5, 6, 9, 12, 14, 16, 18]

# Server Hello Done (HandshakeType = 0x0e)
tls12_Syntax_Groundtruth[b'\x16\x03\x0e'] = [-1, 1, 3, 5, 6, 9]

# Client Key Exchange (HandshakeType = 0x10)
tls12_Syntax_Groundtruth[b'\x16\x03\x10'] = [-1, 1, 3, 5, 6, 9, 12, 14, 16]

# Finished (HandshakeType = 0x14)
tls12_Syntax_Groundtruth[b'\x16\x03\x14'] = [-1, 1, 3, 5, 6, 9, 21]

# Change Cipher Spec (ContentType = 0x14)
tls12_Syntax_Groundtruth[b'\x14\x03\x03'] = [-1, 1, 3, 5, 6]

# Alert (ContentType = 0x15)
tls12_Syntax_Groundtruth[b'\x15\x03\x03'] = [-1, 1, 3, 5, 6, 7]

# Application Data (ContentType = 0x17)
tls12_Syntax_Groundtruth[b'\x17\x03\x03'] = [-1, 1, 3, 5, 6]

# TLS协议特定偏移量定义
tls12_lengthOffset = '3,4'  # TLS Record Length
tls12_commandOffset = '0'   # Content Type
tls12_checksumOffset = None # TLS使用MAC，不是简单校验和

tls12_Semantic_Groundtruth = {}
tls12_Semantic_Functions_Groundtruth = {}

''' Semantic-Type Groundtruth '''

# Client Hello (0x16 0x03 0x01)
tls12_Semantic_Groundtruth[b'\x16\x03\x01'] = {
    '0': semantic_Types[1],       # Content Type (Handshake)
    '1,2': semantic_Types[0],     # TLS Version (0x0303)
    '3,4': semantic_Types[3],     # Record Length
    '5': semantic_Types[1],       # Handshake Type (Client Hello)
    '6,8': semantic_Types[3],     # Handshake Length
    '9,10': semantic_Types[0],    # Client Version
    '11,42': semantic_Types[4],   # Client Random (32 bytes)
    '43': semantic_Types[3],      # Session ID Length
    '44': semantic_Types[4],      # Session ID (if any)
    '45,46': semantic_Types[3],   # Cipher Suites Length
    '47,+': semantic_Types[4]     # Cipher Suites + Extensions
}

# Server Hello (0x16 0x03 0x02)
tls12_Semantic_Groundtruth[b'\x16\x03\x02'] = {
    '0': semantic_Types[1],       # Content Type (Handshake)
    '1,2': semantic_Types[0],     # TLS Version
    '3,4': semantic_Types[3],     # Record Length
    '5': semantic_Types[1],       # Handshake Type (Server Hello)
    '6,8': semantic_Types[3],     # Handshake Length
    '9,10': semantic_Types[0],    # Server Version
    '11,42': semantic_Types[4],   # Server Random (32 bytes)
    '43': semantic_Types[3],      # Session ID Length
    '44': semantic_Types[4],      # Session ID
    '45,46': semantic_Types[3],   # Cipher Suite (2 bytes)
    '47': semantic_Types[3],      # Compression Method
    '48,49': semantic_Types[3],   # Extensions Length
    '50,+': semantic_Types[4]     # Extensions
}

# Certificate (0x16 0x03 0x0b)
tls12_Semantic_Groundtruth[b'\x16\x03\x0b'] = {
    '0': semantic_Types[1],       # Content Type
    '1,2': semantic_Types[0],     # TLS Version
    '3,4': semantic_Types[3],     # Record Length
    '5': semantic_Types[1],       # Handshake Type (Certificate)
    '6,8': semantic_Types[3],     # Handshake Length
    '9,11': semantic_Types[3],    # Certificates Length
    '12,14': semantic_Types[3],   # First Certificate Length
    '15,+': semantic_Types[4]     # Certificate Data
}

# Server Key Exchange (0x16 0x03 0x0c)
tls12_Semantic_Groundtruth[b'\x16\x03\x0c'] = {
    '0': semantic_Types[1],       # Content Type
    '1,2': semantic_Types[0],     # TLS Version
    '3,4': semantic_Types[3],     # Record Length
    '5': semantic_Types[1],       # Handshake Type (Server Key Exchange)
    '6,8': semantic_Types[3],     # Handshake Length
    '9,+': semantic_Types[4]      # Key Exchange Data
}

# Change Cipher Spec (0x14 0x03 0x03)
tls12_Semantic_Groundtruth[b'\x14\x03\x03'] = {
    '0': semantic_Types[1],       # Content Type (Change Cipher Spec)
    '1,2': semantic_Types[0],     # TLS Version
    '3,4': semantic_Types[3],     # Record Length
    '5': semantic_Types[3]        # Change Cipher Spec Message (0x01)
}

# Alert (0x15 0x03 0x03)
tls12_Semantic_Groundtruth[b'\x15\x03\x03'] = {
    '0': semantic_Types[1],       # Content Type (Alert)
    '1,2': semantic_Types[0],     # TLS Version
    '3,4': semantic_Types[3],     # Record Length
    '5': semantic_Types[3],       # Alert Level (Warning/Fatal)
    '6': semantic_Types[3]        # Alert Description
}

# Application Data (0x17 0x03 0x03)
tls12_Semantic_Groundtruth[b'\x17\x03\x03'] = {
    '0': semantic_Types[1],       # Content Type (Application Data)
    '1,2': semantic_Types[0],     # TLS Version
    '3,4': semantic_Types[3],     # Record Length
    '5,+': semantic_Types[4]      # Encrypted Application Data
}

# Finished (0x16 0x03 0x14)
tls12_Semantic_Groundtruth[b'\x16\x03\x14'] = {
    '0': semantic_Types[1],       # Content Type
    '1,2': semantic_Types[0],     # TLS Version
    '3,4': semantic_Types[3],     # Record Length
    '5': semantic_Types[1],       # Handshake Type (Finished)
    '6,8': semantic_Types[3],     # Handshake Length
    '9,20': semantic_Types[4]     # Verify Data (12 bytes)
}

''' Semantic-Function Groundtruth '''

tls12_Semantic_Functions_Groundtruth[b'\x16\x03\x01'] = {
    '0': semantic_Functions[0],      # Content Type (Command)
    '3,4': semantic_Functions[1],    # Record Length
    '5': semantic_Functions[0],      # Handshake Type (Command)
    '6,8': semantic_Functions[1],    # Handshake Length
    '43': semantic_Functions[1],     # Session ID Length
    '45,46': semantic_Functions[1],  # Cipher Suites Length
}

tls12_Semantic_Functions_Groundtruth[b'\x16\x03\x02'] = {
    '0': semantic_Functions[0],      # Content Type
    '3,4': semantic_Functions[1],    # Record Length
    '5': semantic_Functions[0],      # Handshake Type
    '6,8': semantic_Functions[1],    # Handshake Length
    '43': semantic_Functions[1],     # Session ID Length
    '48,49': semantic_Functions[1],  # Extensions Length
}

tls12_Semantic_Functions_Groundtruth[b'\x16\x03\x0b'] = {
    '0': semantic_Functions[0],      # Content Type
    '3,4': semantic_Functions[1],    # Record Length
    '5': semantic_Functions[0],      # Handshake Type
    '6,8': semantic_Functions[1],    # Handshake Length
    '9,11': semantic_Functions[1],   # Certificates Length
    '12,14': semantic_Functions[1],  # Certificate Length
}

tls12_Semantic_Functions_Groundtruth[b'\x16\x03\x0c'] = {
    '0': semantic_Functions[0],      # Content Type
    '3,4': semantic_Functions[1],    # Record Length
    '5': semantic_Functions[0],      # Handshake Type
    '6,8': semantic_Functions[1],    # Handshake Length
}

tls12_Semantic_Functions_Groundtruth[b'\x14\x03\x03'] = {
    '0': semantic_Functions[0],      # Content Type
    '3,4': semantic_Functions[1],    # Record Length
}

tls12_Semantic_Functions_Groundtruth[b'\x15\x03\x03'] = {
    '0': semantic_Functions[0],      # Content Type
    '3,4': semantic_Functions[1],    # Record Length
}

tls12_Semantic_Functions_Groundtruth[b'\x17\x03\x03'] = {
    '0': semantic_Functions[0],      # Content Type
    '3,4': semantic_Functions[1],    # Record Length
}

tls12_Semantic_Functions_Groundtruth[b'\x16\x03\x14'] = {
    '0': semantic_Functions[0],      # Content Type
    '3,4': semantic_Functions[1],    # Record Length
    '5': semantic_Functions[0],      # Handshake Type
    '6,8': semantic_Functions[1],    # Handshake Length
}