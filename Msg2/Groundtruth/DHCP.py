# DHCP (Dynamic Host Configuration Protocol) 协议 Groundtruth 定义
# 基于RFC 2131和RFC 2132

semantic_Types = ['Static', 'Group', 'String', 'Bit Field', 'Bytes']
semantic_Functions = ['Command', 'Length', 'Delim', 'CheckSum', 'Aligned', 'Filename']

dhcp_Syntax_Groundtruth = {}

# DHCP Message Format (基于BOOTP格式，共240字节固定部分 + 可变选项)
# op(1) + htype(1) + hlen(1) + hops(1) + xid(4) + secs(2) + flags(2) +
# ciaddr(4) + yiaddr(4) + siaddr(4) + giaddr(4) + chaddr(16) + sname(64) + file(128) +
# options(variable, 以magic cookie 0x63825363开始)

# DHCP Discover (op=1, options包含Message Type=1)
dhcp_Syntax_Groundtruth[b'\x01\x01'] = [-1, 1, 2, 3, 4, 8, 10, 12, 16, 20, 24, 28, 44, 108, 236, 240, 244, 246]

# DHCP Offer (op=2, options包含Message Type=2)
dhcp_Syntax_Groundtruth[b'\x02\x01'] = [-1, 1, 2, 3, 4, 8, 10, 12, 16, 20, 24, 28, 44, 108, 236, 240, 244, 246]

# DHCP Request (op=1, options包含Message Type=3)
dhcp_Syntax_Groundtruth[b'\x01\x03'] = [-1, 1, 2, 3, 4, 8, 10, 12, 16, 20, 24, 28, 44, 108, 236, 240, 244, 246, 248]

# DHCP ACK (op=2, options包含Message Type=5)
dhcp_Syntax_Groundtruth[b'\x02\x05'] = [-1, 1, 2, 3, 4, 8, 10, 12, 16, 20, 24, 28, 44, 108, 236, 240, 244, 246, 248]

# DHCP NAK (op=2, options包含Message Type=6)
dhcp_Syntax_Groundtruth[b'\x02\x06'] = [-1, 1, 2, 3, 4, 8, 10, 12, 16, 20, 24, 28, 44, 108, 236, 240, 244, 246]

# DHCP Release (op=1, options包含Message Type=7)
dhcp_Syntax_Groundtruth[b'\x01\x07'] = [-1, 1, 2, 3, 4, 8, 10, 12, 16, 20, 24, 28, 44, 108, 236, 240, 244, 246]

# DHCP Inform (op=1, options包含Message Type=8)
dhcp_Syntax_Groundtruth[b'\x01\x08'] = [-1, 1, 2, 3, 4, 8, 10, 12, 16, 20, 24, 28, 44, 108, 236, 240, 244, 246]

# DHCP协议特定偏移量定义
dhcp_lengthOffset = None  # DHCP没有显式长度字段，消息长度由选项决定
dhcp_commandOffset = '0'  # Op字段表示消息类型
dhcp_checksumOffset = None # DHCP依赖UDP校验和

dhcp_Semantic_Groundtruth = {}
dhcp_Semantic_Functions_Groundtruth = {}

''' Semantic-Type Groundtruth '''

# DHCP Discover (op=1, message type=1)
dhcp_Semantic_Groundtruth[b'\x01\x01'] = {
    '0': semantic_Types[1],       # op (1=request, 2=reply)
    '1': semantic_Types[3],       # htype (hardware type)
    '2': semantic_Types[3],       # hlen (hardware address length)
    '3': semantic_Types[3],       # hops
    '4,7': semantic_Types[3],     # xid (transaction ID)
    '8,9': semantic_Types[3],     # secs (seconds elapsed)
    '10,11': semantic_Types[3],   # flags
    '12,15': semantic_Types[3],   # ciaddr (client IP)
    '16,19': semantic_Types[3],   # yiaddr (your IP)
    '20,23': semantic_Types[3],   # siaddr (server IP)
    '24,27': semantic_Types[3],   # giaddr (gateway IP)
    '28,43': semantic_Types[4],   # chaddr (client hardware address, 16 bytes)
    '44,107': semantic_Types[2],  # sname (server name, 64 bytes)
    '108,235': semantic_Types[2], # file (boot filename, 128 bytes)
    '236,239': semantic_Types[0], # magic cookie (0x63825363)
    '240': semantic_Types[3],     # Option 53 (DHCP Message Type)
    '241': semantic_Types[3],     # Length
    '242': semantic_Types[1],     # Message Type Value
    '243,+': semantic_Types[4]    # Other options
}

# DHCP Offer (op=2, message type=2)
dhcp_Semantic_Groundtruth[b'\x02\x01'] = {
    '0': semantic_Types[1],       # op (reply)
    '1': semantic_Types[3],       # htype
    '2': semantic_Types[3],       # hlen
    '3': semantic_Types[3],       # hops
    '4,7': semantic_Types[3],     # xid
    '8,9': semantic_Types[3],     # secs
    '10,11': semantic_Types[3],   # flags
    '12,15': semantic_Types[3],   # ciaddr
    '16,19': semantic_Types[3],   # yiaddr (offered IP)
    '20,23': semantic_Types[3],   # siaddr
    '24,27': semantic_Types[3],   # giaddr
    '28,43': semantic_Types[4],   # chaddr
    '44,107': semantic_Types[2],  # sname
    '108,235': semantic_Types[2], # file
    '236,239': semantic_Types[0], # magic cookie
    '240': semantic_Types[3],     # Option 53
    '241': semantic_Types[3],     # Length
    '242': semantic_Types[1],     # Message Type (2=Offer)
    '243,+': semantic_Types[4]    # Additional options (subnet mask, lease time, etc.)
}

# DHCP Request (op=1, message type=3)
dhcp_Semantic_Groundtruth[b'\x01\x03'] = {
    '0': semantic_Types[1],       # op (request)
    '1,43': semantic_Types[3],    # DHCP header fields
    '44,235': semantic_Types[2],  # sname + file
    '236,239': semantic_Types[0], # magic cookie
    '240': semantic_Types[3],     # Option 53
    '241': semantic_Types[3],     # Length
    '242': semantic_Types[1],     # Message Type (3=Request)
    '243,+': semantic_Types[4]    # Options (requested IP, server identifier, etc.)
}

# DHCP ACK (op=2, message type=5)
dhcp_Semantic_Groundtruth[b'\x02\x05'] = {
    '0': semantic_Types[1],       # op (reply)
    '1,43': semantic_Types[3],    # DHCP header fields
    '16,19': semantic_Types[3],   # yiaddr (assigned IP)
    '44,235': semantic_Types[2],  # sname + file
    '236,239': semantic_Types[0], # magic cookie
    '240': semantic_Types[3],     # Option 53
    '241': semantic_Types[3],     # Length
    '242': semantic_Types[1],     # Message Type (5=ACK)
    '243,+': semantic_Types[4]    # Configuration options
}

# DHCP NAK (op=2, message type=6)
dhcp_Semantic_Groundtruth[b'\x02\x06'] = {
    '0': semantic_Types[1],       # op (reply)
    '1,43': semantic_Types[3],    # DHCP header fields
    '44,235': semantic_Types[2],  # sname + file
    '236,239': semantic_Types[0], # magic cookie
    '240': semantic_Types[3],     # Option 53
    '241': semantic_Types[3],     # Length
    '242': semantic_Types[1],     # Message Type (6=NAK)
    '243,+': semantic_Types[4]    # Error message option
}

# DHCP Release (op=1, message type=7)
dhcp_Semantic_Groundtruth[b'\x01\x07'] = {
    '0': semantic_Types[1],       # op (request)
    '1,43': semantic_Types[3],    # DHCP header fields
    '12,15': semantic_Types[3],   # ciaddr (client IP to release)
    '44,235': semantic_Types[2],  # sname + file
    '236,239': semantic_Types[0], # magic cookie
    '240': semantic_Types[3],     # Option 53
    '241': semantic_Types[3],     # Length
    '242': semantic_Types[1],     # Message Type (7=Release)
    '243,+': semantic_Types[4]    # Server identifier option
}

# DHCP Inform (op=1, message type=8)
dhcp_Semantic_Groundtruth[b'\x01\x08'] = {
    '0': semantic_Types[1],       # op (request)
    '1,43': semantic_Types[3],    # DHCP header fields
    '12,15': semantic_Types[3],   # ciaddr (client IP)
    '44,235': semantic_Types[2],  # sname + file
    '236,239': semantic_Types[0], # magic cookie
    '240': semantic_Types[3],     # Option 53
    '241': semantic_Types[3],     # Length
    '242': semantic_Types[1],     # Message Type (8=Inform)
    '243,+': semantic_Types[4]    # Parameter request list
}

''' Semantic-Function Groundtruth '''

dhcp_Semantic_Functions_Groundtruth[b'\x01\x01'] = {
    '0': semantic_Functions[0],      # op (Command)
    '2': semantic_Functions[1],      # hlen (Length related)
    '241': semantic_Functions[1],    # Option length
    '242': semantic_Functions[0],    # Message Type (Command)
}

dhcp_Semantic_Functions_Groundtruth[b'\x02\x01'] = {
    '0': semantic_Functions[0],      # op
    '2': semantic_Functions[1],      # hlen
    '241': semantic_Functions[1],    # Option length
    '242': semantic_Functions[0],    # Message Type
}

dhcp_Semantic_Functions_Groundtruth[b'\x01\x03'] = {
    '0': semantic_Functions[0],      # op
    '2': semantic_Functions[1],      # hlen
    '241': semantic_Functions[1],    # Option length
    '242': semantic_Functions[0],    # Message Type
}

dhcp_Semantic_Functions_Groundtruth[b'\x02\x05'] = {
    '0': semantic_Functions[0],      # op
    '2': semantic_Functions[1],      # hlen
    '241': semantic_Functions[1],    # Option length
    '242': semantic_Functions[0],    # Message Type
}

dhcp_Semantic_Functions_Groundtruth[b'\x02\x06'] = {
    '0': semantic_Functions[0],      # op
    '2': semantic_Functions[1],      # hlen
    '241': semantic_Functions[1],    # Option length
    '242': semantic_Functions[0],    # Message Type
}

dhcp_Semantic_Functions_Groundtruth[b'\x01\x07'] = {
    '0': semantic_Functions[0],      # op
    '2': semantic_Functions[1],      # hlen
    '241': semantic_Functions[1],    # Option length
    '242': semantic_Functions[0],    # Message Type
}

dhcp_Semantic_Functions_Groundtruth[b'\x01\x08'] = {
    '0': semantic_Functions[0],      # op
    '2': semantic_Functions[1],      # hlen
    '241': semantic_Functions[1],    # Option length
    '242': semantic_Functions[0],    # Message Type
}