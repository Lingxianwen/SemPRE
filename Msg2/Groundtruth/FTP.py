# FTP (File Transfer Protocol) 协议 Groundtruth 定义 - 修复版本
# 基于RFC 959和实际FTP会话分析

semantic_Types = ['Static', 'Group', 'String', 'Bit Field', 'Bytes']
semantic_Functions = ['Command', 'Length', 'Delim', 'CheckSum', 'Aligned', 'Filename']

ftp_Syntax_Groundtruth = {}

# FTP是基于文本的协议，命令和响应都是ASCII格式
# 命令格式: COMMAND [参数]\r\n
# 响应格式: 3位数字代码[空格/连字符][消息]\r\n

# FTP Commands
ftp_Syntax_Groundtruth[b'USER'] = [0, 4, 5]  # USER + space + username
ftp_Syntax_Groundtruth[b'PASS'] = [0, 4, 5]  # PASS + space + password
ftp_Syntax_Groundtruth[b'PWD\r'] = [0, 3, 4, 5]    # PWD + CRLF
ftp_Syntax_Groundtruth[b'CWD '] = [0, 3, 4]  # CWD + space + path
ftp_Syntax_Groundtruth[b'LIST'] = [0, 4, 5]     # LIST [path]
ftp_Syntax_Groundtruth[b'RETR'] = [0, 4, 5]  # RETR + space + filename
ftp_Syntax_Groundtruth[b'STOR'] = [0, 4, 5]  # STOR + space + filename
ftp_Syntax_Groundtruth[b'QUIT'] = [0, 4, 5, 6]     # QUIT + CRLF
ftp_Syntax_Groundtruth[b'TYPE'] = [0, 4, 5, 6, 7, 8]  # TYPE + space + type + CRLF
ftp_Syntax_Groundtruth[b'PORT'] = [0, 4, 5]  # PORT + space + address

# FTP Responses (3位数字代码)
# 220 Service ready responses
ftp_Syntax_Groundtruth[b'220 '] = [0, 3, 4]  # 单行响应
ftp_Syntax_Groundtruth[b'220-'] = [0, 3, 4]  # 多行响应

# 其他常见响应
ftp_Syntax_Groundtruth[b'230 '] = [0, 3, 4]  # User logged in
ftp_Syntax_Groundtruth[b'331 '] = [0, 3, 4]  # User name okay, need password
ftp_Syntax_Groundtruth[b'250 '] = [0, 3, 4]  # Requested file action okay
ftp_Syntax_Groundtruth[b'150 '] = [0, 3, 4]  # File status okay
ftp_Syntax_Groundtruth[b'226 '] = [0, 3, 4]  # Closing data connection
ftp_Syntax_Groundtruth[b'425 '] = [0, 3, 4]  # Can't open data connection
ftp_Syntax_Groundtruth[b'500 '] = [0, 3, 4]  # Syntax error
ftp_Syntax_Groundtruth[b'421 '] = [0, 3, 4]  # Service not available
ftp_Syntax_Groundtruth[b'530 '] = [0, 3, 4]  # Not logged in
ftp_Syntax_Groundtruth[b'550 '] = [0, 3, 4]  # Requested action not taken
ftp_Syntax_Groundtruth[b'257 '] = [0, 3, 4]  # Directory created
ftp_Syntax_Groundtruth[b'200 '] = [0, 3, 4]  # Command okay
ftp_Syntax_Groundtruth[b'213 '] = [0, 3, 4]  # File status
ftp_Syntax_Groundtruth[b'227 '] = [0, 3, 4]  # Entering passive mode
ftp_Syntax_Groundtruth[b'221 '] = [0, 3, 4]  # Service closing

# 多行响应变体
ftp_Syntax_Groundtruth[b'230-'] = [0, 3, 4]
ftp_Syntax_Groundtruth[b'250-'] = [0, 3, 4]
ftp_Syntax_Groundtruth[b'331-'] = [0, 3, 4]

# 默认边界（用于未识别的FTP消息）
ftp_Syntax_Groundtruth['default'] = [0, 3, 4]

# FTP协议特定偏移量定义
ftp_lengthOffset = None  # FTP没有显式长度字段，以CRLF结束
ftp_commandOffset = '0,3'  # 命令字段或响应代码
ftp_checksumOffset = None # FTP依赖TCP的完整性保证

ftp_Semantic_Groundtruth = {}
ftp_Semantic_Functions_Groundtruth = {}

''' Semantic-Type Groundtruth '''

# FTP Commands
ftp_Semantic_Groundtruth[b'USER'] = {
    '0,3': semantic_Types[1],     # Command (USER)
    '4': semantic_Types[2],       # Delimiter (space)
    '5,+': semantic_Types[2]      # Username (string)
}

ftp_Semantic_Groundtruth[b'PASS'] = {
    '0,3': semantic_Types[1],     # Command (PASS)
    '4': semantic_Types[2],       # Delimiter (space)
    '5,+': semantic_Types[2]      # Password (string)
}

ftp_Semantic_Groundtruth[b'PWD\r'] = {
    '0,2': semantic_Types[1],     # Command (PWD)
    '3,4': semantic_Types[2]      # CRLF delimiter
}

ftp_Semantic_Groundtruth[b'CWD '] = {
    '0,2': semantic_Types[1],     # Command (CWD)
    '3': semantic_Types[2],       # Delimiter (space)
    '4,+': semantic_Types[2]      # Directory path (string)
}

ftp_Semantic_Groundtruth[b'LIST'] = {
    '0,3': semantic_Types[1],     # Command (LIST)
    '4': semantic_Types[2],       # Delimiter
    '5,+': semantic_Types[2]      # Optional path (string)
}

ftp_Semantic_Groundtruth[b'RETR'] = {
    '0,3': semantic_Types[1],     # Command (RETR)
    '4': semantic_Types[2],       # Delimiter (space)
    '5,+': semantic_Types[2]      # Filename (string)
}

ftp_Semantic_Groundtruth[b'STOR'] = {
    '0,3': semantic_Types[1],     # Command (STOR)
    '4': semantic_Types[2],       # Delimiter (space)
    '5,+': semantic_Types[2]      # Filename (string)
}

ftp_Semantic_Groundtruth[b'QUIT'] = {
    '0,3': semantic_Types[1],     # Command (QUIT)
    '4,5': semantic_Types[2]      # CRLF delimiter
}

ftp_Semantic_Groundtruth[b'TYPE'] = {
    '0,3': semantic_Types[1],     # Command (TYPE)
    '4': semantic_Types[2],       # Delimiter (space)
    '5': semantic_Types[3],       # Transfer type (A/I/E/L)
    '6,7': semantic_Types[2]      # CRLF delimiter
}

ftp_Semantic_Groundtruth[b'PORT'] = {
    '0,3': semantic_Types[1],     # Command (PORT)
    '4': semantic_Types[2],       # Delimiter (space)
    '5,+': semantic_Types[2]      # Host-port specification (string)
}

# FTP Responses
ftp_Semantic_Groundtruth[b'220 '] = {
    '0,2': semantic_Types[1],     # Response code (220)
    '3': semantic_Types[2],       # Delimiter (space)
    '4,+': semantic_Types[2]      # Response message (string)
}

ftp_Semantic_Groundtruth[b'220-'] = {
    '0,2': semantic_Types[1],     # Response code (220)
    '3': semantic_Types[2],       # Delimiter (dash)
    '4,+': semantic_Types[2]      # Response message (string)
}

ftp_Semantic_Groundtruth[b'230 '] = {
    '0,2': semantic_Types[1],     # Response code (230)
    '3': semantic_Types[2],       # Delimiter (space)
    '4,+': semantic_Types[2]      # Response message (string)
}

ftp_Semantic_Groundtruth[b'331 '] = {
    '0,2': semantic_Types[1],     # Response code (331)
    '3': semantic_Types[2],       # Delimiter (space)
    '4,+': semantic_Types[2]      # Response message (string)
}

ftp_Semantic_Groundtruth[b'250 '] = {
    '0,2': semantic_Types[1],     # Response code (250)
    '3': semantic_Types[2],       # Delimiter (space)
    '4,+': semantic_Types[2]      # Response message (string)
}

ftp_Semantic_Groundtruth[b'150 '] = {
    '0,2': semantic_Types[1],
    '3': semantic_Types[2],
    '4,+': semantic_Types[2]
}

ftp_Semantic_Groundtruth[b'226 '] = {
    '0,2': semantic_Types[1],
    '3': semantic_Types[2],
    '4,+': semantic_Types[2]
}

ftp_Semantic_Groundtruth[b'425 '] = {
    '0,2': semantic_Types[1],
    '3': semantic_Types[2],
    '4,+': semantic_Types[2]
}

# 更多FTP响应的语义类型定义
response_codes = [b'220 ', b'220-', b'230 ', b'230-', b'331 ', b'331-', b'250 ', b'250-',
                  b'150 ', b'226 ', b'425 ', b'500 ', b'421 ', b'530 ', b'550 ',
                  b'257 ', b'200 ', b'213 ', b'227 ', b'221 ']

for code in response_codes:
    if code not in ftp_Semantic_Groundtruth:
        ftp_Semantic_Groundtruth[code] = {
            '0,2': semantic_Types[1],     # Response code
            '3': semantic_Types[2],       # Delimiter
            '4,+': semantic_Types[2]      # Response message (string)
        }

# 默认语义类型
ftp_Semantic_Groundtruth['default'] = {
    '0,2': semantic_Types[1],     # Response code或命令
    '3': semantic_Types[2],       # Delimiter
    '4,+': semantic_Types[2]      # Message (string)
}

''' Semantic-Function Groundtruth '''

# FTP Commands
ftp_Semantic_Functions_Groundtruth[b'USER'] = {
    '0,3': semantic_Functions[0],    # Command
    '4': semantic_Functions[2],      # Delimiter
}

ftp_Semantic_Functions_Groundtruth[b'PASS'] = {
    '0,3': semantic_Functions[0],    # Command
    '4': semantic_Functions[2],      # Delimiter
}

ftp_Semantic_Functions_Groundtruth[b'PWD\r'] = {
    '0,2': semantic_Functions[0],    # Command
    '3,4': semantic_Functions[2],    # Delimiter
}

ftp_Semantic_Functions_Groundtruth[b'CWD '] = {
    '0,2': semantic_Functions[0],    # Command
    '3': semantic_Functions[2],      # Delimiter
}

ftp_Semantic_Functions_Groundtruth[b'RETR'] = {
    '0,3': semantic_Functions[0],    # Command
    '4': semantic_Functions[2],      # Delimiter
    '5,+': semantic_Functions[5],    # Filename
}

ftp_Semantic_Functions_Groundtruth[b'STOR'] = {
    '0,3': semantic_Functions[0],    # Command
    '4': semantic_Functions[2],      # Delimiter
    '5,+': semantic_Functions[5],    # Filename
}

ftp_Semantic_Functions_Groundtruth[b'LIST'] = {
    '0,3': semantic_Functions[0],    # Command
    '4': semantic_Functions[2],      # Delimiter
}

ftp_Semantic_Functions_Groundtruth[b'QUIT'] = {
    '0,3': semantic_Functions[0],    # Command
    '4,5': semantic_Functions[2],    # Delimiter
}

ftp_Semantic_Functions_Groundtruth[b'TYPE'] = {
    '0,3': semantic_Functions[0],    # Command
    '4': semantic_Functions[2],      # Delimiter
}

ftp_Semantic_Functions_Groundtruth[b'PORT'] = {
    '0,3': semantic_Functions[0],    # Command
    '4': semantic_Functions[2],      # Delimiter
}

# FTP Responses
ftp_Semantic_Functions_Groundtruth[b'220 '] = {
    '0,2': semantic_Functions[0],    # Response code (Command equivalent)
    '3': semantic_Functions[2],      # Delimiter
}

ftp_Semantic_Functions_Groundtruth[b'220-'] = {
    '0,2': semantic_Functions[0],    # Response code (Command equivalent)
    '3': semantic_Functions[2],      # Delimiter
}

ftp_Semantic_Functions_Groundtruth[b'230 '] = {
    '0,2': semantic_Functions[0],
    '3': semantic_Functions[2],
}

ftp_Semantic_Functions_Groundtruth[b'331 '] = {
    '0,2': semantic_Functions[0],
    '3': semantic_Functions[2],
}

ftp_Semantic_Functions_Groundtruth[b'250 '] = {
    '0,2': semantic_Functions[0],
    '3': semantic_Functions[2],
}

ftp_Semantic_Functions_Groundtruth[b'150 '] = {
    '0,2': semantic_Functions[0],
    '3': semantic_Functions[2],
}

ftp_Semantic_Functions_Groundtruth[b'226 '] = {
    '0,2': semantic_Functions[0],
    '3': semantic_Functions[2],
}

ftp_Semantic_Functions_Groundtruth[b'425 '] = {
    '0,2': semantic_Functions[0],
    '3': semantic_Functions[2],
}

# 更多FTP响应的语义功能定义
for code in response_codes:
    if code not in ftp_Semantic_Functions_Groundtruth:
        ftp_Semantic_Functions_Groundtruth[code] = {
            '0,2': semantic_Functions[0],    # Response code (Command equivalent)
            '3': semantic_Functions[2],      # Delimiter
        }

# 默认语义功能
ftp_Semantic_Functions_Groundtruth['default'] = {
    '0,2': semantic_Functions[0],    # Response code或命令
    '3': semantic_Functions[2],      # Delimiter
}