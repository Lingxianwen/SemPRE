#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版数据标签生成器
支持9个协议：SMB, SMB2, DNS, S7Comm, DNP3, Modbus, FTP, TLS1.2, DHCP
根据groundtruth生成CSV标签文件
"""

import os
import pandas as pd
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import json
import re

# 导入所有协议的groundtruth定义
from Msg2.Groundtruth.DNP3 import dnp3_Syntax_Groundtruth, dnp3_Semantic_Groundtruth, \
    dnp3_Semantic_Functions_Groundtruth, dnp3_lengthOffset, dnp3_commandOffset, dnp3_checksumOffset
from Msg2.Groundtruth.Modbus import modbus_Syntax_Groundtruth, modbus_Semantic_Groundtruth, \
    modbus_Semantic_Functions_Groundtruth, modbus_lengthOffset, modbus_commandOffset
from Msg2.Groundtruth.SMB import smb_Syntax_Groundtruth, smb_Semantic_Groundtruth, \
    smb_Semantic_Functions_Groundtruth, smb_lengthOffset, smb_commandOffset, smb_checksumOffset
from Msg2.Groundtruth.SMB2 import smb2_Syntax_Groundtruth, smb2_Semantic_Groundtruth, \
    smb2_Semantic_Functions_Groundtruth, smb2_lengthOffset, smb2_commandOffset, smb2_checksumOffset
from Msg2.Groundtruth.DNS import dns_Syntax_Groundtruth, dns_Semantic_Groundtruth, \
    dns_Semantic_Functions_Groundtruth, dns_lengthOffset, dns_commandOffset, dns_checksumOffset
from Msg2.Groundtruth.S7Comm import s7comm_Syntax_Groundtruth, s7comm_Semantic_Groundtruth, \
    s7comm_Semantic_Functions_Groundtruth, s7comm_lengthOffset, s7comm_commandOffset, s7comm_checksumOffset
from Msg2.Groundtruth.FTP import ftp_Syntax_Groundtruth, ftp_Semantic_Groundtruth, \
    ftp_Semantic_Functions_Groundtruth, ftp_lengthOffset, ftp_commandOffset, ftp_checksumOffset
from Msg2.Groundtruth.TLS12 import tls12_Syntax_Groundtruth, tls12_Semantic_Groundtruth, \
    tls12_Semantic_Functions_Groundtruth, tls12_lengthOffset, tls12_commandOffset, tls12_checksumOffset
from Msg2.Groundtruth.DHCP import dhcp_Syntax_Groundtruth, dhcp_Semantic_Groundtruth, \
    dhcp_Semantic_Functions_Groundtruth, dhcp_lengthOffset, dhcp_commandOffset, dhcp_checksumOffset


class EnhancedProtocolLabelGenerator:
    """增强版协议标签生成器，支持9个协议"""

    def __init__(self):
        self.protocols = {
            'dnp3': {
                'syntax_gt': dnp3_Syntax_Groundtruth,
                'semantic_gt': dnp3_Semantic_Groundtruth,
                'function_gt': dnp3_Semantic_Functions_Groundtruth,
                'length_offset': dnp3_lengthOffset,
                'command_offset': dnp3_commandOffset,
                'checksum_offset': dnp3_checksumOffset
            },
            'modbus': {
                'syntax_gt': modbus_Syntax_Groundtruth,
                'semantic_gt': modbus_Semantic_Groundtruth,
                'function_gt': modbus_Semantic_Functions_Groundtruth,
                'length_offset': modbus_lengthOffset,
                'command_offset': modbus_commandOffset,
                'checksum_offset': None
            },
            'smb': {
                'syntax_gt': smb_Syntax_Groundtruth,
                'semantic_gt': smb_Semantic_Groundtruth,
                'function_gt': smb_Semantic_Functions_Groundtruth,
                'length_offset': smb_lengthOffset,
                'command_offset': smb_commandOffset,
                'checksum_offset': smb_checksumOffset
            },
            'smb2': {
                'syntax_gt': smb2_Syntax_Groundtruth,
                'semantic_gt': smb2_Semantic_Groundtruth,
                'function_gt': smb2_Semantic_Functions_Groundtruth,
                'length_offset': smb2_lengthOffset,
                'command_offset': smb2_commandOffset,
                'checksum_offset': smb2_checksumOffset
            },
            'dns': {
                'syntax_gt': dns_Syntax_Groundtruth,
                'semantic_gt': dns_Semantic_Groundtruth,
                'function_gt': dns_Semantic_Functions_Groundtruth,
                'length_offset': dns_lengthOffset,
                'command_offset': dns_commandOffset,
                'checksum_offset': dns_checksumOffset
            },
            's7comm': {
                'syntax_gt': s7comm_Syntax_Groundtruth,
                'semantic_gt': s7comm_Semantic_Groundtruth,
                'function_gt': s7comm_Semantic_Functions_Groundtruth,
                'length_offset': s7comm_lengthOffset,
                'command_offset': s7comm_commandOffset,
                'checksum_offset': s7comm_checksumOffset
            },
            'ftp': {
                'syntax_gt': ftp_Syntax_Groundtruth,
                'semantic_gt': ftp_Semantic_Groundtruth,
                'function_gt': ftp_Semantic_Functions_Groundtruth,
                'length_offset': ftp_lengthOffset,
                'command_offset': ftp_commandOffset,
                'checksum_offset': ftp_checksumOffset
            },
            'tls12': {
                'syntax_gt': tls12_Syntax_Groundtruth,
                'semantic_gt': tls12_Semantic_Groundtruth,
                'function_gt': tls12_Semantic_Functions_Groundtruth,
                'length_offset': tls12_lengthOffset,
                'command_offset': tls12_commandOffset,
                'checksum_offset': tls12_checksumOffset
            },
            'dhcp': {
                'syntax_gt': dhcp_Syntax_Groundtruth,
                'semantic_gt': dhcp_Semantic_Groundtruth,
                'function_gt': dhcp_Semantic_Functions_Groundtruth,
                'length_offset': dhcp_lengthOffset,
                'command_offset': dhcp_commandOffset,
                'checksum_offset': dhcp_checksumOffset
            }
        }

        # 统一的语义标签
        self.unified_semantic_types = [
            'PADDING', 'HEADER', 'ADDRESS', 'COMMAND', 'LENGTH',
            'DATA', 'CHECKSUM', 'CONTROL', 'FUNCTION', 'OPTION',
            'TIMESTAMP', 'VERSION', 'FLAGS', 'PAYLOAD', 'STRING',
            'SIGNATURE', 'IDENTIFIER'
        ]

        self.unified_semantic_functions = [
            'UNKNOWN', 'IDENTIFIER', 'ADDRESSING', 'CONTROL_CMD',
            'DATA_LENGTH', 'PAYLOAD', 'VALIDATION', 'RESERVED',
            'PROTOCOL_SPECIFIC', 'CONFIGURATION', 'SESSION_MGMT',
            'SECURITY', 'ROUTING', 'APPLICATION_DATA', 'DELIMITER',
            'FILENAME', 'MESSAGE_TYPE'
        ]

        # 映射原始标签到统一标签
        self.type_mapping = {
            'Static': 'HEADER',
            'Group': 'COMMAND',
            'String': 'STRING',
            'Bit Field': 'FLAGS',
            'Bytes': 'PAYLOAD'
        }

        self.function_mapping = {
            'Command': 'CONTROL_CMD',
            'Length': 'DATA_LENGTH',
            'Delim': 'DELIMITER',
            'CheckSum': 'VALIDATION',
            'Aligned': 'RESERVED',
            'Filename': 'FILENAME'
        }

    def hex_to_bytes(self, hex_string: str) -> bytes:
        """将十六进制字符串转换为字节"""
        # 清理输入字符串
        hex_string = hex_string.replace(' ', '').replace('\t', '').replace('\n', '').replace('\\x', '')
        # 移除可能的0x前缀
        if hex_string.startswith('0x'):
            hex_string = hex_string[2:]
        # 确保偶数长度
        if len(hex_string) % 2 != 0:
            hex_string = '0' + hex_string
        try:
            return bytes.fromhex(hex_string)
        except ValueError:
            print(f"警告：无法解析十六进制字符串: {hex_string}")
            return b''

    def is_ascii_data(self, data_bytes: bytes) -> bool:
        """检查数据是否为ASCII格式（用于FTP等文本协议）"""
        if len(data_bytes) == 0:
            return False

        # 特殊处理：如果数据全为0，则不是ASCII
        if data_bytes == b'\x00' * len(data_bytes):
            return False

        try:
            # 尝试解码为ASCII
            data_str = data_bytes.decode('ascii')
            # 检查是否包含控制字符（除了常见的CR, LF, TAB）
            printable_count = 0
            for char in data_str:
                if char.isprintable() or char in '\r\n\t':
                    printable_count += 1
                elif ord(char) < 32:
                    # 允许少量控制字符，但不能太多
                    continue
                else:
                    return False

            # 至少70%的字符应该是可打印的
            return printable_count / len(data_str) >= 0.7

        except UnicodeDecodeError:
            return False

    def identify_protocol_format(self, data_bytes: bytes, protocol: str) -> Optional[bytes]:
        """识别协议格式 - 修复SMB2识别逻辑"""
        protocol_info = self.protocols.get(protocol)
        if not protocol_info:
            return None

        syntax_gt = protocol_info['syntax_gt']

        if protocol == 'dnp3':
            # DNP3: 检查起始字节或功能码
            if len(data_bytes) >= 2 and data_bytes[:2] == b'\x05\x64':
                return b'\x05\x64'  # DNP3 Data Link Layer
            elif len(data_bytes) >= 1:
                func_code = data_bytes[0:1]
                if func_code in syntax_gt:
                    return func_code

        elif protocol == 'modbus':
            # Modbus: 检查功能码位置
            if len(data_bytes) >= 8:  # Modbus TCP最小长度
                func_code = data_bytes[7:8]  # 功能码在第7字节
                if func_code in syntax_gt:
                    return func_code

        elif protocol == 'smb':
            # SMB: 修复 - 检查SMB协议标识符和命令字段（第4字节）
            if len(data_bytes) >= 5:
                # 检查SMB协议标识符（前4字节应该是 \xFF\x53\x4D\x42）
                protocol_id = data_bytes[:4]
                if protocol_id == b'\xff\x53\x4d\x42':  # SMB协议标识符
                    # 提取SMB命令（第4字节，索引4）
                    smb_cmd = data_bytes[4:5]
                    if smb_cmd in syntax_gt:
                        return smb_cmd
                    else:
                        # 如果命令不在groundtruth中，仍然返回命令以使用默认处理
                        return smb_cmd
            return None

        elif protocol == 'smb2':
            # SMB2: 修复 - 检查SMB2协议标识符和命令字段
            if len(data_bytes) >= 16:  # SMB2头部至少需要16字节
                # 检查SMB2协议标识符（前4字节应该是 \xfe\x53\x4d\x42）
                protocol_id = data_bytes[:4]
                if protocol_id == b'\xfe\x53\x4d\x42':  # SMB2协议标识符
                    # SMB2命令在第12-13字节（不包含NetBIOS头部）
                    if len(data_bytes) >= 14:
                        smb2_cmd = data_bytes[12:14]
                        if smb2_cmd in syntax_gt:
                            return smb2_cmd
                        else:
                            # 如果命令不在groundtruth中，仍然返回命令以使用默认处理
                            return smb2_cmd
            return None

        elif protocol == 'dns':
            # DNS: 修复 - 提取Flags字段作为键
            if len(data_bytes) >= 4:
                # DNS Flags字段在第2-3字节（从0开始计数）
                flags_bytes = data_bytes[2:4]

                # 先检查精确匹配
                if flags_bytes in syntax_gt:
                    return flags_bytes

                # 如果没有精确匹配，检查是否有对应的hex字符串键
                flags_hex = flags_bytes.hex().upper()
                if flags_hex in syntax_gt:
                    return flags_bytes

                # 检查常见的DNS标志组合
                common_dns_flags = [
                    b'\x01\x00',  # 标准查询 (RD=1)
                    b'\x81\x80',  # 标准响应 (QR=1, RD=1, RA=1)
                    b'\x00\x00',  # 非递归查询
                    b'\x84\x00',  # 权威响应 (QR=1, AA=1)
                ]

                for flag in common_dns_flags:
                    if flags_bytes == flag and flag in syntax_gt:
                        return flag

                # 如果都没有匹配，尝试使用字符串形式的键
                for key in syntax_gt.keys():
                    if isinstance(key, str):
                        # 尝试将字符串键转换为字节进行比较
                        try:
                            if len(key) == 4:  # 假设是hex字符串如 "0100"
                                key_bytes = bytes.fromhex(key)
                                if flags_bytes == key_bytes:
                                    return flags_bytes
                        except ValueError:
                            continue

                # 最后尝试 'default' 键
                if 'default' in syntax_gt:
                    return b'default'

            return None

        elif protocol == 's7comm':
            # S7Comm: 检查TPKT头部和ROSCTR字段
            if len(data_bytes) >= 12:  # S7Comm最小长度
                # 检查TPKT版本（应该是0x03）
                if data_bytes[0] == 0x03:
                    # COTP长度在第4字节，COTP头部长度=第4字节+1
                    cotp_length = data_bytes[4] + 1
                    s7_start = 4 + cotp_length

                    # 检查S7Comm协议ID（应该是0x32）
                    if s7_start < len(data_bytes) and data_bytes[s7_start] == 0x32:
                        # ROSCTR在S7Comm头部的第2字节
                        rosctr_pos = s7_start + 1
                        if rosctr_pos < len(data_bytes):
                            rosctr = data_bytes[rosctr_pos:rosctr_pos + 1]
                            if rosctr in syntax_gt:
                                return rosctr

                            # 对于某些消息，可能需要检查功能码
                            func_pos = s7_start + 10  # 功能码通常在S7头部偏移10处
                            if func_pos < len(data_bytes):
                                func_code = data_bytes[func_pos:func_pos + 1]
                                if func_code in syntax_gt:
                                    return func_code

                            # 使用默认处理
                            if 'default' in syntax_gt:
                                return b'default'

        elif protocol == 'ftp':
            # FTP: 检查ASCII命令或响应码
            if self.is_ascii_data(data_bytes):
                # 首先检查精确匹配
                for key in syntax_gt.keys():
                    if isinstance(key, bytes) and data_bytes.startswith(key):
                        return key

                # 检查FTP响应码模式 (三位数字 + 空格或连字符)
                if len(data_bytes) >= 4:
                    # 检查是否是FTP响应码格式：NNN[space/-]
                    first_4_bytes = data_bytes[:4]
                    if (len(first_4_bytes) == 4 and
                            first_4_bytes[:3].isdigit() and
                            first_4_bytes[3:4] in [b' ', b'-']):
                        # 构建响应码键
                        response_key = first_4_bytes
                        if response_key in syntax_gt:
                            return response_key
                        # 如果找不到精确匹配，使用默认
                        return b'default'

                # 检查FTP命令模式
                if len(data_bytes) >= 4:
                    # 尝试匹配常见的FTP命令
                    for cmd in [b'USER', b'PASS', b'LIST', b'RETR', b'STOR', b'QUIT', b'TYPE', b'PORT', b'CWD', b'PWD']:
                        if data_bytes.startswith(cmd):
                            if cmd + b' ' in syntax_gt:
                                return cmd + b' '
                            elif cmd in syntax_gt:
                                return cmd
                            # 对于包含\r的命令（如PWD\r）
                            elif cmd + b'\r' in syntax_gt:
                                return cmd + b'\r'

                # 对于其他可能的FTP文本数据，使用默认处理
                if 'default' in syntax_gt:
                    return b'default'

        elif protocol == 'tls12':
            # TLS1.2: 检查前3字节（ContentType + Version）
            if len(data_bytes) >= 3:
                for key in syntax_gt.keys():
                    if len(key) <= len(data_bytes) and data_bytes[:len(key)] == key:
                        return key

        elif protocol == 'dhcp':
            # DHCP: 组合op字段和消息类型
            if len(data_bytes) >= 243:  # DHCP最小长度
                op = data_bytes[0:1]
                # 寻找DHCP Message Type选项（option 53）
                if len(data_bytes) >= 243:  # 检查选项区域
                    try:
                        # 查找魔法cookie位置（0x63825363）
                        magic_cookie = b'\x63\x82\x53\x63'
                        cookie_pos = data_bytes.find(magic_cookie)
                        if cookie_pos >= 0 and len(data_bytes) > cookie_pos + 6:
                            # 查找Message Type选项 (53)
                            options_start = cookie_pos + 4
                            i = options_start
                            while i < len(data_bytes) - 2:
                                if data_bytes[i] == 53:  # Message Type option
                                    if i + 2 < len(data_bytes):
                                        msg_type = data_bytes[i + 2:i + 3]
                                        combined_key = op + msg_type
                                        if combined_key in syntax_gt:
                                            return combined_key
                                    break
                                elif data_bytes[i] == 255:  # End option
                                    break
                                elif data_bytes[i] == 0:  # Pad option
                                    i += 1
                                else:
                                    # Skip this option
                                    if i + 1 < len(data_bytes):
                                        option_len = data_bytes[i + 1]
                                        i += 2 + option_len
                                    else:
                                        break
                    except:
                        pass

        return None

    def generate_boundary_labels(self, data_bytes: bytes, format_key: bytes, protocol: str) -> List[int]:
        """生成边界标签"""
        protocol_info = self.protocols[protocol]
        syntax_gt = protocol_info['syntax_gt']

        # 处理特殊键
        if format_key == b'default' and 'default' in syntax_gt:
            boundaries = syntax_gt['default']
        elif format_key not in syntax_gt:
            # 如果format_key不在groundtruth中，使用默认边界
            if 'default' in syntax_gt:
                boundaries = syntax_gt['default']
            else:
                # 最后的备选方案：每8字节一个边界
                boundaries = []
                for i in range(0, len(data_bytes), 8):
                    if i < len(data_bytes):
                        boundaries.append(i)
                return boundaries
        else:
            boundaries = syntax_gt[format_key]

        # 过滤掉-1和超出数据长度的边界
        valid_boundaries = [b for b in boundaries if b != -1 and b < len(data_bytes)]

        # 对于FTP协议，如果没有有效边界，使用基本边界
        if protocol == 'ftp' and len(valid_boundaries) == 0:
            # FTP基本边界：响应码(3) + 分隔符(1)
            if len(data_bytes) >= 4:
                valid_boundaries = [0, 3, 4]
            else:
                valid_boundaries = [0]

        return sorted(valid_boundaries)

    def generate_semantic_labels(self, data_bytes: bytes, format_key: bytes, protocol: str) -> Tuple[
        Dict[int, str], Dict[int, str]]:
        """生成语义标签"""
        protocol_info = self.protocols[protocol]
        semantic_gt = protocol_info['semantic_gt']
        function_gt = protocol_info['function_gt']

        semantic_types = {}
        semantic_functions = {}

        # 处理特殊键
        semantic_key = format_key
        if format_key == b'default' and 'default' in semantic_gt:
            semantic_key = 'default'
        elif format_key not in semantic_gt and 'default' in semantic_gt:
            semantic_key = 'default'

        # 处理语义类型
        if semantic_key in semantic_gt:
            for pos_range, sem_type in semantic_gt[semantic_key].items():
                positions = self.parse_position_range(pos_range, len(data_bytes))
                unified_type = self.type_mapping.get(sem_type, sem_type)
                for pos in positions:
                    if pos < len(data_bytes):
                        semantic_types[pos] = unified_type

        # 处理语义功能
        if semantic_key in function_gt:
            for pos_range, sem_func in function_gt[semantic_key].items():
                positions = self.parse_position_range(pos_range, len(data_bytes))
                unified_func = self.function_mapping.get(sem_func, sem_func)
                for pos in positions:
                    if pos < len(data_bytes):
                        semantic_functions[pos] = unified_func

        # 对于FTP协议，如果没有语义标签，提供基本标签
        if protocol == 'ftp' and len(semantic_types) == 0 and len(data_bytes) > 0:
            # FTP基本语义：响应码/命令(Command) + 分隔符(Delimiter) + 消息(String)
            if len(data_bytes) >= 4:
                for i in range(3):  # 前3字节是响应码或命令
                    semantic_types[i] = 'COMMAND'
                    semantic_functions[i] = 'CONTROL_CMD'
                if len(data_bytes) > 3:
                    semantic_types[3] = 'STRING'  # 分隔符
                    semantic_functions[3] = 'DELIMITER'
                for i in range(4, len(data_bytes)):  # 其余是消息
                    semantic_types[i] = 'STRING'
                    semantic_functions[i] = 'UNKNOWN'
            else:
                # 数据太短，全部标记为命令
                for i in range(len(data_bytes)):
                    semantic_types[i] = 'COMMAND'
                    semantic_functions[i] = 'CONTROL_CMD'

        return semantic_types, semantic_functions

    def parse_position_range(self, pos_range: str, data_length: int) -> List[int]:
        """解析位置范围字符串"""
        positions = []

        if ',' in pos_range:
            parts = pos_range.split(',')
            for part in parts:
                part = part.strip()
                if not part:
                    continue

                if '+' in part:
                    start_part = part.replace('+', '').strip()
                    if start_part:
                        start_pos = int(start_part)
                        positions.extend(range(start_pos, data_length))
                    else:
                        continue
                elif ':' in part:
                    # 处理范围格式如 "0:3"
                    try:
                        start, end = map(int, part.split(':'))
                        positions.extend(range(start, min(end + 1, data_length)))
                    except ValueError:
                        try:
                            positions.append(int(part))
                        except ValueError:
                            print(f"警告：无法解析位置范围 '{part}' 在 '{pos_range}' 中")
                else:
                    try:
                        positions.append(int(part))
                    except ValueError:
                        print(f"警告：无法解析位置范围 '{part}' 在 '{pos_range}' 中")
        else:
            if '+' in pos_range:
                start_part = pos_range.replace('+', '').strip()
                if start_part:
                    start_pos = int(start_part)
                    positions.extend(range(start_pos, data_length))
            elif ':' in pos_range:
                try:
                    start, end = map(int, pos_range.split(':'))
                    positions.extend(range(start, min(end + 1, data_length)))
                except ValueError:
                    try:
                        positions.append(int(pos_range))
                    except ValueError:
                        print(f"警告：无法解析位置范围 '{pos_range}'")
            else:
                try:
                    positions.append(int(pos_range))
                except ValueError:
                    print(f"警告：无法解析位置范围 '{pos_range}'")

        return positions

    def generate_csv_labels(self, txt_file: str, protocol: str, output_csv: str):
        """生成CSV标签文件"""
        print(f"正在处理 {protocol.upper()} 协议数据...")
        print(f"输入文件: {txt_file}")
        print(f"输出文件: {output_csv}")

        # 读取原始数据
        with open(txt_file, 'r', encoding='utf-8') as f:
            hex_lines = [line.strip() for line in f if line.strip()]

        labels_data = []

        for i, hex_line in enumerate(hex_lines):
            try:
                # 转换为字节
                data_bytes = self.hex_to_bytes(hex_line)

                if len(data_bytes) == 0:
                    continue

                # 识别协议格式
                format_key = self.identify_protocol_format(data_bytes, protocol)

                # 特殊处理：检查是否为全零数据或填充数据
                is_padding_data = False
                if format_key is None and protocol == 'ftp':
                    # 检查是否为全零数据
                    if data_bytes == b'\x00' * len(data_bytes):
                        is_padding_data = True
                        # 为全零数据创建特殊标签
                        row = {
                            'Index': i,
                            'HexData': hex_line,
                            'Length': len(data_bytes),
                            'Protocol': protocol.upper(),
                            'FunctionCode': 'FTP_PADDING',
                            'HasBoundary': 0,
                            'BoundaryCount': 0,
                            'SemanticType': 'PADDING',
                            'SemanticFunction': 'RESERVED',
                            'Label': 'FTP_PADDING',
                            'Boundaries': '',
                            'SemanticTypes': '{}',
                            'SemanticFunctions': '{}'
                        }
                        labels_data.append(row)
                        continue

                if format_key is None and not is_padding_data:
                    # 使用默认标签
                    row = {
                        'Index': i,
                        'HexData': hex_line,
                        'Length': len(data_bytes),
                        'Protocol': protocol.upper(),
                        'FunctionCode': 'UNKNOWN',
                        'HasBoundary': 1 if len(data_bytes) > 8 else 0,
                        'BoundaryCount': max(1, len(data_bytes) // 8),
                        'SemanticType': 'DATA',
                        'SemanticFunction': 'UNKNOWN',
                        'Label': 'UNKNOWN',
                        'Boundaries': '',
                        'SemanticTypes': '{}',
                        'SemanticFunctions': '{}'
                    }
                    labels_data.append(row)
                    continue

                # 生成边界标签
                boundaries = self.generate_boundary_labels(data_bytes, format_key, protocol)

                # 生成语义标签
                semantic_types, semantic_functions = self.generate_semantic_labels(data_bytes, format_key, protocol)

                # 确定功能码描述
                func_code = self.get_function_code_description(format_key, protocol)

                # 主要语义类型（最常见的）
                main_semantic_type = 'DATA'
                if semantic_types:
                    type_counts = {}
                    for st in semantic_types.values():
                        type_counts[st] = type_counts.get(st, 0) + 1
                    main_semantic_type = max(type_counts, key=type_counts.get)

                # 主要语义功能
                main_semantic_function = 'UNKNOWN'
                if semantic_functions:
                    func_counts = {}
                    for sf in semantic_functions.values():
                        func_counts[sf] = func_counts.get(sf, 0) + 1
                    main_semantic_function = max(func_counts, key=func_counts.get)

                # 创建标签行
                row = {
                    'Index': i,
                    'HexData': hex_line,
                    'Length': len(data_bytes),
                    'Protocol': protocol.upper(),
                    'FunctionCode': func_code,
                    'HasBoundary': 1 if len(boundaries) > 0 else 0,
                    'BoundaryCount': len(boundaries),
                    'SemanticType': main_semantic_type,
                    'SemanticFunction': main_semantic_function,
                    'Label': func_code,
                    'Boundaries': ','.join(map(str, boundaries)),
                    'SemanticTypes': json.dumps(semantic_types),
                    'SemanticFunctions': json.dumps(semantic_functions)
                }

                labels_data.append(row)

            except Exception as e:
                print(f"处理第 {i} 行数据时出错: {e}")
                print(f"数据内容: {hex_line}")
                # 添加错误数据的默认标签
                row = {
                    'Index': i,
                    'HexData': hex_line,
                    'Length': 0,
                    'Protocol': protocol.upper(),
                    'FunctionCode': 'ERROR',
                    'HasBoundary': 0,
                    'BoundaryCount': 0,
                    'SemanticType': 'DATA',
                    'SemanticFunction': 'UNKNOWN',
                    'Label': 'ERROR',
                    'Boundaries': '',
                    'SemanticTypes': '{}',
                    'SemanticFunctions': '{}'
                }
                labels_data.append(row)

        # 创建DataFrame并保存
        df = pd.DataFrame(labels_data)

        # 确保输出目录存在
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)

        # 保存CSV文件
        df.to_csv(output_csv, index=False, encoding='utf-8')

        print(f"成功生成 {len(labels_data)} 条标签")
        print(f"边界标签统计:")
        print(f"  - 有边界的样本: {df['HasBoundary'].sum()}")
        print(f"  - 平均边界数: {df['BoundaryCount'].mean():.2f}")
        print(f"功能码分布:")
        print(df['FunctionCode'].value_counts().head(10))

        return df

    def get_function_code_description(self, format_key: bytes, protocol: str) -> str:
        """获取功能码描述"""
        if protocol == 'dnp3':
            if format_key == b'\x05\x64':
                return 'DATA_LINK_LAYER'
            else:
                return f'FUNC_{format_key.hex().upper()}'
        elif protocol == 'modbus':
            return f'FUNC_{format_key.hex().upper()}'
        elif protocol == 'smb':
            # SMB功能码描述
            if isinstance(format_key, bytes):
                cmd_hex = format_key.hex().upper()
                cmd_descriptions = {
                    'A2': 'SMB_NT_CREATE_ANDX',
                    '74': 'SMB_LOGOFF_ANDX',
                    '25': 'SMB_TRANSACTION',
                    '72': 'SMB_NEGOTIATE',
                    '73': 'SMB_SESSION_SETUP_ANDX',
                    '75': 'SMB_TREE_CONNECT_ANDX',
                    '2E': 'SMB_READ_ANDX',
                    '2F': 'SMB_WRITE_ANDX',
                    '04': 'SMB_CLOSE',
                    '71': 'SMB_TREE_DISCONNECT',
                    '2B': 'SMB_ECHO',
                    '34': 'SMB_FIND_CLOSE'
                }
                return cmd_descriptions.get(cmd_hex, f'SMB_CMD_{cmd_hex}')
            else:
                return 'SMB_UNKNOWN'
        elif protocol == 'smb2':
            # SMB2功能码描述
            if isinstance(format_key, bytes):
                cmd_hex = format_key.hex().upper()
                cmd_descriptions = {
                    '0000': 'SMB2_NEGOTIATE',
                    '0001': 'SMB2_SESSION_SETUP',
                    '0002': 'SMB2_LOGOFF',
                    '0003': 'SMB2_TREE_CONNECT',
                    '0004': 'SMB2_TREE_DISCONNECT',
                    '0005': 'SMB2_CREATE',
                    '0006': 'SMB2_CLOSE',
                    '0007': 'SMB2_FLUSH',
                    '0008': 'SMB2_READ',
                    '0009': 'SMB2_WRITE',
                    '000A': 'SMB2_LOCK',
                    '000B': 'SMB2_IOCTL',
                    '000C': 'SMB2_CANCEL',
                    '000D': 'SMB2_ECHO',
                    '000E': 'SMB2_QUERY_DIRECTORY',
                    '000F': 'SMB2_CHANGE_NOTIFY',
                    '0010': 'SMB2_QUERY_INFO',
                    '0011': 'SMB2_SET_INFO'
                }
                return cmd_descriptions.get(cmd_hex, f'SMB2_CMD_{cmd_hex}')
            else:
                return 'SMB2_UNKNOWN'
        elif protocol == 'dns':
            # DNS功能码描述基于Flags字段
            if format_key == b'default':
                return 'DNS_DEFAULT'
            else:
                flags_hex = format_key.hex().upper()
                # 解析DNS标志位
                if len(format_key) >= 2:
                    flags_int = int(flags_hex, 16)
                    qr = (flags_int >> 15) & 1  # Query/Response bit
                    opcode = (flags_int >> 11) & 0xF  # Opcode

                    if qr == 0:
                        if opcode == 0:
                            return 'DNS_STANDARD_QUERY'
                        else:
                            return f'DNS_QUERY_OP{opcode}'
                    else:
                        if opcode == 0:
                            return 'DNS_STANDARD_RESPONSE'
                        else:
                            return f'DNS_RESPONSE_OP{opcode}'
                return f'DNS_{flags_hex}'
        elif protocol == 's7comm':
            # S7Comm功能码描述
            if format_key == b'default':
                return 'S7COMM_DEFAULT'
            elif isinstance(format_key, bytes):
                code_hex = format_key.hex().upper()

                # ROSCTR描述
                rosctr_descriptions = {
                    '01': 'JOB_REQUEST',
                    '02': 'ACK',
                    '03': 'ACK_DATA',
                    '07': 'USERDATA'
                }

                # 功能码描述
                function_descriptions = {
                    'F0': 'SETUP_COMMUNICATION',
                    '04': 'READ_VAR',
                    '05': 'WRITE_VAR',
                    '00': 'CPU_SERVICES',
                    '1A': 'REQUEST_DOWNLOAD',
                    '1B': 'DOWNLOAD_BLOCK',
                    '1C': 'DOWNLOAD_ENDED',
                    '1D': 'START_UPLOAD',
                    '1E': 'UPLOAD',
                    '1F': 'END_UPLOAD',
                    '28': 'PLC_CONTROL',
                    '29': 'PLC_STOP'
                }

                if code_hex in rosctr_descriptions:
                    return f'S7COMM_{rosctr_descriptions[code_hex]}'
                elif code_hex in function_descriptions:
                    return f'S7COMM_{function_descriptions[code_hex]}'
                else:
                    return f'S7COMM_{code_hex}'
            else:
                return 'S7COMM_UNKNOWN'
        elif protocol == 'ftp':
            try:
                if format_key == b'default':
                    return 'FTP_DEFAULT'
                # 解码FTP命令或响应
                ftp_text = format_key.decode('ascii', errors='ignore').strip()

                # 检查是否是FTP响应码
                if len(ftp_text) >= 3 and ftp_text[:3].isdigit():
                    response_code = ftp_text[:3]
                    separator = ftp_text[3:4] if len(ftp_text) > 3 else ''

                    response_descriptions = {
                        '220': 'SERVICE_READY',
                        '230': 'USER_LOGGED_IN',
                        '331': 'USER_OK_NEED_PASSWORD',
                        '250': 'FILE_ACTION_OK',
                        '150': 'FILE_STATUS_OK',
                        '226': 'CLOSING_DATA_CONNECTION',
                        '425': 'CANT_OPEN_DATA_CONNECTION',
                        '500': 'SYNTAX_ERROR',
                        '421': 'SERVICE_NOT_AVAILABLE',
                        '530': 'NOT_LOGGED_IN',
                        '550': 'ACTION_NOT_TAKEN',
                        '257': 'DIRECTORY_CREATED',
                        '200': 'COMMAND_OK',
                        '213': 'FILE_STATUS',
                        '227': 'ENTERING_PASSIVE_MODE',
                        '221': 'SERVICE_CLOSING'
                    }

                    base_desc = response_descriptions.get(response_code, f'RESPONSE_{response_code}')
                    if separator == '-':
                        return f'FTP_{base_desc}_MULTILINE'
                    else:
                        return f'FTP_{base_desc}'

                # 检查是否是FTP命令
                else:
                    command_descriptions = {
                        'USER': 'USER_NAME',
                        'PASS': 'PASSWORD',
                        'PWD': 'PRINT_WORKING_DIR',
                        'CWD': 'CHANGE_WORKING_DIR',
                        'LIST': 'LIST_FILES',
                        'RETR': 'RETRIEVE_FILE',
                        'STOR': 'STORE_FILE',
                        'QUIT': 'QUIT',
                        'TYPE': 'TRANSFER_TYPE',
                        'PORT': 'DATA_PORT'
                    }

                    cmd = ftp_text.split()[0] if ftp_text else ftp_text
                    return f'FTP_{command_descriptions.get(cmd.upper(), cmd.upper())}'

            except:
                return f'FTP_{format_key.hex().upper()}'
        elif protocol == 'tls12':
            return f'TLS_{format_key.hex().upper()}'
        elif protocol == 'dhcp':
            return f'DHCP_{format_key.hex().upper()}'
        else:
            return f'FUNC_{format_key.hex().upper()}'


def main():
    """主函数"""
    generator = EnhancedProtocolLabelGenerator()

    # 数据根目录
    data_root = Path("../Msg2")

    # 支持的协议及其文件路径
    protocols = {
        'smb': {
            'txt_file': data_root / "txt" / "smb" / "smb.txt",
            'csv_file': data_root / "csv" / "smb" / "smb.csv"
        },
        'smb2': {
            'txt_file': data_root / "txt" / "smb2" / "smb2.txt",
            'csv_file': data_root / "csv" / "smb2" / "smb2.csv"
        },
        'dns': {
            'txt_file': data_root / "txt" / "dns" / "dns.txt",
            'csv_file': data_root / "csv" / "dns" / "dns.csv"
        },
        's7comm': {
            'txt_file': data_root / "txt" / "s7comm" / "s7comm.txt",
            'csv_file': data_root / "csv" / "s7comm" / "s7comm.csv"
        },
        'dnp3': {
            'txt_file': data_root / "txt" / "dnp3" / "dnp3.txt",
            'csv_file': data_root / "csv" / "dnp3" / "dnp3.csv"
        },
        'modbus': {
            'txt_file': data_root / "txt" / "modbus" / "modbus.txt",
            'csv_file': data_root / "csv" / "modbus" / "modbus.csv"
        },
        'ftp': {
            'txt_file': data_root / "txt" / "ftp" / "ftp.txt",
            'csv_file': data_root / "csv" / "ftp" / "ftp.csv"
        },
        'tls12': {
            'txt_file': data_root / "txt" / "tls" / "tls12.txt",
            'csv_file': data_root / "csv" / "tls" / "tls.csv"
        },
        'dhcp': {
            'txt_file': data_root / "txt" / "dhcp" / "dhcp.txt",
            'csv_file': data_root / "csv" / "dhcp" / "dhcp.csv"
        }
    }

    # 生成每个协议的标签
    for protocol, files in protocols.items():
        txt_file = files['txt_file']
        csv_file = files['csv_file']

        if txt_file.exists():
            print(f"\n{'=' * 50}")
            print(f"生成 {protocol.upper()} 协议标签")
            print(f"{'=' * 50}")

            try:
                df = generator.generate_csv_labels(str(txt_file), protocol, str(csv_file))
                print(f"✅ {protocol.upper()} 标签生成成功")

                # 保存详细的groundtruth信息
                groundtruth_file = csv_file.parent / f"{protocol}_groundtruth.json"

                # 处理syntax_groundtruth中的不同键类型
                syntax_gt_serializable = {}
                for k, v in generator.protocols[protocol]['syntax_gt'].items():
                    if isinstance(k, bytes):
                        syntax_gt_serializable[k.hex()] = v
                    else:
                        syntax_gt_serializable[str(k)] = v

                groundtruth_info = {
                    'protocol': protocol,
                    'syntax_groundtruth': syntax_gt_serializable,
                    'semantic_types_mapping': generator.type_mapping,
                    'semantic_functions_mapping': generator.function_mapping,
                    'unified_semantic_types': generator.unified_semantic_types,
                    'unified_semantic_functions': generator.unified_semantic_functions
                }

                with open(groundtruth_file, 'w', encoding='utf-8') as f:
                    json.dump(groundtruth_info, f, indent=2, ensure_ascii=False)

                print(f"📋 Ground truth信息已保存到: {groundtruth_file}")

            except Exception as e:
                print(f"❌ {protocol.upper()} 标签生成失败: {e}")
                import traceback
                traceback.print_exc()
        else:
            print(f"⚠️  {protocol.upper()} 数据文件不存在: {txt_file}")

    print(f"\n{'=' * 50}")
    print("标签生成完成！")
    print(f"{'=' * 50}")

    # 生成汇总统计
    print("\n📊 协议标签生成汇总:")
    total_protocols = len(protocols)
    successful = 0
    for protocol, files in protocols.items():
        csv_file = files['csv_file']
        if csv_file.exists():
            successful += 1
            df = pd.read_csv(csv_file)
            print(f"  {protocol.upper():<8}: {len(df):>6} 条记录")

    print(f"\n成功处理 {successful}/{total_protocols} 个协议")


if __name__ == "__main__":
    main()