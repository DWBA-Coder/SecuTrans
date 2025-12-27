#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecuTrans 配置文件
配置应用的各种参数和常量
"""

# 颜色配置
GUI_COLORS = {
    'primary': '#005FA5',      # 桂电蓝
    'secondary': '#004080',    # 深蓝色
    'success': '#4CAF50',      # 绿色
    'error': '#F44336',        # 红色
    'warning': '#FFC107',      # 黄色
    'background': '#F5F5F5',   # 背景色
    'text': '#333333',         # 文字颜色
    'white': '#FFFFFF'         # 白色
}

# 加密算法配置
ENCRYPTION_ALGORITHMS = {
    'AES-128': {'key_size': [16], 'modes': ['ECB', 'CBC', 'GCM', 'CFB', 'OFB', 'CTR'], 'secure': True},
    'AES-192': {'key_size': [24], 'modes': ['ECB', 'CBC', 'GCM', 'CFB', 'OFB', 'CTR'], 'secure': True},
    'AES-256': {'key_size': [32], 'modes': ['ECB', 'CBC', 'GCM', 'CFB', 'OFB', 'CTR'], 'secure': True},
    'ChaCha20': {'key_size': [32], 'modes': ['Stream'], 'secure': True},
    'SM4': {'key_size': [16], 'modes': ['ECB', 'CBC', 'CBC + HMAC-SM3', 'CFB', 'OFB', 'CTR'], 'secure': True},
    'Camellia': {'key_size': [16, 24, 32], 'modes': ['ECB', 'CBC', 'CFB', 'OFB', 'CTR'], 'secure': True},
    'DES': {'key_size': [8], 'modes': ['ECB', 'CBC', 'CFB', 'OFB'], 'secure': False},
    'DES3': {'key_size': [16, 24], 'modes': ['ECB', 'CBC', 'CFB', 'OFB'], 'secure': False},
    'Blowfish': {'key_size': [16, 24, 32], 'modes': ['ECB', 'CBC', 'CFB', 'OFB'], 'secure': False},
    'RC4': {'key_size': [16, 24, 32], 'modes': ['Stream'], 'secure': False}
}

# 哈希算法配置
HASH_ALGORITHMS = {
    'MD5': {'secure': False, 'description': '不安全！仅供演示'},
    'SHA-1': {'secure': False, 'description': '不安全！仅供演示'},
    'SHA-256': {'secure': True, 'description': '安全'},
    'SHA-512': {'secure': True, 'description': '安全'},
    'SHA3-256': {'secure': True, 'description': '安全'},
    'BLAKE2b': {'secure': True, 'description': '安全'},
    'BLAKE3': {'secure': True, 'description': '安全'},
    'SM3': {'secure': True, 'description': '安全（国标）'}
}

# 文件大小限制 (100MB)
MAX_FILE_SIZE = 100 * 1024 * 1024

# 网络配置
DEFAULT_PORT = 8888
BUFFER_SIZE = 8192

# 日志配置
LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
DEFAULT_LOG_LEVEL = 'INFO'