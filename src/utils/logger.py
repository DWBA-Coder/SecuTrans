#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecuTrans 日志模块
实现操作日志记录功能
"""

import logging
import os
from datetime import datetime
from typing import Optional
import sys
import os

# 添加src目录到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(current_dir)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from core.config import LOG_LEVELS, DEFAULT_LOG_LEVEL


class Logger:
    """日志管理类"""
    
    def __init__(self, name: str = "SecuTrans", log_file: Optional[str] = None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, DEFAULT_LOG_LEVEL))
        
        # 清除已有的处理器
        self.logger.handlers.clear()
        
        # 创建格式化器
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # 文件处理器
        if log_file:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def debug(self, message: str):
        """记录调试信息"""
        self.logger.debug(message)
    
    def info(self, message: str):
        """记录信息"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """记录警告"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """记录错误"""
        self.logger.error(message)
    
    def critical(self, message: str):
        """记录严重错误"""
        self.logger.critical(message)
    
    def set_level(self, level: str):
        """设置日志级别"""
        if level in LOG_LEVELS:
            self.logger.setLevel(getattr(logging, level))
        else:
            self.warning(f"无效的日志级别: {level}")


# 创建全局日志实例
app_logger = Logger(log_file="secutrans.log")


def get_logger() -> Logger:
    """获取日志实例"""
    return app_logger


def log_operation(operation: str, status: str = "SUCCESS", details: str = ""):
    """记录操作日志"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"[{operation}] - {status}"
    if details:
        message += f" - {details}"
    
    if status == "SUCCESS":
        app_logger.info(message)
    elif status == "WARNING":
        app_logger.warning(message)
    elif status in ["ERROR", "FAILED"]:
        app_logger.error(message)
    else:
        app_logger.info(message)