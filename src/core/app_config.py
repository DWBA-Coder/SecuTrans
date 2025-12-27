#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecuTrans 应用配置管理模块
管理应用配置的保存和加载
"""

import json
import os
from typing import Dict, Any, Optional

CONFIG_FILE = "config/app_config.json"
DEFAULT_CONFIG = {
    "private_key_path": "",
    "public_certificate_path": "",
    "receive_directory": "files/",
    "server_port": "5375",
    "last_algorithm": "AES-256",
    "last_mode": "GCM",
    "auto_generate_key_info": {
        "name": "SecuTrans",
        "email": "user@sectrans.com",
        "organization": "SecuTrans Team",
        "country": "CN"
    }
}


class AppConfig:
    """应用配置管理类"""
    
    def __init__(self):
        self.config = DEFAULT_CONFIG.copy()
        self._ensure_config_dir()
        self.load_config()
    
    def _ensure_config_dir(self):
        """确保配置目录存在"""
        config_dir = os.path.dirname(CONFIG_FILE)
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
    
    def load_config(self):
        """加载配置文件"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                    # 合并配置，保留默认值
                    for key, value in loaded_config.items():
                        if key in self.config:
                            self.config[key] = value
        except Exception as e:
            print(f"加载配置失败，使用默认配置: {e}")
    
    def save_config(self):
        """保存配置文件"""
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"保存配置失败: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值"""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        """设置配置值"""
        self.config[key] = value
        self.save_config()
    
    def get_auto_generate_info(self) -> Dict[str, str]:
        """获取自动生成密钥的信息"""
        return self.config.get("auto_generate_key_info", {})
    
    def set_auto_generate_info(self, info: Dict[str, str]):
        """设置自动生成密钥的信息"""
        self.config["auto_generate_key_info"] = info
        self.save_config()
    
    def get_last_crypto_settings(self) -> tuple:
        """获取上次的加密设置"""
        algorithm = self.get("last_algorithm", "AES-256")
        mode = self.get("last_mode", "GCM")
        return algorithm, mode
    
    def set_last_crypto_settings(self, algorithm: str, mode: str):
        """设置加密设置"""
        self.set("last_algorithm", algorithm)
        self.set("last_mode", mode)


# 全局配置实例
app_config = AppConfig()