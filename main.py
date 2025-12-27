#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecuTrans - 文件安全传输工具
主程序入口文件

项目结构：
SecuTrans/
├── main.py              # 主程序入口
├── requirements.txt     # 依赖包列表
├── src/                # 源代码目录
│   ├── core/          # 核心功能模块
│   │   ├── config.py      # 配置文件
│   │   ├── crypto_utils.py # 加密工具
│   │   └── network_utils.py # 网络工具
│   ├── gui/           # 图形界面模块
│   │   ├── gui_components.py # GUI组件
│   │   └── unified_window.py # 统一界面
│   └── utils/         # 工具模块
│       └── logger.py       # 日志工具
├── tests/             # 测试代码
├── docs/              # 文档
└── examples/          # 示例代码

作者: SecuTrans Team
版本: 2.2.1
描述: 基于网络的文件安全传输工具，支持多种加密算法和数字信封技术
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox

# 添加src目录到Python路径
src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

def check_python_version():
    """检查Python版本"""
    if sys.version_info < (3, 7):
        messagebox.showerror(
            "版本不兼容", 
            f"需要 Python 3.7 或更高版本！\n当前版本: {sys.version}"
        )
        sys.exit(1)

def check_dependencies():
    """检查依赖是否安装"""
    try:
        import cryptography
        import Crypto
        return True
    except ImportError as e:
        messagebox.showerror(
            "依赖缺失", 
            f"缺少必要的依赖包:\n{str(e)}\n\n请运行:\npip install -r requirements.txt"
        )
        return False

def main():
    """主函数"""
    try:
        # 检查Python版本
        check_python_version()
        
        # 检查依赖
        if not check_dependencies():
            return
        
        # 导入并创建应用
        import gui.unified_interface as unified_interface
        from gui.unified_interface import UnifiedInterface
        
        # 创建根窗口
        root = tk.Tk()
        app = UnifiedInterface(root)
        
        # 运行应用
        root.mainloop()
        
    except KeyboardInterrupt:
        print("应用程序被用户中断")
        sys.exit(1)
    except Exception as e:
        messagebox.showerror("启动错误", f"应用程序启动失败:\n{str(e)}")
        print(f"启动错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()