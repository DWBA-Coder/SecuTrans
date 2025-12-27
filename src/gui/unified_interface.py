#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecuTrans 统一界面实现
将发送和接收功能合并到一个界面中
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import time
from datetime import datetime
from typing import Optional

import sys
import os
from Crypto.PublicKey import RSA

# 确保src目录在Python路径中
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(current_dir)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from core.config import GUI_COLORS, ENCRYPTION_ALGORITHMS, HASH_ALGORITHMS, MAX_FILE_SIZE
from core.crypto_utils import CryptoUtils
from core.network_utils import NetworkUtils
from core.app_config import app_config
from utils.logger import get_logger, log_operation


class UnifiedInterface:
    """统一界面类"""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.logger = get_logger()
        self.network_utils = NetworkUtils()
        self.crypto_utils = CryptoUtils()
        
        # 发送方相关
        self.selected_file = None
        self.recipient_public_key = None
        self.is_connected = False
        
        # 接收方相关
        self.private_key = None
        self.server_running = False
        self.client_socket = None
        
        # 进度条
        self.send_progress = None
        self.receive_progress = None
        
        # IP地址变量
        self.local_ip_var = tk.StringVar(value=self.network_utils.get_local_ip())
        
        self._setup_window()
        self._create_widgets()
        self._setup_layout()
        self._load_saved_config()
        self._initialize_progress_bars()
        
        # 记录应用启动
        log_operation("应用程序启动", "SUCCESS")
    
    def _setup_window(self):
        """设置窗口属性"""
        self.root.title("SecuTrans - 文件安全传输工具 v2.2.3")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)
        self.root.configure(bg=GUI_COLORS['background'])
        
        # 设置窗口居中
        self.center_window()
        
        # 窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
    
    def center_window(self):
        """将窗口居中显示"""
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (1200 // 2)
        y = (self.root.winfo_screenheight() // 2) - (800 // 2)
        self.root.geometry(f"1200x800+{x}+{y}")
    
    def _create_widgets(self):
        """创建界面组件"""
        # 创建菜单栏
        self._create_menu()
        
        # 创建主容器
        main_frame = tk.Frame(self.root, bg=GUI_COLORS['background'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 上：密钥管理（左）和文件管理（右）- 按比例2:1
        top_frame = tk.Frame(main_frame, bg=GUI_COLORS['background'])
        top_frame.pack(fill=tk.X, pady=(0, 10))
        self._create_top_section(top_frame)
        
        # 中：文件传输（发送和接收左右布局）
        middle_frame = tk.Frame(main_frame, bg=GUI_COLORS['background'])
        middle_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self._create_middle_section(middle_frame)
        
        # 下：日志记录
        self._create_log_area(main_frame)
    
    def _create_menu(self):
        """创建菜单栏"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="选择发送文件", command=self._menu_select_file, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="生成密钥对", command=self._generate_key_pair, accelerator="Ctrl+G")
        file_menu.add_command(label="导入私钥", command=self._menu_import_private_key, accelerator="Ctrl+I")
        file_menu.add_command(label="导入证书", command=self._menu_import_certificate, accelerator="Ctrl+M")
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self._on_closing, accelerator="Ctrl+Q")
        
        # 工具菜单
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="操作", menu=tools_menu)
        tools_menu.add_command(label="启动服务器", command=self._start_server, accelerator="F2")
        tools_menu.add_command(label="停止服务器", command=self._stop_server, accelerator="F3")
        tools_menu.add_command(label="清空日志", command=self._clear_log, accelerator="Ctrl+L")
        tools_menu.add_command(label="保存日志", command=self._save_log, accelerator="Ctrl+S")
        tools_menu.add_command(label="导出配置", command=self._export_config, accelerator="Ctrl+E")
        tools_menu.add_command(label="导入配置", command=self._import_config, accelerator="Ctrl+P")
        
        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="帮助", menu=help_menu)
        help_menu.add_command(label="使用说明", command=self._show_help, accelerator="F1")
        help_menu.add_command(label="关于", command=self._show_about, accelerator="Ctrl+A")
        
        # 绑定快捷键
        self.root.bind('<Control-o>', lambda e: self._menu_select_file())
        self.root.bind('<Control-g>', lambda e: self._generate_key_pair())
        self.root.bind('<Control-i>', lambda e: self._menu_import_private_key())
        self.root.bind('<Control-m>', lambda e: self._menu_import_certificate())
        self.root.bind('<Control-q>', lambda e: self._on_closing())
        self.root.bind('<F2>', lambda e: self._start_server())
        self.root.bind('<F3>', lambda e: self._stop_server())
        self.root.bind('<Control-l>', lambda e: self._clear_log())
        self.root.bind('<Control-s>', lambda e: self._save_log())
        self.root.bind('<Control-e>', lambda e: self._export_config())
        self.root.bind('<Control-p>', lambda e: self._import_config())
        self.root.bind('<Control-a>', lambda e: self._show_about())
        self.root.bind('<F1>', lambda e: self._show_help())
    
    def _create_top_section(self, parent):
        """创建上部分：密钥管理（左5/8）和文件管理（右3/8）"""
        # 左：密钥管理区域（5/8）
        key_frame = tk.LabelFrame(
            parent,
            text="密钥管理",
            font=('微软雅黑', 12, 'bold'),
            bg=GUI_COLORS['background'],
            fg=GUI_COLORS['text']
        )
        key_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # 密钥管理内部布局：密钥生成（左2/5）和密钥选择（右3/5）
        # 左：密钥生成
        left_frame = tk.Frame(key_frame, bg=GUI_COLORS['background'])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)
        
        gen_label = tk.Label(
            left_frame,
            text="密钥生成",
            font=('微软雅黑', 11, 'bold'),
            bg=GUI_COLORS['background']
        )
        gen_label.pack(anchor='w', pady=(5, 10))
        
        # 密钥生成信息
        info_frame = tk.Frame(left_frame, bg=GUI_COLORS['background'])
        info_frame.pack(fill=tk.X, padx=10)
        
        tk.Label(info_frame, text="姓名:", bg=GUI_COLORS['background']).grid(row=0, column=0, sticky='w', padx=(0, 5))
        self.key_name_var = tk.StringVar(value=app_config.get_auto_generate_info().get('name', 'SecuTrans'))
        tk.Entry(info_frame, textvariable=self.key_name_var, width=25).grid(row=0, column=1, padx=5)
        
        tk.Label(info_frame, text="邮箱:", bg=GUI_COLORS['background']).grid(row=1, column=0, sticky='w', padx=(0, 5), pady=5)
        self.key_email_var = tk.StringVar(value=app_config.get_auto_generate_info().get('email', 'user@sectrans.com'))
        tk.Entry(info_frame, textvariable=self.key_email_var, width=25).grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(info_frame, text="组织:", bg=GUI_COLORS['background']).grid(row=2, column=0, sticky='w', padx=(0, 5))
        self.key_org_var = tk.StringVar(value=app_config.get_auto_generate_info().get('organization', 'SecuTrans Team'))
        tk.Entry(info_frame, textvariable=self.key_org_var, width=25).grid(row=2, column=1, padx=5)
        
        # 生成按钮
        generate_btn_frame = tk.Frame(left_frame, bg=GUI_COLORS['background'])
        generate_btn_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(
            generate_btn_frame,
            text="生成密钥对",
            command=self._generate_key_pair,
            width=18
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            generate_btn_frame,
            text="自定义位置",
            command=self._custom_key_location,
            width=12
        ).pack(side=tk.LEFT, padx=5)
        
        # 右：密钥选择
        right_frame = tk.Frame(key_frame, bg=GUI_COLORS['background'])
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10)
        
        import_label = tk.Label(
            right_frame,
            text="密钥选择",
            font=('微软雅黑', 11, 'bold'),
            bg=GUI_COLORS['background']
        )
        import_label.pack(anchor='w', pady=(5, 10))
        
        # 私钥选择
        private_frame = tk.Frame(right_frame, bg=GUI_COLORS['background'])
        private_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(private_frame, text="我的私钥:", bg=GUI_COLORS['background']).pack(anchor='w')
        self.private_key_var = tk.StringVar()
        private_frame2 = tk.Frame(private_frame, bg=GUI_COLORS['background'])
        private_frame2.pack(fill=tk.X)
        
        tk.Entry(private_frame2, textvariable=self.private_key_var, width=45).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(private_frame2, text="浏览", command=self._browse_private_key, width=8).pack(side=tk.RIGHT, padx=(5, 0))
        
        # 证书选择
        cert_frame = tk.Frame(right_frame, bg=GUI_COLORS['background'])
        cert_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(cert_frame, text="接收方证书:", bg=GUI_COLORS['background']).pack(anchor='w')
        self.cert_var = tk.StringVar()
        cert_frame2 = tk.Frame(cert_frame, bg=GUI_COLORS['background'])
        cert_frame2.pack(fill=tk.X)
        
        tk.Entry(cert_frame2, textvariable=self.cert_var, width=45).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(cert_frame2, text="浏览", command=self._browse_certificate, width=8).pack(side=tk.RIGHT, padx=(5, 0))
        
        # 右：文件管理区域（3/8）
        file_frame = tk.LabelFrame(
            parent,
            text="文件管理",
            font=('微软雅黑', 12, 'bold'),
            bg=GUI_COLORS['background'],
            fg=GUI_COLORS['text'],
            width=500,  # 固定宽度
            height=215  # 固定高度
        )
        file_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        file_frame.pack_propagate(False)  # 防止子组件改变框架大小
        
        # 发送文件选择（上）
        file_select_frame = tk.Frame(file_frame, bg=GUI_COLORS['background'])
        file_select_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))
        
        tk.Label(file_select_frame, text="发送文件:", font=('微软雅黑', 10, 'bold'), bg=GUI_COLORS['background']).pack(anchor='w')
        
        # 文件选择区域
        file_info_frame = tk.Frame(file_select_frame, bg=GUI_COLORS['background'])
        file_info_frame.pack(fill=tk.X, pady=5)
        
        self.file_path_var = tk.StringVar()
        tk.Entry(file_info_frame, textvariable=self.file_path_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(file_info_frame, text="浏览", command=self._browse_file, width=8).pack(side=tk.RIGHT, padx=(5, 5))
        
        # 文件信息显示
        self.file_info_var = tk.StringVar(value="未选择文件")
        file_info_label = tk.Label(file_select_frame, textvariable=self.file_info_var, fg=GUI_COLORS['text'], bg=GUI_COLORS['background'])
        file_info_label.pack(anchor='w', pady=(5, 0))
        
        # 文件保存（下）
        save_frame = tk.Frame(file_frame, bg=GUI_COLORS['background'])
        save_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))
        
        tk.Label(save_frame, text="文件保存:", font=('微软雅黑', 10, 'bold'), bg=GUI_COLORS['background']).pack(anchor='w')
        
        save_info_frame = tk.Frame(save_frame, bg=GUI_COLORS['background'])
        save_info_frame.pack(fill=tk.X, pady=5)
        
        self.save_path_var = tk.StringVar(value=app_config.get("receive_directory", "files/"))
        tk.Entry(save_info_frame, textvariable=self.save_path_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(save_info_frame, text="浏览", command=self._browse_save_path, width=8).pack(side=tk.RIGHT, padx=(5, 5))
    
    def _create_middle_section(self, parent):
        """创建中部分：文件传输区域（左右布局）"""
        transfer_frame = tk.LabelFrame(
            parent,
            text="文件传输",
            font=('微软雅黑', 12, 'bold'),
            bg=GUI_COLORS['background'],
            fg=GUI_COLORS['text']
        )
        transfer_frame.pack(fill=tk.BOTH, expand=True)
        
        # 左：文件发送（包含加密设置和网络设置）
        send_frame = tk.Frame(transfer_frame, bg=GUI_COLORS['background'])
        send_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(send_frame, text="文件发送", font=('微软雅黑', 11, 'bold'), bg=GUI_COLORS['background']).pack(anchor='w')
        
        # 加密设置和网络设置左右布局
        settings_frame = tk.Frame(send_frame, bg=GUI_COLORS['background'])
        settings_frame.pack(fill=tk.X, pady=10)
        
        # 加密设置（左）
        crypto_frame = tk.LabelFrame(
            settings_frame,
            text="加密设置",
            font=('微软雅黑', 10),
            bg=GUI_COLORS['background'],
            width=320,  # 固定宽度
            height=130  # 固定高度
        )
        crypto_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        crypto_frame.pack_propagate(False)  # 防止子组件改变框架大小
        
        # 算法选择
        algo_frame = tk.Frame(crypto_frame, bg=GUI_COLORS['background'])
        algo_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 算法标签、下拉框和说明在同一行
        algo_row = tk.Frame(algo_frame, bg=GUI_COLORS['background'])
        algo_row.pack(fill=tk.X)
        
        tk.Label(algo_row, text="加密算法:", bg=GUI_COLORS['background']).pack(side=tk.LEFT)
        self.algorithm_var = tk.StringVar()
        self.algorithm_combo = ttk.Combobox(algo_row, textvariable=self.algorithm_var, state='readonly', width=16)
        self.algorithm_combo['values'] = list(ENCRYPTION_ALGORITHMS.keys())
        self.algorithm_combo.pack(side=tk.LEFT, padx=(5, 5))
        
        # 算法说明（居左显示，放在下拉框后面）
        self.algo_security_label = tk.Label(algo_row, text="", bg=GUI_COLORS['background'], justify=tk.LEFT)
        self.algo_security_label.pack(side=tk.LEFT, padx=(0, 0))
        
        # 模式选择
        mode_frame = tk.Frame(crypto_frame, bg=GUI_COLORS['background'])
        mode_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 模式标签、下拉框和说明在同一行
        mode_row = tk.Frame(mode_frame, bg=GUI_COLORS['background'])
        mode_row.pack(fill=tk.X)
        
        tk.Label(mode_row, text="加密模式:", bg=GUI_COLORS['background']).pack(side=tk.LEFT)
        self.mode_var = tk.StringVar()
        self.mode_combo = ttk.Combobox(mode_row, textvariable=self.mode_var, state='readonly', width=16)
        self.mode_combo.pack(side=tk.LEFT, padx=(5, 5))
        
        # 模式说明（居左显示，放在下拉框后面）
        self.mode_security_label = tk.Label(mode_row, text="", bg=GUI_COLORS['background'], justify=tk.LEFT)
        self.mode_security_label.pack(side=tk.LEFT, padx=(0, 0))
        
        # 哈希算法选择
        hash_frame = tk.Frame(crypto_frame, bg=GUI_COLORS['background'])
        hash_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 哈希算法标签、下拉框和说明在同一行
        hash_row = tk.Frame(hash_frame, bg=GUI_COLORS['background'])
        hash_row.pack(fill=tk.X)
        
        tk.Label(hash_row, text="哈希算法:", bg=GUI_COLORS['background']).pack(side=tk.LEFT)
        self.hash_var = tk.StringVar()
        self.hash_combo = ttk.Combobox(hash_row, textvariable=self.hash_var, state='readonly', width=16)
        self.hash_combo['values'] = list(HASH_ALGORITHMS.keys())
        self.hash_combo.pack(side=tk.LEFT, padx=(5, 5))
        
        # 哈希算法说明（居左显示，放在下拉框后面）
        self.hash_security_label = tk.Label(hash_row, text="", bg=GUI_COLORS['background'], justify=tk.LEFT)
        self.hash_security_label.pack(side=tk.LEFT, padx=(0, 0))
        
        # 绑定选择事件
        self.algorithm_combo.bind('<<ComboboxSelected>>', self._on_algorithm_changed)
        self.mode_combo.bind('<<ComboboxSelected>>', self._on_mode_changed)
        self.hash_combo.bind('<<ComboboxSelected>>', self._on_hash_changed)
        
        # 设置初始算法
        if list(ENCRYPTION_ALGORITHMS.keys()):
            default_algorithm = list(ENCRYPTION_ALGORITHMS.keys())[0]  # 第一个算法
            self.algorithm_var.set(default_algorithm)
            self.algorithm_combo.set(default_algorithm)
            
            # 初始化加密设置
            self._initialize_crypto_settings()
            # 立即更新模式列表
            self._on_algorithm_changed()
            
            # 初始化哈希算法设置
            if hasattr(self, 'hash_combo') and list(HASH_ALGORITHMS.keys()):
                default_hash = list(HASH_ALGORITHMS.keys())[2]  # SHA-256
                self.hash_var.set(default_hash)
                self.hash_combo.set(default_hash)
                self._update_hash_display()
        
        # 网络设置（右）
        network_frame = tk.LabelFrame(
            settings_frame,
            text="网络设置",
            font=('微软雅黑', 10),
            bg=GUI_COLORS['background']
        )
        network_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        net_info_frame = tk.Frame(network_frame, bg=GUI_COLORS['background'])
        net_info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # IP和端口在同一行
        ip_port_row = tk.Frame(net_info_frame, bg=GUI_COLORS['background'])
        ip_port_row.pack(fill=tk.X, pady=2)
        
        tk.Label(ip_port_row, text="接收方IP:", bg=GUI_COLORS['background']).pack(side=tk.LEFT)
        self.server_ip_var = tk.StringVar(value="127.0.0.1")
        tk.Entry(ip_port_row, textvariable=self.server_ip_var, width=10).pack(side=tk.LEFT, padx=(5, 10))
        
        tk.Label(ip_port_row, text="端口:", bg=GUI_COLORS['background']).pack(side=tk.LEFT)
        self.send_port_var = tk.StringVar(value="5375")
        tk.Entry(ip_port_row, textvariable=self.send_port_var, width=8).pack(side=tk.LEFT, padx=(5, 0))

        # 发送进度条
        self.send_progress_frame = tk.Frame(send_frame, bg=GUI_COLORS['background'])
        self.send_progress_frame.pack(fill=tk.X, pady=10)

        # 发送按钮
        send_btn_frame = tk.Frame(send_frame, bg=GUI_COLORS['background'])
        send_btn_frame.pack(fill=tk.X, pady=10)

        tk.Button(
            send_btn_frame,
            text="传输文件",
            command=self._send_file,
            width=15
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            send_btn_frame,
            text="重置进度",
            command=self._reset_send_progress,
            width=10
        ).pack(side=tk.LEFT, padx=5)

        # 右：文件接收（包含服务器设置和连接状态）
        receive_frame = tk.Frame(transfer_frame, bg=GUI_COLORS['background'])
        receive_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(receive_frame, text="文件接收", font=('微软雅黑', 11, 'bold'), bg=GUI_COLORS['background']).pack(anchor='w')
        
        # 服务器设置和连接状态左右布局
        receive_settings_frame = tk.Frame(receive_frame, bg=GUI_COLORS['background'])
        receive_settings_frame.pack(fill=tk.X, pady=10)
        
        # 服务器设置（左）
        server_frame = tk.LabelFrame(
            receive_settings_frame,
            text="服务器设置",
            font=('微软雅黑', 10),
            bg=GUI_COLORS['background']
        )
        server_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        server_info_frame = tk.Frame(server_frame, bg=GUI_COLORS['background'])
        server_info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 监听端口和本地IP在同一行
        listen_frame = tk.Frame(server_info_frame, bg=GUI_COLORS['background'])
        listen_frame.pack(fill=tk.X, pady=2)
        
        tk.Label(listen_frame, text="监听端口:", bg=GUI_COLORS['background']).pack(side=tk.LEFT)
        self.receive_port_var = tk.StringVar(value=app_config.get("server_port", "5375"))
        self.receive_port_entry = tk.Entry(listen_frame, textvariable=self.receive_port_var, width=8)
        self.receive_port_entry.pack(side=tk.LEFT, padx=(5, 10))
        
        tk.Label(listen_frame, text="本地IP:", bg=GUI_COLORS['background']).pack(side=tk.LEFT)
        tk.Label(listen_frame, textvariable=self.local_ip_var, bg=GUI_COLORS['background'], fg=GUI_COLORS['primary']).pack(side=tk.LEFT, padx=(5, 0))
        
        # 服务器控制
        server_btn_frame = tk.Frame(server_frame, bg=GUI_COLORS['background'])
        server_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_server_btn = tk.Button(
            server_btn_frame,
            text="启动服务器",
            command=self._start_server,
            width=16
        )
        self.start_server_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_server_btn = tk.Button(
            server_btn_frame,
            text="停止服务器",
            command=self._stop_server,
            width=16,
            state=tk.DISABLED
        )
        self.stop_server_btn.pack(side=tk.LEFT, padx=5)
        
        # 连接状态（右）
        status_frame = tk.LabelFrame(
            receive_settings_frame,
            text="连接状态",
            font=('微软雅黑', 10),
            bg=GUI_COLORS['background'],
            width=240,  # 固定宽度
            height=130  # 固定高度
        )
        status_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        status_frame.pack_propagate(False)  # 防止子组件改变框架大小
        
        self.server_status_var = tk.StringVar(value="服务器未启动")
        tk.Label(status_frame, textvariable=self.server_status_var, bg=GUI_COLORS['background'], fg=GUI_COLORS['warning']).pack(anchor='center', pady=5)

        self.client_info_var = tk.StringVar(value="等待连接...")
        tk.Label(status_frame, textvariable=self.client_info_var, bg=GUI_COLORS['background'], fg=GUI_COLORS['text']).pack(anchor='center', pady=5)
        
        # 接收进度条
        self.receive_progress_frame = tk.Frame(receive_frame, bg=GUI_COLORS['background'])
        self.receive_progress_frame.pack(fill=tk.X, pady=10)
        
        # 接收控制按钮
        receive_btn_frame = tk.Frame(receive_frame, bg=GUI_COLORS['background'])
        receive_btn_frame.pack(fill=tk.X, pady=5)
        
        tk.Button(
            receive_btn_frame,
            text="重置进度",
            command=self._reset_receive_progress,
            width=10
        ).pack(side=tk.LEFT, padx=5)
    
    def _update_crypto_display(self):
        """更新加密显示"""
        algorithm = self.algorithm_var.get()
        
        if algorithm in ENCRYPTION_ALGORITHMS:
            # 更新模式列表
            modes = ENCRYPTION_ALGORITHMS[algorithm]['modes']
            
            # 更新模式下拉框
            if hasattr(self, 'mode_combo'):
                # 清空现有值
                self.mode_combo['values'] = []
                self.mode_var.set("")
                
                # 设置新模式列表
                self.mode_combo['values'] = modes
                
                # 设置默认选择第一个模式
                if modes:
                    self.mode_combo.set(modes[0])
                    self.mode_var.set(modes[0])
                    
                    # 强制刷新下拉框
                    self.mode_combo.update()
                else:
                    self.mode_combo.set("")
                    self.mode_var.set("")
            
            # 更新算法安全状态
            is_secure = ENCRYPTION_ALGORITHMS[algorithm].get('secure', True)
            if is_secure:
                self.algo_security_label.config(text="安全", fg='green')
            else:
                self.algo_security_label.config(text="不安全！仅作演示", fg='red')
            
            # 更新模式安全状态
            self._update_mode_security()
    
    def _create_log_area(self, parent):
        """创建日志记录区域"""
        log_frame = tk.LabelFrame(
            parent,
            text="日志记录",
            font=('微软雅黑', 12, 'bold'),
            bg=GUI_COLORS['background'],
            fg=GUI_COLORS['text']
        )
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建日志文本框和滚动条
        log_scroll_frame = tk.Frame(log_frame, bg=GUI_COLORS['background'])
        log_scroll_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(log_scroll_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.log_text = tk.Text(
            log_scroll_frame,
            wrap=tk.WORD,
            yscrollcommand=scrollbar.set,
            font=('Consolas', 9),
            bg=GUI_COLORS['background'],
            fg='black',  # 普通日志黑色
            height=12
        )
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.log_text.yview)
        
        # 配置文本标签颜色
        self.log_text.tag_config('INFO', foreground='black')      # 普通黑色
        self.log_text.tag_config('SUCCESS', foreground='green')    # 成功绿色
        self.log_text.tag_config('WARNING', foreground='orange')    # 警告黄色（橙色）
        self.log_text.tag_config('ERROR', foreground='red')        # 错误红色
    
    def _setup_layout(self):
        """设置布局"""
        pass  # 布局已在_create_widgets中设置
    
    def _load_saved_config(self):
        """加载保存的配置"""
        try:
            # 加载密钥路径
            private_key_path = app_config.get("private_key_path", "")
            if private_key_path and os.path.exists(private_key_path):
                self.private_key_var.set(private_key_path)
                self.private_key = CryptoUtils.load_key_from_file(private_key_path)
            
            cert_path = app_config.get("public_certificate_path", "")
            if cert_path and os.path.exists(cert_path):
                self.cert_var.set(cert_path)
                self.recipient_public_key = CryptoUtils.load_key_from_file(cert_path)
            
            # 加载保存路径
            save_dir = app_config.get("receive_directory", "files/")
            self.save_path_var.set(save_dir)
            
            # 加载端口设置
            self.receive_port_var.set(app_config.get("server_port", "5375"))
            
            # 加载加密设置 - 延迟到界面完全创建后执行
            self.root.after(100, self._initialize_crypto_settings)
            
        except Exception as e:
            self.add_log(f"加载配置失败: {str(e)}", "ERROR")
    
    def _initialize_progress_bars(self):
        """初始化进度条"""
        # 创建发送进度条
        self.send_progress = self._create_progress_bar(self.send_progress_frame)
        self.send_progress.pack(fill=tk.X)
        self.send_progress.set_progress(0)
        
        # 创建接收进度条
        self.receive_progress = self._create_progress_bar(self.receive_progress_frame)
        self.receive_progress.pack(fill=tk.X)
        self.receive_progress.set_progress(0)
    
    def _save_config(self):
        """保存当前配置"""
        try:
            app_config.set("private_key_path", self.private_key_var.get())
            app_config.set("public_certificate_path", self.cert_var.get())
            app_config.set("receive_directory", self.save_path_var.get())
            app_config.set("server_port", self.receive_port_var.get())
            app_config.set_last_crypto_settings(self.algorithm_var.get(), self.mode_var.get())
            
            # 保存密钥生成信息
            app_config.set_auto_generate_info({
                'name': self.key_name_var.get(),
                'email': self.key_email_var.get(),
                'organization': self.key_org_var.get(),
                'country': 'CN'
            })
        except Exception as e:
            self.add_log(f"保存配置失败: {str(e)}", "ERROR")
    
    def _on_closing(self):
        """窗口关闭事件"""
        try:
            # 保存配置
            self._save_config()
            
            # 停止服务器
            if self.server_running:
                self.network_utils.close_connection()
                self.server_running = False
            
            # 关闭网络连接
            if self.is_connected:
                self.network_utils.close_connection()
            
            log_operation("应用程序退出", "SUCCESS")
            self.logger.info("应用程序正常退出")
            self.root.destroy()
        except Exception as e:
            print(f"关闭时出错: {e}")
            self.root.destroy()
    
    def add_log(self, message: str, level: str = 'INFO'):
        """添加日志消息"""
        timestamp = str(datetime.now().strftime("%H:%M:%S"))
        
        # 添加到界面
        self.log_text.insert(tk.END, f"[{timestamp}] ", 'INFO')
        self.log_text.insert(tk.END, f"{message}\n", level)
        self.log_text.see(tk.END)
        
        # 输出到命令行（特别是错误日志）
        if level == 'ERROR':
            print(f"[ERROR] {timestamp} {message}")
        elif level == 'WARNING':
            print(f"[WARNING] {timestamp} {message}")
        elif level == 'SUCCESS':
            print(f"[SUCCESS] {timestamp} {message}")
        else:
            print(f"[INFO] {timestamp} {message}")
        
        # 限制日志行数
        line_count = int(self.log_text.index('end-1c').split('.')[0])
        if line_count > 1000:
            self.log_text.delete('1.0', '100.0')
    
    def _on_algorithm_changed(self, event=None):
        """算法选择改变时的处理"""
        self._update_crypto_display()
    
    def _on_mode_changed(self, event=None):
        """模式选择改变时的处理"""
        self._update_crypto_display()
    
    def _on_hash_changed(self, event=None):
        """哈希算法选择改变时的处理"""
        self._update_hash_display()
    
    def _update_crypto_display(self):
        """更新加密显示"""
        algorithm = self.algorithm_var.get()
        
        if algorithm in ENCRYPTION_ALGORITHMS:
            # 更新模式列表
            modes = ENCRYPTION_ALGORITHMS[algorithm]['modes']
            self.mode_combo['values'] = modes  # 设置可用模式
            
            # 设置默认模式（如果当前模式不在列表中）
            current_mode = self.mode_var.get()
            if current_mode not in modes:
                if modes:
                    self.mode_var.set(modes[0])
                    self.mode_combo.set(modes[0])
                else:
                    self.mode_var.set("")
                    self.mode_combo.set("")
            
            # 更新算法安全状态
            is_secure = ENCRYPTION_ALGORITHMS[algorithm].get('secure', True)
            if is_secure:
                self.algo_security_label.config(text="安全", fg='green')
            else:
                self.algo_security_label.config(text="不安全（仅作演示）", fg='red')
            
            # 更新模式安全状态
            self._update_mode_security()
    
    def _initialize_crypto_settings(self):
        """初始化加密设置"""
        try:
            # 加载保存的加密设置
            algorithm, mode = app_config.get_last_crypto_settings()
            if not algorithm or algorithm not in ENCRYPTION_ALGORITHMS:
                # 设置默认算法为AES-256
                algorithm = 'AES-256'
                mode = 'GCM'
            
            # 设置算法
            if hasattr(self, 'algorithm_combo'):
                self.algorithm_var.set(algorithm)
                self.algorithm_combo.set(algorithm)
            
            # 先设置算法，然后更新模式列表
            self._update_crypto_display()
            
            # 延迟设置模式，确保模式列表已更新
            self.root.after(50, lambda: self._set_crypto_mode(mode))
            
        except Exception as e:
            self.add_log(f"初始化加密设置失败: {str(e)}", "ERROR")
    
    def _set_crypto_mode(self, mode):
        """设置加密模式"""
        try:
            if hasattr(self, 'mode_combo') and hasattr(self, 'mode_var'):
                available_modes = self.mode_combo['values']
                if mode in available_modes:
                    self.mode_var.set(mode)
                    self.mode_combo.set(mode)
                elif available_modes:
                    # 如果保存的模式不可用，选择第一个可用模式
                    default_mode = available_modes[0]
                    self.mode_var.set(default_mode)
                    self.mode_combo.set(default_mode)
                
                # 更新模式安全状态
                self._update_mode_security()

        except Exception as e:
            self.add_log(f"设置加密模式失败: {str(e)}", "ERROR")
    
    def _update_mode_security(self):
        """更新模式安全状态"""
        mode = self.mode_var.get()
        if mode == 'ECB':
            self.mode_security_label.config(text="不安全！仅作演示", fg='red')
        elif mode == 'GCM':
            self.mode_security_label.config(text="认证加密", fg='green')
        elif mode == 'CBC + HMAC-SM3':
            self.mode_security_label.config(text="国密认证模式", fg='green')
        else:
            self.mode_security_label.config(text="")
    
    def _update_hash_display(self):
        """更新哈希算法显示"""
        hash_algo = self.hash_var.get()
        
        if hash_algo in HASH_ALGORITHMS:
            # 更新哈希算法安全状态
            hash_info = HASH_ALGORITHMS[hash_algo]
            description = hash_info.get('description', '')
            
            if hash_info.get('secure', True):
                self.hash_security_label.config(text=description, fg='green')
            else:
                self.hash_security_label.config(text=description, fg='red')
    
    # 文件操作方法
    def _browse_file(self):
        """浏览文件"""
        filename = filedialog.askopenfilename(
            title="选择要发送的文件",
            filetypes=[
                ("所有文件", "*.*"),
                ("文档文件", "*.txt;*.doc;*.docx;*.pdf"),
                ("图片文件", "*.jpg;*.jpeg;*.png;*.gif;*.bmp"),
                ("视频文件", "*.mp4;*.avi;*.mkv;*.mov"),
                ("压缩文件", "*.zip;*.rar;*.7z;*.tar")
            ]
        )
        
        if filename:
            self.selected_file = filename
            self.file_path_var.set(filename)
            self._update_file_info(filename)
    
    def _update_file_info(self, filename: str):
        """更新文件信息显示"""
        try:
            import os
            file_size = os.path.getsize(filename)
            file_mtime = os.path.getmtime(filename)
            file_name = os.path.basename(filename)
            file_ext = os.path.splitext(filename)[1].upper()
            
            # 格式化文件大小
            if file_size < 1024:
                size_str = f"{file_size} B"
            elif file_size < 1024 * 1024:
                size_str = f"{file_size / 1024:.1f} KB"
            elif file_size < 1024 * 1024 * 1024:
                size_str = f"{file_size / (1024 * 1024):.1f} MB"
            else:
                size_str = f"{file_size / (1024 * 1024 * 1024):.1f} GB"
            
            # 格式化日期
            mtime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(file_mtime))
            
            # 设置文件信息
            info_text = f"文件名: {file_name} | 类型: {file_ext} | 大小: {size_str} | 修改时间: {mtime_str}"
            self.file_info_var.set(info_text)
            
        except Exception as e:
            self.file_info_var.set(f"获取文件信息失败: {str(e)}")
    
    def _browse_save_path(self):
        """浏览保存路径"""
        directory = filedialog.askdirectory(title="选择文件保存路径")
        if directory:
            self.save_path_var.set(directory)
    
    def _browse_private_key(self):
        """浏览私钥文件"""
        filename = filedialog.askopenfilename(
            title="选择私钥文件",
            filetypes=[("PEM文件", "*.pem"), ("所有文件", "*.*")]
        )
        
        if filename:
            self.private_key_var.set(filename)
            try:
                self.private_key = CryptoUtils.load_key_from_file(filename)
                self.add_log(f"成功加载私钥: {os.path.basename(filename)}", "SUCCESS")
            except Exception as e:
                self.add_log(f"加载私钥失败: {str(e)}", "ERROR")
    
    def _browse_certificate(self):
        """浏览证书文件"""
        filename = filedialog.askopenfilename(
            title="选择接收方证书文件",
            filetypes=[("PEM文件", "*.pem"), ("所有文件", "*.*")]
        )
        
        if filename:
            self.cert_var.set(filename)
            try:
                self.recipient_public_key = CryptoUtils.load_key_from_file(filename)
                self.add_log(f"成功加载证书: {os.path.basename(filename)}", "SUCCESS")
            except Exception as e:
                self.add_log(f"加载证书失败: {str(e)}", "ERROR")
    
    # 密钥生成方法
    def _generate_key_pair(self):
        """生成密钥对"""
        try:
            # 生成密钥对
            private_key, public_key = CryptoUtils.generate_rsa_keypair()
            
            # 生成文件名
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            name_part = self.key_name_var.get().replace(" ", "_")
            private_filename = f"keys/{name_part}_{timestamp}_private.pem"
            public_filename = f"certificates/{name_part}_{timestamp}_public.pem"
            
            # 确保目录存在
            os.makedirs("keys", exist_ok=True)
            os.makedirs("certificates", exist_ok=True)
            
            # 保存密钥对
            with open(private_filename, 'wb') as f:
                f.write(private_key)
            
            with open(public_filename, 'wb') as f:
                f.write(public_key)
            
            # 自动导入私钥
            self.private_key_var.set(private_filename)
            self.private_key = CryptoUtils.load_key_from_file(private_filename)
            
            # 更新配置
            self._save_config()
            
            messagebox.showinfo(
                "成功",
                f"密钥对已生成:\n\n私钥: {os.path.basename(private_filename)}\n证书: {os.path.basename(public_filename)}\n\n私钥已自动导入。\n请将证书发送给发送方。"
            )
            
            self.add_log(f"密钥对生成成功: {name_part}_{timestamp}", "SUCCESS")
            
        except Exception as e:
            self.add_log(f"生成密钥对失败: {str(e)}", "ERROR")
            messagebox.showerror("错误", f"生成密钥对失败: {str(e)}")
    
    def _custom_key_location(self):
        """自定义密钥保存位置"""
        try:
            # 获取自定义保存目录
            directory = filedialog.askdirectory(title="选择密钥保存目录")
            
            if not directory:
                return
            
            # 生成密钥对
            private_key, public_key = CryptoUtils.generate_rsa_keypair()
            
            # 生成文件名
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            name_part = self.key_name_var.get().replace(" ", "_")
            private_filename = f"{name_part}_{timestamp}_private.pem"
            public_filename = f"{name_part}_{timestamp}_public.pem"
            
            # 完整路径
            private_path = os.path.join(directory, private_filename)
            public_path = os.path.join(directory, public_filename)
            
            # 保存密钥对
            with open(private_path, 'wb') as f:
                f.write(private_key)
            
            with open(public_path, 'wb') as f:
                f.write(public_key)
            
            # 自动导入私钥
            self.private_key_var.set(private_path)
            self.private_key = CryptoUtils.load_key_from_file(private_path)
            
            # 更新配置
            self._save_config()
            
            messagebox.showinfo(
                "成功",
                f"密钥对已生成:\n\n私钥: {private_filename}\n证书: {public_filename}\n\n保存位置: {directory}\n\n私钥已自动导入。\n请将证书发送给发送方。"
            )
            
            self.add_log(f"密钥对生成成功: {name_part}_{timestamp} (自定义位置)", "SUCCESS")
            
        except Exception as e:
            self.add_log(f"生成密钥对失败: {str(e)}", "ERROR")
            messagebox.showerror("错误", f"生成密钥对失败: {str(e)}")
    
    # 网络和传输方法
    def _send_file(self):
        """发送文件"""
        if not self.selected_file:
            messagebox.showerror("错误", "请先选择要发送的文件")
            return
        
        if not self.recipient_public_key:
            messagebox.showerror("错误", "请先导入接收方证书")
            return
        
        if not self.private_key:
            messagebox.showerror("错误", "请先导入自己的私钥（用于数字签名）")
            return
        
        def send_thread():
            try:
                self.add_log("开始发送文件...", "INFO")
                
                # 创建发送进度条
                if not self.send_progress:
                    self.send_progress = self._create_progress_bar(self.send_progress_frame)
                    self.send_progress.pack(fill=tk.X)
                
                # 读取文件
                with open(self.selected_file, 'rb') as f:
                    file_data = f.read()
                
                self.send_progress.set_progress(10)
                self.add_log("文件读取完成", "SUCCESS")
                
                # 获取加密设置
                algorithm = self.algorithm_var.get()
                mode = self.mode_var.get()
                hash_algorithm = self.hash_var.get()
                
                self.add_log(f"使用 {algorithm}-{mode} + {hash_algorithm}", "INFO")
                
                # 生成对称密钥
                key_sizes = ENCRYPTION_ALGORITHMS[algorithm]['key_size']
                key_size = key_sizes[0]
                symmetric_key = CryptoUtils.generate_symmetric_key(algorithm, key_size)
                
                self.send_progress.set_progress(30)
                
                # 获取文件元数据
                original_filename = os.path.basename(self.selected_file)
                file_extension = os.path.splitext(original_filename)[1]
                file_size = len(file_data)
                
                # 创建数字信封（新方案：包含数字签名）
                digital_envelope = CryptoUtils.create_digital_envelope(
                    file_data, algorithm, mode, symmetric_key, 
                    self.recipient_public_key, self.private_key, hash_algorithm
                )
                
                # 扩展传输协议：添加文件元数据
                digital_envelope['file_metadata'] = {
                    'original_filename': original_filename,
                    'file_extension': file_extension,
                    'file_size': file_size,
                    'timestamp': int(time.time())
                }
                
                self.add_log(f"文件信息: {original_filename} ({file_size} bytes)", "INFO")
                self.send_progress.set_progress(60)
                self.add_log("数字信封创建完成（包含数字签名）", "SUCCESS")
                
                # 连接接收方
                host = self.server_ip_var.get()
                port = int(self.send_port_var.get())
                
                self.add_log(f"连接到 {host}:{port}...", "INFO")
                if not self.network_utils.connect_to_server(host, port):
                    raise Exception("连接失败")
                
                self.add_log(f"连接成功", "SUCCESS")
                self.send_progress.set_progress(80)
                
                # 发送数据（包含发送方公钥用于验证签名）
                try:
                    sender_private_key = CryptoUtils.load_key_from_file(self.private_key_var.get())
                    sender_public_key = RSA.import_key(sender_private_key).public_key().export_key()
                except Exception as e:
                    raise Exception(f"获取发送方公钥失败: {str(e)}")
                
                if self.network_utils.send_digital_envelope(
                    self.network_utils.client_socket, digital_envelope, sender_public_key
                ):
                    self.send_progress.set_progress(100)
                    self.add_log("文件发送成功", "SUCCESS")
                    messagebox.showinfo("成功", "文件发送完成！")
                else:
                    raise Exception("发送失败")
                
            except Exception as e:
                self.add_log(f"发送失败: {str(e)}", "ERROR")
                messagebox.showerror("错误", f"发送失败: {str(e)}")
                # 关闭连接
                try:
                    self.network_utils.close_connection()
                except:
                    pass
        
        # 在新线程中执行发送
        threading.Thread(target=send_thread, daemon=True).start()
    
    def _start_server(self):
        """启动服务器"""
        if self.server_running:
            messagebox.showinfo("信息", "服务器已在运行")
            return
        
        def start():
            try:
                port = int(self.receive_port_var.get())
                
                self.add_log(f"启动服务器，端口: {port}", "INFO")
                self.server_status_var.set("正在启动...")
                
                if self.network_utils.start_server(port, self._on_client_connected):
                    self.server_running = True
                    self.server_status_var.set(f"服务器运行中 - {self.local_ip_var.get()}:{port}")
                    self.add_log(f"服务器启动成功", "SUCCESS")
                    
                    # 更新按钮状态
                    self.start_server_btn.config(state=tk.DISABLED)
                    self.stop_server_btn.config(state=tk.NORMAL)
                    self.receive_port_entry.config(state=tk.DISABLED)
                else:
                    raise Exception("服务器启动失败")
                    
            except Exception as e:
                self.server_status_var.set("服务器启动失败")
                self.add_log(f"服务器启动失败: {str(e)}", "ERROR")
                messagebox.showerror("错误", f"服务器启动失败: {str(e)}")
        
        threading.Thread(target=start, daemon=True).start()
    
    def _stop_server(self):
        """停止服务器"""
        try:
            self.network_utils.close_connection()
            self.server_running = False
            self.client_socket = None
            
            self.server_status_var.set("服务器已停止")
            self.client_info_var.set("等待连接...")
            self.add_log("服务器已停止", "INFO")
            
            # 更新按钮状态
            self.start_server_btn.config(state=tk.NORMAL)
            self.stop_server_btn.config(state=tk.DISABLED)
            self.receive_port_entry.config(state=tk.NORMAL)
            
        except Exception as e:
            self.add_log(f"停止服务器失败: {str(e)}", "ERROR")
    
    def _on_client_connected(self, client_socket, address):
        """客户端连接回调"""
        self.client_socket = client_socket
        client_ip = address[0]
        client_port = address[1]
        
        # 更新接收方界面状态
        self.client_info_var.set(f"已连接: {client_ip}:{client_port}")
        self.add_log(f"客户端连接: {client_ip}:{client_port}", "SUCCESS")
        
        # 处理接收
        threading.Thread(target=self._handle_client, args=(client_socket,), daemon=True).start()
    
    def _handle_client(self, client_socket):
        """处理客户端连接"""
        try:
            # 创建接收进度条
            if not self.receive_progress:
                self.receive_progress = self._create_progress_bar(self.receive_progress_frame)
                self.receive_progress.pack(fill=tk.X)
            
            # 接收数字信封和发送方公钥
            self.receive_progress.set_progress(20)
            digital_envelope, sender_public_key = self.network_utils.receive_digital_envelope(client_socket)
            
            if not digital_envelope:
                raise Exception("接收失败")
            
            self.receive_progress.set_progress(40)
            self.add_log("接收到数字信封", "SUCCESS")
            
            if sender_public_key:
                self.add_log("获取发送方公钥成功", "SUCCESS")
            else:
                self.add_log("警告：未获取到发送方公钥，无法验证数字签名", "WARNING")
            
            # 检查接收方私钥
            if not self.private_key:
                raise Exception("未设置接收方私钥，无法解密")
            
            # 解密（新方案：验证数字签名）
            self.receive_progress.set_progress(60)
            
            if sender_public_key:
                decrypted_data = CryptoUtils.open_digital_envelope(
                    digital_envelope, self.private_key, sender_public_key
                )
                self.add_log("数字签名验证成功", "SUCCESS")
            else:
                # 如果没有发送方公钥，使用旧的解密方式
                self.add_log("跳过数字签名验证", "WARNING")
                # 回退到旧的方法（仅解密）
                from Crypto.PublicKey import RSA
                
                # 1. 用接收方私钥解密得到对称密钥
                import base64
                encrypted_key = base64.b64decode(digital_envelope['encrypted_key'])
                symmetric_key = CryptoUtils.decrypt_with_rsa(encrypted_key, self.private_key)
                
                # 2. 用对称密钥解密数据
                algorithm = digital_envelope['algorithm']
                mode = digital_envelope['mode']
                encrypted_data = digital_envelope['encrypted_data']
                decrypted_data = CryptoUtils.decrypt_data(encrypted_data, algorithm, mode, symmetric_key)
                
                self.add_log("文件解密完成（未验证签名）", "WARNING")
            
            self.receive_progress.set_progress(80)
            
            # 验证数据完整性（如果有原始哈希）
            if 'original_hash' in digital_envelope:
                hash_algorithm = digital_envelope.get('hash_algorithm', 'SHA-256')
                calculated_hash = CryptoUtils.calculate_hash(decrypted_data, hash_algorithm)
                if calculated_hash == digital_envelope['original_hash']:
                    self.add_log("数据完整性验证通过", "SUCCESS")
                else:
                    raise Exception("数据完整性验证失败！文件可能被篡改。")
            
            self.receive_progress.set_progress(100)
            self.add_log("文件接收处理完成", "SUCCESS")
            
            # 生成保存文件名（保持原有命名规则）
            algorithm = digital_envelope['algorithm']
            mode = digital_envelope['mode']
            timestamp = int(time.time())
            
            # 获取原始文件扩展名
            if 'file_metadata' in digital_envelope:
                file_extension = digital_envelope['file_metadata'].get('file_extension', '.dat')
                if not file_extension:  # 如果扩展名为空
                    file_extension = '.dat'
                self.add_log(f"检测到文件扩展名: {file_extension}", "INFO")
            else:
                file_extension = '.dat'
                self.add_log("未检测到文件扩展名，使用默认 .dat", "WARNING")
            
            # 按照原有规则命名：received_{算法}_{模式}_{时间戳}{扩展名}
            filename = f"received_{algorithm}_{mode}_{timestamp}{file_extension}"
            save_path = os.path.join(self.save_path_var.get(), filename)
            
            # 确保保存目录存在
            os.makedirs(self.save_path_var.get(), exist_ok=True)
            
            # 保存文件
            with open(save_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.add_log(f"文件已保存: {filename}", "SUCCESS")
            
            # 显示成功消息
            success_msg = f"文件接收完成！\n\n保存路径: {save_path}"
            if sender_public_key:
                success_msg += "\n✓ 数字签名已验证"
            else:
                success_msg += "\n⚠ 数字签名未验证"
                
            messagebox.showinfo("成功", success_msg)
            
        except Exception as e:
            self.add_log(f"接收失败: {str(e)}", "ERROR")
            messagebox.showerror("错误", f"接收失败: {str(e)}")
            # 重置客户端信息
            self.client_info_var.set("等待连接...")
            # 关闭客户端连接
            try:
                if client_socket:
                    client_socket.close()
            except:
                pass
    
    def _create_progress_bar(self, parent):
        """创建进度条"""
        progress_frame = tk.Frame(parent, bg=GUI_COLORS['background'])
        
        progress_bar = ttk.Progressbar(
            progress_frame,
            mode='determinate',
            length=300
        )
        progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        progress_label = tk.Label(
            progress_frame,
            text="0%",
            bg=GUI_COLORS['background'],
            font=('微软雅黑', 9)
        )
        progress_label.pack(side=tk.RIGHT, padx=(10, 0))
        
        def set_progress(value):
            progress_bar['value'] = value
            progress_label.config(text=f"{value}%")
        
        def reset():
            progress_bar['value'] = 0
            progress_label.config(text="0%")
        
        progress_frame.set_progress = set_progress
        progress_frame.reset = reset
        return progress_frame
    
    def _reset_send_progress(self):
        """重置发送进度条"""
        if self.send_progress:
            self.send_progress.reset()
    
    def _reset_receive_progress(self):
        """重置接收进度条"""
        if self.receive_progress:
            self.receive_progress.reset()
    
    # 菜单和帮助方法
    def _menu_select_file(self):
        """从菜单选择文件"""
        self._browse_file()
    
    def _menu_import_private_key(self):
        """从菜单导入私钥"""
        self._browse_private_key()
    
    def _menu_import_certificate(self):
        """从菜单导入证书"""
        self._browse_certificate()
    
    def _clear_log(self):
        """清空日志"""
        self.log_text.delete(1.0, tk.END)
        self.add_log("日志已清空", "INFO")
    
    def _save_log(self):
        """保存日志"""
        filename = filedialog.asksaveasfilename(
            title="保存日志文件",
            defaultextension=".log",
            filetypes=[("日志文件", "*.log"), ("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                self.add_log(f"日志已保存到: {filename}", "SUCCESS")
                messagebox.showinfo("成功", f"日志已保存到:\n{filename}")
            except Exception as e:
                self.add_log(f"保存日志失败: {str(e)}", "ERROR")
    
    def _export_config(self):
        """导出配置"""
        messagebox.showinfo("提示", "导出配置功能将在后续版本中实现。")
    
    def _import_config(self):
        """导入配置"""
        messagebox.showinfo("提示", "导入配置功能将在后续版本中实现。")
    
    def _show_help(self):
        """显示帮助信息"""
        help_text = """SecuTrans 使用说明

1. 密钥管理：
   - 生成密钥对：填写信息后生成私钥和证书
   - 导入密钥：导入现有的私钥文件
   - 导入证书：导入接收方的证书文件

2. 文件管理：
   - 选择要发送的文件
   - 设置文件保存路径

3. 文件传输：
   - 发送：选择加密算法，设置网络，连接并发送
   - 接收：启动服务器，等待连接和文件

4. 安全提示：
   - 使用安全的加密算法（标记为安全的算法）
   - 避免使用不安全的模式
   - 妥善保管私钥文件

5. 推荐配置：
   - 最佳安全性: AES-256 + GCM
   - 高性能: ChaCha20 + Stream
   - 国密标准: SM4 + CBC + HMAC-SM3

快捷键：
Ctrl+O: 选择文件    Ctrl+G: 生成密钥对    Ctrl+I: 导入私钥
Ctrl+M: 导入证书    F2: 启动服务器        F3: 停止服务器
Ctrl+L: 清空日志    Ctrl+S: 保存日志      F1: 帮助

注意：不安全的算法仅作演示使用！"""
        
        messagebox.showinfo("使用说明", help_text)
    
    def _show_about(self):
        """显示关于信息"""
        about_text = """SecuTrans - 文件安全传输工具
版本: 2.2.2

开发者: SecuTrans Team
特性:
• 现代加密算法支持
• 数字信封技术
• 统一界面设计
• 配置自动保存
• 按比例自适应布局

端口: 5375 (SeTs)
本软件仅供学习和研究使用。"""
        
        messagebox.showinfo("关于 SecuTrans", about_text)