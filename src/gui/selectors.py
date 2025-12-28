#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""选择器组件"""

import tkinter as tk
from tkinter import ttk, filedialog
from typing import Optional, List
import os
from core.config import GUI_COLORS, ENCRYPTION_ALGORITHMS
from .buttons import StyledButton


class FileSelector(tk.Frame):
    """文件选择器"""

    def __init__(self, parent, title: str = "选择文件",
                 filetypes: List[tuple] = None, **kwargs):
        super().__init__(parent, **kwargs)

        self.title = title
        self.filetypes = filetypes or [("所有文件", "*.*"),
                                       ("文档文件", "*.txt;*.doc;*.docx;*.pdf"),
                                       ("图片文件", "*.jpg;*.jpeg;*.png;*.gif;*.bmp"),
                                       ("视频文件", "*.mp4;*.avi;*.mkv;*.mov"),
                                       ("压缩文件", "*.zip;*.rar;*.7z;*.tar")]
        self.selected_file = None

        # 文件路径显示
        self.path_var = tk.StringVar()
        self.path_entry = tk.Entry(
            self,
            textvariable=self.path_var,
            font=('微软雅黑', 10),
            width=50
        )
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        # 文件信息标签
        self.info_label = tk.Label(
            self,
            text="",
            font=('微软雅黑', 8),
            fg=GUI_COLORS['text']
        )
        self.info_label.pack(side=tk.LEFT, padx=(0, 5))

        # 浏览按钮
        self.browse_button = StyledButton(
            self,
            text="浏览",
            command=self._browse_file,
            width=10,
            height=1
        )
        self.browse_button.pack(side=tk.RIGHT)

    def _browse_file(self):
        """浏览文件"""
        filename = filedialog.askopenfilename(
            title=self.title,
            filetypes=self.filetypes
        )

        if filename:
            self.selected_file = filename
            self.path_var.set(filename)
            self._update_file_info(filename)

    def _update_file_info(self, filename: str):
        """更新文件信息显示"""
        try:
            file_size = os.path.getsize(filename)
            if file_size < 1024:
                size_str = f"{file_size} B"
            elif file_size < 1024 * 1024:
                size_str = f"{file_size / 1024:.1f} KB"
            elif file_size < 1024 * 1024 * 1024:
                size_str = f"{file_size / (1024 * 1024):.1f} MB"
            else:
                size_str = f"{file_size / (1024 * 1024 * 1024):.1f} GB"

            self.info_label.config(text=f"大小: {size_str}")
        except:
            self.info_label.config(text="")

    def get_selected_file(self) -> Optional[str]:
        """获取选择的文件"""
        return self.selected_file

    def set_file(self, filepath: str):
        """设置文件路径"""
        self.selected_file = filepath
        self.path_var.set(filepath)


class AlgorithmSelector(tk.Frame):
    """算法选择器"""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)

        # 算法选择
        tk.Label(
            self,
            text="加密算法:",
            font=('微软雅黑', 10)
        ).pack(side=tk.LEFT, padx=(0, 5))

        self.algorithm_var = tk.StringVar()
        self.algorithm_combo = ttk.Combobox(
            self,
            textvariable=self.algorithm_var,
            values=list(ENCRYPTION_ALGORITHMS.keys()),
            state='readonly',
            width=18
        )
        self.algorithm_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.algorithm_combo.set('AES-128')

        # 安全状态标签
        self.security_label = tk.Label(
            self,
            text="",
            font=('微软雅黑', 9)
        ).pack(side=tk.LEFT, padx=(0, 10))

        # 模式选择
        tk.Label(
            self,
            text="加密模式:",
            font=('微软雅黑', 10)
        ).pack(side=tk.LEFT, padx=(0, 5))