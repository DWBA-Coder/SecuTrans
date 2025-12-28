#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""日志查看组件"""

import tkinter as tk
from tkinter import ttk
from datetime import datetime
from core.config import GUI_COLORS


class LogViewer(tk.Frame):
    """日志查看器"""

    def __init__(self, parent, height: int = 15, **kwargs):
        super().__init__(parent, **kwargs)

        # 创建滚动条
        scrollbar = ttk.Scrollbar(self)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 创建文本框
        self.text_widget = tk.Text(
            self,
            height=height,
            wrap=tk.WORD,
            yscrollcommand=scrollbar.set,
            font=('Consolas', 9),
            bg=GUI_COLORS['background'],
            fg=GUI_COLORS['text']
        )
        self.text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar.config(command=self.text_widget.yview)

        # 配置文本标签
        self.text_widget.tag_config('INFO', foreground=GUI_COLORS['text'])
        self.text_widget.tag_config('SUCCESS', foreground=GUI_COLORS['success'])
        self.text_widget.tag_config('WARNING', foreground=GUI_COLORS['warning'])
        self.text_widget.tag_config('ERROR', foreground=GUI_COLORS['error'])
        self.text_widget.tag_config('TIMESTAMP', foreground=GUI_COLORS['primary'])

    def add_log(self, message: str, level: str = 'INFO'):
        """添加日志消息"""
        timestamp = str(datetime.now().strftime("%H:%M:%S"))

        self.text_widget.insert(
            tk.END,
            f"[{timestamp}] ",
            'TIMESTAMP'
        )

        self.text_widget.insert(
            tk.END,
            f"{message}\n",
            level
        )

        self.text_widget.see(tk.END)

    def clear(self):
        """清空日志"""
        self.text_widget.delete(1.0, tk.END)

    def save_log(self, filename: str):
        """保存日志到文件"""
        content = self.text_widget.get(1.0, tk.END)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)