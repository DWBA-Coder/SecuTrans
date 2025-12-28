#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""进度条组件"""

import tkinter as tk
from core.config import GUI_COLORS


class ProgressBar(tk.Frame):
    """自定义进度条"""

    def __init__(self, parent, width: int = 300, height: int = 20, **kwargs):
        super().__init__(parent, **kwargs)

        self.canvas = tk.Canvas(
            self,
            width=width,
            height=height,
            bg=GUI_COLORS['background'],
            highlightthickness=1,
            highlightbackground=GUI_COLORS['primary']
        )
        self.canvas.pack(fill=tk.BOTH, expand=True)

        self.progress_rect = self.canvas.create_rectangle(
            0, 0, 0, height,
            fill=GUI_COLORS['primary'],
            outline=''
        )

        self.progress_text = self.canvas.create_text(
            width / 2, height / 2,
            text="0%",
            font=('微软雅黑', 9),
            fill=GUI_COLORS['text']
        )

        self.width = width
        self.height = height
        self.current_progress = 0

    def set_progress(self, value: int):
        """设置进度值 (0-100)"""
        self.current_progress = max(0, min(100, value))
        progress_width = int((self.current_progress / 100) * self.width)

        self.canvas.coords(
            self.progress_rect,
            0, 0, progress_width, self.height
        )

        self.canvas.itemconfig(
            self.progress_text,
            text=f"{self.current_progress}%"
        )

    def reset(self):
        """重置进度条"""
        self.set_progress(0)