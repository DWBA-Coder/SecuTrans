#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""样式化按钮组件"""

import tkinter as tk
from typing import Callable
from core.config import GUI_COLORS


class StyledButton(tk.Button):
    """样式化按钮"""

    def __init__(self, parent, text: str, command: Callable = None,
                 bg_color: str = GUI_COLORS['primary'],
                 fg_color: str = GUI_COLORS['white'],
                 width: int = 20, height: int = 2, **kwargs):

        # 提取state参数
        self.state = kwargs.pop('state', tk.NORMAL)

        super().__init__(
            parent,
            text=text,
            command=command,
            bg=bg_color,
            fg=fg_color,
            width=width,
            height=height,
            relief=tk.FLAT,
            font=('微软雅黑', 10, 'bold'),
            cursor='hand2', **kwargs
        )

        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)

        self.default_bg = bg_color
        self.hover_bg = self._lighten_color(bg_color)
        self.default_color = bg_color

        # 应用初始状态
        self.set_state(self.state)

    def set_state(self, state):
        """设置按钮状态"""
        self.state = state
        if state == tk.DISABLED:
            self.config(state=tk.DISABLED, bg=GUI_COLORS['background'])
        else:
            self.config(state=state, bg=self.default_color)

    def _on_enter(self, event):
        """鼠标进入事件"""
        if self.state != tk.DISABLED:
            self.config(bg=self.hover_bg)

    def _on_leave(self, event):
        """鼠标离开事件"""
        if self.state != tk.DISABLED:
            self.config(bg=self.default_bg)

    def _lighten_color(self, color: str) -> str:
        """使颜色变亮"""
        try:
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)

            r = min(255, r + 30)
            g = min(255, g + 30)
            b = min(255, b + 30)

            return f'#{r:02x}{g:02x}{b:02x}'
        except:
            return color