#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecuTrans GUI组件模块
实现自定义GUI组件和样式
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Callable, Optional, List, Dict, Any
from datetime import datetime

import sys
import os

# 添加src目录到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(current_dir)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from core.config import GUI_COLORS


class StyledButton(tk.Button):
    """样式化按钮"""
    
    def __init__(self, parent, text: str, command: Callable = None, 
                 bg_color: str = GUI_COLORS['primary'], 
                 fg_color: str = GUI_COLORS['white'],
                 width: int = 20, height: int = 2, **kwargs):
        
        # 提取state参数，因为tk.Button不支持这个参数
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
            cursor='hand2',
            **kwargs
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
            width/2, height/2,
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
            import os
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
        
        from core.config import ENCRYPTION_ALGORITHMS
        
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
        )
        self.security_label.pack(side=tk.LEFT, padx=(0, 10))
        
        # 模式选择
        tk.Label(
            self,
            text="加密模式:",
            font=('微软雅黑', 10)
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        self.mode_var = tk.StringVar()
        self.mode_combo = ttk.Combobox(
            self,
            textvariable=self.mode_var,
            state='readonly',
            width=15
        )
        self.mode_combo.pack(side=tk.LEFT)
        
        # 模式安全状态标签
        self.mode_security_label = tk.Label(
            self,
            text="",
            font=('微软雅黑', 9),
            fg=GUI_COLORS['text']
        )
        self.mode_security_label.pack(side=tk.LEFT, padx=(5, 0))
        
        # 绑定算法选择事件
        self.algorithm_combo.bind('<<ComboboxSelected>>', self._on_algorithm_changed)
        self.mode_combo.bind('<<ComboboxSelected>>', self._on_mode_changed)
        
        # 初始化模式列表
        self._update_modes()
        self._update_security_status()
    
    def _on_algorithm_changed(self, event):
        """算法选择改变时更新模式列表"""
        self._update_modes()
        self._update_security_status()
    
    def _on_mode_changed(self, event):
        """模式选择改变时更新安全状态"""
        self._update_mode_security_status()
    
    def _update_modes(self):
        """更新加密模式列表"""
        from core.config import ENCRYPTION_ALGORITHMS
        
        algorithm = self.algorithm_var.get()
        if algorithm in ENCRYPTION_ALGORITHMS:
            modes = ENCRYPTION_ALGORITHMS[algorithm]['modes']
            self.mode_combo['values'] = modes
            if modes:
                self.mode_combo.set(modes[0])
        self._update_mode_security_status()
    
    def _update_security_status(self):
        """更新算法安全状态"""
        from core.config import ENCRYPTION_ALGORITHMS
        
        algorithm = self.algorithm_var.get()
        if algorithm in ENCRYPTION_ALGORITHMS:
            is_secure = ENCRYPTION_ALGORITHMS[algorithm].get('secure', True)
            if is_secure:
                self.security_label.config(
                    text="安全",
                    fg=GUI_COLORS['success']
                )
            else:
                self.security_label.config(
                    text="不安全！仅作演示！",
                    fg=GUI_COLORS['error']
                )
    
    def _update_mode_security_status(self):
        """更新模式安全状态"""
        mode = self.mode_var.get()
        if mode in ['ECB']:
            self.mode_security_label.config(
                text="不安全！仅作演示！",
                fg=GUI_COLORS['error']
            )
        elif mode in ['GCM']:
            self.mode_security_label.config(
                text="认证加密",
                fg=GUI_COLORS['success']
            )
        elif mode in ['CBC + HMAC-SM3']:
            self.mode_security_label.config(
                text="国密认证模式",
                fg=GUI_COLORS['success']
            )
        else:
            self.mode_security_label.config(text="较安全")
    
    def get_selection(self) -> Dict[str, str]:
        """获取选择的算法和模式"""
        return {
            'algorithm': self.algorithm_var.get(),
            'mode': self.mode_var.get()
        }
    
    def set_selection(self, algorithm: str, mode: str):
        """设置算法和模式"""
        self.algorithm_var.set(algorithm)
        self.mode_var.set(mode)
        self._update_modes()
        self._update_security_status()


