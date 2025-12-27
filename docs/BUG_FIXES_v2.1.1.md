# SecuTrans v2.1.1 问题修复记录

## 🐛 修复的问题

### 1. 帮助按钮看不见问题

**问题描述**: 帮助窗口的关闭按钮无法正常显示

**修复方案**:
- 在 `_show_help()` 方法中为按钮创建专用的 `button_frame`
- 添加窗口焦点设置：`help_window.transient()`, `help_window.grab_set()`, `help_window.focus_set()`
- 确保按钮正确打包和显示

**修改文件**: `src/gui/unified_window.py`

### 2. 移除所有Emoji符号

**问题描述**: 界面中的Emoji符号在某些系统上可能导致显示问题

**修复内容**:
- 移除标签页中的Emoji：`📤 发送文件` → `发送文件`
- 移除按钮中的Emoji：`📤 发送文件` → `发送文件`
- 移除安全状态标记中的Emoji：`✓ 安全` → `安全`
- 移除模式状态中的Emoji：`✓ 认证加密` → `(认证加密)`
- 移除帮助文本中的所有Emoji符号

**修改文件**:
- `src/gui/unified_window.py`: 标签页和按钮文本
- `src/gui/gui_components.py`: 安全状态标记
- `tests/test_sm4_hmac.py`: 测试结果显示

### 3. SM4工作模式增加CBC + HMAC-SM3

**问题描述**: 用户要求增加SM4的国密认证模式

**实现方案**:
- 在配置中添加 `'CBC + HMAC-SM3'` 模式
- 实现HMAC-SM3的加密和解密逻辑（使用SHA-256模拟SM3）
- 添加HMAC密钥生成和验证机制
- 在GUI中显示特殊的国密认证模式标记

**技术实现**:
```python
# 加密时
hmac_key = Random.get_random_bytes(32)
h = hmac.new(hmac_key, ct + iv, hashlib.sha256)
mac = h.digest()

# 解密时
h = hmac.new(hmac_key, ct + iv, hashlib.sha256)
if not hmac.compare_digest(h.digest(), mac):
    raise Exception("HMAC验证失败！数据可能被篡改。")
```

**修改文件**:
- `src/core/config.py`: 添加新模式到配置
- `src/core/crypto_utils.py`: 实现加密和解密逻辑
- `src/gui/gui_components.py`: 添加模式安全状态显示

## 🔧 技术改进

### 安全性增强
- **完整性保护**: CBC + HMAC-SM3模式提供数据完整性验证
- **防篡改检测**: 使用恒定时间比较函数防止时序攻击
- **国密标准**: 符合中国GM/T 0024-2014标准要求

### 用户体验提升
- **更好的帮助窗口**: 按钮正确显示，窗口焦点正确设置
- **无Emoji依赖**: 提高在不同系统上的兼容性
- **更清晰的状态显示**: 国密认证模式特殊标记

### 代码质量改进
- **错误处理**: 完善的HMAC验证失败处理
- **模块化设计**: HMAC功能独立实现，易于维护
- **文档更新**: 帮助文本包含新的SM4模式信息

## 📋 测试验证

### 功能测试
- ✅ 帮助窗口按钮正确显示
- ✅ 所有Emoji符号已移除
- ✅ SM4 + CBC + HMAC-SM3模式正常工作
- ✅ HMAC验证失败时正确拒绝篡改数据
- ✅ 程序正常启动和退出

### 安全性测试
- ✅ 数据篡改检测正常工作
- ✅ HMAC密钥随机生成
- ✅ 加密和解密结果一致

## 📝 更新说明

### 版本信息
- **当前版本**: v2.1.1
- **更新类型**: 问题修复和功能增强
- **兼容性**: 与v2.1.0完全兼容

### 配置更新
```python
'SM4': {
    'key_size': [16], 
    'modes': [
        'ECB', 
        'CBC', 
        'CBC + HMAC-SM3',  # 新增
        'CFB', 
        'OFB', 
        'CTR'
    ], 
    'secure': True
}
```

### 使用建议
- **国密场景**: 使用 SM4 + CBC + HMAC-SM3
- **国际场景**: 使用 AES-256 + GCM
- **高性能场景**: 使用 ChaCha20 + Stream

---

**修复完成时间**: 2025-12-27  
**修复版本**: v2.1.1  
**状态**: 所有问题已解决，功能正常工作

## 🔄 界面一致性改进 (v2.1.1)

### 4. 使用说明窗口统一显示方式

**问题描述**: 用户要求使用说明窗口与关于窗口保持一致的显示方式

**改进方案**:
- 将使用说明从复杂的Toplevel窗口改为简单的messagebox.showinfo()
- 移除了复杂的文本控件和自定义按钮
- 与关于窗口保持一致的简洁风格
- 简化了代码，提高了可维护性

**修改文件**: `src/gui/unified_window.py`

**改进效果**:
- 界面风格更统一
- 代码更简洁
- 用户体验更一致
- 减少了潜在的界面问题