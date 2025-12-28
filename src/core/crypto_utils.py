#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecuTrans 加密工具模块
实现各种对称加密算法和数字信封功能
"""

import os
import json
import base64
import hashlib
import secrets
from Crypto.Cipher import AES, DES, DES3, Blowfish, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from typing import Dict, Tuple, Any
# ========== 新增：补充日志和时间依赖 ==========
import logging
from datetime import datetime

# 配置日志（便于排查证书问题）
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - SecuTrans - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("SecuTrans")

# 原有尝试导入部分（保留）
try:
    from Crypto.Cipher import ChaCha20
    CHACHA20_AVAILABLE = True
except ImportError:
    CHACHA20_AVAILABLE = False

try:
    # SM4 需要额外的库支持，这里使用简单的实现
    SM4_AVAILABLE = False
except ImportError:
    SM4_AVAILABLE = False

try:
    from Crypto.Cipher import Camellia
    CAMELLIA_AVAILABLE = True
except ImportError:
    CAMELLIA_AVAILABLE = False

# 尝试导入HMAC
try:
    import hmac
    import hashlib
    HMAC_AVAILABLE = True
except ImportError:
    HMAC_AVAILABLE = False


class CryptoUtils:
    """加密工具类"""
    
    @staticmethod
    def generate_symmetric_key(algorithm: str, key_size: int) -> bytes:
        """生成对称密钥"""
        return secrets.token_bytes(key_size)
    
    @staticmethod
    def generate_rsa_keypair(bits: int = 2048) -> Tuple[bytes, bytes]:
        """生成RSA密钥对"""
        key = RSA.generate(bits)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    
    @staticmethod
    def encrypt_data(data: bytes, algorithm: str, mode: str, key: bytes, iv: bytes = None) -> Dict[str, Any]:
        """加密数据"""
        try:
            if algorithm.startswith('AES'):
                return CryptoUtils._encrypt_aes(data, mode, key, iv)
            elif algorithm == 'ChaCha20':
                return CryptoUtils._encrypt_chacha20(data, key)
            elif algorithm == 'SM4':
                return CryptoUtils._encrypt_sm4(data, mode, key, iv)
            elif algorithm == 'Camellia':
                return CryptoUtils._encrypt_camellia(data, mode, key, iv)
            elif algorithm == 'DES':
                return CryptoUtils._encrypt_des(data, mode, key, iv)
            elif algorithm == 'DES3':
                return CryptoUtils._encrypt_des3(data, mode, key, iv)
            elif algorithm == 'Blowfish':
                return CryptoUtils._encrypt_blowfish(data, mode, key, iv)
            elif algorithm == 'RC4':
                return CryptoUtils._encrypt_rc4(data, key)
            else:
                raise ValueError(f"不支持的加密算法: {algorithm}")
        except Exception as e:
            raise Exception(f"加密失败: {str(e)}")
    
    @staticmethod
    def decrypt_data(encrypted_data: Dict[str, Any], algorithm: str, mode: str, key: bytes) -> bytes:
        """解密数据"""
        try:
            if algorithm.startswith('AES'):
                return CryptoUtils._decrypt_aes(encrypted_data, mode, key)
            elif algorithm == 'ChaCha20':
                return CryptoUtils._decrypt_chacha20(encrypted_data, key)
            elif algorithm == 'SM4':
                return CryptoUtils._decrypt_sm4(encrypted_data, mode, key)
            elif algorithm == 'Camellia':
                return CryptoUtils._decrypt_camellia(encrypted_data, mode, key)
            elif algorithm == 'DES':
                return CryptoUtils._decrypt_des(encrypted_data, mode, key)
            elif algorithm == 'DES3':
                return CryptoUtils._decrypt_des3(encrypted_data, mode, key)
            elif algorithm == 'Blowfish':
                return CryptoUtils._decrypt_blowfish(encrypted_data, mode, key)
            elif algorithm == 'RC4':
                return CryptoUtils._decrypt_rc4(encrypted_data, key)
            else:
                raise ValueError(f"不支持的解密算法: {algorithm}")
        except Exception as e:
            raise Exception(f"解密失败: {str(e)}")
    
    @staticmethod
    def _encrypt_aes(data: bytes, mode: str, key: bytes, iv: bytes = None) -> Dict[str, Any]:
        """AES加密（修复GCM填充+nonce长度）"""
        if iv is None:
            if mode == 'GCM':
                iv = Random.get_random_bytes(12)  # GCM标准nonce长度12字节
            else:
                iv = Random.get_random_bytes(16)
        
        if mode == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
            ct = cipher.encrypt(pad(data, AES.block_size))
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': None, 'tag': None}
        elif mode == 'CBC':
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ct = cipher.encrypt(pad(data, AES.block_size))
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode(), 'tag': None}
        elif mode == 'GCM':
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            ct, tag = cipher.encrypt_and_digest(data)  # GCM模式移除pad
            return {
                'ciphertext': base64.b64encode(ct).decode(), 
                'iv': base64.b64encode(iv).decode(), 
                'tag': base64.b64encode(tag).decode()
            }
        elif mode == 'CFB':
            cipher = AES.new(key, AES.MODE_CFB, iv)
            ct = cipher.encrypt(data)
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode(), 'tag': None}
        elif mode == 'OFB':
            cipher = AES.new(key, AES.MODE_OFB, iv)
            ct = cipher.encrypt(data)
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode(), 'tag': None}
        elif mode == 'CTR':
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
            ct = cipher.encrypt(data)
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode(), 'tag': None}
        else:
            raise ValueError(f"AES不支持{mode}模式")
    
    @staticmethod
    def _decrypt_aes(encrypted_data: Dict[str, Any], mode: str, key: bytes) -> bytes:
        """AES解密（修复GCM填充）"""
        ct = base64.b64decode(encrypted_data['ciphertext'])
        iv = base64.b64decode(encrypted_data['iv']) if encrypted_data['iv'] else None
        tag = base64.b64decode(encrypted_data['tag']) if encrypted_data['tag'] else None
        
        if mode == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt
        elif mode == 'CBC':
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt
        elif mode == 'GCM':
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            pt = cipher.decrypt_and_verify(ct, tag)
            return pt  # GCM模式移除unpad
        elif mode == 'CFB':
            cipher = AES.new(key, AES.MODE_CFB, iv)
            return cipher.decrypt(ct)
        elif mode == 'OFB':
            cipher = AES.new(key, AES.MODE_OFB, iv)
            return cipher.decrypt(ct)
        elif mode == 'CTR':
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
            return cipher.decrypt(ct)
        else:
            raise ValueError(f"AES不支持{mode}模式")
    
    @staticmethod
    def _encrypt_des(data: bytes, mode: str, key: bytes, iv: bytes = None) -> Dict[str, Any]:
        """DES加密"""
        if iv is None:
            iv = Random.get_random_bytes(8)
        
        if mode == 'ECB':
            cipher = DES.new(key, DES.MODE_ECB)
            ct = cipher.encrypt(pad(data, DES.block_size))
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': None}
        elif mode == 'CBC':
            cipher = DES.new(key, DES.MODE_CBC, iv)
            ct = cipher.encrypt(pad(data, DES.block_size))
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode()}
        elif mode == 'CFB':
            cipher = DES.new(key, DES.MODE_CFB, iv)
            ct = cipher.encrypt(data)
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode()}
        elif mode == 'OFB':
            cipher = DES.new(key, DES.MODE_OFB, iv)
            ct = cipher.encrypt(data)
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode()}
        else:
            raise ValueError(f"DES不支持{mode}模式")
    
    @staticmethod
    def _decrypt_des(encrypted_data: Dict[str, Any], mode: str, key: bytes) -> bytes:
        """DES解密"""
        ct = base64.b64decode(encrypted_data['ciphertext'])
        iv = base64.b64decode(encrypted_data['iv']) if encrypted_data['iv'] else None
        
        if mode == 'ECB':
            cipher = DES.new(key, DES.MODE_ECB)
            pt = unpad(cipher.decrypt(ct), DES.block_size)
            return pt
        elif mode == 'CBC':
            cipher = DES.new(key, DES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), DES.block_size)
            return pt
        elif mode == 'CFB':
            cipher = DES.new(key, DES.MODE_CFB, iv)
            return cipher.decrypt(ct)
        elif mode == 'OFB':
            cipher = DES.new(key, DES.MODE_OFB, iv)
            return cipher.decrypt(ct)
        else:
            raise ValueError(f"DES不支持{mode}模式")
    
    @staticmethod
    def _encrypt_des3(data: bytes, mode: str, key: bytes, iv: bytes = None) -> Dict[str, Any]:
        """3DES加密"""
        if iv is None:
            iv = Random.get_random_bytes(8)
        
        if mode == 'ECB':
            cipher = DES3.new(key, DES3.MODE_ECB)
            ct = cipher.encrypt(pad(data, DES3.block_size))
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': None}
        elif mode == 'CBC':
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            ct = cipher.encrypt(pad(data, DES3.block_size))
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode()}
        elif mode == 'CFB':
            cipher = DES3.new(key, DES3.MODE_CFB, iv)
            ct = cipher.encrypt(data)
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode()}
        elif mode == 'OFB':
            cipher = DES3.new(key, DES3.MODE_OFB, iv)
            ct = cipher.encrypt(data)
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode()}
        else:
            raise ValueError(f"3DES不支持{mode}模式")
    
    @staticmethod
    def _decrypt_des3(encrypted_data: Dict[str, Any], mode: str, key: bytes) -> bytes:
        """3DES解密"""
        ct = base64.b64decode(encrypted_data['ciphertext'])
        iv = base64.b64decode(encrypted_data['iv']) if encrypted_data['iv'] else None
        
        if mode == 'ECB':
            cipher = DES3.new(key, DES3.MODE_ECB)
            pt = unpad(cipher.decrypt(ct), DES3.block_size)
            return pt
        elif mode == 'CBC':
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), DES3.block_size)
            return pt
        elif mode == 'CFB':
            cipher = DES3.new(key, DES3.MODE_CFB, iv)
            return cipher.decrypt(ct)
        elif mode == 'OFB':
            cipher = DES3.new(key, DES3.MODE_OFB, iv)
            return cipher.decrypt(ct)
        else:
            raise ValueError(f"3DES不支持{mode}模式")
    
    @staticmethod
    def _encrypt_blowfish(data: bytes, mode: str, key: bytes, iv: bytes = None) -> Dict[str, Any]:
        """Blowfish加密"""
        if iv is None:
            iv = Random.get_random_bytes(8)
        
        if mode == 'ECB':
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
            ct = cipher.encrypt(pad(data, Blowfish.block_size))
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': None}
        elif mode == 'CBC':
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
            ct = cipher.encrypt(pad(data, Blowfish.block_size))
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode()}
        elif mode == 'CFB':
            cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv)
            ct = cipher.encrypt(data)
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode()}
        elif mode == 'OFB':
            cipher = Blowfish.new(key, Blowfish.MODE_OFB, iv)
            ct = cipher.encrypt(data)
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode()}
        else:
            raise ValueError(f"Blowfish不支持{mode}模式")
    
    @staticmethod
    def _decrypt_blowfish(encrypted_data: Dict[str, Any], mode: str, key: bytes) -> bytes:
        """Blowfish解密"""
        ct = base64.b64decode(encrypted_data['ciphertext'])
        iv = base64.b64decode(encrypted_data['iv']) if encrypted_data['iv'] else None
        
        if mode == 'ECB':
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
            pt = unpad(cipher.decrypt(ct), Blowfish.block_size)
            return pt
        elif mode == 'CBC':
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), Blowfish.block_size)
            return pt
        elif mode == 'CFB':
            cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv)
            return cipher.decrypt(ct)
        elif mode == 'OFB':
            cipher = Blowfish.new(key, Blowfish.MODE_OFB, iv)
            return cipher.decrypt(ct)
        else:
            raise ValueError(f"Blowfish不支持{mode}模式")
    
    @staticmethod
    def _encrypt_rc4(data: bytes, key: bytes) -> Dict[str, Any]:
        """RC4加密"""
        cipher = ARC4.new(key)
        ct = cipher.encrypt(data)
        return {'ciphertext': base64.b64encode(ct).decode(), 'iv': None}
    
    @staticmethod
    def _decrypt_rc4(encrypted_data: Dict[str, Any], key: bytes) -> bytes:
        """RC4解密"""
        ct = base64.b64decode(encrypted_data['ciphertext'])
        cipher = ARC4.new(key)
        return cipher.decrypt(ct)
    
    @staticmethod
    def encrypt_with_rsa(data: bytes, public_key: bytes) -> bytes:
        """使用RSA公钥加密（增加日志+长度校验）"""
        try:
            rsa_key = RSA.import_key(public_key)
            max_len = rsa_key.size_in_bytes() - 42  # PKCS1_OAEP 填充占用42字节
            if len(data) > max_len:
                raise ValueError(f"RSA加密数据过长（最大{max_len}字节，当前{len(data)}字节）")
            cipher = PKCS1_OAEP.new(rsa_key)
            encrypted = cipher.encrypt(data)
            logger.info(f"RSA加密成功，数据长度: {len(data)} → 加密后: {len(encrypted)}")
            return encrypted
        except Exception as e:
            logger.error(f"RSA加密失败: {str(e)}")
            raise
    
    @staticmethod
    def decrypt_with_rsa(encrypted_data: bytes, private_key: bytes) -> bytes:
        """使用RSA私钥解密（增加日志）"""
        try:
            rsa_key = RSA.import_key(private_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            decrypted = cipher.decrypt(encrypted_data)
            logger.info(f"RSA解密成功，加密数据长度: {len(encrypted_data)} → 解密后: {len(decrypted)}")
            return decrypted
        except Exception as e:
            logger.error(f"RSA解密失败: {str(e)}（大概率是密钥不匹配或数据篡改）")
            raise
    
    @staticmethod
    def create_digital_envelope(data: bytes, algorithm: str, mode: str, 
                              symmetric_key: bytes, recipient_public_key: bytes,
                              sender_private_key: bytes, hash_algorithm: str = 'SHA-256') -> Dict[str, Any]:
        """创建数字信封（新方案：包含数字签名）"""
        # 1. 计算消息哈希值
        hash_value = CryptoUtils.calculate_hash(data, hash_algorithm)
        
        # 2. 创建数字签名：用发送方私钥加密哈希值
        signature = CryptoUtils.create_digital_signature(hash_value.encode(), sender_private_key)
        
        # 3. 使用对称密钥加密数据
        encrypted_data = CryptoUtils.encrypt_data(data, algorithm, mode, symmetric_key)
        
        # 4. 使用接收方公钥加密对称密钥 → 数字信封
        encrypted_key = CryptoUtils.encrypt_with_rsa(symmetric_key, recipient_public_key)
        
        # 5. 创建包含所有元素的数字信封
        digital_envelope = {
            'algorithm': algorithm,
            'mode': mode,
            'hash_algorithm': hash_algorithm,
            'encrypted_data': encrypted_data,
            'encrypted_key': base64.b64encode(encrypted_key).decode(),
            'signature': base64.b64encode(signature).decode(),
            'original_hash': hash_value  # 用于验证
        }
        
        return digital_envelope
    
    @staticmethod
    def open_digital_envelope(digital_envelope: Dict[str, Any], 
                            receiver_private_key: bytes, sender_public_key: bytes) -> bytes:
        """打开数字信封（精准错误提示）"""
        try:
            # 1. 用接收方私钥解密得到对称密钥
            encrypted_key = base64.b64decode(digital_envelope['encrypted_key'])
            try:
                symmetric_key = CryptoUtils.decrypt_with_rsa(encrypted_key, receiver_private_key)
            except Exception as e:
                raise Exception(f"【RSA解密失败】对称密钥解密失败（密钥不匹配/数据篡改）: {str(e)}")
            
            # 2. 用对称密钥解密得到消息M
            algorithm = digital_envelope['algorithm']
            mode = digital_envelope['mode']
            encrypted_data = digital_envelope['encrypted_data']
            try:
                decrypted_data = CryptoUtils.decrypt_data(encrypted_data, algorithm, mode, symmetric_key)
            except Exception as e:
                raise Exception(f"【对称加密解密失败】算法={algorithm}, 模式={mode}: {str(e)}")
            
            # 3. 用发送方公钥验证数字签名
            signature = base64.b64decode(digital_envelope['signature'])
            original_hash = digital_envelope['original_hash']
            
            # 验证签名
            if not CryptoUtils.verify_digital_signature(
                original_hash.encode(), signature, sender_public_key
            ):
                raise Exception("【签名验证失败】消息来源不可信（非证书/解密错误）")
            
            # 4. 比较哈希值
            hash_algorithm = digital_envelope['hash_algorithm']
            calculated_hash = CryptoUtils.calculate_hash(decrypted_data, hash_algorithm)
            if calculated_hash != original_hash:
                raise Exception("【哈希验证失败】数据被篡改（非证书/解密错误）")
            
            return decrypted_data
            
        except Exception as e:
            raise Exception(f"打开数字信封失败: {str(e)}")
    
    @staticmethod
    def calculate_hash(data: bytes, algorithm: str = 'SHA-256') -> str:
        """计算数据的哈希值"""
        if algorithm == 'MD5':
            hash_obj = hashlib.md5(data)
        elif algorithm == 'SHA-1':
            hash_obj = hashlib.sha1(data)
        elif algorithm == 'SHA-256':
            hash_obj = hashlib.sha256(data)
        elif algorithm == 'SHA-512':
            hash_obj = hashlib.sha512(data)
        elif algorithm == 'SHA3-256':
            hash_obj = hashlib.sha3_256(data)
        elif algorithm == 'BLAKE2b':
            hash_obj = hashlib.blake2b(data)
        elif algorithm == 'BLAKE3':
            # BLAKE3 需要额外库，这里使用 BLAKE2b 作为替代
            hash_obj = hashlib.blake2b(data)
        elif algorithm == 'SM3':
            # SM3 需要额外库，这里使用 SHA-256 作为替代
            hash_obj = hashlib.sha256(data)
        else:
            raise ValueError(f"不支持的哈希算法: {algorithm}")
        
        return hash_obj.hexdigest()
    
    @staticmethod
    def create_digital_signature(data: bytes, private_key: bytes) -> bytes:
        """创建数字签名"""
        from Crypto.Signature import pkcs1_15
        from Crypto.Hash import SHA256
        
        # 导入私钥
        rsa_key = RSA.import_key(private_key)
        
        # 创建哈希对象
        h = SHA256.new(data)
        
        # 创建签名
        signature = pkcs1_15.new(rsa_key).sign(h)
        
        return signature
    
    @staticmethod
    def verify_digital_signature(data: bytes, signature: bytes, public_key: bytes) -> bool:
        """验证数字签名"""
        try:
            from Crypto.Signature import pkcs1_15
            from Crypto.Hash import SHA256
            
            # 导入公钥
            rsa_key = RSA.import_key(public_key)
            
            # 创建哈希对象
            h = SHA256.new(data)
            
            # 验证签名
            pkcs1_15.new(rsa_key).verify(h, signature)
            
            return True
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def generate_key_pair_files(private_key_path: str, public_key_path: str, bits: int = 2048):
        """生成并保存RSA密钥对到文件"""
        private_key, public_key = CryptoUtils.generate_rsa_keypair(bits)
        
        with open(private_key_path, 'wb') as f:
            f.write(private_key)
        
        with open(public_key_path, 'wb') as f:
            f.write(public_key)
    
    @staticmethod
    def _encrypt_chacha20(data: bytes, key: bytes) -> Dict[str, Any]:
        """ChaCha20加密"""
        if not CHACHA20_AVAILABLE:
            raise Exception("ChaCha20算法不可用，请升级pycryptodome库")
        
        # 生成随机nonce
        nonce = Random.get_random_bytes(12)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ct = cipher.encrypt(data)
        return {
            'ciphertext': base64.b64encode(ct).decode(), 
            'iv': base64.b64encode(nonce).decode(),
            'tag': None
        }
    
    @staticmethod
    def _decrypt_chacha20(encrypted_data: Dict[str, Any], key: bytes) -> bytes:
        """ChaCha20解密"""
        if not CHACHA20_AVAILABLE:
            raise Exception("ChaCha20算法不可用，请升级pycryptodome库")
        
        ct = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['iv'])
        cipher = ChaCha20.new(key=key, nonce=nonce)
        return cipher.decrypt(ct)
    
    @staticmethod
    def _encrypt_sm4(data: bytes, mode: str, key: bytes, iv: bytes = None) -> Dict[str, Any]:
        """SM4加密（简化实现）"""
        if not SM4_AVAILABLE:
            # 使用AES作为SM4的替代实现（仅作演示）
            if iv is None:
                iv = Random.get_random_bytes(16)
            
            if mode == 'ECB':
                cipher = AES.new(key, AES.MODE_ECB)
                ct = cipher.encrypt(pad(data, AES.block_size))
                return {'ciphertext': base64.b64encode(ct).decode(), 'iv': None, 'tag': None}
            elif mode == 'CBC':
                cipher = AES.new(key, AES.MODE_CBC, iv)
                ct = cipher.encrypt(pad(data, AES.block_size))
                return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode(), 'tag': None}
            elif mode == 'CBC + HMAC-SM3':
                if not HMAC_AVAILABLE:
                    raise Exception("HMAC功能不可用")
                
                # 使用AES-CBC加密
                cipher = AES.new(key, AES.MODE_CBC, iv)
                ct = cipher.encrypt(pad(data, AES.block_size))
                
                # 生成HMAC（使用SHA-256模拟SM3）
                hmac_key = Random.get_random_bytes(32)  # HMAC密钥
                h = hmac.new(hmac_key, ct + iv, hashlib.sha256)
                mac = h.digest()
                
                return {
                    'ciphertext': base64.b64encode(ct).decode(), 
                    'iv': base64.b64encode(iv).decode(), 
                    'tag': base64.b64encode(mac).decode(),
                    'hmac_key': base64.b64encode(hmac_key).decode()
                }
            elif mode == 'CFB':
                cipher = AES.new(key, AES.MODE_CFB, iv)
                ct = cipher.encrypt(data)
                return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode(), 'tag': None}
            elif mode == 'OFB':
                cipher = AES.new(key, AES.MODE_OFB, iv)
                ct = cipher.encrypt(data)
                return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode(), 'tag': None}
            elif mode == 'CTR':
                cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
                ct = cipher.encrypt(data)
                return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode(), 'tag': None}
            else:
                raise ValueError(f"SM4不支持{mode}模式")
    
    @staticmethod
    def _decrypt_sm4(encrypted_data: Dict[str, Any], mode: str, key: bytes) -> bytes:
        """SM4解密（简化实现）"""
        if not SM4_AVAILABLE:
            # 使用AES作为SM4的替代实现（仅作演示）
            ct = base64.b64decode(encrypted_data['ciphertext'])
            iv = base64.b64decode(encrypted_data['iv']) if encrypted_data['iv'] else None
            
            if mode == 'ECB':
                cipher = AES.new(key, AES.MODE_ECB)
                pt = unpad(cipher.decrypt(ct), AES.block_size)
                return pt
            elif mode == 'CBC':
                cipher = AES.new(key, AES.MODE_CBC, iv)
                pt = unpad(cipher.decrypt(ct), AES.block_size)
                return pt
            elif mode == 'CBC + HMAC-SM3':
                if not HMAC_AVAILABLE:
                    raise Exception("HMAC功能不可用")
                
                # 验证HMAC
                hmac_key = base64.b64decode(encrypted_data['hmac_key'])
                mac = base64.b64decode(encrypted_data['tag'])
                
                h = hmac.new(hmac_key, ct + iv, hashlib.sha256)
                if not hmac.compare_digest(h.digest(), mac):
                    raise Exception("HMAC验证失败！数据可能被篡改。")
                
                # 解密数据
                cipher = AES.new(key, AES.MODE_CBC, iv)
                pt = unpad(cipher.decrypt(ct), AES.block_size)
                return pt
            elif mode == 'CFB':
                cipher = AES.new(key, AES.MODE_CFB, iv)
                return cipher.decrypt(ct)
            elif mode == 'OFB':
                cipher = AES.new(key, AES.MODE_OFB, iv)
                return cipher.decrypt(ct)
            elif mode == 'CTR':
                cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
                return cipher.decrypt(ct)
            else:
                raise ValueError(f"SM4不支持{mode}模式")
    
    @staticmethod
    def _encrypt_camellia(data: bytes, mode: str, key: bytes, iv: bytes = None) -> Dict[str, Any]:
        """Camellia加密"""
        if not CAMELLIA_AVAILABLE:
            raise Exception("Camellia算法不可用，请升级pycryptodome库")
        
        if iv is None:
            iv = Random.get_random_bytes(16)
        
        if mode == 'ECB':
            cipher = Camellia.new(key, Camellia.MODE_ECB)
            ct = cipher.encrypt(pad(data, Camellia.block_size))
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': None, 'tag': None}
        elif mode == 'CBC':
            cipher = Camellia.new(key, Camellia.MODE_CBC, iv)
            ct = cipher.encrypt(pad(data, Camellia.block_size))
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode(), 'tag': None}
        elif mode == 'CFB':
            cipher = Camellia.new(key, Camellia.MODE_CFB, iv)
            ct = cipher.encrypt(data)
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode(), 'tag': None}
        elif mode == 'OFB':
            cipher = Camellia.new(key, Camellia.MODE_OFB, iv)
            ct = cipher.encrypt(data)
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode(), 'tag': None}
        elif mode == 'CTR':
            cipher = Camellia.new(key, Camellia.MODE_CTR, nonce=iv[:8])
            ct = cipher.encrypt(data)
            return {'ciphertext': base64.b64encode(ct).decode(), 'iv': base64.b64encode(iv).decode(), 'tag': None}
        else:
            raise ValueError(f"Camellia不支持{mode}模式")
    
    @staticmethod
    def _decrypt_camellia(encrypted_data: Dict[str, Any], mode: str, key: bytes) -> bytes:
        """Camellia解密"""
        if not CAMELLIA_AVAILABLE:
            raise Exception("Camellia算法不可用，请升级pycryptodome库")
        
        ct = base64.b64decode(encrypted_data['ciphertext'])
        iv = base64.b64decode(encrypted_data['iv']) if encrypted_data['iv'] else None
        
        if mode == 'ECB':
            cipher = Camellia.new(key, Camellia.MODE_ECB)
            pt = unpad(cipher.decrypt(ct), Camellia.block_size)
            return pt
        elif mode == 'CBC':
            cipher = Camellia.new(key, Camellia.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), Camellia.block_size)
            return pt
        elif mode == 'CFB':
            cipher = Camellia.new(key, Camellia.MODE_CFB, iv)
            return cipher.decrypt(ct)
        elif mode == 'OFB':
            cipher = Camellia.new(key, Camellia.MODE_OFB, iv)
            return cipher.decrypt(ct)
        elif mode == 'CTR':
            cipher = Camellia.new(key, Camellia.MODE_CTR, nonce=iv[:8])
            return cipher.decrypt(ct)
        else:
            raise ValueError(f"Camellia不支持{mode}模式")
    
    @staticmethod
    def load_key_from_file(key_path: str) -> bytes:
        """从文件加载密钥"""
        with open(key_path, 'rb') as f:
            return f.read()
    
    # ========== 新增：私钥保存方法（配套证书使用） ==========
    @staticmethod
    def save_private_key(private_key: bytes, save_path: str):
        """保存私钥到文件（带目录自动创建）"""
        # 校验路径并创建父目录
        dir_path = os.path.dirname(save_path)
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path, mode=0o755, exist_ok=True)
            logger.info(f"创建私钥目录: {dir_path}")
        
        # 写入私钥文件
        with open(save_path, 'wb') as f:
            f.write(private_key)
        logger.info(f"私钥已保存到: {save_path}")

    # ========== 新增：证书生成（确保写入文件） ==========
    @staticmethod
    def generate_certificate(public_key: bytes, info: dict, save_path: str) -> None:
        """
        生成并写入证书文件（落地到文件系统）
        :param public_key: RSA公钥字节流
        :param info: 证书信息（如{"name": "测试用户", "org": "测试公司"}）
        :param save_path: 证书保存路径（如 "./certs/test.cert"）
        """
        try:
            # 1. 创建证书父目录（解决路径不存在问题）
            dir_path = os.path.dirname(save_path)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, mode=0o755, exist_ok=True)
                logger.info(f"创建证书目录: {dir_path}")
            
            # 2. 构建证书内容
            cert_data = {
                "version": "1.0",
                "issuer": info,
                "public_key_b64": base64.b64encode(public_key).decode('utf-8'),
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "algorithm": "RSA",
                "hash_algorithm": "SHA-256"
            }
            
            # 3. 写入证书文件（确保编码和格式正确）
            with open(save_path, 'w', encoding='utf-8') as f:
                json.dump(cert_data, f, indent=4, ensure_ascii=False)
            
            # 4. 验证文件是否真的生成
            if os.path.exists(save_path):
                file_size = os.path.getsize(save_path)
                if file_size > 0:
                    logger.info(f"证书已成功写入: {save_path}（大小: {file_size} 字节）")
                else:
                    raise Exception(f"证书文件为空: {save_path}")
            else:
                raise Exception(f"证书文件未生成: {save_path}")
        
        except PermissionError:
            raise Exception(f"权限不足！无法写入证书到 {save_path}，请检查目录权限")
        except Exception as e:
            logger.error(f"生成证书失败: {str(e)}")
            raise

    # ========== 新增：证书读取（确保能解析） ==========
    @staticmethod
    def load_certificate(cert_path: str) -> Tuple[bytes, dict]:
        """
        读取证书文件并解析公钥和信息
        :param cert_path: 证书路径
        :return: (RSA公钥字节流, 证书信息字典)
        """
        try:
            # 1. 校验文件存在性
            if not os.path.exists(cert_path):
                raise FileNotFoundError(f"证书文件不存在: {cert_path}")
            
            # 2. 校验文件非空
            file_size = os.path.getsize(cert_path)
            if file_size == 0:
                raise Exception(f"证书文件为空: {cert_path}")
            
            # 3. 读取并解析证书
            with open(cert_path, 'r', encoding='utf-8') as f:
                cert_data = json.load(f)
            
            # 4. 校验必选字段
            required_fields = ["version", "issuer", "public_key_b64", "created_at", "algorithm"]
            for field in required_fields:
                if field not in cert_data:
                    raise ValueError(f"证书缺少必选字段: {field}")
            
            # 5. 解码公钥
            public_key_bytes = base64.b64decode(cert_data['public_key_b64'])
            
            logger.info(f"成功读取证书: {cert_path}（持有者: {cert_data['issuer'].get('name', '未知')}）")
            return public_key_bytes, cert_data['issuer']
        
        except json.JSONDecodeError:
            raise Exception(f"证书格式错误（非JSON）: {cert_path}，请检查文件内容是否为合法JSON")
        except base64.binascii.Error:
            raise Exception(f"证书中公钥base64解码失败: {cert_path}，公钥可能被篡改")
        except Exception as e:
            logger.error(f"读取证书失败: {str(e)}")
            raise


# ========== 测试代码（验证核心功能） ==========
if __name__ == "__main__":
    # 测试路径（可自定义）
    test_priv_path = "./test_rsa_private.pem"
    test_cert_path = "./certs/test_certificate.cert"
    
    try:
        # 1. 生成RSA密钥对
        priv_key, pub_key = CryptoUtils.generate_rsa_keypair()
        logger.info(f"生成RSA公钥: {pub_key[:50]}...")
        
        # 2. 保存私钥
        CryptoUtils.save_private_key(priv_key, test_priv_path)
        
        # 3. 生成证书（核心验证）
        cert_info = {
            "name": "SecuTrans测试用户",
            "org": "测试公司",
            "email": "test@secutrans.com"
        }
        CryptoUtils.generate_certificate(pub_key, cert_info, test_cert_path)
        
        # 4. 读取证书
        loaded_pub, loaded_info = CryptoUtils.load_certificate(test_cert_path)
        
        # 5. 校验一致性
        assert pub_key == loaded_pub, "读取的公钥与原公钥不一致！"
        assert loaded_info['name'] == cert_info['name'], "证书信息读取错误！"
        logger.info("✅ 证书写入/读取验证成功！")

        # 6. 测试数字信封功能
        # 生成对称密钥
        sym_key = CryptoUtils.generate_symmetric_key("AES", 32)
        # 测试数据
        test_data = "测试数字信封功能".encode('utf-8')
        # 发送方私钥（用于签名）、接收方公钥（用于加密对称密钥）
        send_priv, send_pub = CryptoUtils.generate_rsa_keypair()
        recv_priv, recv_pub = CryptoUtils.generate_rsa_keypair()
        # 创建信封
        envelope = CryptoUtils.create_digital_envelope(
            data=test_data,
            algorithm="AES",
            mode="GCM",
            symmetric_key=sym_key,
            recipient_public_key=recv_pub,
            sender_private_key=send_priv
        )
        # 打开信封
        decrypted_data = CryptoUtils.open_digital_envelope(
            digital_envelope=envelope,
            receiver_private_key=recv_priv,
            sender_public_key=send_pub
        )
        assert decrypted_data == test_data, "数字信封解密结果不一致！"
        logger.info(f"✅ 数字信封功能验证成功，解密结果: {decrypted_data.decode('utf-8')}")
    
    except Exception as e:
        logger.error(f"❌ 测试失败: {str(e)}")
        raise
    
