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

# 尝试导入新的加密算法
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
        """AES加密"""
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
        elif mode == 'GCM':
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            ct, tag = cipher.encrypt_and_digest(pad(data, AES.block_size))
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
        """AES解密"""
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
            return unpad(pt, AES.block_size)
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
        """使用RSA公钥加密"""
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.encrypt(data)
    
    @staticmethod
    def decrypt_with_rsa(encrypted_data: bytes, private_key: bytes) -> bytes:
        """使用RSA私钥解密"""
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.decrypt(encrypted_data)
    
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
        """打开数字信封（新方案：验证数字签名）"""
        try:
            # 1. 用接收方私钥解密得到对称密钥
            encrypted_key = base64.b64decode(digital_envelope['encrypted_key'])
            symmetric_key = CryptoUtils.decrypt_with_rsa(encrypted_key, receiver_private_key)
            
            # 2. 用对称密钥解密得到消息M
            algorithm = digital_envelope['algorithm']
            mode = digital_envelope['mode']
            encrypted_data = digital_envelope['encrypted_data']
            
            decrypted_data = CryptoUtils.decrypt_data(encrypted_data, algorithm, mode, symmetric_key)
            
            # 3. 用发送方公钥验证数字签名
            signature = base64.b64decode(digital_envelope['signature'])
            original_hash = digital_envelope['original_hash']
            
            # 验证签名
            if not CryptoUtils.verify_digital_signature(
                original_hash.encode(), signature, sender_public_key
            ):
                raise Exception("数字签名验证失败！消息来源不可信。")
            
            # 4. 比较哈希值
            hash_algorithm = digital_envelope['hash_algorithm']
            calculated_hash = CryptoUtils.calculate_hash(decrypted_data, hash_algorithm)
            if calculated_hash != original_hash:
                raise Exception("数据完整性验证失败！文件可能被篡改。")
            
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