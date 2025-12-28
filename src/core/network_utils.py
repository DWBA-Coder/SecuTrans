#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecuTrans 网络工具模块
实现文件的网络传输功能（支持TLS/SSL加密）
"""

import socket
import ssl
import json
import threading
import time
from typing import Callable, Optional, Dict, Any
import os
from pathlib import Path


class NetworkUtils:
    """网络工具类（支持TLS/SSL加密传输）"""
    
    def __init__(self, use_tls: bool = True):
        """
        初始化网络工具
        
        Args:
            use_tls: 是否启用TLS/SSL加密传输（默认启用）
        """
        self.server_socket = None
        self.client_socket = None
        self.is_listening = False
        self.is_connected = False
        self.connection_callback = None
        self.progress_callback = None
        self.use_tls = use_tls
        
        # TLS/SSL相关
        self.ssl_context_server = None
        self.ssl_context_client = None
        self.cert_dir = Path("ssl_certs")
        
        if self.use_tls:
            self._init_ssl_context()
    
    def _init_ssl_context(self):
        """初始化SSL上下文"""
        try:
            # 确保证书目录存在
            self.cert_dir.mkdir(exist_ok=True)
            
            # 证书文件路径
            cert_file = self.cert_dir / "server.crt"
            key_file = self.cert_dir / "server.key"
            
            # 如果证书不存在，生成自签名证书
            if not cert_file.exists() or not key_file.exists():
                self._generate_self_signed_cert(str(cert_file), str(key_file))
            
            # 创建服务器SSL上下文
            self.ssl_context_server = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context_server.load_cert_chain(str(cert_file), str(key_file))
            # 禁用主机名和证书验证（自签名证书）
            self.ssl_context_server.check_hostname = False
            self.ssl_context_server.verify_mode = ssl.CERT_NONE
            
            # 创建客户端SSL上下文
            self.ssl_context_client = ssl.create_default_context()
            # 对于自签名证书，禁用验证
            self.ssl_context_client.check_hostname = False
            self.ssl_context_client.verify_mode = ssl.CERT_NONE
            
            print(f"✓ SSL/TLS已启用 (证书: {cert_file})")
            
        except Exception as e:
            print(f"⚠ SSL/TLS初始化失败: {str(e)}")
            self.use_tls = False
    
    def _generate_self_signed_cert(self, cert_file: str, key_file: str):
        """
        生成自签名SSL证书
        
        Args:
            cert_file: 证书文件路径
            key_file: 私钥文件路径
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            from datetime import datetime, timedelta
            
            # 生成RSA私钥
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # 创建证书主题
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecuTrans"),
                x509.NameAttribute(NameOID.COMMON_NAME, "SecuTrans Server"),
            ])
            
            # 创建证书
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # 保存私钥
            with open(key_file, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # 保存证书
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            print(f"✓ 已生成自签名SSL证书: {cert_file}")
            
        except ImportError:
            print("⚠ 警告: cryptography库未安装，无法生成SSL证书")
            print("  请运行: pip install cryptography")
            self.use_tls = False
        except Exception as e:
            print(f"⚠ 生成SSL证书失败: {str(e)}")
            self.use_tls = False
    
    def start_server(self, port: int, connection_callback: Callable = None) -> bool:
        """启动服务器"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(1)
            self.is_listening = True
            self.connection_callback = connection_callback
            
            # 启动监听线程
            listen_thread = threading.Thread(target=self._listen_for_connections)
            listen_thread.daemon = True
            listen_thread.start()
            
            return True
            
        except Exception as e:
            print(f"启动服务器失败: {str(e)}")
            return False
    
    def _listen_for_connections(self):
        """监听连接请求（支持TLS/SSL）"""
        while self.is_listening:
            try:
                client_socket, address = self.server_socket.accept()
                
                # 如果启用TLS，包装socket
                if self.use_tls and self.ssl_context_server:
                    try:
                        client_socket = self.ssl_context_server.wrap_socket(
                            client_socket,
                            server_side=True
                        )
                        print(f"✓ TLS连接建立: {address}")
                    except Exception as e:
                        print(f"⚠ TLS握手失败: {str(e)}")
                        client_socket.close()
                        continue
                
                if self.connection_callback:
                    self.connection_callback(client_socket, address)
            except socket.error:
                break
    
    def connect_to_server(self, host: str, port: int) -> bool:
        """连接到服务器（支持TLS/SSL）"""
        try:
            # 创建原始socket
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.connect((host, port))
            
            # 如果启用TLS，包装socket
            if self.use_tls and self.ssl_context_client:
                try:
                    self.client_socket = self.ssl_context_client.wrap_socket(
                        raw_socket,
                        server_hostname=host
                    )
                    print(f"✓ TLS连接已建立")
                except Exception as e:
                    print(f"⚠ TLS握手失败: {str(e)}")
                    raw_socket.close()
                    return False
            else:
                self.client_socket = raw_socket
            
            self.is_connected = True
            return True
            
        except Exception as e:
            print(f"连接服务器失败: {str(e)}")
            return False
    
    def send_data(self, socket_obj: socket.socket, data: Dict[str, Any]) -> bool:
        """发送数据"""
        try:
            json_data = json.dumps(data).encode('utf-8')
            data_length = len(json_data)
            
            # 发送数据长度
            length_bytes = data_length.to_bytes(4, byteorder='big')
            socket_obj.send(length_bytes)
            
            # 发送数据
            socket_obj.send(json_data)
            return True
            
        except Exception as e:
            print(f"发送数据失败: {str(e)}")
            return False
    
    def receive_data(self, socket_obj: socket.socket) -> Optional[Dict[str, Any]]:
        """接收数据"""
        try:
            # 接收数据长度
            length_bytes = socket_obj.recv(4)
            if len(length_bytes) != 4:
                return None
            
            data_length = int.from_bytes(length_bytes, byteorder='big')
            
            # 接收数据
            received_data = b''
            while len(received_data) < data_length:
                chunk = socket_obj.recv(min(data_length - len(received_data), 8192))
                if not chunk:
                    return None
                received_data += chunk
            
            # 解析JSON数据
            return json.loads(received_data.decode('utf-8'))
            
        except Exception as e:
            print(f"接收数据失败: {str(e)}")
            return None
    
    def send_file(self, socket_obj: socket.socket, file_path: str, 
                  progress_callback: Callable = None) -> bool:
        """发送文件"""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"文件不存在: {file_path}")
            
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            
            # 发送文件信息
            file_info = {
                'type': 'file_info',
                'filename': file_name,
                'filesize': file_size
            }
            
            if not self.send_data(socket_obj, file_info):
                return False
            
            # 发送文件内容
            with open(file_path, 'rb') as f:
                sent_bytes = 0
                while sent_bytes < file_size:
                    chunk_size = min(8192, file_size - sent_bytes)
                    chunk = f.read(chunk_size)
                    socket_obj.send(chunk)
                    sent_bytes += len(chunk)
                    
                    if progress_callback:
                        progress = int((sent_bytes / file_size) * 100)
                        progress_callback(progress)
            
            return True
            
        except Exception as e:
            print(f"发送文件失败: {str(e)}")
            return False
    
    def receive_file(self, socket_obj: socket.socket, save_path: str,
                     progress_callback: Callable = None) -> bool:
        """接收文件"""
        try:
            # 接收文件信息
            file_info = self.receive_data(socket_obj)
            if not file_info or file_info.get('type') != 'file_info':
                raise Exception("无法获取文件信息")
            
            file_name = file_info['filename']
            file_size = file_info['filesize']
            
            # 创建文件保存路径
            if os.path.isdir(save_path):
                file_path = os.path.join(save_path, file_name)
            else:
                file_path = save_path
            
            # 接收文件内容
            received_bytes = 0
            with open(file_path, 'wb') as f:
                while received_bytes < file_size:
                    chunk_size = min(8192, file_size - received_bytes)
                    chunk = socket_obj.recv(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    received_bytes += len(chunk)
                    
                    if progress_callback:
                        progress = int((received_bytes / file_size) * 100)
                        progress_callback(progress)
            
            return True
            
        except Exception as e:
            print(f"接收文件失败: {str(e)}")
            return False
    
    def send_digital_envelope(self, socket_obj: socket.socket, 
                            digital_envelope: Dict[str, Any], sender_public_key: bytes = None) -> bool:
        """发送数字信封"""
        try:
            envelope_data = {
                'type': 'digital_envelope',
                'data': digital_envelope
            }
            
            # 如果提供了发送方公钥，也一起发送
            if sender_public_key:
                import base64
                envelope_data['sender_public_key'] = base64.b64encode(sender_public_key).decode()
            
            return self.send_data(socket_obj, envelope_data)
            
        except Exception as e:
            print(f"发送数字信封失败: {str(e)}")
            return False
    
    def receive_digital_envelope(self, socket_obj: socket.socket) -> tuple:
        """接收数字信封"""
        try:
            received_data = self.receive_data(socket_obj)
            if received_data and received_data.get('type') == 'digital_envelope':
                digital_envelope = received_data['data']
                sender_public_key = None
                
                # 如果包含发送方公钥，提取出来
                if 'sender_public_key' in received_data:
                    import base64
                    sender_public_key = base64.b64decode(received_data['sender_public_key'])
                
                return digital_envelope, sender_public_key
            return None, None
            
        except Exception as e:
            print(f"接收数字信封失败: {str(e)}")
            return None, None
            return None
    
    def close_connection(self):
        """关闭连接"""
        try:
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
                self.is_connected = False
            
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
                self.is_listening = False
                
        except Exception as e:
            print(f"关闭连接失败: {str(e)}")
    
    def get_local_ip(self) -> str:
        """获取本机IP地址"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"