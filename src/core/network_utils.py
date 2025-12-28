#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecuTrans 网络工具模块
实现文件的网络传输功能（支持TLS/SSL加密）

主要功能:
- TCP套接字通信
- TLS/SSL加密传输
- 文件传输
- 数字信封传输
- 多线程支持
- 连接超时控制
- 重试机制
"""

import socket
import ssl
import json
import threading
import time
import logging
from typing import Callable, Optional, Dict, Any, Tuple
from contextlib import contextmanager
import os
from pathlib import Path

# 配置日志
logger = logging.getLogger(__name__)


class NetworkError(Exception):
    """网络操作异常基类"""
    pass


class ConnectionTimeoutError(NetworkError):
    """连接超时异常"""
    pass


class SSLHandshakeError(NetworkError):
    """SSL握手失败异常"""
    pass


class NetworkUtils:
    """
    网络工具类（支持TLS/SSL加密传输）
    
    特性:
    - 支持TLS/SSL加密传输
    - 多线程安全
    - 连接超时控制
    - 自动重试机制
    - 完善的错误处理
    """
    
    # 默认配置
    DEFAULT_CONNECT_TIMEOUT = 30.0  # 连接超时（秒）
    DEFAULT_RECV_TIMEOUT = 60.0    # 接收超时（秒）
    DEFAULT_SEND_TIMEOUT = 60.0     # 发送超时（秒）
    DEFAULT_MAX_RETRIES = 3         # 最大重试次数
    DEFAULT_RETRY_DELAY = 1.0       # 重试延迟（秒）
    BUFFER_SIZE = 8192              # 缓冲区大小
    
    def __init__(self, use_tls: bool = True, connect_timeout: float = None,
                 recv_timeout: float = None, send_timeout: float = None,
                 allow_self_signed: bool = True):
        """
        初始化网络工具

        Args:
            use_tls: 是否启用TLS/SSL加密传输（默认启用）
            connect_timeout: 连接超时时间（秒）
            recv_timeout: 接收超时时间（秒）
            send_timeout: 发送超时时间（秒）
            allow_self_signed: 是否允许自签名证书（默认允许）
        """
        # 基础属性
        self.server_socket = None
        self.client_socket = None
        self.is_listening = False
        self.is_connected = False
        self.connection_callback = None
        self.progress_callback = None
        self.use_tls = use_tls
        self.allow_self_signed = allow_self_signed
        
        # 超时配置
        self.connect_timeout = connect_timeout or self.DEFAULT_CONNECT_TIMEOUT
        self.recv_timeout = recv_timeout or self.DEFAULT_RECV_TIMEOUT
        self.send_timeout = send_timeout or self.DEFAULT_SEND_TIMEOUT
        
        # TLS/SSL相关
        self.ssl_context_server = None
        self.ssl_context_client = None
        self.cert_dir = Path("ssl_certs")
        
        # 线程锁和退出事件
        self._lock = threading.RLock()
        self._listen_thread = None
        self._stop_event = threading.Event()  # 用于优雅退出
        
        # 初始化SSL上下文
        if self.use_tls:
            self._init_ssl_context()
            
        logger.info(f"NetworkUtils初始化完成 (TLS: {self.use_tls})")
    
    def _init_ssl_context(self) -> bool:
        """
        初始化SSL上下文
        
        Returns:
            bool: 初始化是否成功
        """
        try:
            # 确保证书目录存在
            self.cert_dir.mkdir(exist_ok=True)
            
            # 证书文件路径
            cert_file = self.cert_dir / "server.crt"
            key_file = self.cert_dir / "server.key"
            
            # 如果证书不存在，生成自签名证书
            if not cert_file.exists() or not key_file.exists():
                logger.info("生成自签名SSL证书...")
                if not self._generate_self_signed_cert(str(cert_file), str(key_file)):
                    raise NetworkError("生成自签名证书失败")
            
            # 创建服务器SSL上下文
            self.ssl_context_server = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context_server.load_cert_chain(str(cert_file), str(key_file))

            # 根据配置设置证书验证
            if self.allow_self_signed:
                # 开发/测试环境：允许自签名证书
                self.ssl_context_server.check_hostname = False
                self.ssl_context_server.verify_mode = ssl.CERT_NONE
                logger.warning("SSL证书验证已禁用（允许自签名证书）- 仅用于开发/测试")
            else:
                # 生产环境：启用严格验证
                self.ssl_context_server.check_hostname = True
                self.ssl_context_server.verify_mode = ssl.CERT_REQUIRED
                logger.info("SSL证书验证已启用（严格模式）")

            # 创建客户端SSL上下文
            self.ssl_context_client = ssl.create_default_context()
            # 客户端使用相同的安全级别
            if self.allow_self_signed:
                self.ssl_context_client.check_hostname = False
                self.ssl_context_client.verify_mode = ssl.CERT_NONE
                logger.warning("客户端SSL证书验证已禁用（允许自签名证书）- 仅用于开发/测试")
            else:
                self.ssl_context_client.check_hostname = True
                self.ssl_context_client.verify_mode = ssl.CERT_REQUIRED
                logger.info("客户端SSL证书验证已启用（严格模式）")
            
            logger.info(f"SSL/TLS已启用 (证书: {cert_file})")
            return True
            
        except Exception as e:
            logger.error(f"SSL/TLS初始化失败: {str(e)}", exc_info=True)
            self.use_tls = False
            return False
    
    def _generate_self_signed_cert(self, cert_file: str, key_file: str) -> bool:
        """
        生成自签名SSL证书
        
        Args:
            cert_file: 证书文件路径
            key_file: 私钥文件路径
            
        Returns:
            bool: 生成是否成功
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            from datetime import datetime, timedelta
            
            # 生成RSA私钥（2048位）
            logger.info("生成RSA私钥...")
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
            
            # 创建证书（有效期365天）
            logger.info("生成自签名证书...")
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
                    x509.IPAddress(socket.inet_aton("127.0.0.1")),
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
            
            logger.info(f"已生成自签名SSL证书: {cert_file}")
            return True
            
        except ImportError as e:
            logger.error("cryptography库未安装，无法生成SSL证书")
            logger.error("请运行: pip install cryptography")
            return False
        except Exception as e:
            logger.error(f"生成SSL证书失败: {str(e)}", exc_info=True)
            return False
    
    def start_server(self, port: int, connection_callback: Callable = None, 
                    max_connections: int = 5) -> bool:
        """
        启动服务器
        
        Args:
            port: 监听端口号
            connection_callback: 连接回调函数
            max_connections: 最大连接队列长度
            
        Returns:
            bool: 启动是否成功
        """
        with self._lock:
            if self.is_listening:
                logger.warning("服务器已在运行")
                return True
                
            if self.server_socket:
                logger.warning("服务器socket已存在，先关闭")
                try:
                    self.server_socket.close()
                except:
                    pass
        
        try:
            # 创建TCP套接字
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.settimeout(1.0)  # 设置accept超时，以便可以优雅关闭
            
            # 绑定端口并开始监听
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(max_connections)
            
            with self._lock:
                self.is_listening = True
                self.connection_callback = connection_callback
                self._stop_event.clear()  # 重置停止事件
            
            # 启动监听线程
            self._listen_thread = threading.Thread(
                target=self._listen_for_connections,
                name="NetworkListener",
                daemon=True
            )
            self._listen_thread.start()
            
            logger.info(f"服务器启动成功，监听端口: {port}")
            return True
            
        except socket.error as e:
            logger.error(f"启动服务器失败: {str(e)}", exc_info=True)
            with self._lock:
                self.is_listening = False
            return False
        except Exception as e:
            logger.error(f"启动服务器异常: {str(e)}", exc_info=True)
            with self._lock:
                self.is_listening = False
            return False
    
    def _listen_for_connections(self):
        """监听连接请求（支持TLS/SSL）"""
        logger.info("监听线程启动")
        
        while not self._stop_event.is_set():
            with self._lock:
                if not self.is_listening:
                    break
                    
            try:
                # 接受客户端连接
                client_socket, address = self.server_socket.accept()
                logger.info(f"客户端连接请求: {address}")
                
                # 如果启用TLS，包装socket
                if self.use_tls and self.ssl_context_server:
                    try:
                        # 设置TLS超时
                        client_socket.settimeout(self.connect_timeout)
                        client_socket = self.ssl_context_server.wrap_socket(
                            client_socket,
                            server_side=True
                        )
                        logger.info(f"TLS连接建立成功: {address}")
                    except ssl.SSLError as e:
                        logger.error(f"TLS握手失败: {address}, 错误: {str(e)}")
                        try:
                            client_socket.close()
                        except:
                            pass
                        continue
                    except Exception as e:
                        logger.error(f"TLS包装失败: {address}, 错误: {str(e)}")
                        try:
                            client_socket.close()
                        except:
                            pass
                        continue
                
                # 调用连接回调
                callback = None
                with self._lock:
                    callback = self.connection_callback
                
                if callback:
                    try:
                        callback(client_socket, address)
                    except Exception as e:
                        logger.error(f"连接回调执行失败: {str(e)}", exc_info=True)
                        try:
                            client_socket.close()
                        except:
                            pass
                else:
                    logger.warning("未设置连接回调，关闭客户端连接")
                    try:
                        client_socket.close()
                    except:
                        pass
                        
            except socket.timeout:
                # 超时是正常的，继续循环
                continue
            except socket.error as e:
                with self._lock:
                    if self.is_listening:
                        logger.error(f"监听异常: {str(e)}", exc_info=True)
                break
            except Exception as e:
                logger.error(f"监听线程异常: {str(e)}", exc_info=True)
                break
        
        logger.info("监听线程退出")
    
    def connect_to_server(self, host: str, port: int, 
                         max_retries: int = None) -> bool:
        """
        连接到服务器（支持TLS/SSL）
        
        Args:
            host: 服务器主机地址
            port: 服务器端口
            max_retries: 最大重试次数（None表示使用默认值）
            
        Returns:
            bool: 连接是否成功
            
        Raises:
            NetworkError: 网络错误
            ConnectionTimeoutError: 连接超时
        """
        max_retries = max_retries or self.DEFAULT_MAX_RETRIES
        
        with self._lock:
            if self.is_connected and self.client_socket:
                logger.warning("已存在连接，先关闭旧连接")
                self._close_client_socket()
        
        for attempt in range(max_retries):
            try:
                # 创建TCP套接字
                raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_socket.settimeout(self.connect_timeout)
                
                # 连接服务器
                logger.info(f"尝试连接 {host}:{port} (第{attempt + 1}次)...")
                raw_socket.connect((host, port))
                
                # 如果启用TLS，包装socket
                if self.use_tls and self.ssl_context_client:
                    try:
                        raw_socket.settimeout(self.connect_timeout)
                        self.client_socket = self.ssl_context_client.wrap_socket(
                            raw_socket,
                            server_hostname=host
                        )
                        logger.info(f"TLS连接已建立: {host}:{port}")
                    except ssl.SSLError as e:
                        logger.error(f"TLS握手失败: {str(e)}")
                        raw_socket.close()
                        raise SSLHandshakeError(f"TLS握手失败: {str(e)}")
                    except Exception as e:
                        logger.error(f"TLS包装失败: {str(e)}")
                        raw_socket.close()
                        raise NetworkError(f"TLS包装失败: {str(e)}")
                else:
                    self.client_socket = raw_socket
                
                with self._lock:
                    self.is_connected = True
                
                logger.info(f"成功连接到服务器: {host}:{port}")
                return True
                
            except socket.timeout:
                logger.warning(f"连接超时 (第{attempt + 1}次尝试)")
                if attempt < max_retries - 1:
                    time.sleep(self.DEFAULT_RETRY_DELAY)
                else:
                    raise ConnectionTimeoutError(
                        f"连接超时，已尝试{max_retries}次: {host}:{port}"
                    )
                    
            except socket.error as e:
                logger.error(f"连接失败 (第{attempt + 1}次): {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(self.DEFAULT_RETRY_DELAY)
                else:
                    raise NetworkError(
                        f"连接失败，已尝试{max_retries}次: {host}:{port}, 错误: {str(e)}"
                    )
                    
            except Exception as e:
                logger.error(f"连接异常: {str(e)}", exc_info=True)
                if attempt < max_retries - 1:
                    time.sleep(self.DEFAULT_RETRY_DELAY)
                else:
                    raise NetworkError(f"连接异常: {str(e)}")
        
        return False
    
    def _close_client_socket(self):
        """关闭客户端socket（内部方法，快速关闭）"""
        try:
            if self.client_socket:
                try:
                    # 设置短超时，避免关闭时阻塞
                    self.client_socket.settimeout(0.1)
                    # 尝试优雅关闭
                    self.client_socket.shutdown(socket.SHUT_RDWR)
                except:
                    # shutdown失败直接关闭
                    pass
                finally:
                    try:
                        self.client_socket.close()
                    except:
                        pass
                    finally:
                        self.client_socket = None
        except Exception as e:
            logger.debug(f"关闭客户端socket失败: {str(e)}")
        finally:
            self.is_connected = False
    
    def send_data(self, socket_obj: socket.socket, data: Dict[str, Any], 
                 timeout: float = None) -> bool:
        """
        发送数据
        
        Args:
            socket_obj: 套接字对象
            data: 要发送的数据（字典）
            timeout: 发送超时时间（秒）
            
        Returns:
            bool: 发送是否成功
        """
        if timeout:
            socket_obj.settimeout(timeout)
            
        try:
            # 序列化数据
            json_data = json.dumps(data, ensure_ascii=False).encode('utf-8')
            data_length = len(json_data)
            
            logger.debug(f"发送数据，长度: {data_length} bytes")
            
            # 发送数据长度（4字节大端序）
            length_bytes = data_length.to_bytes(4, byteorder='big')
            socket_obj.sendall(length_bytes)
            
            # 发送数据内容
            socket_obj.sendall(json_data)
            
            logger.debug("数据发送成功")
            return True
            
        except socket.timeout:
            logger.error("发送数据超时")
            return False
        except socket.error as e:
            logger.error(f"发送数据失败: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"发送数据异常: {str(e)}", exc_info=True)
            return False
    
    def receive_data(self, socket_obj: socket.socket, 
                    timeout: float = None) -> Optional[Dict[str, Any]]:
        """
        接收数据
        
        Args:
            socket_obj: 套接字对象
            timeout: 接收超时时间（秒）
            
        Returns:
            Optional[Dict[str, Any]]: 接收到的数据，失败返回None
        """
        if timeout:
            socket_obj.settimeout(timeout)
            
        try:
            # 接收数据长度（4字节）
            length_bytes = self._recv_exact(socket_obj, 4)
            if not length_bytes or len(length_bytes) != 4:
                logger.warning("无法接收数据长度")
                return None
            
            data_length = int.from_bytes(length_bytes, byteorder='big')
            logger.debug(f"接收数据，长度: {data_length} bytes")
            
            # 数据长度安全检查
            if data_length > 100 * 1024 * 1024:  # 限制为100MB
                logger.error(f"数据长度过大: {data_length} bytes")
                return None
            
            # 接收数据内容
            received_data = self._recv_exact(socket_obj, data_length)
            if not received_data or len(received_data) != data_length:
                logger.warning("数据接收不完整")
                return None
            
            # 解析JSON数据
            data = json.loads(received_data.decode('utf-8'))
            logger.debug("数据接收成功")
            return data
            
        except socket.timeout:
            logger.error("接收数据超时")
            return None
        except socket.error as e:
            logger.error(f"接收数据失败: {str(e)}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"JSON解析失败: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"接收数据异常: {str(e)}", exc_info=True)
            return None
    
    def _recv_exact(self, socket_obj: socket.socket, length: int) -> Optional[bytes]:
        """
        精确接收指定长度的数据
        
        Args:
            socket_obj: 套接字对象
            length: 要接收的数据长度
            
        Returns:
            Optional[bytes]: 接收到的数据，失败返回None
        """
        received_data = b''
        while len(received_data) < length:
            remaining = length - len(received_data)
            chunk_size = min(remaining, self.BUFFER_SIZE)
            chunk = socket_obj.recv(chunk_size)
            
            if not chunk:
                return None
                
            received_data += chunk
        
        return received_data
    
    def send_file(self, socket_obj: socket.socket, file_path: str, 
                  progress_callback: Callable = None, timeout: float = None) -> bool:
        """
        发送文件
        
        Args:
            socket_obj: 套接字对象
            file_path: 文件路径
            progress_callback: 进度回调函数
            timeout: 发送超时时间（秒）
            
        Returns:
            bool: 发送是否成功
        """
        if not os.path.exists(file_path):
            logger.error(f"文件不存在: {file_path}")
            return False
        
        if not os.path.isfile(file_path):
            logger.error(f"路径不是文件: {file_path}")
            return False
        
        try:
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            
            # 文件大小安全检查
            max_file_size = 10 * 1024 * 1024 * 1024  # 10GB
            if file_size > max_file_size:
                logger.error(f"文件过大: {file_size} bytes (最大 {max_file_size} bytes)")
                return False
            
            logger.info(f"开始发送文件: {file_name} ({file_size} bytes)")
            
            # 发送文件信息
            file_info = {
                'type': 'file_info',
                'filename': file_name,
                'filesize': file_size
            }
            
            if not self.send_data(socket_obj, file_info, timeout):
                logger.error("发送文件信息失败")
                return False
            
            # 发送文件内容
            if timeout:
                socket_obj.settimeout(timeout)
                
            sent_bytes = 0
            last_progress_time = time.time()
            
            with open(file_path, 'rb') as f:
                while sent_bytes < file_size:
                    chunk_size = min(self.BUFFER_SIZE, file_size - sent_bytes)
                    chunk = f.read(chunk_size)
                    
                    if not chunk:
                        break
                    
                    socket_obj.sendall(chunk)
                    sent_bytes += len(chunk)
                    
                    # 更新进度（限制回调频率，每0.1秒最多一次）
                    current_time = time.time()
                    if progress_callback and current_time - last_progress_time >= 0.1:
                        progress = int((sent_bytes / file_size) * 100)
                        progress_callback(progress)
                        last_progress_time = current_time
            
            # 确保最后一次进度更新
            if progress_callback:
                progress_callback(100)
            
            logger.info(f"文件发送成功: {file_name}")
            return True
            
        except socket.timeout:
            logger.error(f"发送文件超时: {file_path}")
            return False
        except socket.error as e:
            logger.error(f"发送文件失败: {file_path}, 错误: {str(e)}")
            return False
        except IOError as e:
            logger.error(f"文件操作失败: {file_path}, 错误: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"发送文件异常: {str(e)}", exc_info=True)
            return False
    
    def receive_file(self, socket_obj: socket.socket, save_path: str,
                     progress_callback: Callable = None, timeout: float = None) -> bool:
        """
        接收文件
        
        Args:
            socket_obj: 套接字对象
            save_path: 文件保存路径
            progress_callback: 进度回调函数
            timeout: 接收超时时间（秒）
            
        Returns:
            bool: 接收是否成功
        """
        try:
            # 接收文件信息
            file_info = self.receive_data(socket_obj, timeout)
            if not file_info or file_info.get('type') != 'file_info':
                logger.error("无法获取文件信息")
                return False
            
            file_name = file_info.get('filename', 'unknown')
            file_size = file_info.get('filesize', 0)
            
            logger.info(f"开始接收文件: {file_name} ({file_size} bytes)")
            
            # 文件大小安全检查
            max_file_size = 10 * 1024 * 1024 * 1024  # 10GB
            if file_size > max_file_size:
                logger.error(f"文件过大: {file_size} bytes")
                return False
            
            # 创建文件保存路径
            if os.path.isdir(save_path):
                file_path = os.path.join(save_path, file_name)
            else:
                file_path = save_path
                
            # 确保目录存在
            directory = os.path.dirname(file_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            
            # 接收文件内容
            if timeout:
                socket_obj.settimeout(timeout)
                
            received_bytes = 0
            last_progress_time = time.time()
            
            with open(file_path, 'wb') as f:
                while received_bytes < file_size:
                    remaining = file_size - received_bytes
                    chunk_size = min(self.BUFFER_SIZE, remaining)
                    chunk = socket_obj.recv(chunk_size)
                    
                    if not chunk:
                        logger.error(f"文件接收不完整: {received_bytes}/{file_size} bytes")
                        # 删除不完整的文件
                        try:
                            os.remove(file_path)
                        except:
                            pass
                        return False
                    
                    f.write(chunk)
                    received_bytes += len(chunk)
                    
                    # 更新进度（限制回调频率）
                    current_time = time.time()
                    if progress_callback and current_time - last_progress_time >= 0.1:
                        progress = int((received_bytes / file_size) * 100)
                        progress_callback(progress)
                        last_progress_time = current_time
            
            # 确保最后一次进度更新
            if progress_callback:
                progress_callback(100)
            
            logger.info(f"文件接收成功: {file_name}, 保存路径: {file_path}")
            return True
            
        except socket.timeout:
            logger.error("接收文件超时")
            return False
        except socket.error as e:
            logger.error(f"接收文件失败: {str(e)}")
            return False
        except IOError as e:
            logger.error(f"文件保存失败: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"接收文件异常: {str(e)}", exc_info=True)
            return False
    
    def send_digital_envelope(self, socket_obj: socket.socket, 
                            digital_envelope: Dict[str, Any], 
                            sender_public_key: bytes = None,
                            timeout: float = None) -> bool:
        """
        发送数字信封
        
        Args:
            socket_obj: 套接字对象
            digital_envelope: 数字信封数据
            sender_public_key: 发送方公钥（用于验证签名）
            timeout: 发送超时时间（秒）
            
        Returns:
            bool: 发送是否成功
        """
        try:
            import base64
            
            envelope_data = {
                'type': 'digital_envelope',
                'data': digital_envelope
            }
            
            # 如果提供了发送方公钥，也一起发送
            if sender_public_key:
                envelope_data['sender_public_key'] = base64.b64encode(sender_public_key).decode()
                logger.debug("发送方公钥已包含在数字信封中")
            
            logger.debug("开始发送数字信封...")
            result = self.send_data(socket_obj, envelope_data, timeout)
            
            if result:
                logger.info("数字信封发送成功")
            else:
                logger.error("数字信封发送失败")
                
            return result
            
        except Exception as e:
            logger.error(f"发送数字信封异常: {str(e)}", exc_info=True)
            return False
    
    def receive_digital_envelope(self, socket_obj: socket.socket, 
                               timeout: float = None) -> Tuple[Optional[Dict], Optional[bytes]]:
        """
        接收数字信封
        
        Args:
            socket_obj: 套接字对象
            timeout: 接收超时时间（秒）
            
        Returns:
            Tuple[Optional[Dict], Optional[bytes]]: 
            - 数字信封数据
            - 发送方公钥（如果有）
        """
        try:
            import base64
            
            logger.debug("开始接收数字信封...")
            received_data = self.receive_data(socket_obj, timeout)
            
            if not received_data:
                logger.error("未接收到数据")
                return None, None
                
            if received_data.get('type') != 'digital_envelope':
                logger.error(f"数据类型错误: {received_data.get('type')}")
                return None, None
            
            digital_envelope = received_data.get('data')
            sender_public_key = None
            
            # 如果包含发送方公钥，提取出来
            if 'sender_public_key' in received_data:
                try:
                    sender_public_key = base64.b64decode(received_data['sender_public_key'])
                    logger.debug("成功提取发送方公钥")
                except Exception as e:
                    logger.warning(f"解码发送方公钥失败: {str(e)}")
            
            logger.info("数字信封接收成功")
            return digital_envelope, sender_public_key
            
        except Exception as e:
            logger.error(f"接收数字信封异常: {str(e)}", exc_info=True)
            return None, None
    
    def close_connection(self):
        """快速关闭所有连接（避免阻塞）"""
        # 设置停止事件，通知所有线程退出
        self._stop_event.set()
        
        with self._lock:
            logger.info("开始关闭所有连接...")
            
            # 关闭客户端连接
            if self.client_socket:
                try:
                    # 快速关闭客户端socket
                    self._close_client_socket()
                    logger.debug("客户端socket已关闭")
                except Exception as e:
                    logger.debug(f"关闭客户端连接失败: {str(e)}")
            
            # 关闭服务器socket（打断accept阻塞）
            if self.server_socket:
                try:
                    self.server_socket.close()
                    logger.debug("服务器socket已关闭")
                except Exception as e:
                    logger.debug(f"关闭服务器socket失败: {str(e)}")
                finally:
                    self.server_socket = None
                    self.is_listening = False
        
        # 等待监听线程结束（最多等待0.5秒）
        if self._listen_thread and self._listen_thread.is_alive():
            logger.debug("等待监听线程结束...")
            self._listen_thread.join(timeout=0.5)
            if self._listen_thread.is_alive():
                logger.debug("监听线程仍在运行，将继续后台退出")
        
        logger.info("所有连接已关闭")
    
    @contextmanager
    def connection_context(self, host: str, port: int, use_tls: bool = None):
        """
        连接上下文管理器（用于with语句）
        
        Args:
            host: 服务器主机地址
            port: 服务器端口
            use_tls: 是否使用TLS（None表示使用默认设置）
            
        Yields:
            socket.socket: 连接成功的套接字对象
            
        Example:
            with network.connection_context('127.0.0.1', 5375) as sock:
                network.send_data(sock, {'message': 'hello'})
        """
        original_tls = self.use_tls
        if use_tls is not None:
            self.use_tls = use_tls
            
        try:
            if self.connect_to_server(host, port):
                yield self.client_socket
            else:
                raise NetworkError(f"连接失败: {host}:{port}")
        finally:
            self._close_client_socket()
            self.use_tls = original_tls
    
    def get_local_ip(self) -> str:
        """
        获取本机IP地址
        
        Returns:
            str: 本机IP地址，失败返回127.0.0.1
        """
        try:
            # 尝试连接到公网DNS服务器获取本地IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logger.warning(f"获取本机IP失败: {str(e)}，使用127.0.0.1")
            return "127.0.0.1"
    
    def is_connection_active(self) -> bool:
        """
        检查连接是否活跃
        
        Returns:
            bool: 连接是否活跃
        """
        with self._lock:
            if not self.is_connected or not self.client_socket:
                return False
        
        try:
            # 发送零字节数据包测试连接
            self.client_socket.send(b'')
            return True
        except Exception as e:
            logger.debug(f"连接检查失败: {str(e)}")
            with self._lock:
                self.is_connected = False
            return False
    
    def get_connection_info(self) -> Dict[str, Any]:
        """
        获取连接信息
        
        Returns:
            Dict[str, Any]: 连接信息字典
        """
        with self._lock:
            return {
                'is_listening': self.is_listening,
                'is_connected': self.is_connected,
                'use_tls': self.use_tls,
                'has_server_socket': self.server_socket is not None,
                'has_client_socket': self.client_socket is not None,
                'listen_thread_alive': self._listen_thread.is_alive() if self._listen_thread else False
            }
    
    def __del__(self):
        """析构函数，确保资源释放"""
        try:
            # 析构时使用快速关闭，避免阻塞
            self._stop_event.set()

            # 关闭客户端socket
            if self.client_socket:
                try:
                    self.client_socket.settimeout(0.1)
                    self.client_socket.close()
                except (socket.error, OSError, ValueError):
                    # 关闭时的异常是正常的，忽略
                    pass
                except Exception as e:
                    # 其他异常记录但不影响析构
                    logger.debug(f"析构时关闭客户端socket异常: {str(e)}")
                finally:
                    self.client_socket = None

            # 关闭服务器socket
            if self.server_socket:
                try:
                    self.server_socket.close()
                except (socket.error, OSError, ValueError):
                    # 关闭时的异常是正常的，忽略
                    pass
                except Exception as e:
                    # 其他异常记录但不影响析构
                    logger.debug(f"析构时关闭服务器socket异常: {str(e)}")
                finally:
                    self.server_socket = None
        except Exception:
            # 析构函数中不应该抛出异常
            pass
    
    def reset(self):
        """重置网络工具状态"""
        logger.debug("重置网络工具状态")
        self._stop_event.clear()
        with self._lock:
            self.is_listening = False
            self.is_connected = False