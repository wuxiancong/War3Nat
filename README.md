# War3Nat

War3Nat 是一个专为《魔兽争霸 III》P2P 连接设计的 STUN 服务器，基于 C++ 和 Qt 框架开发，用于 NAT 类型检测和公网地址发现。
```bash
客户端A (内网) → War3Nat STUN服务器 (公网IP:3478) ← 客户端B (内网)
        ↓                               ↓
   发现公网地址                     发现公网地址  
        ↓                               ↓
客户端A (公网IP:端口) ←--------→ 客户端B (公网IP:端口)
             直接P2P连接
```

# 功能特性

- 完整的 STUN 协议支持 (RFC 5389)

- NAT 类型检测 - 支持完全锥形、限制锥形、端口限制、对称型 NAT 检测

- 公网地址发现 - 准确获取客户端的公网映射地址

- 高性能 UDP 处理 - 异步非阻塞网络通信

- 双服务器协同检测 - 支持多服务器协同进行准确的 NAT 类型分析

- 跨平台支持 - Windows、Linux、macOS

# 快速安装

## Ubuntu 系统

```bash
# 1. 安装依赖
sudo apt update
sudo apt install -y build-essential cmake
sudo apt install qtbase5-dev qt5-qmake libqt5core5a libqt5network5

# 2. 克隆项目
git clone https://github.com/wuxiancong/War3Nat.git
cd War3Nat

# 3. 编译安装
mkdir build && cd build
cmake ..
make -j$(nproc)

# 4. 测试运行
./war3nat --help

# 5. 重新编译
cd /root/War3Nat/build
rm -rf *
cd ~
cd War3Nat
rm -rf *

```
# 系统服务配置
## 创建系统用户
```bash
sudo useradd -r -s /bin/false -d /opt/war3nat war3nat
```
## 创建目录
```bash
sudo mkdir -p /var/log/war3nat /etc/war3nat
sudo chown -R war3nat:war3nat /var/log/war3nat
```
## 配置服务
war3nat.service:
sudo nano /etc/systemd/system/war3nat.service
```bash
[Unit]
Description=War3Nat Warcraft III Proxy
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/War3Nat/build
ExecStart=/root/War3Nat/build/war3nat -p 6112
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable war3nat
sudo systemctl start war3nat
sudo systemctl stop war3nat
```
# 配置文件
/etc/war3nat/war3nat.ini:
```bash
[server]
port=3478
force_port_reuse=false
max_connections=1000
bind_address=0.0.0.0

[log]
level=info
enable_console=true
log_file=/var/log/war3nat/war3nat.log
max_size=10485760
backup_count=5

[stun]
protocol_version=5389
max_request_size=1024
response_timeout=5000

[security]
enable_whitelist=false
max_requests_per_minute=1000
```

# 使用方法
```bash
# 命令行运行
# 杀死所有包含 war3nat 的进程
pkill -f war3nat
# 停止服务
sudo systemctl stop war3nat
# 启动服务
sudo systemctl start war3nat
# 查看状态
sudo systemctl status war3nat
# 查看日志
sudo journalctl -u war3nat -f
```
```bash
# 查看所有 war3nat 进程
ps aux | grep war3nat

# 杀死所有 war3nat 进程
pkill -f war3nat

# 查看 3478 端口是否被监听
netstat -tulpn | grep 3478

# 或者使用 ss 命令
ss -tulpn | grep 3478

# 查看 UDP 端口
ss -ulpn | grep 3478

```

# 防火墙
```bash
# Ubuntu UFW
sudo ufw status
sudo ufw allow 3478/udp
sudo ufw reload

# CentOS Firewalld
sudo firewall-cmd --permanent --add-port=3478/udp
sudo firewall-cmd --reload
sudo firewall-cmd --list-ports

# 检查端口状态
firewall-cmd --query-port=3478/udp

```
# 基本测试
```bash
# 检查 STUN 端口
sudo netstat -tulpn | grep 3478

# 查看 UDP 连接
ss -ulpn | grep 3478
```
# TUN 协议测试
```bash
# 使用 stunclient 测试
sudo apt install stuntman-client
stunclient 127.0.0.1 3478

# 输出示例：
# Binding test: success
# Local address: 192.168.1.100:54321
# Mapped address: 123.45.67.89:54321
# Behavior test: success
# Nat behavior: Endpoint Independent Mapping
# Filtering test: success
# Nat filtering: Endpoint Independent Filtering
```
# 网络流量监控
```bash
# 监控 STUN 流量
sudo tcpdump -i any -n udp port 3478

# 详细数据包分析
sudo tcpdump -i any -n -X udp port 3478
```

# 使用 CMD 验证
```bash
# 查看 3478 端口使用情况
netstat -ano | findstr 3478

# 查看 UDP 端口
netstat -ano -p UDP | findstr 3478

# 测试网络连通性
telnet your-server-ip 3478

# PowerShell 测试
Test-NetConnection your-server-ip -Port 3478 -UDP
```

## Python 测试客户端
```bash
#!/usr/bin/env python3
import socket
import struct
import binascii

def test_stun_server(server_ip='127.0.0.1', port=3478):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    # 创建 STUN Binding Request
    transaction_id = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b'
    stun_request = struct.pack('>HH', 0x0001, 0)  # Binding Request
    stun_request += struct.pack('>I', 0x2112A442)  # Magic Cookie
    stun_request += transaction_id  # Transaction ID
    
    # 发送 STUN 请求
    sock.sendto(stun_request, (server_ip, port))
    print(f"STUN 请求已发送到 {server_ip}:{port}")
    
    try:
        # 接收响应
        response, addr = sock.recvfrom(1024)
        print(f"收到 STUN 响应 from {addr}")
        print(f"响应数据: {binascii.hexlify(response)}")
        
        # 解析响应
        if len(response) >= 20:
            msg_type = struct.unpack('>H', response[0:2])[0]
            if msg_type == 0x0101:  # Binding Response
                print("✅ STUN 服务器响应正常")
                return True
    except socket.timeout:
        print("❌ STUN 请求超时")
    finally:
        sock.close()
    
    return False

if __name__ == "__main__":
    test_stun_server()

```
# 项目结构
```bash
War3Nat/
├── CMakeLists.txt
├── War3Nat.pro
├── include/
│   ├── war3nat.h
│   └── logger.h
├── src/
│   ├── main.cpp
│   ├── war3nat.cpp
│   └── logger.cpp
├── config/
│   ├── war3nat.ini
│   └── war3nat.service
└── bin/
    └── war3nat
```

# 故障排查
```bash
# 调试模式运行
/root/War3Nat/build/war3nat -l debug

# 检查服务状态
sudo systemctl status war3nat

# 查看详细日志
sudo journalctl -u war3nat --no-pager -n 50

# 调试模式运行
./war3nat -l debug -p 6112
```

# 协议支持
## 支持的 STUN 方法
-Binding Request (0x0001) - 绑定请求

- Binding Response (0x0101) - 绑定响应

## 支持的属性
- XOR-MAPPED-ADDRESS (0x0020) - 异或映射地址

- SOFTWARE (0x8022) - 软件标识

- FINGERPRINT (0x8028) - 指纹验证


# NAT 类型检测

- Full Cone NAT - 完全锥形 NAT

- Restricted Cone NAT - 限制锥形 NAT

- Port Restricted Cone NAT - 端口限制锥形 NAT

- Symmetric NAT - 对称型 NAT

# 故障排查
## 常见问题解决
```bash
War3Nat 获取到公网地址后，等待另一个客户端连接
当两个客户端都连接后，War3Nat 交换它们的公网地址
```

## 阶段3: 打洞和通信

```bash
# 端口被占用错误
ERROR: Port 3478 is already in use

# 解决方案：
./war3nat -k -p 3478  # 终止占用进程
./war3nat -f -p 3478  # 强制端口重用

# 权限错误
ERROR: Cannot bind to port 3478: Permission denied

# 解决方案：
sudo setcap 'cap_net_bind_service=+ep' /path/to/war3nat
# 或者使用大于1024的端口
```

# 调试模式
```bash
# 启用详细日志
./war3nat -l debug -p 3478

# 查看详细日志
sudo journalctl -u war3nat --no-pager -n 100

# 实时日志监控
sudo journalctl -u war3nat -f
```
# 性能监控
```bash
# 监控服务器性能
top -p $(pgrep war3nat)

# 监控网络连接
ss -u -a | grep 3478

# 监控内存使用
ps -o pid,ppid,cmd,%mem,%cpu -p $(pgrep war3nat)
```
# 客户端集成示例
## C++ 客户端使用
```bash
#include "NetworkDetector.h"

// 使用 War3Nat 进行 NAT 检测
NetworkDetector& detector = NetworkDetector::instance();

// 连接到自定义 STUN 服务器
detector.startDualServerNATDetection(
    QHostAddress("stun1.yourdomain.com"), 3478,
    QHostAddress("stun2.yourdomain.com"), 3478
);

// 处理检测结果
connect(&detector, &NetworkDetector::dualServerNATTestCompleted,
        [](NetworkDetector::DualServerNATType type) {
    qDebug() << "NAT 类型:" << detector.dualServerNATTypeToString(type);
    qDebug() << "公网地址:" << detector.getPublicAddress() 
             << ":" << detector.getPublicPort();
});
```
# 卸载
```bash
# 停止并禁用服务
sudo systemctl stop war3nat
sudo systemctl disable war3nat

# 移除服务文件
sudo rm /etc/systemd/system/war3nat.service

# 移除应用程序
sudo rm -rf /opt/war3nat

# 移除日志和配置
sudo rm -rf /var/log/war3nat /etc/war3nat

# 移除系统用户
sudo userdel war3nat

# 移除依赖包（如果需要）
sudo apt remove qtbase5-dev qt5-qmake libqt5core5a libqt5network5
sudo apt autoremove
```

# 技术支持
- 文档: War3Nat Wiki

- 问题报告: GitHub Issues

- 版本更新: 查看 Releases 页面获取最新版本

这个 War3Nat STUN 服务器专门为《魔兽争霸 III》的 P2P 联机优化，提供准确的 NAT 类型检测和公网地址发现服务，帮助玩家建立直接的游戏连接。