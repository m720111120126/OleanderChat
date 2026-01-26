# Oleander Chat

Oleander Chat 是一个基于 IPv6 的加密即时通讯应用程序，专注于提供安全、私密的端到端加密通信体验。

## 项目特点

- **端到端加密**：使用 ECC+AES-256-GCM 混合加密算法，确保消息安全传输
- **基于 IPv6**：利用 IPv6 协议实现点对点通信，减少对中心化服务器的依赖
- **用户身份验证**：采用基于密钥对的用户身份验证机制
- **安全的消息签名**：使用 SHA256 哈希和 PKCS1.5 签名确保消息完整性和真实性
- **友好的图形界面**：基于 Tkinter 和 ttkbootstrap 构建的现代化用户界面
- **好友管理**：支持添加、删除好友及本地好友列表管理

## 项目结构

```
OleanderChat/
├── app/                    # 客户端应用目录
│   ├── addressBook/        # 好友信息存储目录
│   ├── output/             # 临时文件输出目录
│   ├── build.bat           # Windows下的打包脚本文件
│   ├── connect.py          # 连接模块
│   ├── icon.ico            # 应用图标文件
│   ├── main.py             # 主程序文件
│   ├── user.py             # 用户管理和加密功能模块
│   └── VersionInfo.txt     # 版本信息文件
├── server/                 # 服务器端脚本
│   ├── id_allocator.php    # 用户ID分配服务
│   ├── ipv6_allocator.php  # IPv6地址注册服务
│   └── ipv6_query.php      # IPv6地址查询服务
├── LICENSE                 # 项目许可证文件
└── README.md               # 项目说明文档
```

## 技术栈

- **客户端**：Python 3.x （仅验证Python3.7及3.12版本）
  - Tkinter/ttkbootstrap - 图形用户界面
  - PyCryptoDome - 加密库
  - socket - 网络通信
  - threading - 多线程处理
  - queue - 线程间通信
- **服务器端**：PHP + MySQL （仅验证PHP-7.4和MySQL5.6.51版本）
  - 提供用户ID分配
  - 管理IPv6地址注册和查询

## 核心功能

### 用户系统
- **用户注册**：创建新用户时生成ECC密钥对，分配唯一用户ID
- **用户登录**：通过密码解密本地存储的用户凭证
- **身份验证**：使用公钥/私钥对进行身份验证和消息签名

### 消息系统
- **加密消息传输**：使用接收方公钥加密消息
- **消息签名**：使用发送方私钥对消息进行签名
- **签名验证**：接收方验证消息签名确保消息完整性和真实性
- **聊天记录**：本地存储聊天记录

### 网络通信
- **IPv6地址管理**：自动获取并注册本地IPv6地址
- **点对点连接**：基于IPv6的直接消息传输
- **服务器辅助**：使用服务器进行用户ID分配和IPv6地址解析

### 好友管理
- **添加好友**：通过导入好友的公共信息文件添加好友
- **删除好友**：从好友列表中移除好友
- **好友列表**：本地维护好友信息

## 安装与配置

### 客户端要求

- Python 3.X （仅验证Python3.7及3.12版本）
- 以下Python库：
  - pycrypto/pycryptodome
  - pyzipper
  - ttkbootstrap
  - tkinter (通常随Python安装)
- （可选）如果您自己搭建了服务器，请将`https://oleanderchat.asia` 替换为您的服务器地址

### 安装依赖

```bash
pip install pycryptodome pyzipper ttkbootstrap
```

### 服务器配置

1. 将 `server/` 目录下的PHP文件部署到支持PHP的Web服务器
2. 创建MySQL数据库并配置以下表：
   - `id_sequence` 表：用于ID分配，包含 `id` 字段自动递增
   - `ipv6_records` 表：包含 `uuid` 和 `ipv6_address` 字段
3. 修改PHP文件中的数据库连接参数

创建表时建议使用：
  ```sql
  USE 你的数据库名称;

  CREATE TABLE id_sequence (
    id INT AUTO_INCREMENT PRIMARY KEY
  );

  INSERT INTO ids (last_allocated_id) VALUES (0);

  CREATE TABLE ipv6_records (
    uuid CHAR(36) PRIMARY KEY,
    ipv6_address VARCHAR(45) NOT NULL
);
```

## 使用说明

### 首次使用

1. 确保您的系统已配置IPv6网络
2. 运行主程序：
   ```bash
   python app/main.py
   ```
3. 首次运行会提示创建新用户，输入用户名和密码
4. 系统会生成用户密钥对并在服务器注册
5. 应用会创建 `user.zip` 文件存储加密的用户凭证

### 添加好友

1. 从好友处获取其 `me.zip` 文件
2. 在应用中右键点击好友列表区域，选择"加好友"
3. 选择好友的 `me.zip` 文件导入
4. 好友将出现在您的好友列表中

### 发送消息

1. 在好友列表中选择一个好友
2. 在消息输入框中输入消息（最多128字符）
3. 点击"发送"按钮或按Enter键发送消息

### 注意事项

- 确保双方都在线且网络连接正常
- 首次使用需要服务器连接以注册用户ID和IPv6地址（仅用于获取其它用户IPv6地址）
- 好友添加需要对方的公开信息文件（`me.zip`）
- 如果您的修改可以兼容原版OleanderChat，务必允许用户自主选择服务器（包括自建服务器和官方服务器）。
- 如果您的修改无法兼容原版OleanderChat，请务必使用您自己搭建的服务器
- 在中国使用本软件需遵守中国法律法规，禁止用于非法用途

## 安全性

- **加密存储**：用户凭证使用AES加密存储在本地
- **端到端加密**：消息在发送前使用接收方公钥加密
- **身份验证**：通过密钥对和数字签名验证用户身份
- **防止篡改**：消息签名确保消息在传输过程中未被篡改

## 许可证

本项目采用Apache License Version 2.0开源协议

## 贡献

欢迎对本项目进行贡献，包括功能改进、Bug修复和文档完善。
        