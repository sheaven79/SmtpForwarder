# SmtpForwarder-内网邮件转发器
![SmtpForwarder](https://github.com/user-attachments/assets/189059ab-a880-43a9-9d0b-85a7bed9af70)

## 项目简介
SMTP 邮件转发器是一个轻量级的邮件转发服务，支持将本地SMTP服务接收到的邮件转发到外部SMTP服务器。适用于部署在内网环境中，接收并通过外部SMTP服务器转发各类监控和设备的告警邮件的场景。

更适合运维人员，用于解决内部网络中无法直接访问外部SMTP服务器的问题，同时兼容各类系统SMTP的配置要求（如：只兼容25端口的老设备、不支持填用户密码的、必须要填用户密码的、填了用户密码必须要启用SSL/TLS加密协议的各类奇葩配置要求）。

## 功能特性
- 支持本地SMTP服务（普通/TLS/SSL）
- 支持转发到外部SMTP服务器（TLS/SSL）
- 灵活的IP白名单控制
- 详细的日志记录（支持日志轮转）
- 邮件队列管理（支持重试机制）
- 集成错误钉钉告警功能
- 简单易用的YAML配置文件
- 支持 SMTP AUTH Plain 认证（启用情况下客户端也能跳过，只是为了兼容某些 SMTP client 强制需要服务端支持 AUTH）

## 快速开始
1. 克隆项目
   ```bash
   git clone https://github.com/sheaven79/SmtpForwarder.git
   cd SmtpForwarder
   ```

2. 复制示例配置文件，并根据实际需求修改
   ```bash
   cp config.yaml.example config.yaml
   ```

3. 编辑配置文件
   根据实际情况修改`config.yaml`文件中的配置项。

4. 下载依赖文件
   ```bash
   go mod download
   ```

5. 运行服务
   ```bash
   go run main.go
   ```

6. 编译后运行
   ```bash
   go build -o ./bin/smtpforwarder -ldflags "-s -w" -a ./main.go
   ./bin/smtpforwarder
   ```

## 配置说明
配置文件采用YAML格式，基本配置如下（详细请看日志注释）：

### 本地SMTP服务配置
```yaml
local:
  port: 25          # 普通SMTP端口
  allowed_ips:      # Client IP白名单
    - "127.0.0.1"
    - "192.168.1.0/24"
  enable_auth: true  # 是否启用SMTP认证
  username: "your-username"  # 认证用户名（仅在enable_auth为true时有效）
  password: "your-password"  # 认证密码（仅在enable_auth为true时有效）
```

### 外部SMTP服务器配置
```yaml
remote:
  host: "smtp.example.com"  # SMTP服务器地址
  port: 465                 # SMTP服务器端口
  use_tls: false            # 是否使用TLS
  use_ssl: true             # 是否使用SSL
  username: "your-username" # 认证用户名
  password: "your-password" # 认证密码
  from: "sender@example.com" # 发件人邮箱，部分邮箱要求 from 和登录的 username 一致
```

## 许可证
MIT License
