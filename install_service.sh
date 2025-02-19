#!/bin/bash

# 检查是否以root权限运行
if [ "$(id -u)" != "0" ]; then
    echo "此脚本需要root权限运行"
    exit 1
fi

# 设置变量
APP_NAME="smtpforwarder"
APP_DIR="/opt/${APP_NAME}"
BIN_DIR="/opt/${APP_NAME}"
CONFIG_DIR="/opt/${APP_NAME}"
SERVICE_FILE="/lib/systemd/system/${APP_NAME}.service"

# 创建必要的目录
mkdir -p "${APP_DIR}"
mkdir -p "${CONFIG_DIR}"
mkdir -p "${APP_DIR}/cert"
mkdir -p "${APP_DIR}/data"
mkdir -p "${APP_DIR}/logs"

# 复制应用程序文件
cp -f "./bin/${APP_NAME}" "${APP_DIR}/"
chmod +x "${APP_DIR}/${APP_NAME}"

# 复制配置文件
if [ ! -f "${CONFIG_DIR}/config.yaml" ]; then
    cp -f "config.yaml.example" "${CONFIG_DIR}/config.yaml"
fi

# 创建systemd服务单元文件
cat > "${SERVICE_FILE}" << EOL
[Unit]
Description=SMTP Forwarder Service
After=network.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/${APP_NAME} -config ${CONFIG_DIR}/config.yaml
WorkingDirectory=${APP_DIR}

[Install]
WantedBy=multi-user.target
EOL

# 设置权限
chmod 644 "${SERVICE_FILE}"
chmod 755 "${APP_DIR}/data"
chmod 755 "${APP_DIR}/logs"

# 重新加载systemd配置
systemctl daemon-reload

# 启用并启动服务
systemctl enable "${APP_NAME}"
systemctl start "${APP_NAME}"

echo "安装完成！"
echo "服务状态："
systemctl status "${APP_NAME}"

echo "
使用以下命令管理服务："
echo "启动服务：systemctl start ${APP_NAME}"
echo "停止服务：systemctl stop ${APP_NAME}"
echo "重启服务：systemctl restart ${APP_NAME}"
echo "查看状态：systemctl status ${APP_NAME}"
echo "查看日志：journalctl -u ${APP_NAME}"