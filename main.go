// Package main 实现了一个SMTP邮件转发服务器，用于接收本地SMTP请求并转发到远程SMTP服务器。
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sheaven79/smtpforwarder/config"
	"github.com/sheaven79/smtpforwarder/logger"
	"github.com/sheaven79/smtpforwarder/queue"
	"github.com/sheaven79/smtpforwarder/smtp"
)

var (
	configFile string
)

// init 初始化命令行参数
func init() {
	flag.StringVar(&configFile, "config", "config.yaml", "配置文件路径")
}

// main 程序入口函数，负责初始化配置、启动服务并处理退出信号
func main() {
	// 解析命令行参数
	flag.Parse()

	// 加载配置文件
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		fmt.Printf("加载配置文件失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志
	if err := logger.Setup(cfg); err != nil {
		fmt.Printf("初始化日志失败: %v\n", err)
		os.Exit(1)
	}

	// 创建邮件队列
	q, err := queue.NewQueue(cfg)
	if err != nil {
		logger.Error(cfg, "创建邮件队列失败: %v", err)
		os.Exit(1)
	}

	// 创建SMTP服务器
	server := smtp.NewServer(cfg, q)

	// 启动SMTP服务
	if err := server.Start(); err != nil {
		logger.Error(cfg, "启动SMTP服务失败: %v", err)
		os.Exit(1)
	}

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	logger.Info("收到信号 %v，正在关闭服务...", sig)
}
