package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 表示应用程序的配置结构
type Config struct {
	// 本地SMTP服务配置
	Local struct {
		// 普通SMTP端口，默认25
		Port int `yaml:"port"`
		// TLS端口，默认587
		TLSPort int `yaml:"tls_port"`
		// SSL端口，默认465
		SSLPort int `yaml:"ssl_port"`
		// TLS证书文件路径
		CertFile string `yaml:"cert_file"`
		// TLS密钥文件路径
		KeyFile string `yaml:"key_file"`
		// IP白名单，支持IP或CIDR格式
		AllowedIPs []string `yaml:"allowed_ips"`
		// 是否启用认证
		EnableAuth bool `yaml:"enable_auth"`
		// 认证用户名
		Username string `yaml:"username"`
		// 认证密码
		Password string `yaml:"password"`
	} `yaml:"local"`

	// 外部SMTP配置
	Remote struct {
		// SMTP服务器地址
		Host string `yaml:"host"`
		// SMTP服务器端口
		Port int `yaml:"port"`
		// 是否使用TLS
		UseTLS bool `yaml:"use_tls"`
		// 是否使用SSL
		UseSSL bool `yaml:"use_ssl"`
		// 认证用户名
		Username string `yaml:"username"`
		// 认证密码
		Password string `yaml:"password"`
		// 发件人邮箱
		From string `yaml:"from"`
	} `yaml:"remote"`

	// 钉钉告警配置
	DingTalk struct {
		// Webhook地址
		Webhook string `yaml:"webhook"`
		// 安全密钥
		Secret string `yaml:"secret"`
	} `yaml:"dingtalk"`

	// 日志配置
	Log struct {
		// 日志级别：debug, info, warn, error
		Level string `yaml:"level"`
		// 日志输出模式：file, stdout
		Mode string `yaml:"mode"`
		// 日志文件路径
		File string `yaml:"file"`
		// 日志目录，用于存放按天分割的日志文件
		Dir string `yaml:"dir"`
		// 日志保留天数，默认7天
		RetentionDays int `yaml:"retention_days"`
	} `yaml:"log"`

	// 邮件队列配置
	Queue struct {
		// 队列存储目录
		Dir string `yaml:"dir"`
		// 重试间隔时间（秒）
		RetryInterval int `yaml:"retry_interval"`
		// 最大重试次数
		MaxRetries int `yaml:"max_retries"`
		// 失败邮件存储目录
		FailedQueueDir string `yaml:"failed_queue_dir"`
	} `yaml:"queue"`
}

// LoadConfig 从YAML文件加载配置，并设置默认值
//
// 参数:
//   - file: 配置文件路径
//
// 返回:
//   - *Config: 配置对象指针
//   - error: 错误信息
func LoadConfig(file string) (*Config, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 设置默认值
	config.setDefaults()

	// 验证配置
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}

	return &config, nil
}

// setDefaults 设置配置默认值
func (c *Config) setDefaults() {
	if c.Local.Port == 0 {
		c.Local.Port = 25
	}
	if c.Local.TLSPort == 0 {
		c.Local.TLSPort = 587
	}
	if c.Local.SSLPort == 0 {
		c.Local.SSLPort = 465
	}
	if c.Queue.RetryInterval == 0 {
		c.Queue.RetryInterval = 300 // 默认5分钟
	}
	if c.Queue.MaxRetries == 0 {
		c.Queue.MaxRetries = 3 // 默认3次重试
	}
	if c.Queue.FailedQueueDir == "" {
		c.Queue.FailedQueueDir = "data/failed_queue" // 默认失败队列目录
	}
	if c.Log.RetentionDays == 0 {
		c.Log.RetentionDays = 7 // 默认保留7天
	}
}

// validate 验证配置是否合法
func (c *Config) validate() error {
	// 验证本地SMTP配置
	if c.Local.Port < 1 || c.Local.Port > 65535 {
		return fmt.Errorf("无效的SMTP端口: %d", c.Local.Port)
	}
	if c.Local.TLSPort < 1 || c.Local.TLSPort > 65535 {
		return fmt.Errorf("无效的TLS端口: %d", c.Local.TLSPort)
	}
	if c.Local.SSLPort < 1 || c.Local.SSLPort > 65535 {
		return fmt.Errorf("无效的SSL端口: %d", c.Local.SSLPort)
	}

	// 验证TLS证书配置
	if (c.Local.CertFile != "" && c.Local.KeyFile == "") || (c.Local.CertFile == "" && c.Local.KeyFile != "") {
		return fmt.Errorf("TLS证书和密钥必须同时配置")
	}

	// 验证远程SMTP配置
	if c.Remote.Host == "" {
		return fmt.Errorf("远程SMTP服务器地址不能为空")
	}
	if c.Remote.Port < 1 || c.Remote.Port > 65535 {
		return fmt.Errorf("无效的远程SMTP端口: %d", c.Remote.Port)
	}
	if c.Remote.UseTLS && c.Remote.UseSSL {
		return fmt.Errorf("TLS和SSL不能同时启用")
	}
	if c.Remote.From == "" {
		return fmt.Errorf("发件人邮箱不能为空")
	}

	// 验证日志配置
	if c.Log.Level != "debug" && c.Log.Level != "info" && c.Log.Level != "warn" && c.Log.Level != "error" {
		return fmt.Errorf("无效的日志级别: %s", c.Log.Level)
	}
	if c.Log.Mode != "file" && c.Log.Mode != "stdout" {
		return fmt.Errorf("无效的日志输出模式: %s", c.Log.Mode)
	}

	return nil
}

// IsIPAllowed 检查IP是否在白名单中
func (c *Config) IsIPAllowed(ipStr string) bool {
	if len(c.Local.AllowedIPs) == 0 {
		return true
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, allowed := range c.Local.AllowedIPs {
		if strings.Contains(allowed, "/") {
			_, ipnet, err := net.ParseCIDR(allowed)
			if err == nil && ipnet.Contains(ip) {
				return true
			}
		} else if allowed == ipStr {
			return true
		}
	}

	return false
}
