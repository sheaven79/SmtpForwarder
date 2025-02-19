package logger

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sheaven79/smtpforwarder/config"
	"github.com/sirupsen/logrus"
)

var (
	log = logrus.New()
	currentLogFile *os.File
	lastRotateTime time.Time
)

// Setup 初始化日志配置
//
// 参数:
//   - cfg: 配置对象，包含日志相关的配置信息
//
// 返回:
//   - error: 错误信息
func Setup(cfg *config.Config) error {
	// 设置日志级别
	level, err := logrus.ParseLevel(cfg.Log.Level)
	if err != nil {
		level = logrus.InfoLevel
		Warn("无效的日志级别 %s，使用默认级别 info", cfg.Log.Level)
	}
	log.SetLevel(level)

	// 设置日志格式，添加更多上下文信息
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:    true,
		TimestampFormat: "2006-01-02 15:04:05.000",
		DisableColors:   true,
	})

	// 根据配置的模式设置日志输出
	if cfg.Log.Mode == "file" {
		// 初始化日志文件
		if err := initLogFile(cfg); err != nil {
			return fmt.Errorf("初始化日志文件失败: %w", err)
		}

		// 启动日志轮转和清理协程
		go rotateAndCleanLogs(cfg)
	} else {
		// stdout模式，使用标准输出
		log.SetOutput(os.Stdout)
	}

	return nil
}

// initLogFile 初始化日志文件，根据配置创建或打开日志文件
//
// 参数:
//   - cfg: 配置对象，包含日志相关的配置信息
//
// 返回:
//   - error: 错误信息
func initLogFile(cfg *config.Config) error {
	// 如果配置了日志目录，则使用按天分割的日志文件
	if cfg.Log.Dir != "" {
		// 检查日志目录是否存在
		if _, err := os.Stat(cfg.Log.Dir); os.IsNotExist(err) {
			// 目录不存在时创建
			if err := os.MkdirAll(cfg.Log.Dir, 0755); err != nil {
				return fmt.Errorf("创建日志目录失败: %w", err)
			}
		} else if err != nil {
			return fmt.Errorf("检查日志目录状态失败: %w", err)
		}

		// 打开当天的日志文件
		fileName := time.Now().Format("2006-01-02") + ".log"
		filePath := filepath.Join(cfg.Log.Dir, fileName)
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("无法打开日志文件: %w", err)
		}

		// 关闭之前的日志文件
		if currentLogFile != nil {
			currentLogFile.Close()
		}

		currentLogFile = file
		log.SetOutput(file)
		lastRotateTime = time.Now()
		Info("已切换到新的日志文件: %s", filePath)
	} else if cfg.Log.File != "" {
		// 如果只配置了单个日志文件
		file, err := os.OpenFile(cfg.Log.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("无法打开日志文件: %w", err)
		}
		log.SetOutput(file)
		Info("已打开日志文件: %s", cfg.Log.File)
	}

	return nil
}

// rotateAndCleanLogs 执行日志轮转和清理操作
//
// 参数:
//   - cfg: 配置对象，包含日志相关的配置信息
func rotateAndCleanLogs(cfg *config.Config) {
	if cfg.Log.Dir == "" {
		return
	}

	// 更改检查间隔为15分钟
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// 检查是否需要轮转日志（判断是否跨天）
		currentDay := time.Now().Format("2006-01-02")
		lastRotateDay := lastRotateTime.Format("2006-01-02")
		
		if currentDay != lastRotateDay {
			if err := initLogFile(cfg); err != nil {
				Error(cfg, "轮转日志文件失败: %v", err)
				continue
			}
			Info("完成日志轮转操作")
		}

		// 清理过期日志
		if cfg.Log.RetentionDays > 0 {
			cleanExpiredLogs(cfg)
		}
	}
}

// cleanExpiredLogs 清理过期日志文件
func cleanExpiredLogs(cfg *config.Config) {
	files, err := os.ReadDir(cfg.Log.Dir)
	if err != nil {
		Error(cfg, "读取日志目录失败: %v", err)
		return
	}

	expireTime := time.Now().AddDate(0, 0, -cfg.Log.RetentionDays)
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".log") {
			// 从文件名解析日期
			fileDate, err := time.Parse("2006-01-02.log", file.Name())
			if err != nil {
				continue
			}

			// 删除过期日志文件
			if fileDate.Before(expireTime) {
				filePath := filepath.Join(cfg.Log.Dir, file.Name())
				if err := os.Remove(filePath); err != nil {
					Error(cfg, "删除过期日志文件失败: %v", err)
				} else {
					Info("已删除过期日志文件: %s", filePath)
				}
			}
		}
	}
}

// Debug 输出调试日志
func Debug(format string, args ...interface{}) {
	log.Debugf(format, args...)
}

// Info 输出信息日志
func Info(format string, args ...interface{}) {
	log.Infof(format, args...)
}

// Warn 输出警告日志
func Warn(format string, args ...interface{}) {
	log.Warnf(format, args...)
}

// Error 输出错误日志并发送钉钉告警
func Error(cfg *config.Config, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Errorf("%s", msg)

	// 发送钉钉告警
	if cfg != nil && cfg.DingTalk.Webhook != "" {
		go sendDingTalkAlert(cfg, msg)
	}
}

// sendDingTalkAlert 发送钉钉告警
func sendDingTalkAlert(cfg *config.Config, msg string) {
	// 生成签名
	timestamp := time.Now().UnixMilli()
	sign := ""
	if cfg.DingTalk.Secret != "" {
		strToSign := fmt.Sprintf("%d\n%s", timestamp, cfg.DingTalk.Secret)
		h := hmac.New(sha256.New, []byte(cfg.DingTalk.Secret))
		h.Write([]byte(strToSign))
		sign = base64.StdEncoding.EncodeToString(h.Sum(nil))
	}

	// 构造请求URL
	webhookURL := cfg.DingTalk.Webhook
	if sign != "" {
		webhookURL = fmt.Sprintf("%s&timestamp=%d&sign=%s", cfg.DingTalk.Webhook, timestamp, url.QueryEscape(sign))
	}

	// 构造请求体
	body := map[string]interface{}{
		"msgtype": "text",
		"text": map[string]string{
			"content": fmt.Sprintf("SMTP转发服务告警:\n%s", msg),
		},
	}

	// 发送请求
	jsonBody, _ := json.Marshal(body)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Errorf("发送钉钉告警失败: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorf("钉钉告警发送失败，状态码: %d", resp.StatusCode)
	}
}
