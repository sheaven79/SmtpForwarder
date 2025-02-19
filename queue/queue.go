// Package queue 提供了邮件队列的管理功能，包括邮件的入队、出队、重试和失败处理。
package queue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sheaven79/smtpforwarder/config"
	"github.com/sheaven79/smtpforwarder/logger"
)

// Mail 表示一封待发送的邮件
type Mail struct {
	// 邮件ID
	ID string `json:"id"`
	// 发件人
	From string `json:"from"`
	// 收件人列表
	To []string `json:"to"`
	// 抄送列表
	Cc []string `json:"cc"`
	// 密送列表
	Bcc []string `json:"bcc"`
	// 主题
	Subject string `json:"subject"`
	// 创建时间
	CreateTime time.Time `json:"create_time"`
	// 邮件数据文件路径
	DataFile string `json:"data_file"`
	// 重试次数
	RetryAttempts int `json:"retry_attempts"`
	// 上次重试时间
	LastRetryTime time.Time `json:"last_retry_time"`
	// 邮件状态: queued, failed
	Status string `json:"status"`
}

// Queue 表示邮件队列
type Queue struct {
	// 队列目录
	dir string
	// 配置信息
	cfg *config.Config
}

// NewQueue 创建一个新的邮件队列
//
// 参数:
//   - cfg: 配置对象，包含队列相关的配置信息
//
// 返回:
//   - *Queue: 队列对象指针
//   - error: 错误信息
func NewQueue(cfg *config.Config) (*Queue, error) {
	// 检查队列目录是否存在
	if _, err := os.Stat(cfg.Queue.Dir); os.IsNotExist(err) {
		// 目录不存在时创建
		if err := os.MkdirAll(cfg.Queue.Dir, 0755); err != nil {
			return nil, fmt.Errorf("创建队列目录失败: %v", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("检查队列目录失败: %v", err)
	}

	return &Queue{
		dir: cfg.Queue.Dir,
		cfg: cfg,
	}, nil
}

// Push 将一封邮件加入队列
//
// 参数:
//   - mail: 待入队的邮件对象
//
// 返回:
//   - error: 错误信息
func (q *Queue) Push(mail *Mail) error {
	// 生成邮件ID
	mail.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	mail.CreateTime = time.Now()
	// 初始化重试相关字段
	mail.RetryAttempts = 0
	mail.LastRetryTime = time.Time{}
	mail.Status = "queued"

	// 创建邮件目录
	mailDir := filepath.Join(q.dir, mail.ID)
	if err := os.MkdirAll(mailDir, 0755); err != nil {
		return fmt.Errorf("创建邮件目录失败: %v", err)
	}

	// 保存邮件元数据
	metaFile := filepath.Join(mailDir, "meta.json")
	metaData, err := json.Marshal(mail)
	if err != nil {
		return fmt.Errorf("序列化邮件元数据失败: %v", err)
	}

	if err := os.WriteFile(metaFile, metaData, 0644); err != nil {
		return fmt.Errorf("保存邮件元数据失败: %v", err)
	}

	logger.Info("邮件已加入队列，ID: %s", mail.ID)
	return nil
}

// Remove 从队列中删除一封邮件
//
// 参数:
//   - id: 邮件ID
//
// 返回:
//   - error: 错误信息
func (q *Queue) Remove(id string) error {
	mailDir := filepath.Join(q.dir, id)
	if err := os.RemoveAll(mailDir); err != nil {
		return fmt.Errorf("删除邮件目录失败: %v", err)
	}

	logger.Info("邮件已从队列中删除，ID: %s", id)
	return nil
}

// SaveMailData 保存邮件数据
func (q *Queue) SaveMailData(id string, data []byte) error {
	dataFile := filepath.Join(q.dir, id, "data.eml")
	if err := os.WriteFile(dataFile, data, 0644); err != nil {
		return fmt.Errorf("保存邮件数据失败: %v", err)
	}
	return nil
}

// LoadMailData 加载邮件数据
func (q *Queue) LoadMailData(id string) ([]byte, error) {
	dataFile := filepath.Join(q.dir, id, "data.eml")
	data, err := os.ReadFile(dataFile)
	if err != nil {
		return nil, fmt.Errorf("读取邮件数据失败: %v", err)
	}
	return data, nil
}
