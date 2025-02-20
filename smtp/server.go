package smtp

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"
	"github.com/sheaven79/smtpforwarder/config"
	"github.com/sheaven79/smtpforwarder/logger"
	"github.com/sheaven79/smtpforwarder/queue"
)

// Server SMTP服务器
type Server struct {
	cfg   *config.Config
	queue *queue.Queue
}

// Session SMTP会话
type Session struct {
	server     *Server
	from       string
	to         []string
	clientIP   string
	serverPort int // 新增服务器端口字段
}

// NewSession 创建新的SMTP会话
func (s *Server) NewSession(state *gosmtp.Conn) (gosmtp.Session, error) {
	serverPort := 0
	if state.Conn().LocalAddr().Network() == "tcp" {
		_, portStr, err := net.SplitHostPort(state.Conn().LocalAddr().String())
		if err == nil {
			fmt.Sscan(portStr, &serverPort)
		}
	}
	// 获取客户端地址并分离IP和端口
	remoteAddr := state.Conn().RemoteAddr().String()
	clientIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		logger.Error(s.cfg, "解析客户端IP失败: %v", err)
		return nil, fmt.Errorf("解析客户端IP失败: %v", err)
	}

	// 记录连接日志并验证IP白名单
	isAllowed := s.cfg.IsIPAllowed(clientIP)
	logger.Info("服务器端口: %d 收到SMTP连接请求，客户端IP: %s，IP白名单验证: %v", serverPort, clientIP, isAllowed)

	// 如果IP不在白名单中，直接返回错误
	if !isAllowed {
		logger.Warn("IP %s 不在白名单中，拒绝访问", clientIP)
		return nil, fmt.Errorf("IP不在白名单中")
	}

	return &Session{server: s, clientIP: clientIP, serverPort: serverPort}, nil
}

// AuthMechanisms 返回支持的认证机制列表。
// 如果启用了本地认证（EnableAuth 为 true），则返回 PLAIN 认证机制。
// 否则，返回 nil，表示不支持认证。
func (s *Session) AuthMechanisms() []string {
	if s.server.cfg.Local.EnableAuth {
		return []string{sasl.Plain}
	}
	return nil
}

// Auth 处理客户端认证请求。
// 如果未启用认证，返回一个虚拟的 sasl.Server，该服务器将拒绝所有认证尝试。
// 如果启用了认证，且 mech 为 "PLAIN"，则使用提供的用户名和密码进行认证。
// 如果用户名和密码与配置中的不匹配，则认证失败。
// 如果 mech 不是 "PLAIN"，则返回“不支持的认证方式”错误。
func (s *Session) Auth(mech string) (sasl.Server, error) {
	// 如果未启用认证，直接返回一个虚拟的 sasl.Server
	if !s.server.cfg.Local.EnableAuth {
		return sasl.NewPlainServer(func(identity, username, password string) error {
			return fmt.Errorf("authentication is disabled")
		}), nil
	}
	switch mech {
	case "PLAIN":
		// 验证用户名和密码
		return sasl.NewPlainServer(func(identity, username, password string) error {
			if username != s.server.cfg.Local.Username || password != s.server.cfg.Local.Password {
				logger.Warn("SMTP认证失败，用户名或密码错误，客户端IP: %s", s.clientIP)
				return fmt.Errorf("authentication failed")
			}
			logger.Info("SMTP认证成功，客户端IP: %s，用户名: %s", s.clientIP, username)
			return nil
		}), nil
	default:
		// 其他认证方式
		logger.Warn("不支持的认证方式: %s", mech)
		return nil, fmt.Errorf("不支持的认证方式: %s", mech)
	}
}

// NewServer 创建SMTP服务器
//
// 参数:
//   - cfg: 配置对象，包含SMTP服务器配置信息
//   - q: 邮件队列对象
//
// 返回:
//   - *Server: 服务器对象指针
func NewServer(cfg *config.Config, q *queue.Queue) *Server {
	return &Server{
		cfg:   cfg,
		queue: q,
	}
}

// Start 启动SMTP服务
//
// 返回:
//   - error: 错误信息
func (s *Server) Start() error {
	// 创建普通SMTP服务器
	if err := s.startServer(s.cfg.Local.Port, nil); err != nil {
		return fmt.Errorf("启动普通SMTP服务失败: %v", err)
	}

	// 创建 TLS 和 SSL 服务器（如果已配置）
	if s.cfg.Local.CertFile != "" && s.cfg.Local.KeyFile != "" {
		tlsConfig, err := s.loadTLSConfig()
		if err != nil {
			return fmt.Errorf("加载TLS配置失败: %v", err)
		}

		// 启动TLS服务器
		if err := s.startServer(s.cfg.Local.TLSPort, tlsConfig); err != nil {
			return fmt.Errorf("启动TLS SMTP服务失败: %v", err)
		}

		// 启动SSL服务器
		if err := s.startServer(s.cfg.Local.SSLPort, tlsConfig); err != nil {
			return fmt.Errorf("启动SSL SMTP服务失败: %v", err)
		}
	}

	return nil
}

// startServer 启动指定端口的SMTP服务器
//
// 参数:
//   - port: 监听端口
//   - tlsConfig: TLS配置，如果为nil则启动普通SMTP服务
//
// 返回:
//   - error: 错误信息
func (s *Server) startServer(port int, tlsConfig *tls.Config) error {
	// 创建SMTP服务器
	server := gosmtp.NewServer(s)

	// 设置服务器配置
	server.Domain = "localhost"
	server.AllowInsecureAuth = true
	server.TLSConfig = tlsConfig
	server.Addr = fmt.Sprintf(":%d", port)

	// 启动服务器
	go func() {
		switch port {
		case s.cfg.Local.SSLPort:
			logger.Info("启动 SSL SMTP 服务，监听端口: %d", port)
			if err := server.ListenAndServeTLS(); err != nil {
				logger.Error(s.cfg, "SSL SMTP 服务异常: %v", err)
			}
		case s.cfg.Local.TLSPort:
			logger.Info("启动 TLS SMTP 服务，监听端口: %d", port)
			if err := server.ListenAndServe(); err != nil {
				logger.Error(s.cfg, "TLS SMTP 服务异常: %v", err)
			}
		default:
			logger.Info("启动普通SMTP服务，监听端口: %d", port)
			if err := server.ListenAndServe(); err != nil {
				logger.Error(s.cfg, "普通SMTP服务异常: %v", err)
			}
		}
	}()

	return nil
}

// loadTLSConfig 加载TLS配置
func (s *Server) loadTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(s.cfg.Local.CertFile, s.cfg.Local.KeyFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// Mail 处理MAIL FROM命令
func (s *Session) Mail(from string, opts *gosmtp.MailOptions) error {
	// 记录发件人信息
	s.from = from
	return nil
}

// Rcpt 处理RCPT TO命令
func (s *Session) Rcpt(to string, opts *gosmtp.RcptOptions) error {
	// 记录收件人信息
	s.to = append(s.to, to)
	return nil
}

// Data 处理邮件数据
func (s *Session) Data(r io.Reader) error {
	// 读取邮件数据
	data, err := io.ReadAll(r)
	if err != nil {
		logger.Error(s.server.cfg, "读取邮件数据失败: %v", err)
		return err
	}

	// 创建邮件对象
	mail := &queue.Mail{
		From:    s.server.cfg.Remote.From, // 使用配置的发件人
		To:      s.to,
		Subject: "转发邮件", // 实际主题会从邮件数据中解析
	}

	// 从邮件数据中解析主题
	subject := ""
	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("Subject: ")) {
			subject = string(bytes.TrimPrefix(line, []byte("Subject: ")))
			mail.Subject = subject

			// 解码主题
			d := mime.WordDecoder{}
			decodedSubject, err := d.DecodeHeader(subject)
			if err == nil {
				subject = decodedSubject
			}
			break
		}
	}

	// 记录收到邮件的日志
	logger.Debug("收到邮件，客户端IP: %s，发件人：%v，收件人: %v，主题: %s", s.clientIP, s.from, s.to, subject)

	// 将邮件加入队列
	if err := s.server.queue.Push(mail); err != nil {
		logger.Error(s.server.cfg, "邮件加入队列失败: %v", err)
		return err
	}

	// 保存邮件数据
	if err := s.server.queue.SaveMailData(mail.ID, data); err != nil {
		logger.Error(s.server.cfg, "保存邮件数据失败: %v", err)
		return err
	}

	// 异步转发邮件
	go func() {
		if err := s.server.forwardMail(mail, data); err != nil {
			logger.Error(s.server.cfg, "转发邮件失败: %v", err)
		}
	}()

	return nil
}

// Reset 重置会话状态
func (s *Session) Reset() {
	s.from = ""
	s.to = nil
}

// Logout 处理登出
func (s *Session) Logout() error {
	return nil
}

// forwardMail 转发邮件到外部SMTP服务器
func (s *Server) forwardMail(mail *queue.Mail, data []byte) error {
	// 最大重试次数
	maxRetries := s.cfg.Queue.MaxRetries
	// 重试间隔
	retryInterval := time.Duration(s.cfg.Queue.RetryInterval) * time.Second

	// 定义发送邮件的内部函数
	attemptSend := func() error {
		var client *gosmtp.Client
		var err error

		// 初始化 TLS 配置
		tlsConfig := &tls.Config{
			ServerName:         s.cfg.Remote.Host,
			InsecureSkipVerify: true,
		}

		// 根据配置选择连接方式
		if s.cfg.Remote.UseSSL {
			logger.Debug("使用SSL模式连接SMTP服务器: %s:%d", s.cfg.Remote.Host, s.cfg.Remote.Port)
			client, err = gosmtp.DialTLS(fmt.Sprintf("%s:%d", s.cfg.Remote.Host, s.cfg.Remote.Port), tlsConfig)
			if err != nil {
				logger.Error(s.cfg, "SSL连接外部SMTP服务器失败: %v", err)
				return err
			}
		} else if s.cfg.Remote.UseTLS {
			logger.Debug("使用TLS模式连接SMTP服务器: %s:%d", s.cfg.Remote.Host, s.cfg.Remote.Port)
			client, err = gosmtp.DialStartTLS(fmt.Sprintf("%s:%d", s.cfg.Remote.Host, s.cfg.Remote.Port), tlsConfig)
			if err != nil {
				logger.Error(s.cfg, "TLS连接外部SMTP服务器失败: %v", err)
				return err
			}
		} else {
			logger.Debug("使用普通模式连接SMTP服务器: %s:%d", s.cfg.Remote.Host, s.cfg.Remote.Port)
			client, err = gosmtp.Dial(fmt.Sprintf("%s:%d", s.cfg.Remote.Host, s.cfg.Remote.Port))
			if err != nil {
				logger.Error(s.cfg, "连接外部SMTP服务器失败: %v", err)
				return err
			}
		}
		defer client.Close()

		// 登录认证
		if s.cfg.Remote.Username != "" {
			auth := sasl.NewPlainClient("", s.cfg.Remote.Username, s.cfg.Remote.Password)
			if err := client.Auth(auth); err != nil {
				logger.Error(s.cfg, "SMTP认证失败: %v", err)
				return err
			}
		}

		// 发送邮件
		reader := bytes.NewReader(data)
		if err := client.SendMail(s.cfg.Remote.From, mail.To, reader); err != nil {
			logger.Error(s.cfg, "发送邮件失败: %v", err)
			return err
		}

		return nil
	}

	// 重试循环
	for {
		// 尝试发送邮件
		err := attemptSend()
		if err == nil {
			// 发送成功，删除邮件
			logger.Info("邮件转发成功，ID: %s", mail.ID)
			if err := s.queue.Remove(mail.ID); err != nil {
				return fmt.Errorf("删除邮件失败: %v", err)
			}
			return nil
		}

		// 更新重试次数
		mail.RetryAttempts++
		mail.LastRetryTime = time.Now()
		mail.Status = "failed"

		// 检查是否达到最大重试次数
		if mail.RetryAttempts >= maxRetries {
			// 移动到失败队列的逻辑
			dataDir := filepath.Join(s.cfg.Queue.FailedQueueDir, mail.ID)
			if err := os.MkdirAll(dataDir, 0755); err != nil {
				return fmt.Errorf("创建失败队列目录失败: %v", err)
			}

			dataFile := filepath.Join(dataDir, "data.eml")
			if err := os.WriteFile(dataFile, data, 0644); err != nil {
				return fmt.Errorf("保存邮件数据到失败队列失败: %v", err)
			}

			metaFile := filepath.Join(dataDir, "meta.json")
			metaData, err := json.Marshal(mail)
			if err != nil {
				return fmt.Errorf("序列化邮件元数据失败: %v", err)
			}
			if err := os.WriteFile(metaFile, metaData, 0644); err != nil {
				return fmt.Errorf("保存邮件元数据到失败队列失败: %v", err)
			}

			// 从原始队列中删除邮件
			if err := s.queue.Remove(mail.ID); err != nil {
				return fmt.Errorf("从原始队列删除邮件失败: %v", err)
			}

			logger.Info("邮件重试次数已达上限，已移动到失败队列目录，ID: %s", mail.ID)
			return nil
		}

		// 等待重试间隔
		time.Sleep(retryInterval)
		continue
	}
}
