package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"gotunnel/pkg/crypto"
	"gotunnel/pkg/proto"
)

const (
	tunnelChunkSize = 16 * 1024
)

type logLevel int

const (
	levelDebug logLevel = iota
	levelInfo
	levelWarn
	levelError
)

var (
	currentLogLevel = levelInfo
	tunnelBufPool   = sync.Pool{New: func() any { return make([]byte, tunnelChunkSize) }}
)

func parseLogLevel(s string) (logLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return levelDebug, nil
	case "info":
		return levelInfo, nil
	case "warn":
		return levelWarn, nil
	case "error":
		return levelError, nil
	default:
		return levelInfo, fmt.Errorf("无效日志级别: %s", s)
	}
}

func logf(level logLevel, format string, args ...interface{}) {
	if level < currentLogLevel {
		return
	}
	prefix := "[INFO] "
	switch level {
	case levelDebug:
		prefix = "[DEBUG] "
	case levelWarn:
		prefix = "[WARN] "
	case levelError:
		prefix = "[ERROR] "
	}
	log.Printf(prefix+format, args...)
}

func configureTCPConn(conn net.Conn) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(30 * time.Second)
}

type TunnelSpec struct {
	Name       string
	LocalAddr  string
	RemotePort int
}

type Client struct {
	serverAddr string
	token      string
	key        []byte
	tunnels    []TunnelSpec
	authLabel  string
	ctrlLabel  string
	s2cLabel   string
	c2sLabel   string

	idleTimeout time.Duration
	dataSem     chan struct{}
}

func NewClient(serverAddr, token string, kdfSalt []byte, authLabel, ctrlLabel, s2cLabel, c2sLabel string, tunnels []TunnelSpec, maxDataConns int, idleTimeout time.Duration) *Client {
	return &Client{
		serverAddr:  serverAddr,
		token:       token,
		key:         crypto.KeyFromPassword(token, kdfSalt),
		tunnels:     tunnels,
		authLabel:   authLabel,
		ctrlLabel:   ctrlLabel,
		s2cLabel:    s2cLabel,
		c2sLabel:    c2sLabel,
		idleTimeout: idleTimeout,
		dataSem:     make(chan struct{}, maxDataConns),
	}
}

func (c *Client) Run() {
	for {
		logf(levelInfo, "[client] 连接服务端 %s ...", c.serverAddr)
		if err := c.connect(); err != nil {
			logf(levelWarn, "[client] 连接失败: %v，5秒后重试", err)
		}
		time.Sleep(5 * time.Second)
	}
}

func (c *Client) connect() error {
	conn, err := net.DialTimeout("tcp", c.serverAddr, 10*time.Second)
	if err != nil {
		return err
	}
	configureTCPConn(conn)
	eConn, err := crypto.NewEncryptedConn(conn, crypto.DeriveControlKey(c.key, c.ctrlLabel))
	if err != nil {
		_ = conn.Close()
		return err
	}

	nonce, err := readChallenge(eConn, 10*time.Second)
	if err != nil {
		_ = eConn.Close()
		return fmt.Errorf("读取 Challenge 失败: %w", err)
	}

	tunnels := make([]proto.TunnelConfig, 0, len(c.tunnels))
	for _, t := range c.tunnels {
		tunnels = append(tunnels, proto.TunnelConfig{
			Name: t.Name, LocalAddr: t.LocalAddr, RemotePort: t.RemotePort,
		})
	}

	payload := proto.HelloAuthPayload{Type: proto.TypeHello, Nonce: nonce, Tunnels: tunnels}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		_ = eConn.Close()
		return fmt.Errorf("marshal hello payload: %w", err)
	}
	mac := crypto.HMACSHA256(crypto.DeriveHMACKey(c.key, c.authLabel), payloadBytes)
	hello := proto.Hello{
		Type: proto.TypeHello, Nonce: nonce, Tunnels: tunnels,
		Auth: base64.StdEncoding.EncodeToString(mac),
	}
	helloBytes, err := json.Marshal(hello)
	if err != nil {
		_ = eConn.Close()
		return fmt.Errorf("marshal hello: %w", err)
	}
	if err := eConn.WriteMsg(helloBytes); err != nil {
		_ = eConn.Close()
		return fmt.Errorf("发送 Hello 失败: %w", err)
	}

	_ = eConn.Conn().SetReadDeadline(time.Now().Add(10 * time.Second))
	data, err := eConn.ReadMsg()
	if err != nil {
		_ = eConn.Close()
		return fmt.Errorf("读取 HelloAck 失败: %w", err)
	}
	_ = eConn.Conn().SetReadDeadline(time.Time{})

	var ack proto.HelloAck
	if err := json.Unmarshal(data, &ack); err != nil {
		_ = eConn.Close()
		return fmt.Errorf("解析 HelloAck 失败: %w", err)
	}
	if ack.Status != "ok" {
		_ = eConn.Close()
		return fmt.Errorf("服务端拒绝: %s", ack.Message)
	}
	logf(levelInfo, "[client] 连接成功，隧道已就绪")

	go c.heartbeat(eConn)
	return c.controlLoop(eConn)
}

func (c *Client) controlLoop(eConn *crypto.EncryptedConn) error {
	defer eConn.Close()
	for {
		_ = eConn.Conn().SetReadDeadline(time.Now().Add(90 * time.Second))
		data, err := eConn.ReadMsg()
		if err != nil {
			return fmt.Errorf("控制连接断开: %w", err)
		}
		_ = eConn.Conn().SetReadDeadline(time.Time{})

		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		switch msg["type"] {
		case proto.TypeNewConn:
			var nc proto.NewConn
			if err := json.Unmarshal(data, &nc); err != nil {
				continue
			}
			go c.handleNewConn(nc)
		}
	}
}

func (c *Client) handleNewConn(nc proto.NewConn) {
	select {
	case c.dataSem <- struct{}{}:
		defer func() { <-c.dataSem }()
	default:
		logf(levelWarn, "[client] 活跃数据连接已达上限(%d)，丢弃 connID=%s", cap(c.dataSem), nc.ConnID)
		return
	}

	localAddr := ""
	for _, t := range c.tunnels {
		if t.RemotePort == nc.RemotePort {
			localAddr = t.LocalAddr
			break
		}
	}
	if localAddr == "" {
		logf(levelWarn, "[client] 未找到端口 %d 对应的本地地址", nc.RemotePort)
		return
	}

	dataConn, err := net.DialTimeout("tcp", c.serverAddr, 10*time.Second)
	if err != nil {
		logf(levelWarn, "[client] 数据连接失败: %v", err)
		return
	}
	configureTCPConn(dataConn)
	eDataConn, err := crypto.NewEncryptedConn(dataConn, crypto.DeriveControlKey(c.key, c.ctrlLabel))
	if err != nil {
		_ = dataConn.Close()
		return
	}

	nonce, err := readChallenge(eDataConn, 10*time.Second)
	if err != nil {
		_ = eDataConn.Close()
		return
	}
	payload := proto.ConnReadyAuthPayload{Type: proto.TypeConnReady, Nonce: nonce, ConnID: nc.ConnID}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		_ = eDataConn.Close()
		return
	}
	mac := crypto.HMACSHA256(crypto.DeriveHMACKey(c.key, c.authLabel), payloadBytes)
	ready := proto.ConnReady{
		Type: proto.TypeConnReady, ConnID: nc.ConnID, Nonce: nonce,
		Auth: base64.StdEncoding.EncodeToString(mac),
	}
	readyBytes, err := json.Marshal(ready)
	if err != nil {
		_ = eDataConn.Close()
		return
	}
	if err := eDataConn.WriteMsg(readyBytes); err != nil {
		_ = eDataConn.Close()
		return
	}
	logf(levelDebug, "[client] 数据连接就绪 connID=%s 转发 -> %s", nc.ConnID, localAddr)

	localConn, err := net.DialTimeout("tcp", localAddr, 10*time.Second)
	if err != nil {
		logf(levelWarn, "[client] 连接本地服务 %s 失败: %v", localAddr, err)
		_ = eDataConn.Close()
		return
	}
	configureTCPConn(localConn)
	proxyDecrypt(localConn, eDataConn.Conn(), c.key, nc.ConnID, c.s2cLabel, c.c2sLabel, c.idleTimeout)
}

// proxyDecrypt 读取服务端握手发来的 nonce base，然后双向 AEAD 分块转发。
// 服务端：nonceBaseSend -> 客户端解密；nonceBaseRecv -> 客户端加密
func proxyDecrypt(local net.Conn, remote net.Conn, key []byte, connID string, s2cLabel, c2sLabel string, idleTimeout time.Duration) {
	defer local.Close()
	defer remote.Close()

	nonceBuf := make([]byte, 24)
	_ = remote.SetReadDeadline(time.Now().Add(idleTimeout))
	if _, err := io.ReadFull(remote, nonceBuf); err != nil {
		return
	}
	nonceBaseDec := nonceBuf[:12]
	nonceBaseEnc := nonceBuf[12:]

	decKey := crypto.DeriveAES128Key(key, nonceBaseDec, s2cLabel)
	encKey := crypto.DeriveAES128Key(key, nonceBaseEnc, c2sLabel)
	decAEAD, err := crypto.NewAESGCM128(decKey)
	if err != nil {
		return
	}
	encAEAD, err := crypto.NewAESGCM128(encKey)
	if err != nil {
		return
	}

	aadDec := []byte("s2c:" + connID)
	aadEnc := []byte("c2s:" + connID)

	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		defer tryCloseWrite(local)

		maxFrameLen := tunnelChunkSize + decAEAD.Overhead()
		cipherBuf := make([]byte, maxFrameLen)
		plainBuf := make([]byte, 0, tunnelChunkSize)

		var counter uint64
		var lenBuf [2]byte
		for {
			_ = remote.SetReadDeadline(time.Now().Add(idleTimeout))
			if _, err := io.ReadFull(remote, lenBuf[:]); err != nil {
				return
			}
			frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))
			if frameLen < decAEAD.Overhead() || frameLen > maxFrameLen {
				return
			}
			_ = remote.SetReadDeadline(time.Now().Add(idleTimeout))
			if _, err := io.ReadFull(remote, cipherBuf[:frameLen]); err != nil {
				return
			}
			nonce, nerr := crypto.GCMNonceFromBase(nonceBaseDec, counter)
			if nerr != nil {
				return
			}
			counter++
			plaintext, derr := decAEAD.Open(plainBuf[:0], nonce, cipherBuf[:frameLen], aadDec)
			if derr != nil {
				return
			}
			_ = local.SetWriteDeadline(time.Now().Add(idleTimeout))
			if werr := crypto.WriteFull(local, plaintext); werr != nil {
				return
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		defer tryCloseWrite(remote)

		buf := tunnelBufPool.Get().([]byte)
		defer tunnelBufPool.Put(buf)

		sealBuf := make([]byte, 0, tunnelChunkSize+encAEAD.Overhead())
		var counter uint64
		var lenBuf [2]byte
		for {
			_ = local.SetReadDeadline(time.Now().Add(idleTimeout))
			n, err := local.Read(buf)
			if n > 0 {
				nonce, nerr := crypto.GCMNonceFromBase(nonceBaseEnc, counter)
				if nerr != nil {
					return
				}
				counter++
				ciphertext := encAEAD.Seal(sealBuf[:0], nonce, buf[:n], aadEnc)
				binary.BigEndian.PutUint16(lenBuf[:], uint16(len(ciphertext)))
				_ = remote.SetWriteDeadline(time.Now().Add(idleTimeout))
				if werr := crypto.WriteFull(remote, lenBuf[:]); werr != nil {
					return
				}
				_ = remote.SetWriteDeadline(time.Now().Add(idleTimeout))
				if werr := crypto.WriteFull(remote, ciphertext); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
	<-done
}

func tryCloseWrite(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

func (c *Client) heartbeat(eConn *crypto.EncryptedConn) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		msg, _ := json.Marshal(proto.Heartbeat{Type: proto.TypeHeartbeat})
		if err := eConn.WriteMsg(msg); err != nil {
			return
		}
	}
}

func readChallenge(eConn *crypto.EncryptedConn, timeout time.Duration) (string, error) {
	_ = eConn.Conn().SetReadDeadline(time.Now().Add(timeout))
	data, err := eConn.ReadMsg()
	if err != nil {
		return "", err
	}
	_ = eConn.Conn().SetReadDeadline(time.Time{})

	var ch proto.Challenge
	if err := json.Unmarshal(data, &ch); err != nil {
		return "", err
	}
	if ch.Type != proto.TypeChallenge || ch.Nonce == "" {
		return "", fmt.Errorf("invalid challenge")
	}
	return ch.Nonce, nil
}

func parseTunnels(specs []string) ([]TunnelSpec, error) {
	var tunnels []TunnelSpec
	for _, spec := range specs {
		parts := strings.SplitN(spec, ":", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("格式错误 %q，应为 name:host:localPort:remotePort", spec)
		}
		localAddr := parts[1] + ":" + parts[2]
		var remotePort int
		fmt.Sscanf(parts[3], "%d", &remotePort)
		if remotePort == 0 {
			return nil, fmt.Errorf("无效的远程端口: %s", parts[3])
		}
		tunnels = append(tunnels, TunnelSpec{Name: parts[0], LocalAddr: localAddr, RemotePort: remotePort})
	}
	return tunnels, nil
}

func main() {
	serverAddr := flag.String("server", "127.0.0.1:7000", "服务端地址 host:port")
	token := flag.String("token", "mysecret", "认证 token（需与服务端一致）")
	kdfSaltHex := flag.String("kdf-salt", crypto.KDFSaltHexDefault, "KDF salt (hex，客户端/服务端必须一致)")
	authLabel := flag.String("auth-label", crypto.AuthLabelDefault, "HMAC label（客户端/服务端必须一致）")
	ctrlLabel := flag.String("control-label", crypto.ControlLabelDefault, "控制通道 label（客户端/服务端必须一致）")
	s2cLabel := flag.String("data-s2c-label", crypto.DataLabelS2CDefault, "数据通道 s2c label（客户端/服务端必须一致）")
	c2sLabel := flag.String("data-c2s-label", crypto.DataLabelC2SDefault, "数据通道 c2s label（客户端/服务端必须一致）")
	logLevelFlag := flag.String("log-level", "info", "日志级别: debug|info|warn|error")
	maxDataConns := flag.Int("max-data-conns", 512, "客户端活跃数据连接上限")
	idleTimeout := flag.Duration("idle-timeout", 2*time.Minute, "数据连接空闲读写超时")
	flag.Parse()

	if *maxDataConns <= 0 {
		log.Fatal("max-data-conns 必须大于 0")
	}
	if *idleTimeout <= 0 {
		log.Fatal("idle-timeout 必须大于 0")
	}

	lvl, err := parseLogLevel(*logLevelFlag)
	if err != nil {
		log.Fatalf("日志级别错误: %v", err)
	}
	currentLogLevel = lvl

	salt, err := hex.DecodeString(strings.TrimSpace(*kdfSaltHex))
	if err != nil || len(salt) == 0 {
		log.Fatalf("kdf-salt 必须是有效 hex 且非空: %v", err)
	}

	specs := flag.Args()
	if len(specs) == 0 {
		log.Fatal("请指定至少一个隧道，格式: name:host:localPort:remotePort\n示例: web:127.0.0.1:8080:8080")
	}
	tunnels, err := parseTunnels(specs)
	if err != nil {
		log.Fatalf("解析隧道失败: %v", err)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	logf(levelInfo, "[client] GoTunnel 客户端启动，服务端: %s", *serverAddr)
	for _, t := range tunnels {
		logf(levelInfo, "[client] 隧道 [%s]: 本地 %s <-- 公网 :%d", t.Name, t.LocalAddr, t.RemotePort)
	}
	NewClient(*serverAddr, *token, salt, *authLabel, *ctrlLabel, *s2cLabel, *c2sLabel, tunnels, *maxDataConns, *idleTimeout).Run()
}
