package main

import (
	"crypto/rand"
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
	"sync/atomic"
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

type pendingConn struct {
	conn      net.Conn
	createdAt time.Time
	session   *controlSession
}

type controlSession struct {
	ctrl *crypto.EncryptedConn

	writeMu    sync.Mutex
	listenerMu sync.Mutex
	listeners  []net.Listener
	closeOnce  sync.Once
}

func newControlSession(ctrl *crypto.EncryptedConn) *controlSession {
	return &controlSession{ctrl: ctrl}
}

func (cs *controlSession) WriteMsg(data []byte) error {
	cs.writeMu.Lock()
	defer cs.writeMu.Unlock()
	return cs.ctrl.WriteMsg(data)
}

func (cs *controlSession) addListener(ln net.Listener) {
	cs.listenerMu.Lock()
	defer cs.listenerMu.Unlock()
	cs.listeners = append(cs.listeners, ln)
}

func (cs *controlSession) Close() {
	cs.closeOnce.Do(func() {
		cs.listenerMu.Lock()
		listeners := cs.listeners
		cs.listeners = nil
		cs.listenerMu.Unlock()

		for _, ln := range listeners {
			_ = ln.Close()
		}
		_ = cs.ctrl.Close()
	})
}

type Server struct {
	bindAddr           string
	controlPort        int
	token              string
	key                []byte
	authLabel          string
	ctrlLabel          string
	s2cLabel           string
	c2sLabel           string
	pendingTTL         time.Duration
	idleTimeout        time.Duration
	maxPendingConns    int
	maxActiveDataConns int

	mu              sync.Mutex
	pendingConns    map[string]*pendingConn
	activeDataConns atomic.Int64
}

func NewServer(bindAddr string, controlPort int, token string, kdfSalt []byte, authLabel, ctrlLabel, s2cLabel, c2sLabel string, maxPendingConns, maxActiveDataConns int, pendingTTL, idleTimeout time.Duration) *Server {
	return &Server{
		bindAddr:           bindAddr,
		controlPort:        controlPort,
		token:              token,
		key:                crypto.KeyFromPassword(token, kdfSalt),
		authLabel:          authLabel,
		ctrlLabel:          ctrlLabel,
		s2cLabel:           s2cLabel,
		c2sLabel:           c2sLabel,
		pendingTTL:         pendingTTL,
		idleTimeout:        idleTimeout,
		maxPendingConns:    maxPendingConns,
		maxActiveDataConns: maxActiveDataConns,
		pendingConns:       make(map[string]*pendingConn),
	}
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.bindAddr, s.controlPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("监听控制端口失败: %w", err)
	}
	logf(levelInfo, "[server] 控制端口监听: %s", addr)
	go s.cleanupPendingConns()
	for {
		conn, err := ln.Accept()
		if err != nil {
			logf(levelWarn, "[server] Accept 错误: %v", err)
			continue
		}
		configureTCPConn(conn)
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	eConn, err := crypto.NewEncryptedConn(conn, crypto.DeriveControlKey(s.key, s.ctrlLabel))
	if err != nil {
		_ = conn.Close()
		return
	}
	challenge, err := s.sendChallenge(eConn, 10*time.Second)
	if err != nil {
		_ = eConn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	data, err := eConn.ReadMsg()
	if err != nil {
		_ = eConn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	var msg map[string]interface{}
	if err := json.Unmarshal(data, &msg); err != nil {
		_ = eConn.Close()
		return
	}
	switch msg["type"] {
	case proto.TypeHello:
		s.handleControlConn(eConn, data, challenge)
	case proto.TypeConnReady:
		s.handleDataConn(eConn, data, challenge)
	default:
		logf(levelWarn, "[server] 未知消息类型: %v", msg["type"])
		_ = eConn.Close()
	}
}

func (s *Server) handleControlConn(eConn *crypto.EncryptedConn, firstMsg []byte, challenge string) {
	remoteAddr := eConn.Conn().RemoteAddr()
	logf(levelInfo, "[server] 新控制连接: %s", remoteAddr)
	session := newControlSession(eConn)

	var hello proto.Hello
	if err := json.Unmarshal(firstMsg, &hello); err != nil {
		session.Close()
		return
	}
	if err := s.verifyHelloAuth(&hello, challenge); err != nil {
		ack, _ := json.Marshal(proto.HelloAck{Type: proto.TypeHelloAck, Status: "error", Message: "auth 失败"})
		_ = session.WriteMsg(ack)
		session.Close()
		logf(levelWarn, "[server] %s auth 失败: %v", remoteAddr, err)
		return
	}
	ack, _ := json.Marshal(proto.HelloAck{Type: proto.TypeHelloAck, Status: "ok"})
	if err := session.WriteMsg(ack); err != nil {
		session.Close()
		return
	}
	logf(levelInfo, "[server] %s 认证成功，隧道数: %d", remoteAddr, len(hello.Tunnels))

	for _, t := range hello.Tunnels {
		go s.listenPublic(session, t)
	}
	s.controlLoop(session)
}

func (s *Server) listenPublic(session *controlSession, tunnel proto.TunnelConfig) {
	addr := fmt.Sprintf("%s:%d", s.bindAddr, tunnel.RemotePort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logf(levelError, "[server] 无法监听端口 %d: %v", tunnel.RemotePort, err)
		return
	}
	session.addListener(ln)
	defer ln.Close()
	logf(levelInfo, "[server] 隧道 [%s]: 公网 :%d --> 客户端 %s", tunnel.Name, tunnel.RemotePort, tunnel.LocalAddr)

	for {
		extConn, err := ln.Accept()
		if err != nil {
			return
		}
		configureTCPConn(extConn)

		connID := genID()
		now := time.Now()

		s.mu.Lock()
		if len(s.pendingConns) >= s.maxPendingConns {
			s.mu.Unlock()
			logf(levelWarn, "[server] pending 连接已达上限(%d)，拒绝来自 %s 的连接", s.maxPendingConns, extConn.RemoteAddr())
			_ = extConn.Close()
			continue
		}
		s.pendingConns[connID] = &pendingConn{conn: extConn, createdAt: now}
		s.pendingConns[connID].session = session
		s.mu.Unlock()

		logf(levelDebug, "[server] 外部连接 connID=%s port=%d from=%s", connID, tunnel.RemotePort, extConn.RemoteAddr())
		msg, _ := json.Marshal(proto.NewConn{Type: proto.TypeNewConn, ConnID: connID, RemotePort: tunnel.RemotePort})
		if err := session.WriteMsg(msg); err != nil {
			logf(levelWarn, "[server] 发送 NewConn 失败: %v", err)
			_ = extConn.Close()
			s.mu.Lock()
			delete(s.pendingConns, connID)
			s.mu.Unlock()
			return
		}
	}
}

func (s *Server) handleDataConn(eConn *crypto.EncryptedConn, firstMsg []byte, challenge string) {
	var ready proto.ConnReady
	if err := json.Unmarshal(firstMsg, &ready); err != nil {
		_ = eConn.Close()
		return
	}
	if err := s.verifyConnReadyAuth(&ready, challenge); err != nil {
		logf(levelWarn, "[server] 数据连接 auth 失败: %v", err)
		_ = eConn.Close()
		return
	}
	s.mu.Lock()
	pc, ok := s.pendingConns[ready.ConnID]
	if ok {
		delete(s.pendingConns, ready.ConnID)
	}
	s.mu.Unlock()

	if !ok {
		logf(levelWarn, "[server] 未找到 connID=%s", ready.ConnID)
		_ = eConn.Close()
		return
	}

	active := s.activeDataConns.Add(1)
	if int(active) > s.maxActiveDataConns {
		s.activeDataConns.Add(-1)
		logf(levelWarn, "[server] 活跃数据连接已达上限(%d)，丢弃 connID=%s", s.maxActiveDataConns, ready.ConnID)
		_ = pc.conn.Close()
		_ = eConn.Close()
		return
	}

	logf(levelDebug, "[server] 数据连接就绪 connID=%s active=%d", ready.ConnID, active)
	go func() {
		defer s.activeDataConns.Add(-1)
		proxyWithEncryption(pc.conn, eConn.Conn(), s.key, ready.ConnID, s.s2cLabel, s.c2sLabel, s.idleTimeout)
	}()
}

func (s *Server) controlLoop(session *controlSession) {
	defer session.Close()
	defer s.cleanupSessionPendingConns(session)
	for {
		_ = session.ctrl.Conn().SetReadDeadline(time.Now().Add(90 * time.Second))
		data, err := session.ctrl.ReadMsg()
		if err != nil {
			logf(levelInfo, "[server] 控制连接断开: %v", err)
			return
		}
		var msg map[string]string
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg["type"] == proto.TypeHeartbeat {
			resp, _ := json.Marshal(proto.Heartbeat{Type: proto.TypeHeartbeatAck})
			if err := session.WriteMsg(resp); err != nil {
				return
			}
		}
	}
}

func (s *Server) sendChallenge(eConn *crypto.EncryptedConn, timeout time.Duration) (string, error) {
	nonce, err := crypto.NewRandomBytes(32)
	if err != nil {
		return "", err
	}
	ch := proto.Challenge{Type: proto.TypeChallenge, Nonce: base64.StdEncoding.EncodeToString(nonce)}
	data, err := json.Marshal(ch)
	if err != nil {
		return "", err
	}
	_ = eConn.Conn().SetWriteDeadline(time.Now().Add(timeout))
	if err := eConn.WriteMsg(data); err != nil {
		return "", err
	}
	_ = eConn.Conn().SetWriteDeadline(time.Time{})
	return ch.Nonce, nil
}

func (s *Server) verifyHelloAuth(hello *proto.Hello, challenge string) error {
	if hello.Type != proto.TypeHello {
		return fmt.Errorf("type mismatch")
	}
	if hello.Nonce != challenge {
		return fmt.Errorf("nonce mismatch")
	}
	authBytes, err := base64.StdEncoding.DecodeString(hello.Auth)
	if err != nil {
		return fmt.Errorf("invalid auth")
	}
	payload := proto.HelloAuthPayload{Type: proto.TypeHello, Nonce: hello.Nonce, Tunnels: hello.Tunnels}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	key := crypto.DeriveHMACKey(s.key, s.authLabel)
	if !crypto.VerifyHMACSHA256(key, payloadBytes, authBytes) {
		return fmt.Errorf("auth mismatch")
	}
	return nil
}

func (s *Server) verifyConnReadyAuth(ready *proto.ConnReady, challenge string) error {
	if ready.Type != proto.TypeConnReady {
		return fmt.Errorf("type mismatch")
	}
	if ready.Nonce != challenge {
		return fmt.Errorf("nonce mismatch")
	}
	authBytes, err := base64.StdEncoding.DecodeString(ready.Auth)
	if err != nil {
		return fmt.Errorf("invalid auth")
	}
	payload := proto.ConnReadyAuthPayload{Type: proto.TypeConnReady, Nonce: ready.Nonce, ConnID: ready.ConnID}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	key := crypto.DeriveHMACKey(s.key, s.authLabel)
	if !crypto.VerifyHMACSHA256(key, payloadBytes, authBytes) {
		return fmt.Errorf("auth mismatch")
	}
	return nil
}

func (s *Server) cleanupSessionPendingConns(session *controlSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, pc := range s.pendingConns {
		if pc.session != session {
			continue
		}
		_ = pc.conn.Close()
		delete(s.pendingConns, id)
		logf(levelDebug, "[server] 清理控制连接断开遗留 connID=%s", id)
	}
}

// proxyWithEncryption 外部连接（明文）<-> 数据连接（AES-128-GCM 分块加密）
// 握手：服务端先写 nonceBaseSend(12B)+nonceBaseRecv(12B)
func proxyWithEncryption(plain net.Conn, encrypted net.Conn, key []byte, connID string, s2cLabel, c2sLabel string, idleTimeout time.Duration) {
	defer plain.Close()
	defer encrypted.Close()

	nonceBaseSend, err := crypto.NewRandomBytes(12)
	if err != nil {
		return
	}
	nonceBaseRecv, err := crypto.NewRandomBytes(12)
	if err != nil {
		return
	}
	_ = encrypted.SetWriteDeadline(time.Now().Add(idleTimeout))
	if err := crypto.WriteFull(encrypted, nonceBaseSend); err != nil {
		return
	}
	_ = encrypted.SetWriteDeadline(time.Now().Add(idleTimeout))
	if err := crypto.WriteFull(encrypted, nonceBaseRecv); err != nil {
		return
	}

	sendKey := crypto.DeriveAES128Key(key, nonceBaseSend, s2cLabel)
	recvKey := crypto.DeriveAES128Key(key, nonceBaseRecv, c2sLabel)
	sendAEAD, err := crypto.NewAESGCM128(sendKey)
	if err != nil {
		return
	}
	recvAEAD, err := crypto.NewAESGCM128(recvKey)
	if err != nil {
		return
	}

	aadSend := []byte("s2c:" + connID)
	aadRecv := []byte("c2s:" + connID)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer tryCloseWrite(encrypted)

		buf := tunnelBufPool.Get().([]byte)
		defer tunnelBufPool.Put(buf)

		sealBuf := make([]byte, 0, tunnelChunkSize+sendAEAD.Overhead())
		var counter uint64
		var lenBuf [2]byte
		for {
			_ = plain.SetReadDeadline(time.Now().Add(idleTimeout))
			n, err := plain.Read(buf)
			if n > 0 {
				nonce, nerr := crypto.GCMNonceFromBase(nonceBaseSend, counter)
				if nerr != nil {
					return
				}
				counter++
				ciphertext := sendAEAD.Seal(sealBuf[:0], nonce, buf[:n], aadSend)
				binary.BigEndian.PutUint16(lenBuf[:], uint16(len(ciphertext)))
				_ = encrypted.SetWriteDeadline(time.Now().Add(idleTimeout))
				if werr := crypto.WriteFull(encrypted, lenBuf[:]); werr != nil {
					return
				}
				_ = encrypted.SetWriteDeadline(time.Now().Add(idleTimeout))
				if werr := crypto.WriteFull(encrypted, ciphertext); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer tryCloseWrite(plain)

		maxFrameLen := tunnelChunkSize + recvAEAD.Overhead()
		cipherBuf := make([]byte, maxFrameLen)
		plainBuf := make([]byte, 0, tunnelChunkSize)

		var counter uint64
		var lenBuf [2]byte
		for {
			_ = encrypted.SetReadDeadline(time.Now().Add(idleTimeout))
			if _, err := io.ReadFull(encrypted, lenBuf[:]); err != nil {
				return
			}
			frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))
			if frameLen < recvAEAD.Overhead() || frameLen > maxFrameLen {
				return
			}
			_ = encrypted.SetReadDeadline(time.Now().Add(idleTimeout))
			if _, err := io.ReadFull(encrypted, cipherBuf[:frameLen]); err != nil {
				return
			}
			nonce, nerr := crypto.GCMNonceFromBase(nonceBaseRecv, counter)
			if nerr != nil {
				return
			}
			counter++
			plaintext, derr := recvAEAD.Open(plainBuf[:0], nonce, cipherBuf[:frameLen], aadRecv)
			if derr != nil {
				return
			}
			_ = plain.SetWriteDeadline(time.Now().Add(idleTimeout))
			if werr := crypto.WriteFull(plain, plaintext); werr != nil {
				return
			}
		}
	}()

	wg.Wait()
}

func tryCloseWrite(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

func (s *Server) cleanupPendingConns() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		for id, pc := range s.pendingConns {
			if time.Since(pc.createdAt) > s.pendingTTL {
				_ = pc.conn.Close()
				delete(s.pendingConns, id)
				logf(levelDebug, "[server] 清理超时 connID=%s", id)
			}
		}
		s.mu.Unlock()
	}
}

func genID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	bindAddr := flag.String("bind", "0.0.0.0", "绑定地址")
	controlPort := flag.Int("port", 7000, "控制端口")
	token := flag.String("token", "mysecret", "认证 token（用于派生加密密钥）")
	kdfSaltHex := flag.String("kdf-salt", crypto.KDFSaltHexDefault, "KDF salt (hex，客户端/服务端必须一致)")
	authLabel := flag.String("auth-label", crypto.AuthLabelDefault, "HMAC label（客户端/服务端必须一致）")
	ctrlLabel := flag.String("control-label", crypto.ControlLabelDefault, "控制通道 label（客户端/服务端必须一致）")
	s2cLabel := flag.String("data-s2c-label", crypto.DataLabelS2CDefault, "数据通道 s2c label（客户端/服务端必须一致）")
	c2sLabel := flag.String("data-c2s-label", crypto.DataLabelC2SDefault, "数据通道 c2s label（客户端/服务端必须一致）")
	logLevelFlag := flag.String("log-level", "info", "日志级别: debug|info|warn|error")
	maxPendingConns := flag.Int("max-pending", 4096, "待配对外部连接上限")
	maxDataConns := flag.Int("max-data-conns", 2048, "活跃数据连接上限")
	pendingTTL := flag.Duration("pending-ttl", 15*time.Second, "待配对连接超时")
	idleTimeout := flag.Duration("idle-timeout", 2*time.Minute, "数据连接空闲读写超时")
	flag.Parse()

	lvl, err := parseLogLevel(*logLevelFlag)
	if err != nil {
		log.Fatalf("日志级别错误: %v", err)
	}
	if *maxPendingConns <= 0 || *maxDataConns <= 0 {
		log.Fatal("max-pending 和 max-data-conns 必须大于 0")
	}
	if *pendingTTL <= 0 || *idleTimeout <= 0 {
		log.Fatal("pending-ttl 和 idle-timeout 必须大于 0")
	}

	salt, err := hex.DecodeString(strings.TrimSpace(*kdfSaltHex))
	if err != nil || len(salt) == 0 {
		log.Fatalf("kdf-salt 必须是有效 hex 且非空: %v", err)
	}

	currentLogLevel = lvl
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	logf(levelInfo, "[server] GoTunnel 服务端启动")

	s := NewServer(*bindAddr, *controlPort, *token, salt, *authLabel, *ctrlLabel, *s2cLabel, *c2sLabel, *maxPendingConns, *maxDataConns, *pendingTTL, *idleTimeout)
	log.Fatal(s.Start())
}
