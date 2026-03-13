package proto

// 消息类型
const (
	TypeHello        = "hello"
	TypeHelloAck     = "hello_ack"
	TypeChallenge    = "challenge"
	TypeNewConn      = "new_conn"
	TypeConnReady    = "conn_ready"
	TypeHeartbeat    = "heartbeat"
	TypeHeartbeatAck = "heartbeat_ack"
)

// TunnelConfig 单条隧道配置
type TunnelConfig struct {
	RemotePort int    `json:"remote_port"` // 服务端监听端口（公网）
	LocalAddr  string `json:"local_addr"`  // 客户端本地地址（如 127.0.0.1:80）
	Name       string `json:"name"`
}

// Challenge 服务端下发挑战
type Challenge struct {
	Type  string `json:"type"`
	Nonce string `json:"nonce"` // base64 随机数
}

// Hello 客户端握手请求（挑战-响应）
type Hello struct {
	Type    string         `json:"type"`
	Nonce   string         `json:"nonce"` // 来自服务端 Challenge
	Tunnels []TunnelConfig `json:"tunnels"`
	Auth    string         `json:"auth"` // base64 HMAC-SHA256
}

// HelloAck 服务端握手响应
type HelloAck struct {
	Type    string `json:"type"`
	Status  string `json:"status"` // "ok" or "error"
	Message string `json:"message,omitempty"`
}

// NewConn 服务端通知客户端有新的外部连接
type NewConn struct {
	Type       string `json:"type"`
	ConnID     string `json:"conn_id"`
	RemotePort int    `json:"remote_port"`
}

// ConnReady 客户端告知服务端已准备好数据连接
type ConnReady struct {
	Type   string `json:"type"`
	ConnID string `json:"conn_id"`
	Nonce  string `json:"nonce"` // 来自服务端 Challenge
	Auth   string `json:"auth"`  // base64 HMAC-SHA256
}

// Heartbeat / HeartbeatAck
type Heartbeat struct {
	Type string `json:"type"`
}

// HelloAuthPayload 用于计算握手 HMAC（不含 Auth）
type HelloAuthPayload struct {
	Type    string         `json:"type"`
	Nonce   string         `json:"nonce"`
	Tunnels []TunnelConfig `json:"tunnels"`
}

// ConnReadyAuthPayload 用于计算数据连接 HMAC（不含 Auth）
type ConnReadyAuthPayload struct {
	Type   string `json:"type"`
	Nonce  string `json:"nonce"`
	ConnID string `json:"conn_id"`
}
