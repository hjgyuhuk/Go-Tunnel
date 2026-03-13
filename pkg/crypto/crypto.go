package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/scrypt"
)

const (
	AuthLabelDefault    = "a6925a5bb60fe300f253ba47957f1ff5"
	ControlLabelDefault = "4ce332c594383ce4dce6ee9042f2fd1b"
	DataLabelS2CDefault = "802c7a38a51445cfe8d6a35f9a11ccd2"
	DataLabelC2SDefault = "ba9afbd6178ae7cf3de03957f29f8ff0"
	KDFSaltHexDefault   = "72c0b1ab35fe9b2c91b31daa2c0192ef"
)

// KeyFromPassword 从密码派生 32 字节 AES 密钥（scrypt）。
func KeyFromPassword(password string, salt []byte) []byte {
	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	return key
}

// EncryptedConn 使用 AES-GCM 对消息进行加密/解密（带消息帧）
// 格式：[4字节长度][nonce+密文]
type EncryptedConn struct {
	conn net.Conn
	gcm  cipher.AEAD
}

func NewEncryptedConn(conn net.Conn, key []byte) (*EncryptedConn, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &EncryptedConn{conn: conn, gcm: gcm}, nil
}

func (c *EncryptedConn) WriteMsg(data []byte) error {
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	encrypted := c.gcm.Seal(nonce, nonce, data, nil)

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(encrypted)))

	buf := append(lenBuf, encrypted...)
	_, err := c.conn.Write(buf)
	return err
}

func (c *EncryptedConn) ReadMsg() ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(c.conn, lenBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf)
	if length > 16*1024*1024 {
		return nil, fmt.Errorf("消息过大: %d bytes", length)
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return nil, err
	}

	nonceSize := c.gcm.NonceSize()
	if len(buf) < nonceSize {
		return nil, fmt.Errorf("密文过短")
	}
	return c.gcm.Open(nil, buf[:nonceSize], buf[nonceSize:], nil)
}

func (c *EncryptedConn) Close() error {
	return c.conn.Close()
}

func (c *EncryptedConn) Conn() net.Conn {
	return c.conn
}

// DeriveAES128Key 从会话密钥派生 16 字节 AES-128 密钥（仅标准库实现）。
func DeriveAES128Key(secret []byte, salt []byte, label string) []byte {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(secret)
	h.Write([]byte{0})
	h.Write(salt)
	sum := h.Sum(nil)
	k := make([]byte, 16)
	copy(k, sum[:16])
	return k
}

// DeriveHMACKey 从会话密钥派生 32 字节 HMAC 密钥。
func DeriveHMACKey(secret []byte, label string) []byte {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(secret)
	return h.Sum(nil)
}

// DeriveControlKey 为控制通道加密派生独立密钥。
func DeriveControlKey(secret []byte, label string) []byte {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(secret)
	return h.Sum(nil)
}

// HMACSHA256 计算 HMAC-SHA256。
func HMACSHA256(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

// VerifyHMACSHA256 使用常量时间比较校验 HMAC-SHA256。
func VerifyHMACSHA256(key []byte, data []byte, mac []byte) bool {
	expected := HMACSHA256(key, data)
	return hmac.Equal(expected, mac)
}

func NewAESGCM128(key []byte) (cipher.AEAD, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("AES-128 key length must be 16, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func NewRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// GCMNonceFromBase 使用 12 字节随机 base，并将 counter XOR 混入后 8 字节，构造 12 字节 GCM nonce。
func GCMNonceFromBase(base []byte, counter uint64) ([]byte, error) {
	if len(base) != 12 {
		return nil, fmt.Errorf("nonce base length must be 12, got %d", len(base))
	}
	nonce := make([]byte, 12)
	copy(nonce, base)
	existing := binary.BigEndian.Uint64(nonce[4:])
	binary.BigEndian.PutUint64(nonce[4:], existing^counter)
	return nonce, nil
}

func WriteFull(conn net.Conn, p []byte) error {
	for len(p) > 0 {
		n, err := conn.Write(p)
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}
