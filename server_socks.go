package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/proxy"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	pionudp "github.com/pion/transport/v4/udp"
)

const (
	wgIfaceName           = "wdtt0"
	wgServerAddr          = "10.66.66.1"
	wgClientAddr          = "10.66.66.2"
	wgClientCIDR          = wgClientAddr + "/32"
	wgServerCIDR          = wgServerAddr + "/24"
	wgMTU                 = 1360
	defaultInternalWGPort = 51820
	wrapKeyLen            = 32
	tproxyPort            = 12345
)

var (
	totalConns           int64
	activeConns          int32
	totalBytesFromClient int64
	totalBytesToClient   int64

	bufPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 1600)
			return &b
		},
	}

	serverKeys   *wgKeys
	clientKeys   *wgKeys
	socksDialer  proxy.Dialer
	serverWrapKeys *wrapKeyStore
)

// ==================== Cryptography & Obfuscation ====================

type wgKeys struct {
	serverPrivate, serverPublic, clientPrivate, clientPublic string
}

func b64ToHex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(b) != 32 {
		return "", fmt.Errorf("key length %d != 32", len(b))
	}
	return hex.EncodeToString(b), nil
}

func generateKeyPair() (privB64, pubB64 string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	privB64 = base64.StdEncoding.EncodeToString(priv[:])
	pubB64 = base64.StdEncoding.EncodeToString(pub[:])
	return privB64, pubB64, nil
}

type wrapKeyEntry struct {
	id  string
	key []byte
}

type wrapKeyStore struct {
	mu      sync.RWMutex
	entries []wrapKeyEntry
}

func newWrapKeyStore() *wrapKeyStore {
	return &wrapKeyStore{}
}

func deriveWrapKey(password string) ([]byte, error) {
	key := make([]byte, wrapKeyLen)
	reader := hkdf.New(sha256.New, []byte(password), nil, []byte("WDTT-OBFS-KEY-v1"))
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func wrapKeyID(password string) string {
	sum := sha256.Sum256([]byte("WDTT-WRAP-ID-v1\x00" + password))
	return hex.EncodeToString(sum[:8])
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (s *wrapKeyStore) AddPassword(password string) error {
	key, err := deriveWrapKey(password)
	if err != nil {
		return err
	}
	id := "pass:" + wrapKeyID(password)

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.entries {
		if entry.id == id {
			zeroBytes(key)
			return nil
		}
	}
	s.entries = append(s.entries, wrapKeyEntry{id: id, key: key})
	return nil
}

func (s *wrapKeyStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

func (s *wrapKeyStore) Unwrap(raw, dst []byte) ([]byte, int, error) {
	if !obfsIsRTPPacket(raw) {
		return nil, 0, errors.New("wrap: not a fake RTP packet")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, entry := range s.entries {
		n, err := obfsUnwrapPacket(entry.key, raw, dst)
		if err == nil {
			return entry.key, n, nil
		}
	}
	return nil, 0, errors.New("wrap: decryption failed for all keys")
}

type ObfsConfig struct {
	SSRC        uint32
	PayloadType uint8
	PaddingMax  int
}

type ObfsState struct {
	mu  sync.Mutex
	seq uint16
	ts  uint32
}

func NewObfsConfig() *ObfsConfig {
	var buf [4]byte
	rand.Read(buf[:])
	return &ObfsConfig{
		SSRC:        binary.BigEndian.Uint32(buf[:]),
		PayloadType: 111,
		PaddingMax:  24,
	}
}

func NewObfsState() *ObfsState {
	var buf [6]byte
	rand.Read(buf[:])
	return &ObfsState{
		seq: binary.BigEndian.Uint16(buf[0:2]),
		ts:  binary.BigEndian.Uint32(buf[2:6]),
	}
}

func obfsBuildNonce(ssrc uint32, seq uint16, ts uint32) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint32(n[0:4], ssrc)
	binary.BigEndian.PutUint16(n[4:6], seq)
	binary.BigEndian.PutUint32(n[8:12], ts)
	return n
}

func obfsWrapPacket(key, payload []byte, cfg *ObfsConfig, state *ObfsState) ([]byte, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("obfs: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	if len(payload) == 0 {
		return nil, errors.New("obfs: empty payload")
	}
	state.mu.Lock()
	seq := state.seq
	ts := state.ts
	state.seq++
	state.ts += 960
	state.mu.Unlock()

	nonce := obfsBuildNonce(cfg.SSRC, seq, ts)
	padRand := 0
	if cfg.PaddingMax > 0 {
		var rndBuf [1]byte
		rand.Read(rndBuf[:])
		padRand = int(rndBuf[0]) % cfg.PaddingMax
	}
	padTotal := padRand + 1
	outLen := 12 + len(payload) + chacha20poly1305.Overhead + padTotal
	out := make([]byte, outLen)

	out[0] = 0x80 | 0x20
	out[1] = cfg.PayloadType & 0x7F
	binary.BigEndian.PutUint16(out[2:4], seq)
	binary.BigEndian.PutUint32(out[4:8], ts)
	binary.BigEndian.PutUint32(out[8:12], cfg.SSRC)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("obfs: cipher init: %w", err)
	}
	sealed := aead.Seal(out[12:12], nonce, payload, out[:12])
	padStart := 12 + len(sealed)
	if padRand > 0 {
		rand.Read(out[padStart : padStart+padRand])
	}
	out[outLen-1] = byte(padTotal)
	return out, nil
}

func obfsUnwrapPacket(key, wire, dst []byte) (int, error) {
	if len(key) != wrapKeyLen {
		return 0, fmt.Errorf("obfs: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	if len(wire) < 13 {
		return 0, errors.New("obfs: packet too short")
	}
	if (wire[0] >> 6) != 2 {
		return 0, errors.New("obfs: not RTP v2")
	}
	seq := binary.BigEndian.Uint16(wire[2:4])
	ts := binary.BigEndian.Uint32(wire[4:8])
	ssrc := binary.BigEndian.Uint32(wire[8:12])

	payloadEnd := len(wire)
	if wire[0]&0x20 != 0 {
		padLen := int(wire[len(wire)-1])
		if padLen == 0 || padLen > payloadEnd-12 {
			return 0, fmt.Errorf("obfs: invalid padding length %d", padLen)
		}
		payloadEnd -= padLen
	}
	ciphertextLen := payloadEnd - 12
	if ciphertextLen <= chacha20poly1305.Overhead {
		return 0, errors.New("obfs: no payload")
	}
	if ciphertextLen-chacha20poly1305.Overhead > len(dst) {
		return 0, errors.New("obfs: dst buffer too small")
	}
	nonce := obfsBuildNonce(ssrc, seq, ts)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return 0, fmt.Errorf("obfs: cipher init: %w", err)
	}
	plain, err := aead.Open(dst[:0], nonce, wire[12:payloadEnd], wire[:12])
	if err != nil {
		return 0, fmt.Errorf("obfs: auth: %w", err)
	}
	return len(plain), nil
}

func obfsIsRTPPacket(wire []byte) bool {
	if len(wire) < 13 {
		return false
	}
	if (wire[0] >> 6) != 2 {
		return false
	}
	pt := wire[1] & 0x7F
	return pt == 111
}

// ==================== Custom Packet Listener ====================

func listenWrapped(addr *net.UDPAddr, keys *wrapKeyStore) (dtlsnet.PacketListener, error) {
	if keys == nil || keys.Count() == 0 {
		return nil, errors.New("wrap: no active keys")
	}
	inner, err := pionudp.Listen("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("wrap: udp listen: %w", err)
	}
	return &wrapPacketListener{
		inner: dtlsnet.PacketListenerFromListener(inner),
		keys:  keys,
	}, nil
}

type wrapPacketListener struct {
	inner dtlsnet.PacketListener
	keys  *wrapKeyStore
}

func (l *wrapPacketListener) Accept() (net.PacketConn, net.Addr, error) {
	pc, addr, err := l.inner.Accept()
	if err != nil {
		return pc, addr, err
	}
	return &wrapPacketConn{inner: pc, keys: l.keys}, addr, nil
}

func (l *wrapPacketListener) Close() error   { return l.inner.Close() }
func (l *wrapPacketListener) Addr() net.Addr { return l.inner.Addr() }

type wrapPacketConn struct {
	inner     net.PacketConn
	keys      *wrapKeyStore
	key       []byte
	selected  int32
	authLog   int32
	obfsCfg   *ObfsConfig
	obfsWrite *ObfsState
}

func (c *wrapPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, len(p)+80)
	n, addr, err := c.inner.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	raw := buf[:n]

	if atomic.LoadInt32(&c.selected) == 0 {
		key, m, uErr := c.keys.Unwrap(raw, p)
		if uErr != nil {
			if atomic.CompareAndSwapInt32(&c.authLog, 0, 1) {
				log.Printf("[WRAP] Отказ: RTP AEAD auth failed from %s", addr.String())
			}
			return 0, addr, uErr
		}
		c.key = append([]byte(nil), key...)
		c.obfsCfg = NewObfsConfig()
		c.obfsWrite = NewObfsState()
		atomic.StoreInt32(&c.selected, 1)
		if atomic.CompareAndSwapInt32(&c.authLog, 0, 1) {
			log.Printf("[WRAP] OK: Аутентификация успешна для %s", addr.String())
		}
		return m, addr, nil
	}

	m, uErr := obfsUnwrapPacket(c.key, raw, p)
	if uErr != nil {
		key, m2, uErr2 := c.keys.Unwrap(raw, p)
		if uErr2 == nil {
			c.key = append([]byte(nil), key...)
			c.obfsCfg = NewObfsConfig()
			c.obfsWrite = NewObfsState()
			log.Printf("[WRAP] Обновлен ключ на лету для %s", addr.String())
			return m2, addr, nil
		}
		return 0, addr, fmt.Errorf("obfs unwrap: %w", uErr)
	}
	return m, addr, nil
}

func (c *wrapPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if atomic.LoadInt32(&c.selected) == 0 || len(c.key) != wrapKeyLen {
		return 0, errors.New("wrap: key not selected")
	}
	if c.obfsCfg == nil || c.obfsWrite == nil {
		c.obfsCfg = NewObfsConfig()
		c.obfsWrite = NewObfsState()
	}
	wrapped, wErr := obfsWrapPacket(c.key, p, c.obfsCfg, c.obfsWrite)
	if wErr != nil {
		return 0, fmt.Errorf("obfs wrap: %w", wErr)
	}
	if _, err := c.inner.WriteTo(wrapped, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wrapPacketConn) Close() error                       { return c.inner.Close() }
func (c *wrapPacketConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *wrapPacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *wrapPacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *wrapPacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

// ==================== System Utilities ====================

func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func runCmdSilent(name string, args ...string) string {
	out, _ := exec.Command(name, args...).CombinedOutput()
	return string(out)
}

func getBuf() *[]byte  { return bufPool.Get().(*[]byte) }
func putBuf(b *[]byte) { bufPool.Put(b) }

// ==================== WireGuard setup ====================

func startUserspaceWG(keys *wgKeys, wgPort int) (*device.Device, error) {
	runCmdSilent("ip", "link", "del", wgIfaceName)
	time.Sleep(100 * time.Millisecond)

	tunDev, err := tun.CreateTUN(wgIfaceName, wgMTU)
	if err != nil {
		return nil, fmt.Errorf("CreateTUN: %w", err)
	}

	ifaceName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("TUN name: %w", err)
	}

	logger := device.NewLogger(device.LogLevelError, "[WG] ")
	bind := conn.NewDefaultBind()
	dev := device.NewDevice(tunDev, bind, logger)

	serverPrivHex, _ := b64ToHex(keys.serverPrivate)

	if err := dev.IpcSet(fmt.Sprintf(
		"private_key=%s\nlisten_port=%d\n",
		serverPrivHex, wgPort,
	)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("IpcSet: %w", err)
	}

	// Регистрируем единственного клиента
	pubHex, _ := b64ToHex(keys.clientPublic)
	if pubHex != "" {
		dev.IpcSet(fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", pubHex, wgClientAddr))
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("device.Up: %w", err)
	}

	if err := configureInterface(ifaceName); err != nil {
		dev.Close()
		return nil, err
	}

	if err := setupTransparentProxyRedirect(ifaceName); err != nil {
		dev.Close()
		return nil, err
	}

	go func() {
		uapiFile, err := ipc.UAPIOpen(ifaceName)
		if err != nil {
			return
		}
		uapi, err := ipc.UAPIListen(ifaceName, uapiFile)
		if err != nil {
			return
		}
		defer uapi.Close()
		for {
			c, err := uapi.Accept()
			if err != nil {
				return
			}
			go dev.IpcHandle(c)
		}
	}()

	log.Printf("[WG] Запущен на порту %d", wgPort)
	return dev, nil
}

func configureInterface(ifaceName string) error {
	for _, cmd := range [][]string{
		{"ip", "addr", "add", wgServerCIDR, "dev", ifaceName},
		{"ip", "link", "set", "mtu", fmt.Sprintf("%d", wgMTU), "dev", ifaceName},
		{"ip", "link", "set", ifaceName, "up"},
	} {
		out, err := runCmd(cmd[0], cmd[1:]...)
		if err != nil && !strings.Contains(out, "File exists") {
			return fmt.Errorf("%s: %s", strings.Join(cmd, " "), out)
		}
	}
	return nil
}

func setupTransparentProxyRedirect(wgIface string) error {
	log.Println("[NAT] Настройка перенаправления TCP трафика на прозрачный прокси...")
	os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)

	// Удаляем возможные старые правила
	exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-i", wgIface, "-p", "tcp", "-j", "REDIRECT", "--to-ports", strconv.Itoa(tproxyPort)).Run()
	
	// Перенаправляем все входящие TCP пакеты с интерфейса WireGuard на локальный порт tproxyPort
	err := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-i", wgIface, "-p", "tcp", "-j", "REDIRECT", "--to-ports", strconv.Itoa(tproxyPort)).Run()
	if err != nil {
		return fmt.Errorf("iptables redirect: %w", err)
	}

	log.Printf("[NAT] Все TCP пакеты с %s успешно перенаправляются на порт %d", wgIface, tproxyPort)
	return nil
}

func cleanupIptables() {
	log.Println("[SYS] Очистка правил iptables...")
	exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-i", wgIfaceName, "-p", "tcp", "-j", "REDIRECT", "--to-ports", strconv.Itoa(tproxyPort)).Run()
}

func buildClientConfig(serverPublic, clientPrivate, clientIP, clientPort string) string {
	return fmt.Sprintf("SERVER_PUB:%s\nCLIENT_PRIV:%s\nCLIENT_IP:%s\nCLIENT_PORT:%s\n",
		serverPublic, clientPrivate, clientIP, clientPort)
}

// ==================== TCP Transparent Proxy & SOCKS ====================

func startTCPTransparentProxy(socksDialer proxy.Dialer) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", tproxyPort))
	if err != nil {
		log.Fatalf("[TPROXY] Не удалось запустить Listener на порту %d: %v", tproxyPort, err)
	}
	defer listener.Close()

	log.Printf("[TPROXY] Прозрачный TCP прокси запущен на порту %d", tproxyPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			conn.Close()
			continue
		}
		go handleTransparentConnection(tcpConn, socksDialer)
	}
}

func getOriginalDst(clientConn *net.TCPConn) (string, error) {
	rawConn, err := clientConn.SyscallConn()
	if err != nil {
		return "", err
	}

	var addr string
	var err2 error
	err = rawConn.Control(func(fd uintptr) {
		// SO_ORIGINAL_DST = 80, SOL_IP = 0
		var raw syscall.RawSockaddrInet4
		size := uint32(unsafe.Sizeof(raw))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			0, // SOL_IP = 0 on Linux
			80, // SO_ORIGINAL_DST = 80
			uintptr(unsafe.Pointer(&raw)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			err2 = errno
			return
		}

		ip := net.IP(raw.Addr[:])
		// raw.Port inside RawSockaddrInet4 is uint16 in big endian (network byte order)
		port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&raw.Port))[:]))
		addr = net.JoinHostPort(ip.String(), strconv.Itoa(port))
	})
	if err != nil {
		return "", err
	}
	return addr, err2
}

func handleTransparentConnection(clientConn *net.TCPConn, socksDialer proxy.Dialer) {
	defer clientConn.Close()

	destAddr, err := getOriginalDst(clientConn)
	if err != nil {
		log.Printf("[TPROXY] Ошибка получения оригинального назначения: %v", err)
		return
	}

	// Подключаемся к SOCKS5 прокси, а через него - к финальной точке назначения
	socksConn, err := socksDialer.Dial("tcp", destAddr)
	if err != nil {
		log.Printf("[TPROXY] Ошибка Dial через SOCKS к %s: %v", destAddr, err)
		return
	}
	defer socksConn.Close()

	// Перенаправляем потоки данных в обе стороны
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(socksConn, clientConn)
		socksConn.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, socksConn)
		clientConn.Close()
	}()

	wg.Wait()
}

// ==================== DNS Forwarder over SOCKS5 TCP ====================

func startDNSForwarder(socksDialer proxy.Dialer) {
	addr, err := net.ResolveUDPAddr("udp", wgServerAddr+":53")
	if err != nil {
		log.Fatalf("[DNS] ResolveUDPAddr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("[DNS] ListenUDP: %v", err)
	}
	defer conn.Close()

	log.Printf("[DNS] Сервер запущен на %s:53. DNS запросы будут пересылаться в SOCKS через TCP.", wgServerAddr)
	buf := make([]byte, 512)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		query := buf[:n]
		go forwardDNSQuery(conn, clientAddr, append([]byte(nil), query...), socksDialer)
	}
}

func forwardDNSQuery(udpConn *net.UDPConn, clientAddr *net.UDPAddr, query []byte, socksDialer proxy.Dialer) {
	// Подключаемся к общественному DNS серверу 8.8.8.8 по TCP порту 53 через SOCKS5
	dnsConn, err := socksDialer.Dial("tcp", "8.8.8.8:53")
	if err != nil {
		log.Printf("[DNS] Не удалось подключиться к DNS по TCP через SOCKS: %v", err)
		return
	}
	defer dnsConn.Close()

	// В DNS-over-TCP перед пакетом отправляется его длина (2 байта)
	length := uint16(len(query))
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], length)

	if _, err := dnsConn.Write(append(lenBuf[:], query...)); err != nil {
		return
	}

	// Читаем 2 байта длины ответа
	if _, err := io.ReadFull(dnsConn, lenBuf[:]); err != nil {
		return
	}
	respLen := binary.BigEndian.Uint16(lenBuf[:])

	// Читаем сам ответ
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(dnsConn, resp); err != nil {
		return
	}

	// Отправляем ответ клиенту по UDP
	udpConn.WriteToUDP(resp, clientAddr)
}

// ==================== Connection Handling ====================

func handleConn(ctx context.Context, clientConn net.Conn, wgEndpoint string, wgDev *device.Device, keys *wgKeys, clientPass string) {
	atomic.AddInt64(&totalConns, 1)

	dtlsConn, ok := clientConn.(*dtls.Conn)
	if !ok {
		return
	}

	hctx, hcancel := context.WithTimeout(ctx, 30*time.Second)
	if err := dtlsConn.HandshakeContext(hctx); err != nil {
		hcancel()
		return
	}
	hcancel()

	atomic.AddInt32(&activeConns, 1)
	defer atomic.AddInt32(&activeConns, -1)

	buf := make([]byte, 1600)
	clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil {
		return
	}
	clientConn.SetReadDeadline(time.Time{})

	firstPacket := buf[:n]
	firstStr := string(firstPacket)

	if strings.HasPrefix(firstStr, "GETCONF:") {
		parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(firstStr, "GETCONF:")), "|")
		clientPort := "9000"
		password := ""
		if len(parts) > 0 {
			clientPort = parts[0]
		}
		if len(parts) > 2 {
			password = parts[2]
		}

		// Сверяем единственный пароль
		if password != "" && password == clientPass {
			// Высылаем статическую конфигурацию клиенту
			clientConn.Write([]byte(buildClientConfig(keys.serverPublic, keys.clientPrivate, wgClientAddr, clientPort)))
			log.Printf("[WG] Выдана конфигурация для авторизованного клиента")
		} else {
			clientConn.Write([]byte("DENIED:wrong_password"))
			log.Printf("[WG] Отказ в авторизации: неверный пароль")
			return
		}

		clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err = clientConn.Read(buf)
		if err != nil {
			return
		}
		clientConn.SetReadDeadline(time.Time{})
		firstPacket = buf[:n]
		firstStr = string(firstPacket)
	}

	if firstStr == "READY" {
		clientConn.Write([]byte("READY_OK"))
		clientConn.SetReadDeadline(time.Now().Add(10 * time.Minute))
		n, err = clientConn.Read(buf)
		if err != nil {
			return
		}
		clientConn.SetReadDeadline(time.Time{})
		firstPacket = buf[:n]
	}

	// WG прокси
	wgConn, err := net.Dial("udp", wgEndpoint)
	if err != nil {
		return
	}
	defer wgConn.Close()

	if uc, ok := wgConn.(*net.UDPConn); ok {
		uc.SetReadBuffer(2 * 1024 * 1024)
		uc.SetWriteBuffer(2 * 1024 * 1024)
	}

	if _, err := wgConn.Write(firstPacket); err != nil {
		return
	}
	atomic.AddInt64(&totalBytesFromClient, int64(len(firstPacket)))

	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()

	context.AfterFunc(pctx, func() {
		clientConn.SetDeadline(time.Now())
		wgConn.SetDeadline(time.Now())
	})

	var proxyWg sync.WaitGroup
	proxyWg.Add(2)

	// Клиент → WG
	go func() {
		defer proxyWg.Done()
		defer pcancel()
		b := getBuf()
		defer putBuf(b)
		for {
			select {
			case <-pctx.Done():
				return
			default:
			}
			clientConn.SetReadDeadline(time.Now().Add(30 * time.Minute))
			nn, err := clientConn.Read(*b)
			if err != nil {
				return
			}
			if nn == 1 && (*b)[0] == 0xFF {
				continue
			}
			atomic.AddInt64(&totalBytesFromClient, int64(nn))
			if _, err := wgConn.Write((*b)[:nn]); err != nil {
				return
			}
		}
	}()

	// WG → Клиент
	go func() {
		defer proxyWg.Done()
		defer pcancel()
		b := getBuf()
		defer putBuf(b)
		for {
			select {
			case <-pctx.Done():
				return
			default:
			}
			wgConn.SetReadDeadline(time.Now().Add(30 * time.Minute))
			nn, err := wgConn.Read(*b)
			if err != nil {
				return
			}
			atomic.AddInt64(&totalBytesToClient, int64(nn))
			if _, err := clientConn.Write((*b)[:nn]); err != nil {
				return
			}
		}
	}()

	proxyWg.Wait()
}

func statsLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			active := atomic.LoadInt32(&activeConns)
			total := atomic.LoadInt64(&totalConns)
			rx := atomic.LoadInt64(&totalBytesFromClient)
			tx := atomic.LoadInt64(&totalBytesToClient)
			log.Printf("[STATS] Активно: %d | Всего коннектов: %d | RX: %.2f MB | TX: %.2f MB",
				active, total, float64(rx)/(1024*1024), float64(tx)/(1024*1024))
		}
	}
}

// ==================== Main ====================

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "DTLS адрес сервера")
	wgPort := flag.Int("wg-port", defaultInternalWGPort, "WireGuard UDP порт")
	clientPass := flag.String("password", "default_secret_pass", "Единственный пароль для аутентификации клиента")
	socksServer := flag.String("socks-server", "127.0.0.1:1080", "Адрес SOCKS5 сервера (IP:Порт)")
	socksUser := flag.String("socks-user", "", "Имя пользователя для SOCKS5 прокси (опционально)")
	socksPass := flag.String("socks-pass", "", "Пароль для SOCKS5 прокси (опционально)")
	flag.Parse()

	// Override flags with environment variables if present
	if envPass := os.Getenv("CLIENT_PASSWORD"); envPass != "" {
		*clientPass = envPass
	}
	if envSocks := os.Getenv("SOCKS_SERVER"); envSocks != "" {
		*socksServer = envSocks
	}
	if envUser := os.Getenv("SOCKS_USER"); envUser != "" {
		*socksUser = envUser
	}
	if envPass := os.Getenv("SOCKS_PASS"); envPass != "" {
		*socksPass = envPass
	}


	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Println("══════════════════════════════════════════")
	log.Println("   WDTT Server SOCKS Redirect (Stateless)")
	log.Println("══════════════════════════════════════════")

	if *clientPass == "" || *clientPass == "default_secret_pass" {
		log.Println("[WARNING] Используется стандартный пароль! Рекомендуется сменить его через флаг -password")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		<-sig
		cleanupIptables()
		cancel()
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()

	// 1. Инициализация SOCKS5 прокси-клиента
	var auth *proxy.Auth
	if *socksUser != "" {
		auth = &proxy.Auth{
			User:     *socksUser,
			Password: *socksPass,
		}
	}
	var err error
	socksDialer, err = proxy.SOCKS5("tcp", *socksServer, auth, proxy.Direct)
	if err != nil {
		log.Fatalf("[SOCKS] Не удалось инициализировать SOCKS5 Dialer: %v", err)
	}
	log.Printf("[SOCKS] Успешно настроен SOCKS5 прокси-клиент для %s", *socksServer)

	// 2. Инициализация хранилища ключей обфускации
	serverWrapKeys = newWrapKeyStore()
	if err := serverWrapKeys.AddPassword(*clientPass); err != nil {
		log.Fatalf("[WRAP] Не удалось инициализировать ключи обфускации: %v", err)
	}

	// 3. Генерация эфемерных WireGuard ключей (в памяти)
	serverPriv, serverPub, _ := generateKeyPair()
	clientPriv, clientPub, _ := generateKeyPair()
	serverKeys = &wgKeys{
		serverPrivate: serverPriv,
		serverPublic:  serverPub,
		clientPrivate: clientPriv,
		clientPublic:  clientPub,
	}
	log.Println("[WG] Сгенерированы эфемерные ключи WireGuard для сессии")

	// 4. Запуск WireGuard
	wgDev, err := startUserspaceWG(serverKeys, *wgPort)
	if err != nil {
		log.Fatalf("[WG] Не удалось запустить WireGuard: %v", err)
	}
	defer func() {
		wgDev.Close()
		runCmdSilent("ip", "link", "del", wgIfaceName)
	}()

	// 5. Запуск прозрачного TCP прокси и DNS-сервера
	go startTCPTransparentProxy(socksDialer)
	go startDNSForwarder(socksDialer)
	go statsLoop(ctx)

	// 6. Запуск DTLS-приемника
	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatalf("[DTLS] ResolveUDPAddr: %v", err)
	}
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		log.Fatalf("[DTLS] Ошибка генерации сертификата: %v", err)
	}

	wrapListener, err := listenWrapped(addr, serverWrapKeys)
	if err != nil {
		log.Fatalf("[WRAP] %v", err)
	}

	listener, err := dtls.NewListenerWithOptions(wrapListener,
		dtls.WithCertificates(cert),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)),
	)
	if err != nil {
		log.Fatalf("[DTLS] %v", err)
	}
	defer listener.Close()

	log.Printf("[DTLS] Сервер слушает входящие соединения на %s", *listen)
	wgEndpoint := fmt.Sprintf("127.0.0.1:%d", *wgPort)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[DTLS] Accept error: %v", err)
				continue
			}
		}
		go handleConn(ctx, clientConn, wgEndpoint, wgDev, serverKeys, *clientPass)
	}
}
