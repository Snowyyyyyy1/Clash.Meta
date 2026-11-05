package snell

// Integration tests against a real Snell v6 server (official snell-server or
// mihomo's own inbound). They are skipped unless SNELL_V6_INTEGRATION=1 and
// SNELL_PSK are set.
//
// Example:
//   SNELL_V6_INTEGRATION=1 SNELL_PSK=... SNELL_ADDR=127.0.0.1:17177 \
//   SNELL_HTTP_TARGET=127.0.0.1:18080 SNELL_ECHO_TARGET=127.0.0.1:18081 \
//   SNELL_UDP_TARGET=127.0.0.1:18082 go test ./transport/snell -run TestV6Integration -v

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func v6IntegrationEnv(t *testing.T) (string, []byte, V6Mode) {
	t.Helper()
	if os.Getenv("SNELL_V6_INTEGRATION") == "" {
		t.Skip("set SNELL_V6_INTEGRATION=1 to run")
	}
	psk := os.Getenv("SNELL_PSK")
	if psk == "" {
		t.Fatal("SNELL_PSK is required")
	}
	mode, err := ParseV6Mode(os.Getenv("SNELL_MODE"))
	if err != nil {
		t.Fatal(err)
	}
	addr := os.Getenv("SNELL_ADDR")
	if addr == "" {
		addr = "127.0.0.1:17177"
	}
	return addr, []byte(psk), mode
}

func v6IntegrationDial(t *testing.T, addr string, psk []byte, mode V6Mode, target string) *Snell {
	t.Helper()
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	sc := StreamConnV6(conn, psk, mode)
	if err := WriteV6Header(sc, host, uint(port), CommandConnect); err != nil {
		_ = sc.Close()
		t.Fatal(err)
	}
	return sc
}

func TestV6IntegrationHTTP(t *testing.T) {
	addr, psk, mode := v6IntegrationEnv(t)
	target := os.Getenv("SNELL_HTTP_TARGET")
	if target == "" {
		target = "127.0.0.1:18080"
	}
	sc := v6IntegrationDial(t, addr, psk, mode, target)
	defer sc.Close()
	if _, err := fmt.Fprintf(sc, "GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", target); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 5 || string(body[:5]) != "HTTP/" {
		t.Fatalf("unexpected HTTP response: %q", body)
	}
	t.Logf("HTTP response: %d bytes", len(body))
}

func TestV6IntegrationEcho(t *testing.T) {
	addr, psk, mode := v6IntegrationEnv(t)
	target := os.Getenv("SNELL_ECHO_TARGET")
	if target == "" {
		target = "127.0.0.1:18081"
	}
	sc := v6IntegrationDial(t, addr, psk, mode, target)
	defer sc.Close()

	const total = 2 * 1024 * 1024
	data := make([]byte, total)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := sc.Write(data)
		errCh <- err
	}()
	got := make([]byte, total)
	if _, err := io.ReadFull(sc, got); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, got) {
		t.Fatal("echo payload mismatch")
	}
	t.Logf("echoed %d bytes", total)
}

func TestV6IntegrationUDP(t *testing.T) {
	addr, psk, mode := v6IntegrationEnv(t)
	target := os.Getenv("SNELL_UDP_TARGET")
	if target == "" {
		target = "127.0.0.1:18082"
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatal(err)
	}

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	sc := StreamConnV6(conn, psk, mode)
	defer sc.Close()
	if err := WriteV6UDPHeader(sc); err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("SNELL_UDP_TARGET must be IPv4 for this test: %s", target)
	}
	payload := []byte("hello-snell-v6-udp")
	req := []byte{0x01, 0x00, 0x04, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	req = append(req, payload...)
	if _, err := sc.WritePacketFrame(req); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := sc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte("echo:"), payload...)
	if n < 7+len(want) {
		t.Fatalf("short UDP response: %d", n)
	}
	body := buf[7:n]
	if !bytes.Equal(body, want) {
		t.Fatalf("UDP response mismatch: %x vs %x", body, want)
	}
	t.Logf("UDP response ok: %q", body)
}
func TestV6IntegrationHalfClose(t *testing.T) {
	addr, psk, mode := v6IntegrationEnv(t)
	target := os.Getenv("SNELL_HALFCLOSE_TARGET")
	if target == "" {
		target = "127.0.0.1:18183"
	}
	sc := v6IntegrationDial(t, addr, psk, mode, target)
	defer sc.Close()
	payload := []byte("half-close-request")
	if _, err := sc.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := sc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(sc)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("after-eof:" + string(payload))
	if !bytes.Equal(got, want) {
		t.Fatalf("half-close response = %q, want %q", got, want)
	}
	t.Logf("half-close response ok: %q", got)
}
