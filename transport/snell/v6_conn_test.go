package snell

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestV6ConnRoundTrip(t *testing.T) {
	for _, mode := range []V6Mode{V6ModeDefault, V6ModeUnshaped, V6ModeUnsafeRaw} {
		t.Run(mode.String(), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			host := "example.com"
			headerLen := 4 + len(host) + 2
			msg := bytes.Repeat([]byte("snell-v6-pipe-"), 1000)
			serverErr := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				defer conn.Close()
				server := newV6Conn(conn, []byte("v6-npipe-psk-123456"), mode, true)
				hdr := make([]byte, headerLen)
				if _, err := io.ReadFull(server, hdr); err != nil {
					serverErr <- err
					return
				}
				if hdr[0] != 0x01 || hdr[1] != CommandConnect || hdr[2] != 0 {
					serverErr <- io.ErrUnexpectedEOF
					return
				}
				got := make([]byte, len(msg))
				if _, err := io.ReadFull(server, got); err != nil {
					serverErr <- err
					return
				}
				if !bytes.Equal(got, msg) {
					serverErr <- io.ErrUnexpectedEOF
					return
				}
				if _, err := server.Write(append([]byte{0x00}, got...)); err != nil {
					serverErr <- err
					return
				}
				var one [1]byte
				if _, err := server.Read(one[:]); err != io.EOF {
					serverErr <- io.ErrUnexpectedEOF
					return
				}
				serverErr <- nil
			}()

			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			client := newV6Conn(conn, []byte("v6-npipe-psk-123456"), mode, false)
			clientSnell := &Snell{Conn: client, reply: true}
			if err := WriteV6Header(clientSnell, host, 443, CommandConnect); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Write(msg); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(client, got); err != nil {
				t.Fatalf("client read: %v", err)
			}
			if !bytes.Equal(got, msg) {
				t.Fatal("round trip payload mismatch")
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-serverErr:
				if err != nil {
					t.Fatalf("server side: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("server goroutine did not finish")
			}
		})
	}
}
func TestV6ZeroRecordEncoding(t *testing.T) {
	psk := []byte("zero-record-psk-123456")
	profile := newV6Profile(psk)
	c := newV6Conn(nil, psk, V6ModeDefault, false)
	if err := c.initTx(); err != nil {
		t.Fatal(err)
	}
	got := c.encodeChunk(0, nil, 0)
	wantLen := profile.prefixLen(0) + v6CtrlWireLen + profile.interPadLen(0, 0, 0)
	if len(got) != wantLen {
		t.Fatalf("zero record length = %d, want %d (extra payload tag?)", len(got), wantLen)
	}
	if c.txNonce != 1 {
		t.Fatalf("zero record consumed %d nonces, want 1", c.txNonce)
	}
}
func TestV6PacketFrameLimits(t *testing.T) {
	for _, mode := range []V6Mode{V6ModeDefault, V6ModeUnshaped, V6ModeUnsafeRaw} {
		c := newV6Conn(nil, []byte("frame-limit-psk-123456"), mode, false)
		if err := c.initTx(); err != nil {
			t.Fatal(err)
		}
		if _, err := c.WritePacketFrame(nil); err == nil {
			t.Fatalf("%s: empty UDP datagram accepted", mode)
		}
		if mode != V6ModeDefault {
			if _, err := c.WritePacketFrame(make([]byte, 0x4000)); err == nil {
				t.Fatalf("%s: oversized UDP datagram accepted", mode)
			}
		}
	}
}
