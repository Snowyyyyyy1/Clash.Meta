package snell

// Snell v6 connection framing and AEAD record layer.
//
// A v6 session is a single TCP connection:
//   client -> server: [salt block] [chunk 0] [chunk 1] ...
//   server -> client: [salt block] [chunk 0] [chunk 1] ...
// Each chunk is [prefix_pad][AEAD control][inter_pad][AEAD payload].

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	Version6 = 6

	v6SaltLen      = 16
	v6KeyLen       = 32
	v6CtrlPlainLen = 7
	v6CtrlWireLen  = v6CtrlPlainLen + 16
	v6RecordType   = 0x04
	v6MaxPayload   = 0xffff
)

// V6Mode is the Snell v6 wire mode (must match on client and server).
type V6Mode uint8

const (
	V6ModeDefault   V6Mode = 0
	V6ModeUnshaped  V6Mode = 1
	V6ModeUnsafeRaw V6Mode = 2
)

func ParseV6Mode(s string) (V6Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "default":
		return V6ModeDefault, nil
	case "unshaped":
		return V6ModeUnshaped, nil
	case "unsafe-raw":
		return V6ModeUnsafeRaw, nil
	default:
		return V6ModeDefault, fmt.Errorf("invalid snell v6 mode: %s", s)
	}
}

func (m V6Mode) String() string {
	switch m {
	case V6ModeDefault:
		return "default"
	case V6ModeUnshaped:
		return "unshaped"
	case V6ModeUnsafeRaw:
		return "unsafe-raw"
	default:
		return fmt.Sprintf("mode(%d)", uint8(m))
	}
}

// V6ServerError is the error frame returned by a Snell server after a tunnel
// has been established.
type V6ServerError struct {
	Status byte
	Reason string
}

func (e *V6ServerError) Error() string {
	return fmt.Sprintf("server reported code: %d, message: %s", e.Status, e.Reason)
}

type v6Conn struct {
	net.Conn
	psk     []byte
	profile *v6Profile
	mode    V6Mode
	server  bool

	writeMu sync.Mutex
	readMu  sync.Mutex

	txStarted   bool
	txKey       []byte
	txAEAD      cipher.AEAD
	txSalt      [16]byte
	txNonce     uint64
	txSeq       uint32
	txTarget    uint16
	txLastWrite int64

	rxStarted bool
	rxKey     []byte
	rxAEAD    cipher.AEAD
	rxNonce   uint64
	rxSeq     uint32
	rxReader  *bufio.Reader
	rxPending []byte
	rxStatus  bool
}

func newV6Conn(conn net.Conn, psk []byte, mode V6Mode, server bool) *v6Conn {
	return &v6Conn{
		Conn:    conn,
		psk:     append([]byte(nil), psk...),
		profile: getV6Profile(psk),
		mode:    mode,
		server:  server,
	}
}

// StreamConnV6 wraps a client-side net.Conn with the Snell v6 record layer.
func StreamConnV6(conn net.Conn, psk []byte, mode V6Mode) *Snell {
	return &Snell{Conn: newV6Conn(conn, psk, mode, false), reply: true}
}

// ServerStreamConnV6 wraps a server-side net.Conn with the Snell v6 record layer.
func ServerStreamConnV6(conn net.Conn, psk []byte, mode V6Mode) *Snell {
	return &Snell{Conn: newV6Conn(conn, psk, mode, true), reply: true}
}

func v6DeriveKey(psk, salt []byte) []byte {
	return argon2.IDKey(psk, salt, 3, 8, 1, v6KeyLen)
}

func v6MakeNonce(counter uint64) [12]byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[:8], counter)
	return nonce
}

func (c *v6Conn) initTx() error {
	if c.txStarted {
		return nil
	}
	var realSalt [16]byte
	if _, err := io.ReadFull(rand.Reader, realSalt[:]); err != nil {
		return err
	}
	key := v6DeriveKey(c.psk, realSalt[:])
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	c.txKey = key
	c.txAEAD = aead
	c.txStarted = true
	c.txSalt = realSalt
	return nil
}

func (c *v6Conn) buildSaltPart() []byte {
	switch c.mode {
	case V6ModeDefault:
		block := make([]byte, c.profile.saltBlockLen)
		c.profile.saltObfuscate(c.txSalt, block)
		return block
	case V6ModeUnshaped:
		return append([]byte(nil), c.txSalt[:]...)
	default:
		return nil
	}
}

func (c *v6Conn) saltLenForPrior() int {
	switch c.mode {
	case V6ModeDefault:
		return c.profile.saltBlockLen
	case V6ModeUnshaped:
		return v6SaltLen
	default:
		return 0
	}
}

// writeSaltAndFirst sends the client handshake (salt + chunk 0).
func (c *v6Conn) writeSaltAndFirst(payload []byte, prior int) error {
	saltPart := c.buildSaltPart()
	rec := c.encodeChunk(c.txSeq, payload, prior)
	c.txSeq++
	if c.mode == V6ModeDefault {
		c.profile.chunkReset(&c.txTarget)
	}
	buf := make([]byte, 0, len(saltPart)+len(rec))
	buf = append(buf, saltPart...)
	buf = append(buf, rec...)
	if _, err := c.Conn.Write(buf); err != nil {
		return err
	}
	if c.mode == V6ModeDefault {
		c.profile.chunkAdvance(&c.txTarget)
	}
	return nil
}

// WriteRequestHeader sends the client handshake (salt + chunk 0).
func (c *v6Conn) WriteRequestHeader(host string, port uint, cmd byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.server {
		return errors.New("snell v6: server cannot send request header")
	}
	if c.txStarted {
		return errors.New("snell v6: request header already sent")
	}
	if err := c.initTx(); err != nil {
		return err
	}
	if len(host) > 255 {
		return fmt.Errorf("snell v6: target hostname too long: %d", len(host))
	}
	hdr := make([]byte, 0, 3+len(host)+2)
	hdr = append(hdr, 0x01, cmd, 0x00)
	if cmd != 0x06 {
		hdr = append(hdr, byte(len(host)))
		hdr = append(hdr, host...)
		hdr = append(hdr, byte(port>>8), byte(port))
	}
	return c.writeSaltAndFirst(hdr, c.saltLenForPrior())
}

// writeServerFirstPass sends the server salt block followed by the first
// response record(s). The caller holds writeMu.
func (c *v6Conn) writeServerFirstPass(b []byte) (int, error) {
	if err := c.initTx(); err != nil {
		return 0, err
	}
	if c.mode == V6ModeDefault {
		c.profile.chunkReset(&c.txTarget)
	}
	saltPart := c.buildSaltPart()
	out := make([]byte, 0, len(saltPart)+len(b)+1024)
	out = append(out, saltPart...)
	written := 0
	first := true
	if len(b) == 0 {
		// The first server->client payload must carry the status byte.
		// A direct empty first write becomes a status-only record, not a
		// zero-trunk (which would look like EOF before the status).
		rec := c.encodeChunk(c.txSeq, []byte{0x00}, len(saltPart))
		c.txSeq++
		out = append(out, rec...)
		if c.mode == V6ModeDefault {
			c.profile.chunkAdvance(&c.txTarget)
		}
	}
	for written < len(b) {
		chunk := len(b) - written
		if c.mode == V6ModeDefault {
			want := c.profile.chunkLen(c.txSeq, chunk, &c.txTarget)
			if chunk > want {
				chunk = want
			}
		} else if chunk > 0x3fff {
			chunk = 0x3fff
		}
		prior := 0
		if first {
			prior = len(saltPart)
			first = false
		}
		rec := c.encodeChunk(c.txSeq, b[written:written+chunk], prior)
		c.txSeq++
		out = append(out, rec...)
		written += chunk
		if c.mode == V6ModeDefault {
			c.profile.chunkAdvance(&c.txTarget)
		}
	}
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	c.txLastWrite = time.Now().Unix()
	return len(b), nil
}

func (c *v6Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.server && !c.txStarted {
		if len(b) == 0 {
			return c.writeServerFirstPass(nil)
		}
		return c.writeServerFirstPass(b)
	}
	if !c.txStarted {
		return 0, errors.New("snell v6: write before handshake")
	}
	if len(b) == 0 {
		rec := c.encodeChunk(c.txSeq, nil, 0)
		c.txSeq++
		if _, err := c.Conn.Write(rec); err != nil {
			return 0, err
		}
		return 0, nil
	}

	if c.mode == V6ModeDefault {
		now := time.Now().Unix()
		if c.txLastWrite != 0 && now-c.txLastWrite > int64(c.profile.idleGapS) {
			c.txTarget = uint16(c.profile.chunkMin)
		}
		c.txLastWrite = now
	}

	var out []byte
	written := 0
	for written < len(b) {
		chunk := len(b) - written
		if c.mode == V6ModeDefault {
			want := c.profile.chunkLen(c.txSeq, chunk, &c.txTarget)
			if chunk > want {
				chunk = want
			}
		} else if chunk > 0x3fff {
			chunk = 0x3fff
		}
		rec := c.encodeChunk(c.txSeq, b[written:written+chunk], 0)
		c.txSeq++
		out = append(out, rec...)
		written += chunk
		if c.mode == V6ModeDefault {
			c.profile.chunkAdvance(&c.txTarget)
		}
	}
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

// WritePacketFrame sends exactly one datagram as one v6 chunk.
func (c *v6Conn) WritePacketFrame(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(b) == 0 {
		return 0, errors.New("snell v6 empty UDP datagram")
	}
	if c.mode != V6ModeDefault && len(b) > 0x3fff {
		return 0, errors.New("snell v6 UDP datagram too large for non-default mode")
	}
	if c.server && !c.txStarted {
		if err := c.initTx(); err != nil {
			return 0, err
		}
		if len(b) > v6MaxPayload {
			return 0, errors.New("snell v6 frame too large")
		}
		saltPart := c.buildSaltPart()
		rec := c.encodeChunk(c.txSeq, b, len(saltPart))
		c.txSeq++
		buf := make([]byte, 0, len(saltPart)+len(rec))
		buf = append(buf, saltPart...)
		buf = append(buf, rec...)
		if _, err := c.Conn.Write(buf); err != nil {
			return 0, err
		}
		c.txLastWrite = time.Now().Unix()
		return len(b), nil
	}
	if !c.txStarted {
		return 0, errors.New("snell v6: write before handshake")
	}
	if len(b) > v6MaxPayload {
		return 0, errors.New("snell v6 frame too large")
	}
	rec := c.encodeChunk(c.txSeq, b, 0)
	c.txSeq++
	if _, err := c.Conn.Write(rec); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *v6Conn) encodeChunk(seq uint32, payload []byte, prior int) []byte {
	if c.mode == V6ModeUnsafeRaw {
		out := make([]byte, 7+len(payload))
		out[0] = v6RecordType
		binary.BigEndian.PutUint16(out[5:7], uint16(len(payload)))
		copy(out[7:], payload)
		return out
	}
	prefixLen := 0
	padLen := 0
	if c.mode == V6ModeDefault {
		prefixLen = c.profile.prefixLen(seq)
		padLen = c.profile.interPadLen(seq, len(payload), prior)
	}
	out := make([]byte, 0, prefixLen+v6CtrlWireLen+padLen+len(payload)+16)
	prefix := make([]byte, prefixLen)
	c.profile.fillPad(seq, prefix)
	out = append(out, prefix...)

	var ctl [v6CtrlPlainLen]byte
	ctl[0] = v6RecordType
	binary.BigEndian.PutUint16(ctl[3:5], uint16(padLen))
	binary.BigEndian.PutUint16(ctl[5:7], uint16(len(payload)))
	nonce := v6MakeNonce(c.txNonce)
	c.txNonce++
	out = append(out, c.txAEAD.Seal(nil, nonce[:], ctl[:], prefix)...)

	pad := make([]byte, padLen)
	c.profile.fillPad(seq, pad)
	if len(payload) == 0 {
		// Zero-length record ("zero trunk"): control record + inter_pad only.
		// There is no payload AEAD record and no extra nonce/tag.
		out = append(out, pad...)
		return out
	}
	nonce = v6MakeNonce(c.txNonce)
	c.txNonce++
	payloadCipher := c.txAEAD.Seal(nil, nonce[:], payload, pad)
	if padLen > 0 {
		c.profile.deinterleave(seq, pad, payloadCipher)
	}
	out = append(out, pad...)
	out = append(out, payloadCipher...)
	return out
}

func (c *v6Conn) initRx() error {
	if c.rxStarted {
		return nil
	}
	c.rxReader = bufio.NewReaderSize(c.Conn, 64*1024)
	if c.mode == V6ModeUnsafeRaw {
		c.rxStarted = true
		return nil
	}
	var realSalt [16]byte
	if c.mode == V6ModeDefault {
		block := make([]byte, c.profile.saltBlockLen)
		if _, err := io.ReadFull(c.rxReader, block); err != nil {
			return err
		}
		realSalt = c.profile.saltDeobfuscate(block)
	} else {
		if _, err := io.ReadFull(c.rxReader, realSalt[:]); err != nil {
			return err
		}
	}
	key := v6DeriveKey(c.psk, realSalt[:])
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	c.rxKey = key
	c.rxAEAD = aead
	c.rxStarted = true
	return nil
}

func (c *v6Conn) readRecord() ([]byte, error) {
	if c.mode == V6ModeUnsafeRaw {
		var hdr [7]byte
		if _, err := io.ReadFull(c.rxReader, hdr[:]); err != nil {
			return nil, err
		}
		if hdr[0] != v6RecordType || hdr[1] != 0 || hdr[2] != 0 || hdr[3] != 0 || hdr[4] != 0 {
			return nil, errors.New("snell v6 invalid raw frame header")
		}
		n := int(binary.BigEndian.Uint16(hdr[5:7]))
		if n == 0 {
			c.rxSeq++
			return nil, io.EOF
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(c.rxReader, payload); err != nil {
			return nil, err
		}
		c.rxSeq++
		return payload, nil
	}

	prefixLen := 0
	if c.mode == V6ModeDefault {
		prefixLen = c.profile.prefixLen(c.rxSeq)
	}
	prefix := make([]byte, prefixLen)
	if _, err := io.ReadFull(c.rxReader, prefix); err != nil {
		return nil, err
	}
	ctlCipher := make([]byte, v6CtrlWireLen)
	if _, err := io.ReadFull(c.rxReader, ctlCipher); err != nil {
		return nil, err
	}
	nonce := v6MakeNonce(c.rxNonce)
	ctl, err := c.rxAEAD.Open(nil, nonce[:], ctlCipher, prefix)
	if err != nil || len(ctl) != v6CtrlPlainLen || ctl[0] != v6RecordType {
		return nil, errors.New("snell v6 invalid control record")
	}
	padLen := int(binary.BigEndian.Uint16(ctl[3:5]))
	payloadLen := int(binary.BigEndian.Uint16(ctl[5:7]))
	if payloadLen == 0 {
		if padLen > 0 {
			discard := make([]byte, padLen)
			if _, err := io.ReadFull(c.rxReader, discard); err != nil {
				return nil, err
			}
		}
		c.rxNonce++
		c.rxSeq++
		return nil, io.EOF
	}
	body := make([]byte, padLen+payloadLen+16)
	if _, err := io.ReadFull(c.rxReader, body); err != nil {
		return nil, err
	}
	pad := body[:padLen]
	payloadCipher := body[padLen:]
	c.profile.deinterleave(c.rxSeq, pad, payloadCipher)
	nonce = v6MakeNonce(c.rxNonce + 1)
	payload, err := c.rxAEAD.Open(nil, nonce[:], payloadCipher, pad)
	if err != nil {
		return nil, errors.New("snell v6 invalid payload record")
	}
	c.rxNonce += 2
	c.rxSeq++
	return payload, nil
}

func (c *v6Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if err := c.initRx(); err != nil {
		return 0, err
	}
	for len(c.rxPending) == 0 {
		payload, err := c.readRecord()
		if err != nil {
			return 0, err
		}
		if !c.server && !c.rxStatus {
			if len(payload) == 0 {
				continue
			}
			c.rxStatus = true
			if payload[0] != 0x00 {
				status := payload[0]
				reason := ""
				if payload[0] == 0x02 && len(payload) >= 2 {
					status = payload[1]
					if len(payload) >= 3 {
						n := int(payload[2])
						if 3+n <= len(payload) {
							reason = string(payload[3 : 3+n])
						}
					}
				}
				return 0, &V6ServerError{Status: status, Reason: reason}
			}
			payload = payload[1:]
			if len(payload) == 0 {
				continue
			}
		}
		c.rxPending = payload
	}
	n := copy(b, c.rxPending)
	c.rxPending = c.rxPending[n:]
	return n, nil
}

func (c *v6Conn) Close() error { return c.Conn.Close() }

// CloseWrite sends a zero-length v6 record (half-close) without closing the TCP
// connection, so the peer can still send its remaining response.
func (c *v6Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if !c.txStarted {
		return c.Conn.Close()
	}
	rec := c.encodeChunk(c.txSeq, nil, 0)
	c.txSeq++
	_, err := c.Conn.Write(rec)
	return err
}

// WriteV6Header writes the Snell v6 request header for a TCP CONNECT command.
func WriteV6Header(s *Snell, host string, port uint, cmd byte) error {
	c, ok := s.Conn.(*v6Conn)
	if !ok {
		return errors.New("snell v6: invalid connection type")
	}
	return c.WriteRequestHeader(host, port, cmd)
}

// WriteV6UDPHeader writes the Snell v6 request header for native UDP mode.
func WriteV6UDPHeader(s *Snell) error {
	c, ok := s.Conn.(*v6Conn)
	if !ok {
		return errors.New("snell v6: invalid connection type")
	}
	return c.WriteRequestHeader("", 0, 0x06)
}
