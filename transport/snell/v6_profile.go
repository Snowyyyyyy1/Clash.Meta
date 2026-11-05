package snell

// Snell v6 traffic-shaping profile. Everything in this file is derived
// deterministically from the PSK and mirrors the reference server's PRNG and
// shaping pipeline (see snell-v6-poc/PROTOCOL.md and snell_shape.c).

import (
	"encoding/binary"
	"sync"

	"golang.org/x/crypto/blake2b"
)

var v6SeedPrefix = [24]byte{
	0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb,
	0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18, 0xc0, 0x6e,
	0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
}

type v6PRNG struct {
	seed    [32]byte
	sCtx60  uint64
	sCtxA8  uint64
	sCtxC0  uint64
	sCtx108 uint64
	sCtx120 uint64
	sCtx138 uint64
	sCtxE8  uint64
}

func v6Splitmix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func v6Rotl64(x uint64, c uint) uint64 { return (x << c) | (x >> (64 - c)) }
func v6Rotr64(x uint64, c uint) uint64 { return (x >> c) | (x << (64 - c)) }

func v6SeedWord(seed *[32]byte, i int) uint64 {
	return binary.LittleEndian.Uint64(seed[i*8 : i*8+8])
}

func v6Subseed(seed *[32]byte, idx uint32, k uint64) uint64 {
	s0 := v6SeedWord(seed, 0)
	s1 := v6SeedWord(seed, 1)
	s2 := v6SeedWord(seed, 2)
	s3 := v6SeedWord(seed, 3)
	x := uint64(idx)*0xd6e8feb86659fd93 ^
		(k + 0xa0761d6478bd642f) ^
		s0 ^
		(s1 + 0x9e3779b97f4a7c15) ^
		v6Rotl64(s2, 17) ^
		v6Rotr64(s3, 11)
	return v6Splitmix64(x)
}

func newV6PRNG(psk []byte) *v6PRNG {
	p := &v6PRNG{}
	if len(psk) > 512 {
		psk = psk[:512]
	}
	h, _ := blake2b.New256(nil)
	_, _ = h.Write(v6SeedPrefix[:])
	_, _ = h.Write(psk)
	copy(p.seed[:], h.Sum(nil))

	p.sCtxC0 = v6Subseed(&p.seed, 5, 0xb46c2e7d9a1538f1)
	p.sCtxA8 = v6Subseed(&p.seed, 0, 0x5d9217c083e64ab9)
	p.sCtx120 = v6Subseed(&p.seed, 2, 0xa71f0c54d8396e2b)
	p.sCtxE8 = v6Subseed(&p.seed, 3, 0x3e8a91b52740f6cd)
	p.sCtx60 = v6Subseed(&p.seed, 0x10, 0xc9f4260b7d1e835a)
	p.sCtx108 = v6Subseed(&p.seed, 0x15, 0x62d0b5e19c4a783f)
	p.sCtx138 = v6Subseed(&p.seed, 0x1c, 0x917b3c48e6a205d4)
	return p
}

func (p *v6PRNG) getter(sel uint32) uint64 {
	switch sel {
	case 0, 1, 14, 15, 33, 34:
		return p.sCtxA8
	case 2:
		return p.sCtx120
	case 3, 16, 17, 18, 19, 20:
		return p.sCtx60
	case 21, 22, 23, 24, 25, 26, 38, 39:
		return p.sCtx108
	case 28, 29, 30, 31, 32, 35, 36, 37:
		return p.sCtx138
	default:
		return p.sCtxC0
	}
}

func v6Wymix(a uint64, sel, seq, round uint32) uint32 {
	rcx := uint64(round)*0x589965cc75374cc3 + 0x33a213ec50ffe2e9
	rsi := uint64(sel) * 0x9e3779b97f4a7c15
	rdx := uint64(seq)*0xe7037ed1a0b428db + 0x8f3907f7b2b80c35
	s := v6Splitmix64(a ^ rcx ^ rsi ^ rdx)
	return uint32(s ^ (s >> 32))
}

func (p *v6PRNG) prng(sel, seq, round uint32) uint32 {
	return v6Wymix(p.getter(sel), sel, seq, round)
}

func v6RangeMap(v uint32, lo, hi uint16) uint32 {
	if hi <= lo {
		return uint32(lo)
	}
	return uint32(lo) + v%(uint32(hi)-uint32(lo)+1)
}

type v6Profile struct {
	// salt obfuscation
	saltS        [16]byte
	saltPRF      [16]byte
	saltBlockLen int

	// de-interleave / shaping
	deintMode     int
	deintRounds   int
	strideBase    int
	phaseSeed     int
	deintBlockLen int
	padLo         uint16
	padHi         uint16

	// pad-content shaping
	padMode     int
	padM0Step   int
	padM0Span   int
	padM1WA     int
	padM1WB     int
	padM1WC     int
	padM2Off    int
	padM3Period int
	padM3Base   int

	// chunk-size selection
	chunkMode   int
	chunkMax    int
	chunkMin    int
	chunkJitter int
	chunkGrow   int
	chunkHist   [8]int

	// inter-pad cadence and length pipeline
	cadencePeriod     int
	cadencePayloadMax int
	interLo           int
	interHi           int
	interSzRand       [8]int
	interSzSeq        [8]int
	interJitterMode   int
	interWarmupSeqs   int
	interJitterSpan   int
	interTargetPct    int
	idleGapS          int

	prng v6PRNG
}

var v6ProfileCache sync.Map // string(psk) -> *v6Profile

func getV6Profile(psk []byte) *v6Profile {
	key := string(psk)
	if v, ok := v6ProfileCache.Load(key); ok {
		return v.(*v6Profile)
	}
	p := newV6Profile(psk)
	actual, _ := v6ProfileCache.LoadOrStore(key, p)
	return actual.(*v6Profile)
}

func newV6Profile(psk []byte) *v6Profile {
	p := &v6Profile{}
	p.prng = *newV6PRNG(psk)

	p.padLo = uint16(v6RangeMap(p.prng.prng(0x0e, 0, 0), 8, 0x50))
	p.padHi = uint16(uint32(p.padLo) + v6RangeMap(p.prng.prng(0x0f, 0, 0), 0x10, 0xa0))
	if p.padHi > 0x80 {
		p.padHi = 0x80
	}
	if p.padLo > p.padHi {
		p.padLo = p.padHi
	}

	p.deintMode = int(p.prng.prng(0x10, 0, 0) % 3)
	p.deintRounds = int(v6RangeMap(p.prng.prng(0x11, 0, 0), 1, 3))
	p.strideBase = int(v6RangeMap(p.prng.prng(0x12, 0, 0), 2, 0x0d))
	p.phaseSeed = int(v6RangeMap(p.prng.prng(0x13, 0, 0), 0, 0x0f))
	p.deintBlockLen = int(v6RangeMap(p.prng.prng(0x14, 0, 0), 8, 0x40))

	p.padMode = int(p.prng.prng(0x06, 0, 0) & 3)
	p.padM1WA = int(v6RangeMap(p.prng.prng(0x06, 0, 1), 0x18, 0x80))
	p.padM1WB = int(v6RangeMap(p.prng.prng(0x06, 0, 2), 0x10, 0x60))
	p.padM1WC = int(v6RangeMap(p.prng.prng(0x06, 0, 3), 0x10, 0x60))
	p.padM2Off = int(v6RangeMap(p.prng.prng(0x06, 0, 4), 0, 9))
	p.padM3Base = int(v6RangeMap(p.prng.prng(0x06, 0, 5), 1, 8))
	p.padM3Period = int(v6RangeMap(p.prng.prng(0x06, 0, 6), 7, 0x17))
	p.padM0Step = int(v6RangeMap(p.prng.prng(0x0c, 0, 0), 0x18, 0x29))
	p.padM0Span = int(v6RangeMap(p.prng.prng(0x0d, 0, 0), 0x3a, 0x4c))

	p.chunkMode = int(p.prng.prng(0x15, 0, 0) % 3)
	p.chunkMax = int(v6RangeMap(p.prng.prng(0x17, 0, 0), 0x2000, 0x3fff))
	p.chunkMin = int(v6RangeMap(p.prng.prng(0x16, 0, 0), 0x200, 0x5b4))
	p.chunkJitter = int(v6RangeMap(p.prng.prng(0x19, 0, 0), 0x10, 0xc0))
	if p.chunkJitter > 0xb6 {
		p.chunkJitter = 0xb6
	}
	for i := 0; i < 8; i++ {
		v := int(v6RangeMap(p.prng.prng(0x1a, 0, uint32(i)), 0x1000, uint16(p.chunkMax)))
		if v < 0x400 {
			v = 0x1000
		}
		p.chunkHist[i] = v
	}
	p.chunkGrow = int(v6RangeMap(p.prng.prng(0x18, 0, 0), 0x400, 0x1000))
	if p.chunkGrow > 0xb68 {
		p.chunkGrow = 0xb68
	}
	p.cadencePeriod = int(v6RangeMap(p.prng.prng(0x0a, 0, 0), 2, 0x0b))
	p.cadencePayloadMax = int(v6RangeMap(p.prng.prng(0x0b, 0, 0), 0x60, 0x300))

	s07 := int(v6RangeMap(p.prng.prng(0x07, 0, 0), 0x18, 0xa0))
	p.interHi = s07 + int(v6RangeMap(p.prng.prng(0x08, 0, 0), 0xa0, 0x3c0))
	if p.interHi > 0x2da {
		p.interHi = 0x2da
	}
	p.interLo = s07
	if p.interLo > p.interHi {
		p.interLo = p.interHi
	}
	for i := 0; i < 8; i++ {
		p.interSzRand[i] = int(v6RangeMap(p.prng.prng(0x1e, 0, uint32(i)), 0x140, 0x5b4))
	}
	for i := 0; i < 8; i++ {
		p.interSzSeq[i] = int(v6RangeMap(p.prng.prng(0x1f, 0, uint32(i)), 0x168, 0x5b4))
	}
	p.interJitterMode = int(p.prng.prng(0x1c, 0, 0) % 3)
	p.interWarmupSeqs = int(v6RangeMap(p.prng.prng(0x1d, 0, 0), 4, 8))
	p.interJitterSpan = int(v6RangeMap(p.prng.prng(0x20, 0, 0), 8, 0x60))
	p.interTargetPct = int(v6RangeMap(p.prng.prng(0x1c, 0, 0x504c), 8, 0x30))
	p.idleGapS = int(v6RangeMap(p.prng.prng(0x1b, 0, 0), 0xc, 0x5a))

	p.saltBlockLen = p.deriveSalt()
	return p
}

// deriveSalt computes block_len, S[16], PRF[16] (snell_salt.c).
func (p *v6Profile) deriveSalt() int {
	saltPrng := func(sel, arg uint32) uint32 { return p.prng.prng(sel, 0, arg) }
	blkLo := uint16(v6RangeMap(saltPrng(0x0e, 0x7053), 0x10, 0x60))
	blkHi := uint16(uint32(blkLo) + v6RangeMap(saltPrng(0x0f, 0x7053), 0x10, 0xa0))
	if blkHi > 0x80 {
		blkHi = 0x80
	}
	if blkLo > blkHi {
		blkLo = blkHi
	}
	ksaRounds := int(v6RangeMap(saltPrng(0x11, 0x51a7), 1, 4))
	multiplier := uint8(v6RangeMap(saltPrng(0x12, 0x51a7), 0x11, 0xfb))
	blockLen := int(0x10 + v6RangeMap(saltPrng(0x21, 0x7053), blkLo, blkHi))

	perm := make([]byte, blockLen)
	for i := range perm {
		perm[i] = byte(i)
	}
	state := p.prng.sCtxE8
	for r := 0; r < ksaRounds; r++ {
		salt := uint32(0x51a7 + r)
		for j := 0; j < blockLen; j++ {
			pick := j + int(v6KSAprf(state, salt, uint32(j))%uint32(blockLen-j))
			perm[j], perm[pick] = perm[pick], perm[j]
		}
	}
	for i := 0; i < 16; i++ {
		p.saltS[i] = perm[i]
	}
	for i := uint32(0); i < 16; i++ {
		wmix := v6Wymix(state, 2, 0x51a7, i)
		mul := uint16(uint8(i)) * uint16(multiplier)
		p.saltPRF[i] = byte(mul ^ uint16(wmix))
	}
	return blockLen
}

func v6KSAprf(state uint64, salt, idx uint32) uint32 {
	rdx := uint64(idx)*0x589965cc75374cc3 + 0x33a213ec50ffe2e9
	rdx ^= state ^ 0xdaa66d2c7ddf743f
	rsi := uint64(salt)*0xe7037ed1a0b428db + 0x8f3907f7b2b80c35
	v := v6Splitmix64(rsi ^ rdx)
	return uint32(v ^ (v >> 32))
}

func (p *v6Profile) prefixLen(seq uint32) int {
	return int(v6RangeMap(p.prng.prng(0x21, seq, 0), p.padLo, p.padHi))
}

func (p *v6Profile) saltObfuscate(realSalt [16]byte, block []byte) {
	p.fillPad(0xffffffff, block)
	for i := 0; i < 16; i++ {
		block[p.saltS[i]] = realSalt[i] ^ p.saltPRF[i]
	}
}

func (p *v6Profile) saltDeobfuscate(block []byte) (realSalt [16]byte) {
	for i := 0; i < 16; i++ {
		realSalt[i] = block[p.saltS[i]] ^ p.saltPRF[i]
	}
	return
}

func (p *v6Profile) chunkLen(seq uint32, remaining int, target *uint16) int {
	_ = remaining
	tgt := uint32(*target)
	if tgt == 0 {
		tgt = uint32(p.chunkMin)
	}
	var picked int
	switch p.chunkMode {
	case 1:
		picked = p.chunkHist[p.prng.prng(0x26, seq, tgt)%8]
	case 2:
		span := 2*p.chunkJitter + 1
		off := int(p.prng.prng(0x27, seq, tgt)%uint32(span)) - p.chunkJitter
		val := int(tgt) + off
		if val < 0x40 {
			val = 0x40
		}
		picked = val
	default:
		picked = int(tgt)
	}
	sz := picked
	if sz > p.chunkMax {
		sz = p.chunkMax
	}
	if sz <= 0x3f {
		sz = 0x40
	}
	return sz
}

func (p *v6Profile) chunkAdvance(target *uint16) {
	if *target == 0 {
		*target = uint16(p.chunkMin)
		return
	}
	t := int(*target) + p.chunkGrow
	if t < p.chunkMax {
		*target = uint16(t)
	} else {
		*target = uint16(p.chunkMax)
	}
}

func (p *v6Profile) chunkReset(target *uint16) { *target = uint16(p.chunkMin) }
