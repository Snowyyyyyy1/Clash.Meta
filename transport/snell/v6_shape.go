package snell

// Pad-content shaping, inter-pad length pipeline and de-interleave for Snell v6.

var v6GFTable = [128]byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
	0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18, 0x24,
	0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70, 0xe0,
	0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78, 0xf0,
	0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f, 0x1f,
	0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9, 0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7, 0xdb,
	0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f, 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f,
}

func v6StreamFill(p *v6Profile, sel, seq uint32, dest []byte) {
	g := p.prng.sCtxA8
	if sel == 2 {
		g = p.prng.sCtx120
	}
	s := (uint64(0xb57de1f3f82cb33f) + uint64(seq)*0xd6e8feb86659fd93) ^
		(uint64(sel) * 0xa24baed4963ee407) ^
		(uint64(uint32(len(dest)))*0x165667b19e3779f9 + 0x0d4cd3e7b14a36d7) ^
		g
	for off := 0; off < len(dest); {
		s += 0x9e3779b97f4a7c15
		w := v6Splitmix64(s)
		for b := 0; b < 8 && off < len(dest); b, off = b+1, off+1 {
			dest[off] = byte(w >> (8 * b))
		}
	}
}

func v6MapByte(b byte, lo, hi int) byte {
	if hi <= lo {
		return byte(lo)
	}
	return byte(lo + int(b)%(hi-lo+1))
}

func (p *v6Profile) fillPad(seq uint32, dest []byte) {
	if len(dest) <= 0 {
		return
	}
	v6StreamFill(p, 0, seq, dest)
	switch p.padMode {
	case 2:
		o := p.padM2Off
		for i := range dest {
			a := dest[i]
			low := ((int(a&0x0f) + (i & 1) + o) % 10)
			high := ((int(a>>4) + (i & 3) + 3) & 0x0f)
			dest[i] = byte((high << 4) | low)
		}
	case 1:
		w := p.padM1WA + p.padM1WB + p.padM1WC
		if w <= 0 {
			w = 1
		}
		for i := range dest {
			b := dest[i]
			rem := int(b) % w
			if rem < p.padM1WA {
				dest[i] = v6MapByte(byte(int(b)+i), 0x20, 0x7e)
			} else if rem < p.padM1WA+p.padM1WB {
				dest[i] = v6MapByte(byte(int(b)^i), 0x80, 0xbf)
			} else {
				dest[i] = v6MapByte(byte(int(b)+i*7), 0xc0, 0xff)
			}
		}
	case 0:
		v := int(v6RangeMap(p.prng.prng(1, seq, 0), uint16(p.padM0Step), uint16(p.padM0Span)))
		e := (v & 0xff) << 3
		k := 1
		if e > 0x31 {
			k = (e + 0x32) / 100
		}
		if e > 0x2ed {
			k = 7
		}
		if k < 1 {
			k = 1
		}
		if k > 7 {
			k = 7
		}
		for i := range dest {
			a := dest[i]
			ed := (i + int(a)) & 0xff
			tv := v6GFTable[k*16+((ed^int(a))&0x0f)]
			c := ((int(a) >> 4) ^ ed) & 7
			if c != 0 {
				dest[i] = (tv << c) | (tv >> (8 - c))
			} else {
				dest[i] = tv
			}
		}
	case 3:
		period := p.padM3Period
		if period < 5 {
			period = 5
		}
		a := p.padM3Base
		g := a * 4
		if g > 0x20 {
			g = 0x20
		}
		if g < 1 {
			g = 1
		}
		scratch := make([]byte, 32)
		v6StreamFill(p, 2, seq, scratch)
		for i := range dest {
			m := i % period
			if m < period-3 {
				dest[i] = byte(((a + 3) * i) ^ int(scratch[i%g]))
			} else if m == period-1 {
				// keep base byte
			} else {
				dest[i] = byte(0x30 + int(dest[i])%10)
			}
		}
	}
}

func (p *v6Profile) iplCadence(seq uint32, payload int) bool {
	warmup := v6RangeMap(p.prng.prng(0x09, 0, 0), 2, 8)
	if warmup > seq {
		return true
	}
	if p.cadencePeriod != 0 && seq%uint32(p.cadencePeriod) == 0 {
		return true
	}
	if payload != 0 {
		return uint64(payload) <= uint64(uint32(p.cadencePayloadMax))
	}
	return false
}

func (p *v6Profile) iplStage1(seq uint32, payload int) int {
	if !p.iplCadence(seq, payload) {
		return 0
	}
	return int(v6RangeMap(p.prng.prng(0x22, seq, uint32(payload)), uint16(p.interLo), uint16(p.interHi)))
}

func (p *v6Profile) iplStage2(seq uint32, total uint64) int {
	if total > 0x5b3 {
		if total <= 0xfffe {
			return int(total)
		}
		return 0xffff
	}
	var r10, r11 uint32
	if uint32(p.interWarmupSeqs) > seq {
		r10 = uint32(p.interSzSeq[seq])
	} else {
		r10 = uint32(p.interSzRand[p.prng.prng(0x23, seq, uint32(total))%8])
	}
	if p.interJitterMode == 2 {
		pv := p.prng.prng(0x24, seq, 0)
		den := 2*uint32(p.interJitterSpan) + 1
		jit := int(pv%den) - p.interJitterSpan
		eax := int(uint16(r10)) + jit
		edx := int(r10) + jit
		if eax > 0 {
			r10 = uint32(edx)
		} else {
			r10 = 1
		}
	}
	div100 := (uint64(uint32(p.interTargetPct)) * total) / 100
	if uint32(0x2da) >= uint32(div100) {
		r11 = uint32(div100)
	} else {
		r11 = 0x2da
	}
	if p.prng.prng(0x23, seq, r11)&1 != 0 {
		dx := uint16(r11) >> 1
		if uint16(r10) > dx {
			r10 -= uint32(dx)
		}
	} else {
		sum := r11 + uint32(uint16(r10))
		if sum <= 0xffff {
			r10 += r11
		} else {
			r10 = 0xffffffff
		}
	}
	for uint64(uint16(r10)) < total {
		tv := uint16(p.interSzRand[p.prng.prng(0x25, seq, r10)%8])
		if uint16(r10) >= tv {
			r11 += uint32(p.interHi)
			r10 += uint32(p.interHi)
			if int32(r11) > 0xffff {
				r10 = 0xffffffff
			}
		} else {
			r10 = uint32(tv)
		}
	}
	return int(r10)
}

func (p *v6Profile) interPadLen(seq uint32, payload, prior int) int {
	s1 := p.iplStage1(seq, payload)
	pfx := p.prefixLen(seq)
	ovh := 0
	if payload != 0 {
		ovh = 0x10
	}
	total := uint64(s1) + uint64(payload+0x17) + uint64(pfx) + uint64(ovh) + uint64(prior)
	s2 := p.iplStage2(seq, total)
	inter := s1
	if total < uint64(uint32(s2)) {
		gap := uint64(uint32(s2)) - total
		if gap < 0x2da {
			inter = s1 + int(gap)
		} else {
			inter = s1 + 0x2da
		}
	}
	return int(uint16(inter))
}

func (p *v6Profile) deinterleave(seq uint32, a, b []byte) {
	if len(a) <= 0 || len(b) <= 0 {
		return
	}
	l := len(a)
	if len(b) < l {
		l = len(b)
	}
	if p.deintMode == 1 {
		blockLen := p.deintBlockLen
		if blockLen <= 0 {
			blockLen = 1
		}
		nblk := l / blockLen
		for k := 0; k < p.deintRounds; k++ {
			parity := k & 1
			for i := parity; i < nblk; i += 2 {
				ao := i * blockLen
				for j := 0; j < blockLen; j++ {
					a[ao+j], b[ao+j] = b[ao+j], a[ao+j]
				}
			}
		}
		return
	}
	for r := 0; r < p.deintRounds; r++ {
		stride := p.strideBase + (r % 3)
		if stride <= 0 {
			stride = 1
		}
		var phase int
		if p.deintMode == 2 {
			pv := p.prng.prng(3, seq, uint32(r))
			phase = int((uint64(pv) + uint64(uint32(p.phaseSeed))) % uint64(uint32(stride)))
		} else {
			phase = p.phaseSeed % stride
		}
		for j := phase; j < l; j += stride {
			a[j], b[j] = b[j], a[j]
		}
	}
}
