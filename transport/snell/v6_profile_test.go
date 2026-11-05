package snell

import (
	"fmt"
	"strings"
	"testing"
)

// v6TestProfileString renders the same deterministic fields as the C reference
// harness used to generate the golden vector (snell-v6-poc/vectors.c).
func v6TestProfileString(p *v6Profile) string {
	var b strings.Builder
	fmt.Fprintf(&b, "seed=%x\n", p.prng.seed)
	fmt.Fprintf(&b, "pad_lo=%d pad_hi=%d deint_mode=%d rounds=%d stride=%d phase=%d block=%d\n",
		p.padLo, p.padHi, p.deintMode, p.deintRounds, p.strideBase, p.phaseSeed, p.deintBlockLen)
	fmt.Fprintf(&b, "pad_mode=%d m0step=%d m0span=%d m1=%d,%d,%d m2off=%d m3base=%d m3period=%d\n",
		p.padMode, p.padM0Step, p.padM0Span, p.padM1WA, p.padM1WB, p.padM1WC, p.padM2Off, p.padM3Base, p.padM3Period)
	fmt.Fprintf(&b, "chunk_mode=%d min=%d max=%d grow=%d jitter=%d hist=", p.chunkMode, p.chunkMin, p.chunkMax, p.chunkGrow, p.chunkJitter)
	for i := 0; i < 8; i++ {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%d", p.chunkHist[i])
	}
	b.WriteByte('\n')
	fmt.Fprintf(&b, "cadence_period=%d cadence_payload_max=%d inter_lo=%d inter_hi=%d\n", p.cadencePeriod, p.cadencePayloadMax, p.interLo, p.interHi)
	fmt.Fprintf(&b, "inter_sz_rand=")
	for i := 0; i < 8; i++ {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%d", p.interSzRand[i])
	}
	fmt.Fprintf(&b, "\ninter_sz_seq=")
	for i := 0; i < 8; i++ {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%d", p.interSzSeq[i])
	}
	fmt.Fprintf(&b, "\ninter_jitter_mode=%d warmup=%d span=%d pct=%d idle=%d\n", p.interJitterMode, p.interWarmupSeqs, p.interJitterSpan, p.interTargetPct, p.idleGapS)
	fmt.Fprintf(&b, "salt_block_len=%d salt_S=%x salt_PRF=%x\n", p.saltBlockLen, p.saltS, p.saltPRF)
	fmt.Fprintf(&b, "prefix=")
	for s := uint32(0); s < 8; s++ {
		if s > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%d", p.prefixLen(s))
	}
	fmt.Fprintf(&b, "\ninter=")
	pls := []int{0, 1, 17, 100, 384, 1000, 4096, 16000}
	pris := []int{0, 87}
	for pi := 0; pi < 2; pi++ {
		for i := 0; i < 8; i++ {
			fmt.Fprintf(&b, "%d:%d:%d=%d", pls[i], pris[pi], 0, p.interPadLen(uint32(i), pls[i], pris[pi]))
			if !(pi == 1 && i == 7) {
				b.WriteByte(' ')
			}
		}
	}
	fmt.Fprintf(&b, "\nchunks=")
	var target uint16
	p.chunkReset(&target)
	for i := 0; i < 12; i++ {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%d", p.chunkLen(uint32(i), 16000, &target))
		p.chunkAdvance(&target)
	}
	fmt.Fprintf(&b, "\npad=")
	pad := make([]byte, 64)
	p.fillPad(7, pad)
	fmt.Fprintf(&b, "%x\n", pad)
	a := make([]byte, 48)
	bb := make([]byte, 64)
	for i := 0; i < 48; i++ {
		a[i] = byte(i*3 + 1)
	}
	for i := 0; i < 64; i++ {
		bb[i] = byte(255 - i*2)
	}
	p.deinterleave(5, a, bb)
	fmt.Fprintf(&b, "deintA=%x\ndeintB=%x\n", a, bb)
	return b.String()
}

func TestV6ProfileGolden(t *testing.T) {
	const want = `seed=46631e38dc97f4a79f1a3d00af375b40809b0d2bfe2df8b2ad75f7419e152f93
pad_lo=11 pad_hi=91 deint_mode=0 rounds=3 stride=10 phase=12 block=53
pad_mode=1 m0step=30 m0span=75 m1=126,46,18 m2off=2 m3base=1 m3period=12
chunk_mode=2 min=1170 max=14534 grow=2037 jitter=47 hist=14380 9150 4248 12165 8040 4153 13748 7440
cadence_period=7 cadence_payload_max=304 inter_lo=79 inter_hi=730
inter_sz_rand=384 408 746 1020 564 602 857 633
inter_sz_seq=402 944 1057 584 514 1028 641 706
inter_jitter_mode=0 warmup=6 span=69 pct=24 idle=27
salt_block_len=119 salt_S=20511b4e285e691447153d1056740113 salt_PRF=7560fbf8fdac632ddc664d9179a4c3ad
prefix=61 50 40 65 39 17 77 37
inter=0:0:0=549 1:0:0=793 17:0:0=916 100:0:0=321 384:0:0=990 1000:0:0=694 4096:0:0=433 16000:0:0=220 0:87:0=350 1:87:0=910 17:87:0=819 100:87:0=566 384:87:0=471 1000:87:0=460 4096:87:0=433 16000:87:0=220
chunks=1123 3239 5231 7285 9290 11378 13424 14534 14497 14534 14534 14510
pad=3e33745836bb5e267c8a355739d162da953a8b302b4a5d312e884b8f2a23644b9f6c438966f12d53962b6a5974aa52892d5da0213ebcab7b737740d35c4f7d5c
deintA=fffdfb0a0d101316191c1f22e7282b2e3134373a3d40d3d1cf4c4f5255585b5ebf64bb6ab7707376797cab8285a58b8e
deintB=010407f9f7f5f3f1efedebe925e5e3e1dfdddbd9d7d5434649cdcbc9c7c5c3c161bd67b96db5b3b1afad7fa9a788a3a19f9d9b99979593918f8d8b8987858381
`
	got := v6TestProfileString(newV6Profile([]byte("snell-v6-golden-psk-0001")))
	if got != want {
		t.Fatalf("profile mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestV6ProfileDeterministic(t *testing.T) {
	psk := []byte("v6-determinism-psk-123456")
	a := newV6Profile(psk)
	b := newV6Profile(psk)
	if v6TestProfileString(a) != v6TestProfileString(b) {
		t.Fatal("profile derivation is not deterministic")
	}
	if a.saltBlockLen < 16 || a.saltBlockLen > 160 {
		t.Fatalf("nonsensical salt block length %d", a.saltBlockLen)
	}
}

func TestV6SaltRoundTrip(t *testing.T) {
	for _, psk := range []string{"salt-psk-1-abcdef", "salt-psk-2-abcdef", "salt-psk-3-abcdef"} {
		p := newV6Profile([]byte(psk))
		var real [16]byte
		for i := range real {
			real[i] = byte(i*7 + 3)
		}
		block := make([]byte, p.saltBlockLen)
		p.saltObfuscate(real, block)
		got := p.saltDeobfuscate(block)
		if got != real {
			t.Fatalf("salt round trip failed for %s", psk)
		}
	}
}

func TestV6DeinterleaveInvolution(t *testing.T) {
	for _, psk := range []string{"deint-psk-1-abcdef", "deint-psk-2-abcdef", "deint-psk-3-abcdef"} {
		p := newV6Profile([]byte(psk))
		for _, n := range []int{1, 7, 31, 128, 300} {
			a := make([]byte, n)
			b := make([]byte, n+16)
			for i := range a {
				a[i] = byte(i*11 + 5)
			}
			for i := range b {
				b[i] = byte(i*13 + 7)
			}
			origA := append([]byte(nil), a...)
			origB := append([]byte(nil), b...)
			p.deinterleave(9, a, b)
			p.deinterleave(9, a, b)
			for i := range a {
				if a[i] != origA[i] {
					t.Fatalf("deinterleave not involutive: psk=%s n=%d index=%d", psk, n, i)
				}
			}
			for i := range b {
				if b[i] != origB[i] {
					t.Fatalf("deinterleave not involutive: psk=%s n=%d index=%d", psk, n, i)
				}
			}
		}
	}
}
