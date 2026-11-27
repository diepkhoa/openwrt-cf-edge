package edgefw

import (
	"math/big"
	"net/netip"
	"sort"
	"strings"
)

type bigRange struct {
	start *big.Int
	end   *big.Int
}

// SplitAndMergeCIDRs parses raw CIDR strings into canonical, non-overlapping IPv4 and IPv6 CIDRs.
// Any lines beginning with '#' or blank lines are ignored; malformed CIDRs are returned in invalid.
func SplitAndMergeCIDRs(lines []string) (v4 []string, v6 []string, invalid []string) {
	p4, p6, invalid := parseCIDRLines(lines)
	return mergePrefixes(p4, 32), mergePrefixes(p6, 128), invalid
}

func parseFamilyCIDRs(lines []string, wantV6 bool) ([]string, []string) {
	p4, p6, _ := parseCIDRLines(lines)
	if !wantV6 {
		out := make([]string, len(p4))
		for i, p := range p4 {
			out[i] = p.String()
		}
		return out, nil
	}
	out := make([]string, len(p6))
	for i, p := range p6 {
		out[i] = p.String()
	}
	return nil, out
}

func parseCIDRLines(lines []string) (p4 []netip.Prefix, p6 []netip.Prefix, invalid []string) {
	for _, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if idx := strings.IndexByte(s, '#'); idx >= 0 {
			s = strings.TrimSpace(s[:idx])
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			invalid = append(invalid, s)
			continue
		}
		p = p.Masked()
		if p.Addr().Is4() {
			p4 = append(p4, p)
		} else if p.Addr().Is6() && !p.Addr().Is4In6() {
			p6 = append(p6, p)
		}
	}
	return p4, p6, invalid
}

func mergePrefixes(prefixes []netip.Prefix, width int) []string {
	if len(prefixes) == 0 {
		return nil
	}
	ranges := make([]bigRange, 0, len(prefixes))
	for _, p := range prefixes {
		ranges = append(ranges, prefixToRange(p, width))
	}

	sort.Slice(ranges, func(i, j int) bool {
		if cmp := ranges[i].start.Cmp(ranges[j].start); cmp != 0 {
			return cmp < 0
		}
		return ranges[i].end.Cmp(ranges[j].end) < 0
	})

	merged := make([]bigRange, 0, len(ranges))
	cur := ranges[0]
	one := big.NewInt(1)
	for _, r := range ranges[1:] {
		curNext := new(big.Int).Add(cur.end, one)
		if r.start.Cmp(curNext) <= 0 {
			if r.end.Cmp(cur.end) > 0 {
				cur.end = r.end
			}
			continue
		}
		merged = append(merged, cur)
		cur = r
	}
	merged = append(merged, cur)

	var out []string
	for _, r := range merged {
		out = append(out, rangeToCIDRs(r.start, r.end, width)...)
	}
	return out
}

func prefixToRange(p netip.Prefix, width int) bigRange {
	addrBytes := p.Addr().AsSlice()
	start := new(big.Int).SetBytes(addrBytes)
	hostBits := width - p.Bits()
	size := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	end := new(big.Int).Add(start, size)
	end.Sub(end, big.NewInt(1))
	return bigRange{start: start, end: end}
}

func rangeToCIDRs(start, end *big.Int, width int) []string {
	var out []string
	cur := new(big.Int).Set(start)
	one := big.NewInt(1)

	for cur.Cmp(end) <= 0 {
		maxBit := width
		if cur.Sign() > 0 {
			tz := trailingZeroBits(cur, width)
			if tz < maxBit {
				maxBit = tz
			}
		}
		remaining := new(big.Int).Sub(end, cur)
		remaining.Add(remaining, one)
		remBit := remaining.BitLen() - 1
		if remBit < maxBit {
			maxBit = remBit
		}

		prefixLen := width - maxBit
		addr := intToAddr(cur, width)
		out = append(out, netip.PrefixFrom(addr, prefixLen).String())

		step := new(big.Int).Lsh(one, uint(maxBit))
		cur.Add(cur, step)
	}
	return out
}

func trailingZeroBits(v *big.Int, maxBits int) int {
	for b := 0; b < maxBits; b++ {
		if v.Bit(b) != 0 {
			return b
		}
	}
	return maxBits
}

func intToAddr(v *big.Int, width int) netip.Addr {
	n := width / 8
	buf := make([]byte, n)
	raw := v.Bytes()
	copy(buf[n-len(raw):], raw)
	addr, _ := netip.AddrFromSlice(buf)
	return addr
}
