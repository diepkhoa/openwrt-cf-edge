package reconcile

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const dnsQueryTimeout = 3 * time.Second

// Outcome classifies the result of querying external DNS resolvers.
type Outcome int

const (
	OutcomeOK Outcome = iota
	OutcomeNXDOMAIN
	OutcomeNODATA
	OutcomeNetError
)

// QueryResult captures the resolved IPs or classification from direct DNS queries.
type QueryResult struct {
	Outcome Outcome
	IPs     []netip.Addr
	Err     error
}

// Resolver queries DNS directly bypassing router local caches.
type Resolver interface {
	Query(ctx context.Context, subdomain, recordType string) QueryResult
}

// DirectResolver sends pure-Go UDP/TCP DNS queries sequentially to configured resolvers.
type DirectResolver struct {
	servers []string
	timeout time.Duration
}

// NewDirectResolver constructs a DirectResolver for server addresses (host:port).
func NewDirectResolver(servers []string, timeout time.Duration) *DirectResolver {
	if timeout <= 0 {
		timeout = dnsQueryTimeout
	}
	return &DirectResolver{
		servers: append([]string(nil), servers...),
		timeout: timeout,
	}
}

// Query queries each configured resolver in order until a definitive answer is received.
func (r *DirectResolver) Query(ctx context.Context, subdomain, recordType string) QueryResult {
	qType := dnsmessage.TypeA
	if strings.EqualFold(recordType, "AAAA") {
		qType = dnsmessage.TypeAAAA
	}
	fqdn := strings.TrimSuffix(subdomain, ".") + "."

	var lastErr error
	for _, srv := range r.servers {
		res := querySingleServer(ctx, srv, fqdn, qType, r.timeout)
		if res.Outcome != OutcomeNetError {
			return res
		}
		lastErr = res.Err
	}
	return QueryResult{Outcome: OutcomeNetError, Err: lastErr}
}

func querySingleServer(ctx context.Context, server, fqdn string, qType dnsmessage.Type, timeout time.Duration) QueryResult {
	name, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return QueryResult{Outcome: OutcomeNetError, Err: err}
	}

	req := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               uint16(time.Now().UnixNano() & 0xffff),
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  qType,
			Class: dnsmessage.ClassINET,
		}},
	}
	wire, err := req.Pack()
	if err != nil {
		return QueryResult{Outcome: OutcomeNetError, Err: err}
	}

	respWire, err := exchangeUDP(ctx, server, wire, timeout)
	if err != nil {
		return QueryResult{Outcome: OutcomeNetError, Err: err}
	}

	msg, ips, outcome, err := parseDNSResponse(respWire, qType)
	if err != nil {
		return QueryResult{Outcome: OutcomeNetError, Err: err}
	}
	if msg.Header.Truncated {
		tcpWire, tcpErr := exchangeTCP(ctx, server, wire, timeout)
		if tcpErr == nil {
			_, tcpIPs, tcpOutcome, parseErr := parseDNSResponse(tcpWire, qType)
			if parseErr == nil {
				return QueryResult{Outcome: tcpOutcome, IPs: tcpIPs}
			}
		}
	}
	return QueryResult{Outcome: outcome, IPs: ips}
}

func exchangeUDP(ctx context.Context, server string, query []byte, timeout time.Duration) ([]byte, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func exchangeTCP(ctx context.Context, server string, query []byte, timeout time.Duration) ([]byte, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func parseDNSResponse(wire []byte, wantType dnsmessage.Type) (dnsmessage.Message, []netip.Addr, Outcome, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(wire); err != nil {
		return msg, nil, OutcomeNetError, err
	}
	switch msg.Header.RCode {
	case dnsmessage.RCodeNameError:
		return msg, nil, OutcomeNXDOMAIN, nil
	case dnsmessage.RCodeSuccess:
	default:
		return msg, nil, OutcomeNetError, fmt.Errorf("dns rcode %s", msg.Header.RCode.String())
	}

	var ips []netip.Addr
	for _, ans := range msg.Answers {
		if ans.Header.Type != wantType {
			continue
		}
		switch body := ans.Body.(type) {
		case *dnsmessage.AResource:
			if wantType == dnsmessage.TypeA {
				ips = append(ips, netip.AddrFrom4(body.A))
			}
		case *dnsmessage.AAAAResource:
			if wantType == dnsmessage.TypeAAAA {
				ips = append(ips, netip.AddrFrom16(body.AAAA))
			}
		}
	}
	if len(ips) == 0 {
		return msg, nil, OutcomeNODATA, nil
	}
	return msg, ips, OutcomeOK, nil
}
