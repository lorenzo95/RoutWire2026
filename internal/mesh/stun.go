package mesh

import (
	"context"
	"net"
	"strconv"
	"time"

	stun "github.com/pion/stun/v3"
)

// GatherSRFLX queries each STUN server for our reflexive mapping, deduped by
// IP in server order. Failures are per-server and silent — candidates are
// best-effort by design.
func GatherSRFLX(ctx context.Context, servers []string, per time.Duration) []Candidate {
	var out []Candidate
	for _, s := range servers {
		for _, network := range []string{"udp4", "udp6"} {
			if ctx.Err() != nil {
				break
			}
			addr, err := srflxOne(ctx, network, s, per)
			if err != nil {
				continue // family may genuinely be unavailable (e.g. no v6 route)
			}
			dup := false
			for _, c := range out {
				if c.Addr == addr {
					dup = true
					break
				}
			}
			if !dup {
				out = append(out, Candidate{Type: CandSRFLX, Addr: addr})
			}
		}
	}
	return out
}

func srflxOne(ctx context.Context, network, server string, per time.Duration) (string, error) {
	d := net.Dialer{Timeout: per}
	conn, err := d.DialContext(ctx, network, server)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	c, err := stun.NewClient(conn)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetRTO(per)

	type outcome struct {
		addr string
		err  error
	}
	ch := make(chan outcome, 1)
	go func() {
		req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		var xor stun.XORMappedAddress
		doErr := c.Do(req, func(e stun.Event) {
			if e.Error != nil {
				ch <- outcome{"", e.Error}
				return
			}
			if perr := e.Message.Parse(&xor); perr != nil {
				ch <- outcome{"", perr}
				return
			}
		})
		if doErr != nil {
			ch <- outcome{"", doErr}
			return
		}
		if xor.IP == nil {
			ch <- outcome{"", errStunFailed}
			return
		}
		ch <- outcome{net.JoinHostPort(xor.IP.String(), strconv.Itoa(xor.Port)), nil}
	}()

	timer := time.NewTimer(2 * per)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		conn.Close()
		return "", ctx.Err()
	case <-timer.C:
		conn.Close()
		return "", errStunFailed
	case o := <-ch:
		return o.addr, o.err
	}
}

type stunError string

func (e stunError) Error() string { return string(e) }

const errStunFailed = stunError("stun: no mapped address")
