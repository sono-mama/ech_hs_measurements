package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/miekg/dns"
)

/* ------------------------------------------------------------------ */
/* Atomic counters for heartbeat                                       */
/* ------------------------------------------------------------------ */

var (
	totalDomains uint64
	dnsDone      uint64
	tlsDone      uint64
	echOK        uint64
	echAttempted uint64
	errs         uint64
)

/* ------------------------------------------------------------------ */
/* Pipeline structs                                                    */
/* ------------------------------------------------------------------ */

type DNSLine struct {
	FQDN       string
	ECHB64     string
	IPv4       []string
	IPv6       []string
	TargetFQDN string // HTTPS/SVCB TargetName (may equal FQDN)
}

type ProbeLine struct {
	FQDN         string `json:"fqdn"`
	IP           string `json:"ip"`
	ConnMs       uint32 `json:"conn_ms"`
	ECHAttempted bool   `json:"ech_attempted"`
	ECHAccepted  bool   `json:"ech_accepted"`
	RetryUsed    bool   `json:"retry_used"`
	Error        string `json:"error,omitempty"`
}

/* ------------------------------------------------------------------ */
/* CLI flags                                                           */
/* ------------------------------------------------------------------ */

var (
	/* I/O */
	inFile  = flag.String("in", "-", "domain list ( - = stdin ) or unused when -ck-source-query is set")
	outFile = flag.String("out", "-", "probe JSONL file ( - = stdout )")

	/* DNS */
	resolver    = flag.String("dns", "8.8.8.8:53", "upstream DNS server")
	dnsTO       = flag.Duration("dns-timeout", 3*time.Second, "DNS query timeout")
	dnsWorkers  = flag.Int("dns-workers", 512, "parallel DNS goroutines")
	emitDNSMiss = flag.Bool("emit-dns-miss", true, "emit a synthetic row when no IPv4 targets are found")

	/* TLS */
	dialTO      = flag.Duration("dial-timeout", 2*time.Second, "TCP dial timeout")
	hsTO        = flag.Duration("handshake-timeout", 4*time.Second, "TLS handshake timeout")
	tlsWorkers  = flag.Int("tls-workers", 512, "parallel TLS goroutines")
	perIPLimit  = flag.Int("per-ip-limit", 64, "max concurrent dials to the same IP")
	enableRetry = flag.Bool("retry", true, "retry once on ECHRejectionError (server-provided RetryConfig)")
	disableV6   = flag.Bool("disable-ipv6", false, "skip IPv6 addresses for probing")

	/* ClickHouse sink & source */
	ckDSN      = flag.String("ck-dsn", "", "ClickHouse DSN")
	ckTable    = flag.String("ck-table", "ech.handshakes", "ClickHouse target table")
	ckBatch    = flag.Int("ck-batch", 50000, "rows per ClickHouse INSERT")
	ckPeriod   = flag.Duration("ck-period", 2*time.Second, "flush period for partial batch")
	ckSrcQuery = flag.String("ck-source-query", "", "SQL returning column 'fqdn' (name) to feed scanner")
	runDateStr = flag.String("run-date", "", "run_date to stamp rows (YYYY-MM-DD). Default: today()")
)

/* ------------------------------------------------------------------ */
/* Globals                                                             */
/* ------------------------------------------------------------------ */

var (
	ckConnGlobal clickhouse.Conn
	runDateVal   time.Time
	ipLimiter    *perIPLimiter
)

/* ------------------------------------------------------------------ */

func main() {
	flag.Parse()
	rand.Seed(time.Now().UnixNano())

	/* ---------- run_date ---------- */
	if *runDateStr != "" {
		t, err := time.Parse("2006-01-02", *runDateStr)
		must(err)
		runDateVal = t
	} else {
		runDateVal = time.Now().UTC()
	}

	/* ---------- ClickHouse connection (optional) ---------- */
	if *ckDSN != "" {
		opts, err := clickhouse.ParseDSN(*ckDSN)
		must(err)
		ckConnGlobal, err = clickhouse.Open(opts)
		must(err)
	}

	/* ---------- channels ---------- */
	dnsJobs := make(chan string, 10_000)
	tlsJobs := make(chan DNSLine, 10_000)
	results := make(chan ProbeLine, 10_000)

	/* ---------- WaitGroups ---------- */
	var dnsWG, tlsWG, writerWG sync.WaitGroup

	/* ---------- writer ---------- */
	writerWG.Add(1)
	go writer(results, &writerWG)

	/* ---------- per-IP limiter ---------- */
	ipLimiter = newPerIPLimiter(*perIPLimit)

	/* ---------- TLS workers ---------- */
	tlsWG.Add(*tlsWorkers)
	for i := 0; i < *tlsWorkers; i++ {
		go func() {
			defer tlsWG.Done()
			for d := range tlsJobs {
				runProbes(d, results)
				atomic.AddUint64(&dnsDone, 1) // DNS result consumed
			}
		}()
	}

	/* ---------- DNS workers ---------- */
	dnsWG.Add(*dnsWorkers)
	for i := 0; i < *dnsWorkers; i++ {
		go func() {
			defer dnsWG.Done()
			for dom := range dnsJobs {
				if d, ok := resolveDomain(dom); ok {
					tlsJobs <- d
				} else {
					// No DNS record at all; optionally emit a synthetic miss row
					if *emitDNSMiss {
						results <- ProbeLine{
							FQDN:         dom,
							IP:           "0.0.0.0",
							ConnMs:       0,
							ECHAttempted: false,
							ECHAccepted:  false,
							RetryUsed:    false,
							Error:        "dns:lookup_failed",
						}
					}
					atomic.AddUint64(&dnsDone, 1) // skipped
				}
			}
		}()
	}

	/* ---------- domain producer ---------- */
	if *ckSrcQuery != "" {
		if ckConnGlobal == nil {
			log.Fatal("-ck-source-query requires -ck-dsn")
		}
		streamDomainsFromClickHouse(ckConnGlobal, *ckSrcQuery, dnsJobs)
	} else {
		streamDomainsFromFile(*inFile, dnsJobs)
	}

	/* ---------- heartbeat ---------- */
	go heartbeat()

	/* ---------- shutdown chain ---------- */
	dnsWG.Wait()
	close(tlsJobs)
	tlsWG.Wait()
	close(results)
	writerWG.Wait()
}

/* ====================== Producers ====================== */

func streamDomainsFromFile(path string, out chan<- string) {
	defer close(out)
	var r *os.File
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		must(err)
		defer f.Close()
		r = f
	}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if d := strings.TrimSpace(sc.Text()); d != "" {
			out <- d
			atomic.AddUint64(&totalDomains, 1)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "scanner:", err)
	}
}

func streamDomainsFromClickHouse(conn clickhouse.Conn, query string, out chan<- string) {
	rows, err := conn.Query(context.Background(), query)
	must(err)
	go func() {
		defer rows.Close()
		defer close(out)
		for rows.Next() {
			var fqdn string
			_ = rows.Scan(&fqdn)
			if fqdn != "" {
				out <- fqdn
				atomic.AddUint64(&totalDomains, 1)
			}
		}
	}()
}

/* ====================== Writer ====================== */

func writer(results <-chan ProbeLine, wg *sync.WaitGroup) {
	defer wg.Done()

	/* JSON sink */
	var (
		jsonEnabled bool
		enc         *json.Encoder
		bw          *bufio.Writer
	)
	{
		jsonEnabled = true
		var w *os.File
		if *outFile == "-" {
			w = os.Stdout
		} else {
			f, err := os.Create(*outFile)
			must(err)
			w = f
		}
		bw = bufio.NewWriterSize(w, 1<<20)
		enc = json.NewEncoder(bw)
	}

	/* ClickHouse batch buffer */
	batch := make([]ProbeLine, 0, *ckBatch)
	timer := time.NewTimer(*ckPeriod)

	flushCK := func() {
		if ckConnGlobal != nil && len(batch) > 0 {
			sendBatch(batch)
			batch = batch[:0]
		}
		timer.Reset(*ckPeriod)
	}
	flushJSON := func() {
		if jsonEnabled && bw != nil {
			_ = bw.Flush()
		}
	}

	for {
		select {
		case p, ok := <-results:
			if !ok {
				flushCK()
				flushJSON()
				return
			}
			if jsonEnabled {
				_ = enc.Encode(p)
			}
			if ckConnGlobal != nil {
				batch = append(batch, p)
				if len(batch) >= *ckBatch {
					flushCK()
				}
			}
			/* heartbeat counters */
			if p.ECHAttempted {
				atomic.AddUint64(&echAttempted, 1)
			}
			if p.ECHAccepted {
				atomic.AddUint64(&echOK, 1)
			}
			if p.Error != "" {
				atomic.AddUint64(&errs, 1)
			}
			atomic.AddUint64(&tlsDone, 1)

		case <-timer.C:
			flushCK()
		}
	}
}

/* ====================== DNS helpers ====================== */

func resolveDomain(domain string) (DNSLine, bool) {
	domainFQDN := dns.Fqdn(domain)

	cli := &dns.Client{Timeout: *dnsTO}
	// 1) Ask for HTTPS (SVCB) first
	httpsMsg := new(dns.Msg)
	httpsMsg.SetQuestion(domainFQDN, dns.TypeHTTPS)
	if r, _, err := cli.Exchange(httpsMsg, *resolver); err == nil && len(r.Answer) > 0 {
		for _, rr := range r.Answer {
			if h, ok := rr.(*dns.HTTPS); ok {
				var ech []byte
				var v4, v6 []string
				for _, v := range h.Value {
					switch t := v.(type) {
					case *dns.SVCBECHConfig:
						ech = t.ECH
					case *dns.SVCBIPv4Hint:
						for _, ip := range t.Hint {
							v4 = append(v4, ip.String())
						}
					case *dns.SVCBIPv6Hint:
						for _, ip := range t.Hint {
							v6 = append(v6, ip.String())
						}
					}
				}

				// If no IPv4 hints, try A(TargetName). If still none, A(original)
				target := strings.TrimSuffix(h.Target, ".")
				if target == "" || target == "." {
					target = domain
				}
				if len(v4) == 0 {
					v4 = append(v4, dnsLookupA(cli, target)...)
					if len(v4) == 0 && target != domain {
						v4 = append(v4, dnsLookupA(cli, domain)...)
					}
				}
				// (IPv6 available if not disabled)
				if !*disableV6 && len(v6) == 0 {
					v6 = append(v6, dnsLookupAAAA(cli, target)...)
					if len(v6) == 0 && target != domain {
						v6 = append(v6, dnsLookupAAAA(cli, domain)...)
					}
				}

				return DNSLine{
					FQDN:       domain,
					ECHB64:     base64.StdEncoding.EncodeToString(ech),
					IPv4:       dedup(v4),
					IPv6:       dedup(v6),
					TargetFQDN: target,
				}, true
			}
		}
	}

	// 2) No HTTPS answer → fallback A/AAAA on original name
	cli.Timeout = *dnsTO
	v4 := dnsLookupA(cli, domain)
	var v6 []string
	if !*disableV6 {
		v6 = dnsLookupAAAA(cli, domain)
	}

	if len(v4)+len(v6) == 0 {
		return DNSLine{}, false
	}
	return DNSLine{
		FQDN:       domain,
		ECHB64:     "",
		IPv4:       dedup(v4),
		IPv6:       dedup(v6),
		TargetFQDN: domain,
	}, true
}

func dnsLookupA(cli *dns.Client, name string) []string {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeA)
	r, _, err := cli.Exchange(msg, *resolver)
	if err != nil || len(r.Answer) == 0 {
		return nil
	}
	out := make([]string, 0, len(r.Answer))
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			out = append(out, a.A.String())
		}
	}
	return out
}

func dnsLookupAAAA(cli *dns.Client, name string) []string {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
	r, _, err := cli.Exchange(msg, *resolver)
	if err != nil || len(r.Answer) == 0 {
		return nil
	}
	out := make([]string, 0, len(r.Answer))
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.AAAA); ok {
			out = append(out, a.AAAA.String())
		}
	}
	return out
}

func dedup(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

/* ====================== TLS stage ====================== */

func runProbes(d DNSLine, out chan<- ProbeLine) {
	echBytes, _ := base64.StdEncoding.DecodeString(d.ECHB64)

	targets := append([]string{}, d.IPv4...)
	if !*disableV6 {
		targets = append(targets, d.IPv6...)
	}
	if len(targets) == 0 {
		if *emitDNSMiss {
			out <- ProbeLine{
				FQDN:         d.FQDN,
				IP:           "0.0.0.0",
				ConnMs:       0,
				ECHAttempted: false,
				ECHAccepted:  false,
				RetryUsed:    false,
				Error:        "dns:no_ipv4_targets",
			}
		}
		return
	}
	for _, ip := range targets {
		out <- probeOne(d.FQDN, ip, echBytes)
	}
}

func probeOne(fqdn, ip string, echCfg []byte) ProbeLine {
	pl := ProbeLine{
		FQDN:         fqdn,
		IP:           ip,
		ECHAttempted: len(echCfg) > 0,
	}

	ipLimiter.acquire(ip)
	defer ipLimiter.release(ip)

	// --- Attempt 1: dial + handshake
	cfg := tlsConfig(fqdn, echCfg)
	start := time.Now()
	conn, err := dialAndHandshake(ip, cfg)
	pl.ConnMs = uint32(time.Since(start).Milliseconds())
	if err == nil {
		pl.ECHAccepted = conn.ConnectionState().ECHAccepted
		_ = conn.Close()
		return pl
	}

	// If not an ECH rejection (or retry disabled), return error
	echErr, ok := err.(*tls.ECHRejectionError)
	if !ok || !*enableRetry || len(echErr.RetryConfigList) == 0 {
		pl.Error = err.Error()
		return pl
	}

	// --- Attempt 2: retry with RetryConfigList
	pl.RetryUsed = true
	cfg2 := tlsConfig(fqdn, echErr.RetryConfigList)
	start = time.Now()
	conn2, err2 := dialAndHandshake(ip, cfg2)
	pl.ConnMs = uint32(time.Since(start).Milliseconds())
	if err2 == nil {
		pl.ECHAccepted = conn2.ConnectionState().ECHAccepted
		_ = conn2.Close()
	} else {
		pl.Error = err2.Error()
	}
	return pl
}

func tlsConfig(server string, ech []byte) *tls.Config {
	return &tls.Config{
		ServerName:                     server,
		MinVersion:                     tls.VersionTLS13,
		EncryptedClientHelloConfigList: ech,
		InsecureSkipVerify:             true,
	}
}

func dialAndHandshake(ip string, cfg *tls.Config) (*tls.Conn, error) {
	// TCP dial with its own timeout
	ctx, cancel := context.WithTimeout(context.Background(), *dialTO)
	defer cancel()

	d := &net.Dialer{}
	tcpConn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return nil, err
	}

	// Handshake with deadline
	_ = tcpConn.SetDeadline(time.Now().Add(*hsTO))
	tlsConn := tls.Client(tcpConn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	// clear deadlines
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() || strings.Contains(strings.ToLower(err.Error()), "timeout")
}

/* ====================== ClickHouse sink ====================== */

func sendBatch(rows []ProbeLine) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	stmt := fmt.Sprintf(`
	  INSERT INTO %s
	      (run_date, ts, fqdn, ip, conn_ms, ech_attempted, ech_accepted, retry_used, error)
	`, *ckTable)

	b, err := ckConnGlobal.PrepareBatch(ctx, stmt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ck prepare:", err)
		return
	}
	for _, r := range rows {
		var ipAddr net.IP
		if r.IP != "" {
			ipAddr = net.ParseIP(r.IP)
			if ipAddr == nil {
				// allow "0.0.0.0" synthetic to parse
				ipAddr = net.ParseIP("0.0.0.0")
			}
		}
		err = b.Append(
			runDateVal,       // run_date (Date)
			time.Now().UTC(), // ts
			r.FQDN,           // fqdn
			ipAddr,           // ip (IPv6)
			r.ConnMs,         // conn_ms
			boolToUInt8(r.ECHAttempted),
			boolToUInt8(r.ECHAccepted),
			boolToUInt8(r.RetryUsed),
			r.Error,
		)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ck append:", err)
			return
		}
	}
	if err := b.Send(); err != nil {
		fmt.Fprintln(os.Stderr, "ck send:", err)
	}
}

func boolToUInt8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

/* ====================== Heartbeat ====================== */

func heartbeat() {
	start := time.Now()
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		td := atomic.LoadUint64(&totalDomains)
		dd := atomic.LoadUint64(&dnsDone)
		hd := atomic.LoadUint64(&tlsDone)
		ok := atomic.LoadUint64(&echOK)
		at := atomic.LoadUint64(&echAttempted)
		er := atomic.LoadUint64(&errs)

		rate := float64(hd) / time.Since(start).Seconds()
		eta := "n/a"
		if hd > 0 && td > 0 && hd < td {
			remain := float64(td - hd)
			etaDur := time.Duration(remain/rate) * time.Second
			eta = etaDur.Round(time.Minute).String()
		}

		fmt.Fprintf(os.Stderr,
			"[%.8s] dns:%d/%d tls:%d/%d ok:%d tried:%d err:%d rate:%.0f/s eta:%s\n",
			time.Now().Format(time.RFC3339),
			dd, td, hd, td, ok, at, er, rate, eta)
	}
}

/* ------------------------------------------------------------------ */
/* Per-IP concurrency limiter                                          */
/* ------------------------------------------------------------------ */

type perIPLimiter struct {
	mu  sync.Mutex
	m   map[string]chan struct{}
	cap int
}

func newPerIPLimiter(cap int) *perIPLimiter {
	if cap <= 0 {
		cap = 1
	}
	return &perIPLimiter{
		m:   make(map[string]chan struct{}),
		cap: cap,
	}
}

func (l *perIPLimiter) acquire(ip string) {
	l.mu.Lock()
	ch, ok := l.m[ip]
	if !ok {
		ch = make(chan struct{}, l.cap)
		l.m[ip] = ch
	}
	l.mu.Unlock()
	ch <- struct{}{}
}

func (l *perIPLimiter) release(ip string) {
	l.mu.Lock()
	ch := l.m[ip]
	l.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

/* ------------------------------------------------------------------ */
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
