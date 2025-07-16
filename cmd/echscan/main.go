package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
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
	FQDN   string
	ECHB64 string
	IPv4   []string
	IPv6   []string
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
	inFile  = flag.String("in", "-", "domain list ( - = stdin )")
	outFile = flag.String("out", "-", "probe JSONL file ( - = stdout )")

	/* DNS */
	resolver   = flag.String("dns", "8.8.8.8:53", "upstream DNS server")
	dnsTO      = flag.Duration("dns-timeout", 3*time.Second, "DNS query timeout")
	dnsWorkers = flag.Int("dns-workers", 512, "parallel DNS goroutines")

	/* TLS */
	hsTO        = flag.Duration("handshakeTO", 7*time.Second, "TLS handshake timeout")
	tlsWorkers  = flag.Int("tls-workers", 512, "parallel TLS goroutines")
	enableRetry = flag.Bool("retry", true, "retry once on ECHRejectionError")
	disableV6   = flag.Bool("disable-ipv6", false, "skip IPv6 addresses")

	/* ClickHouse sink & source */
	ckDSN      = flag.String("ck-dsn", "", "ClickHouse DSN")
	ckBatch    = flag.Int("ck-batch", 50000, "rows per ClickHouse INSERT")
	ckPeriod   = flag.Duration("ck-period", 2*time.Second, "flush period for partial batch")
	ckSrcQuery = flag.String("ck-source-query", "", "SQL returning column 'fqdn' to feed scanner")
)

/* ------------------------------------------------------------------ */

func main() {
	flag.Parse()

	/* ---------- ClickHouse connection (optional) ---------- */
	var ckConn clickhouse.Conn
	if *ckDSN != "" {
		opts, err := clickhouse.ParseDSN(*ckDSN)
		must(err)
		ckConn, err = clickhouse.Open(opts)
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
	go writer(results, ckConn, &writerWG)

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
					atomic.AddUint64(&dnsDone, 1) // skipped
				}
			}
		}()
	}

	/* ---------- domain producer ---------- */
	if *ckSrcQuery != "" {
		if ckConn == nil {
			log.Fatal("-ck-source-query requires -ck-dsn")
		}
		streamDomainsFromClickHouse(ckConn, *ckSrcQuery, dnsJobs)
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
	r := os.Stdin
	if path != "-" {
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
			rows.Scan(&fqdn)
			out <- fqdn
			atomic.AddUint64(&totalDomains, 1)
		}
	}()
}

/* ====================== Writer ====================== */

func writer(results <-chan ProbeLine, ckConn clickhouse.Conn, wg *sync.WaitGroup) {
	defer wg.Done()

	/* JSON sink (optional) */
	var (
		jsonEnabled bool
		enc         *json.Encoder
		bw          *bufio.Writer
	)
	if *outFile != "-" {
		jsonEnabled = true
		f, err := os.Create(*outFile)
		must(err)
		bw = bufio.NewWriterSize(f, 1<<20)
		enc = json.NewEncoder(bw)
	}

	/* ClickHouse batch buffer */
	batch := make([]ProbeLine, 0, *ckBatch)
	timer := time.NewTimer(*ckPeriod)

	flushCK := func() {
		if ckConn != nil && len(batch) > 0 {
			sendBatch(ckConn, batch)
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
			if ckConn != nil {
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

/* ====================== DNS stage ====================== */

func resolveDomain(domain string) (DNSLine, bool) {
	c := &dns.Client{Timeout: *dnsTO}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)

	r, _, err := c.Exchange(msg, *resolver)
	if err == nil && len(r.Answer) > 0 {
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
				return DNSLine{
					FQDN:   domain,
					ECHB64: base64.StdEncoding.EncodeToString(ech),
					IPv4:   v4,
					IPv6:   v6,
				}, true
			}
		}
	}

	var rslv net.Resolver
	ctx, cancel := context.WithTimeout(context.Background(), *dnsTO)
	defer cancel()
	v4, _ := rslv.LookupIP(ctx, "ip4", domain)
	v6, _ := rslv.LookupIP(ctx, "ip6", domain)
	if len(v4)+len(v6) == 0 {
		return DNSLine{}, false
	}
	out := DNSLine{FQDN: domain}
	for _, ip := range v4 {
		out.IPv4 = append(out.IPv4, ip.String())
	}
	for _, ip := range v6 {
		out.IPv6 = append(out.IPv6, ip.String())
	}
	return out, true
}

/* ====================== TLS stage ====================== */

func runProbes(d DNSLine, out chan<- ProbeLine) {
	echBytes, _ := base64.StdEncoding.DecodeString(d.ECHB64)

	targets := append([]string{}, d.IPv4...)
	if !*disableV6 {
		targets = append(targets, d.IPv6...)
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

	cfg := tlsConfig(fqdn, echCfg)
	start := time.Now()
	conn, err := dialTLS(ip, cfg)
	pl.ConnMs = uint32(time.Since(start).Milliseconds())

	if err == nil {
		pl.ECHAccepted = conn.ConnectionState().ECHAccepted
		conn.Close()
		return pl
	}

	echErr, ok := err.(*tls.ECHRejectionError)
	if !ok || !*enableRetry || len(echErr.RetryConfigList) == 0 {
		pl.Error = err.Error()
		return pl
	}

	pl.RetryUsed = true
	cfg2 := tlsConfig(fqdn, echErr.RetryConfigList)
	start = time.Now()
	conn2, err2 := dialTLS(ip, cfg2)
	pl.ConnMs = uint32(time.Since(start).Milliseconds())
	if err2 == nil {
		pl.ECHAccepted = conn2.ConnectionState().ECHAccepted
		conn2.Close()
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

func dialTLS(ip string, cfg *tls.Config) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: *hsTO}
	return tls.DialWithDialer(d, "tcp", net.JoinHostPort(ip, "443"), cfg)
}

/* ====================== ClickHouse sink ====================== */

func sendBatch(conn clickhouse.Conn, rows []ProbeLine) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, err := conn.PrepareBatch(ctx, "INSERT INTO ech.results")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ck prepare:", err)
		return
	}
	for _, r := range rows {
		err = b.Append(
			time.Now(),
			r.FQDN,
			net.ParseIP(r.IP),
			r.ConnMs,
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

		// if hd >= td && td > 0 {
		// 	ticker.Stop()
		// 	return
		// }
	}
}

/* ------------------------------------------------------------------ */
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
