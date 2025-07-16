package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

/* ---------- Stage-1 input ---------- */
type DNSLine struct {
	FQDN   string   `json:"fqdn"`
	ECHB64 string   `json:"ech_b64,omitempty"`
	IPv4   []string `json:"ipv4,omitempty"`
	IPv6   []string `json:"ipv6,omitempty"`
}

/* ---------- probe output ---------- */
type ProbeLine struct {
	FQDN         string `json:"fqdn"`
	IP           string `json:"ip"`
	ConnMs       uint32 `json:"conn_ms"`
	ECHAttempted bool   `json:"ech_attempted"`
	ECHAccepted  bool   `json:"ech_accepted"`
	RetryUsed    bool   `json:"retry_used"`
	Error        string `json:"error,omitempty"`
}

/* ---------- flags ---------- */
var (
	inFile      = flag.String("in", "-", "dns.jsonl from Stage 1 ( - = stdin )")
	outFile     = flag.String("out", "-", "probe results JSONL ( - = stdout )")
	workers     = flag.Int("workers", 512, "parallel TLS goroutines")
	hsTimeout   = flag.Duration("handshakeTO", 7*time.Second, "per-handshake timeout")
	enableRetry = flag.Bool("retry", true, "retry once on ECHRejectionError")
)

/* ------------------------------------------------------------------ */

func main() {
	flag.Parse()

	/* input */
	in := os.Stdin
	if *inFile != "-" {
		f, err := os.Open(*inFile)
		must(err)
		defer f.Close()
		in = f
	}
	sc := bufio.NewScanner(in)

	/* output */
	out := os.Stdout
	if *outFile != "-" {
		f, err := os.Create(*outFile)
		must(err)
		defer f.Close()
		out = f
	}
	bufw := bufio.NewWriterSize(out, 1<<20)
	enc := json.NewEncoder(bufw)

	/* channels */
	jobs := make(chan DNSLine, 10_000)
	res  := make(chan ProbeLine, 10_000)

	var tlsWG, wrWG sync.WaitGroup

	/* writer */
	wrWG.Add(1)
	go func() {
		defer func() { bufw.Flush(); wrWG.Done() }()
		for p := range res {
			_ = enc.Encode(p)
		}
	}()

	/* TLS workers */
	tlsWG.Add(*workers)
	for i := 0; i < *workers; i++ {
		go func() {
			defer tlsWG.Done()
			for d := range jobs { runProbes(d, res) }
		}()
	}

	/* feed jobs */
	for sc.Scan() {
		var d DNSLine
		if err := json.Unmarshal(sc.Bytes(), &d); err == nil {
			jobs <- d
		}
	}
	close(jobs)

	tlsWG.Wait()
	close(res)
	wrWG.Wait()
}

/* ---------- per-domain ---------- */
func runProbes(d DNSLine, out chan<- ProbeLine) {
	echBytes, _ := base64.StdEncoding.DecodeString(d.ECHB64)
	for _, ip := range append(d.IPv4, d.IPv6...) {
		out <- probeOne(d.FQDN, ip, echBytes)
	}
}

/* ---------- single handshake ---------- */
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
		_ = conn.Close()
		return pl
	}

	echErr, ok := err.(*tls.ECHRejectionError)
	if !ok || !*enableRetry || len(echErr.RetryConfigList) == 0 {
		pl.Error = err.Error()
		return pl
	}

	/* retry once */
	pl.RetryUsed = true
	cfg2 := tlsConfig(fqdn, echErr.RetryConfigList)
	start = time.Now()
	conn2, err2 := dialTLS(ip, cfg2)
	pl.ConnMs = uint32(time.Since(start).Milliseconds())

	if err2 == nil {
		pl.ECHAccepted = conn2.ConnectionState().ECHAccepted
		_ = conn2.Close()
	} else {
		pl.Error = err2.Error()
	}
	return pl
}

/* ---------- helpers ---------- */
func tlsConfig(server string, ech []byte) *tls.Config {
	return &tls.Config{
		ServerName:                    server,
		MinVersion:                    tls.VersionTLS13,
		EncryptedClientHelloConfigList: ech,   // ← current API
		InsecureSkipVerify:            true,   // measurement only
	}
}

func dialTLS(ip string, cfg *tls.Config) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: *hsTimeout}
	return tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, "443"), cfg)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
