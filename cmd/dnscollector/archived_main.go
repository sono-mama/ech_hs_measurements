package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------
// Data model for one DNS result line
// ---------------------------------------------------------------------

type Output struct {
	FQDN    string   `json:"fqdn"`
	ECHB64  string   `json:"ech_b64,omitempty"`
	IPv4    []string `json:"ipv4,omitempty"`
	IPv6    []string `json:"ipv6,omitempty"`
	TTLUnix int64    `json:"ttl_unix,omitempty"`
	// Error  string   `json:"error,omitempty"`   // uncomment if you decide to keep failures too
}

// ---------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------

var (
	resolver = flag.String("dns", "1.1.1.1:53", "upstream DNS server host:port")
	timeout  = flag.Duration("timeout", 3*time.Second, "DNS query timeout")
	inFile   = flag.String("in", "-", "file with domains (one per line), - = stdin")
	outFile  = flag.String("out", "-", "write JSONL here, - = stdout")
	workers  = flag.Int("workers", 512, "parallel DNS lookups")
)

// ---------------------------------------------------------------------
// main()
// ---------------------------------------------------------------------

func main() {
	flag.Parse()

	// ----- input ------------------------------------------------------
	in := os.Stdin
	var err error
	if *inFile != "-" {
		in, err = os.Open(*inFile)
		must(err)
		defer in.Close()
	}
	scanner := bufio.NewScanner(in)

	// ----- output -----------------------------------------------------
	out := os.Stdout
	if *outFile != "-" {
		out, err = os.Create(*outFile)
		must(err)
		defer out.Close()
	}
	bufw := bufio.NewWriterSize(out, 1<<20) // 1 MiB
	enc := json.NewEncoder(bufw)

	// ----- channels ---------------------------------------------------
	jobs := make(chan string, 10_000)
	results := make(chan Output, 10_000)

	var dnsWG sync.WaitGroup    // DNS workers
	var writerWG sync.WaitGroup // writer goroutine

	// ----- writer goroutine ------------------------------------------
	writerWG.Add(1)
	go func() {
		defer func() {
			bufw.Flush() // ensure bytes reach disk/stdout
			writerWG.Done()
		}()
		for res := range results {
			_ = enc.Encode(res) // ignore per-line error for now
			// fmt.Fprintln(os.Stderr, "WROTE", res.FQDN) // debug
		}
	}()

	// ----- DNS worker pool -------------------------------------------
	dnsWG.Add(*workers)
	for i := 0; i < *workers; i++ {
		go func() {
			defer dnsWG.Done()
			for domain := range jobs {
				if res, ok := handleDomain(domain); ok {
					results <- res
				}
			}
		}()
	}

	// ----- feed input -------------------------------------------------
	for scanner.Scan() {
		if d := strings.TrimSpace(scanner.Text()); d != "" {
			jobs <- d
		}
	}
	close(jobs)     // no more work for DNS workers
	dnsWG.Wait()    // wait until they’re all done
	close(results)  // let writer drain remaining structs
	writerWG.Wait() // wait until JSON is fully flushed

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "scanner:", err)
	}
}

// ---------------------------------------------------------------------
// DNS helpers
// ---------------------------------------------------------------------

func handleDomain(domain string) (Output, bool) {
	if o, err := querySvcb(domain); err == nil {
		return o, true
	}

	// fallback to plain A/AAAA so later stages can still probe TLS
	v4, v6 := queryA(domain)
	if len(v4)+len(v6) == 0 {
		// fmt.Fprintln(os.Stderr, "DNS FAIL", domain, err) // debug
		return Output{}, false
	}
	return Output{FQDN: domain, IPv4: v4, IPv6: v6}, true
}

func querySvcb(domain string) (Output, error) {
	c := &dns.Client{Timeout: *timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)

	r, _, err := c.Exchange(msg, *resolver)
	if err != nil || len(r.Answer) == 0 {
		return Output{}, fmt.Errorf("no answer")
	}
	for _, rr := range r.Answer {
		h, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}
		var echRaw []byte
		var v4, v6 []string
		for _, p := range h.Value {
			switch pv := p.(type) {
			case *dns.SVCBECHConfig: // >= v1.1.66
				echRaw = pv.ECH
			case *dns.SVCBIPv4Hint:
				for _, ip := range pv.Hint {
					v4 = append(v4, ip.String())
				}
			case *dns.SVCBIPv6Hint:
				for _, ip := range pv.Hint {
					v6 = append(v6, ip.String())
				}
			}
		}
		if len(echRaw) > 0 {
			return Output{
				FQDN:    domain,
				ECHB64:  base64.StdEncoding.EncodeToString(echRaw),
				IPv4:    v4,
				IPv6:    v6,
				TTLUnix: time.Now().Add(time.Duration(h.Hdr.Ttl) * time.Second).Unix(),
			}, nil
		}
	}
	return Output{}, fmt.Errorf("no ech")
}

func queryA(domain string) (v4, v6 []string) {
	var r net.Resolver
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if ips, _ := r.LookupIP(ctx, "ip4", domain); ips != nil {
		for _, ip := range ips {
			v4 = append(v4, ip.String())
		}
	}
	if ips, _ := r.LookupIP(ctx, "ip6", domain); ips != nil {
		for _, ip := range ips {
			v6 = append(v6, ip.String())
		}
	}
	return
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
