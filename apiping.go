package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"crypto/tls"

	"golang.org/x/term"
)

var (
	count           int
	interval        time.Duration
	verbose         bool
	showBody        bool
	basicAuth       string
	bearer          string
	jsonOut         bool
	timeout         time.Duration
	insecure        bool
	dnsOnly         bool
	dnsTrace        bool
	tcpPing         string
	followRedirects bool
	maxRedirects    int
	headerPairs     []string
)

func init() {
	flag.IntVar(&count, "c", 0, "Stop after sending COUNT requests")
	flag.DurationVar(&interval, "i", 1*time.Second, "Interval between requests")
	flag.BoolVar(&verbose, "v", false, "Enable verbose output")
	flag.BoolVar(&showBody, "b", false, "Show response body size")
	flag.StringVar(&basicAuth, "auth", "", "Basic auth in format: user:pass")
	flag.StringVar(&bearer, "bearer", "", "Bearer token for Authorization header")
	flag.BoolVar(&jsonOut, "j", false, "Output in JSON format")
	flag.DurationVar(&timeout, "t", 10*time.Second, "Timeout for each request")
	flag.BoolVar(&insecure, "insecure", false, "Skip TLS certificate verification")
	flag.BoolVar(&dnsOnly, "dns", false, "Resolve DNS only (no HTTP request)")
	flag.BoolVar(&dnsTrace, "dns-trace", false, "Show full DNS resolution trace (like dig +trace)")
	flag.StringVar(&tcpPing, "tcp", "", "Test TCP connection to host:port")
	flag.BoolVar(&followRedirects, "L", false, "Follow HTTP redirects")
	flag.IntVar(&maxRedirects, "max-redirects", 10, "Maximum number of redirects to follow")
	flag.Var((*stringValue)(&headerPairs), "H", "Custom HTTP header(s), e.g., -H \"Authorization: Bearer token\"")
}

type stringValue []string

func (v *stringValue) Set(s string) error {
	*v = append(*v, s)
	return nil
}

func (v *stringValue) String() string {
	return fmt.Sprintf("%v", *v)
}

type PingResult struct {
	URL          string   `json:"url"`
	RTT          float64  `json:"rtt_ms"`
	StatusCode   int      `json:"status_code,omitempty"`
	BodySize     int      `json:"body_size,omitempty"`
	DNSDuration  float64  `json:"dns_ms,omitempty"`
	ConnDuration float64  `json:"conn_ms,omitempty"`
	Error        string   `json:"error,omitempty"`
	Timestamp    string   `json:"timestamp"`
	Redirects    []string `json:"redirects,omitempty"`
}

func supportsColor() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

func colorize(color, msg string) string {
	if !supportsColor() {
		return msg
	}
	colors := map[string]string{
		"green": "\033[32m",
		"red":   "\033[31m",
		"reset": "\033[0m",
	}
	return colors[color] + msg + colors["reset"]
}

func dnsLookup(host string) error {
	ips, err := net.LookupIP(host)
	if err != nil {
		return err
	}
	fmt.Printf("Resolved %s:\n", host)
	for _, ip := range ips {
		fmt.Println(ip.String())
	}
	return nil
}

func dnsTraceLookup(domain string) error {
	resolver := &net.Resolver{}

	fmt.Printf(";; DNS trace for %s\n", domain)

	// Step 1: Get NS records from root resolver
	ns, err := resolver.LookupNS(context.Background(), ".")
	if err != nil {
		return fmt.Errorf("failed to query root servers: %w", err)
	}
	fmt.Printf(";; Querying root servers for .\n")
	for _, srv := range ns {
		fmt.Printf(".\tIN\tNS\t%s\n", srv.Host)
	}

	// Step 2: Query TLD
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) < 2 {
		return fmt.Errorf("invalid domain")
	}
	tld := "." + parts[1]
	tldServers, err := resolver.LookupNS(context.Background(), tld)
	if err != nil {
		return fmt.Errorf("failed to query TLD servers for %s: %w", tld, err)
	}
	fmt.Printf(";; Querying TLD servers for %s\n", tld)
	for _, srv := range tldServers {
		fmt.Printf("%s\tIN\tNS\t%s\n", tld, srv.Host)
	}

	// Step 3: Query authoritative nameservers for domain
	authServers, err := resolver.LookupNS(context.Background(), domain)
	if err != nil {
		return fmt.Errorf("failed to query authoritative servers for %s: %w", domain, err)
	}
	fmt.Printf(";; Querying authoritative servers for %s\n", domain)
	for _, srv := range authServers {
		fmt.Printf("%s\tIN\tNS\t%s\n", domain, srv.Host)
	}

	// Step 4: Final lookup
	ips, err := resolver.LookupIP(context.Background(), "ip", domain)
	if err != nil {
		return fmt.Errorf("failed to resolve IP for %s: %w", err)
	}
	fmt.Printf(";; Final A/AAAA records for %s\n", domain)
	for _, ip := range ips {
		fmt.Printf("%s\tIN\tA\t%s\n", domain, ip.String())
	}

	return nil
}

func tcpPingHost(addr string, timeout time.Duration) error {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	rtt := time.Since(start).Seconds() * 1000 // ms

	if err != nil {
		fmt.Printf("TCP connect failed to %s: %v\n", addr, err)
		return err
	}
	defer conn.Close()
	fmt.Printf("TCP connected to %s: rtt=%.2f ms\n", addr, rtt)
	return nil
}

func apiping(targetURL string) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}

	if insecure {
		client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	// Redirect handling
	var redirects []string
	if followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			redirects = append(redirects, req.URL.String())
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		}
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		fmt.Printf("Request failed: %s\n", err)
		return
	}

	// Apply custom headers
	for _, h := range headerPairs {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			req.Header.Set(key, val)
		}
	}

	// Basic Auth
	if basicAuth != "" {
		userPass := strings.SplitN(basicAuth, ":", 2)
		if len(userPass) == 2 {
			req.SetBasicAuth(userPass[0], userPass[1])
		}
	}

	// Bearer Token
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	dnsStart := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(dnsStart).Seconds() * 1000 // total RTT in ms

	var result PingResult
	result.URL = targetURL
	result.Timestamp = time.Now().Format(time.RFC3339)
	result.Redirects = redirects

	if err != nil {
		result.Error = err.Error()
		if jsonOut {
			jsonData, _ := json.Marshal(result)
			fmt.Println(string(jsonData))
		} else {
			fmt.Println(colorize("red", "[ERROR] "+err.Error()))
		}
		return
	}
	defer resp.Body.Close()

	bodySize := 0
	if showBody {
		body, _ := io.ReadAll(resp.Body)
		bodySize = len(body)
	}

	result.StatusCode = resp.StatusCode
	result.RTT = rtt
	result.BodySize = bodySize

	if jsonOut {
		jsonData, _ := json.Marshal(result)
		fmt.Println(string(jsonData))
		return
	}

	// Colorized output
	status := fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		status = colorize("green", status)
	} else {
		status = colorize("red", status)
	}

	if verbose {
		host := req.URL.Hostname()
		ipAddr, lookupErr := net.LookupIP(host)
		var ip string
		if lookupErr == nil && len(ipAddr) > 0 {
			ip = ipAddr[0].String()
		} else {
			ip = "N/A"
		}
		fmt.Printf("HTTP/%d.%d %s %d bytes from %s (%s): rtt=%.2f ms\n",
			resp.ProtoMajor, resp.ProtoMinor, status, bodySize, host, ip, rtt)

		// Show redirect path if any
		if len(redirects) > 0 {
			fmt.Printf("Redirect path:\n")
			for i, loc := range redirects {
				fmt.Printf(" #%d  %s\n", i+1, loc)
			}
		}
	} else {
		fmt.Printf("[%s] %.2f ms\n", status, rtt)
	}
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] <URL>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Error: missing URL")
		flag.Usage()
	}

	targetURL := args[0]

	// Normalize URL if no scheme is provided
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid URL: %v\n", err)
		os.Exit(1)
	}

	host := u.Hostname()

	if dnsOnly {
		if dnsTrace {
			err := dnsTraceLookup(host)
		} else {
			err := dnsLookup(host)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "DNS lookup failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if tcpPing != "" {
		addr := tcpPing
		if !strings.Contains(addr, ":") {
			addr = addr + ":80"
		}
		tcpPingHost(addr, timeout)
		return
	}

	if count <= 0 {
		for {
			apiping(targetURL)
			time.Sleep(interval)
		}
	} else {
		for i := 0; i < count; i++ {
			apiping(targetURL)
			time.Sleep(interval)
		}
	}
}
