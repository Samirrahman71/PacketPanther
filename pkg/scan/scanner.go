package scan

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Samirrahman71/PacketPanther/pkg/storage"
)

// Scanner provides fast TCP port scanning with a worker pool
type Scanner struct {
	workerCount int
	timeout     time.Duration
}

// ScanResult represents the result of a port scan
type ScanResult struct {
	Host      string
	Port      int
	Open      bool
	Latency   time.Duration
	Timestamp time.Time
}

// NewScanner creates a new port scanner with the specified number of workers
func NewScanner(workerCount int) *Scanner {
	return &Scanner{
		workerCount: workerCount,
		timeout:     500 * time.Millisecond,
	}
}

// ScanHosts scans a list of hosts for open ports
func (s *Scanner) ScanHosts(ctx context.Context, hosts []string, ports []int, db *storage.Database) {
	// Create a channel for scan jobs
	jobCh := make(chan struct {
		host string
		port int
	}, len(hosts)*len(ports))

	// Create a channel for scan results
	resultCh := make(chan ScanResult, len(hosts)*len(ports))

	// Create a wait group to wait for all workers to finish
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < s.workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, jobCh, resultCh)
		}()
	}

	// Submit scan jobs
	go func() {
		for _, host := range hosts {
			for _, port := range ports {
				select {
				case <-ctx.Done():
					// Context cancelled, stop submitting jobs
					close(jobCh)
					return
				case jobCh <- struct {
					host string
					port int
				}{host, port}:
					// Job submitted
				}
			}
		}
		close(jobCh)
	}()

	// Process results in a separate goroutine
	go func() {
		var results []ScanResult
		for result := range resultCh {
			if result.Open {
				log.Printf("Found open port: %s:%d (%.2fms)", result.Host, result.Port, float64(result.Latency.Microseconds())/1000)
			}
			results = append(results, result)

			// Batch insert results every 100 results
			if len(results) >= 100 {
				// Convert []ScanResult to []interface{}
				interfaceResults := make([]interface{}, len(results))
				for i, r := range results {
					interfaceResults[i] = r
				}
				if err := db.SaveScanResults(interfaceResults); err != nil {
					log.Printf("Error saving scan results: %v", err)
				}
				results = nil
			}
		}

		// Save any remaining results
		if len(results) > 0 {
			// Convert []ScanResult to []interface{}
			interfaceResults := make([]interface{}, len(results))
			for i, r := range results {
				interfaceResults[i] = r
			}
			if err := db.SaveScanResults(interfaceResults); err != nil {
				log.Printf("Error saving scan results: %v", err)
			}
		}
	}()

	// Wait for all workers to finish
	wg.Wait()
	close(resultCh)
}

// worker is a scan worker that performs port scans
func (s *Scanner) worker(ctx context.Context, jobCh <-chan struct {
	host string
	port int
}, resultCh chan<- ScanResult) {
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-jobCh:
			if !ok {
				// Job channel closed
				return
			}

			// Perform port scan
			start := time.Now()
			open := s.isPortOpen(job.host, job.port)
			latency := time.Since(start)

			// Send result
			select {
			case <-ctx.Done():
				return
			case resultCh <- ScanResult{
				Host:      job.host,
				Port:      job.port,
				Open:      open,
				Latency:   latency,
				Timestamp: start,
			}:
				// Result sent
			}
		}
	}
}

// isPortOpen checks if a TCP port is open
func (s *Scanner) isPortOpen(host string, port int) bool {
	address := net.JoinHostPort(host, toString(port))
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// GetOpenPortsForHost retrieves all open ports found for a specific host
func (s *Scanner) GetOpenPortsForHost(host string, db *storage.Database) ([]int, error) {
	return db.GetOpenPortsForHost(host)
}

// toString converts an integer to a string
func toString(i int) string {
	return intToStringMap[i]
}

// Pre-computed map of int to string for common ports
var intToStringMap = map[int]string{
	1: "1", 2: "2", 3: "3", 4: "4", 5: "5", 6: "6", 7: "7", 8: "8", 9: "9", 10: "10",
	11: "11", 12: "12", 13: "13", 14: "14", 15: "15", 16: "16", 17: "17", 18: "18", 19: "19", 20: "20",
	21: "21", 22: "22", 23: "23", 24: "24", 25: "25", 26: "26", 27: "27", 28: "28", 29: "29", 30: "30",
	31: "31", 32: "32", 33: "33", 34: "34", 35: "35", 36: "36", 37: "37", 38: "38", 39: "39", 40: "40",
	41: "41", 42: "42", 43: "43", 44: "44", 45: "45", 46: "46", 47: "47", 48: "48", 49: "49", 50: "50",
	51: "51", 52: "52", 53: "53", 54: "54", 55: "55", 56: "56", 57: "57", 58: "58", 59: "59", 60: "60",
	61: "61", 62: "62", 63: "63", 64: "64", 65: "65", 66: "66", 67: "67", 68: "68", 69: "69", 70: "70",
	71: "71", 72: "72", 73: "73", 74: "74", 75: "75", 76: "76", 77: "77", 78: "78", 79: "79", 80: "80",
	81: "81", 82: "82", 83: "83", 84: "84", 85: "85", 86: "86", 87: "87", 88: "88", 89: "89", 90: "90",
	91: "91", 92: "92", 93: "93", 94: "94", 95: "95", 96: "96", 97: "97", 98: "98", 99: "99", 100: "100",
	110: "110", 119: "119", 123: "123", 137: "137", 138: "138", 139: "139", 143: "143", 161: "161", 162: "162", 389: "389",
	443: "443", 445: "445", 465: "465", 587: "587", 993: "993", 995: "995", 1080: "1080", 1194: "1194", 1433: "1433", 1434: "1434",
	1521: "1521", 1701: "1701", 1723: "1723", 1900: "1900", 2049: "2049", 2082: "2082", 2083: "2083", 2222: "2222", 3128: "3128", 3306: "3306",
	3389: "3389", 5060: "5060", 5061: "5061", 5432: "5432", 5900: "5900", 5901: "5901", 6379: "6379", 6667: "6667", 8000: "8000", 8080: "8080",
	8443: "8443", 8888: "8888", 9100: "9100", 9200: "9200", 9418: "9418", 27017: "27017", 27018: "27018", 27019: "27019", 28017: "28017", 49152: "49152",
}
