package tracer

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Samirrahman71/PacketPanther/pkg/storage"
)

// Tracer handles hop-by-hop traceroutes
type Tracer struct {
	maxHops    int
	timeoutSec int
	packetSize int
}

// HopResult represents the result of a single hop in a traceroute
type HopResult struct {
	Target    string
	Hop       int
	Address   string
	Hostname  string
	Latency   time.Duration
	Timestamp time.Time
}

// NewTracer creates a new traceroute handler
func NewTracer() *Tracer {
	return &Tracer{
		maxHops:    30,
		timeoutSec: 1,
		packetSize: 52,
	}
}

// TraceHosts traces routes to a list of target hosts
func (t *Tracer) TraceHosts(ctx context.Context, hosts []string, db *storage.Database) {
	for _, host := range hosts {
		select {
		case <-ctx.Done():
			return
		default:
			err := t.TraceHost(ctx, host, db)
			if err != nil {
				log.Printf("Error tracing host %s: %v", host, err)
			}
		}
	}
}

// TraceHost performs a traceroute to a single host
func (t *Tracer) TraceHost(ctx context.Context, host string, db *storage.Database) error {
	log.Printf("Starting traceroute to %s", host)
	
	// Resolve host if it's not already an IP
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("failed to resolve host %s: %v", host, err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("no IP addresses found for host %s", host)
		}
		ip = ips[0]
	}
	
	// Prepare the traceroute command based on the OS
	var cmd *exec.Cmd
	var args []string
	
	if runtime.GOOS == "windows" {
		// Windows uses tracert
		args = []string{"-d", "-h", strconv.Itoa(t.maxHops), "-w", strconv.Itoa(t.timeoutSec * 1000), ip.String()}
		cmd = exec.CommandContext(ctx, "tracert", args...)
	} else {
		// Linux/macOS uses traceroute
		args = []string{"-n", "-m", strconv.Itoa(t.maxHops), "-w", strconv.Itoa(t.timeoutSec), ip.String()}
		cmd = exec.CommandContext(ctx, "traceroute", args...)
	}
	
	// Get the output pipe
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %v", err)
	}
	
	// Start the command
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start traceroute: %v", err)
	}
	
	// Regular expressions for parsing output
	var hopRegex *regexp.Regexp
	if runtime.GOOS == "windows" {
		// Windows tracert format
		hopRegex = regexp.MustCompile(`^\s*(\d+)\s+(\d+)\s+ms\s+(\d+)\s+ms\s+(\d+)\s+ms\s+(.*)$`)
	} else {
		// Linux/macOS traceroute format
		hopRegex = regexp.MustCompile(`^\s*(\d+)\s+(.*)\s+(\d+\.\d+)\s+ms\s+(\d+\.\d+)\s+ms\s+(\d+\.\d+)\s+ms\s*$`)
	}
	
	// Process the output
	scanner := bufio.NewScanner(stdout)
	var results []interface{}
	
	for scanner.Scan() {
		line := scanner.Text()
		
		// Skip header lines
		if strings.Contains(line, "Tracing route") || strings.Contains(line, "traceroute to") {
			continue
		}
		
		matches := hopRegex.FindStringSubmatch(line)
		if len(matches) > 0 {
			// Parse hop number
			hop, _ := strconv.Atoi(matches[1])
			
			// Parse latency (use average of 3 probes)
			var latencySum float64
			var latencyCount int
			
			if runtime.GOOS == "windows" {
				// Windows format (e.g., "1    1 ms    1 ms    1 ms  192.168.1.1")
				for i := 2; i <= 4; i++ {
					if ms, err := strconv.Atoi(matches[i]); err == nil {
						latencySum += float64(ms)
						latencyCount++
					}
				}
				
				// Parse address 
				address := matches[5]
				
				// Create result
				result := HopResult{
					Target:    host,
					Hop:       hop,
					Address:   address,
					Hostname:  "", // Windows tracert doesn't provide hostname separately
					Latency:   time.Duration(latencySum/float64(latencyCount)) * time.Millisecond,
					Timestamp: time.Now(),
				}
				
				log.Printf("Hop %d: %v %v", hop, address, result.Latency)
				results = append(results, result)
			} else {
				// Linux format
				for i := 3; i <= 5; i++ {
					if ms, err := strconv.ParseFloat(matches[i], 64); err == nil {
						latencySum += ms
						latencyCount++
					}
				}
				
				// Parse address
				address := matches[2]
				
				// Create result
				result := HopResult{
					Target:    host,
					Hop:       hop,
					Address:   address,
					Hostname:  "", // We're using -n so no hostname resolution
					Latency:   time.Duration(latencySum/float64(latencyCount)) * time.Millisecond,
					Timestamp: time.Now(),
				}
				
				log.Printf("Hop %d: %v %v", hop, address, result.Latency)
				results = append(results, result)
			}
		}
	}
	
	// Wait for the command to complete
	err = cmd.Wait()
	if err != nil {
		// Some error codes are expected (like destination unreachable)
		log.Printf("Traceroute command exited with: %v", err)
	}
	
	// Save results
	log.Printf("Completed traceroute to %s with %d hops", host, len(results))
	if len(results) > 0 && db != nil {
		err = db.SaveTraceResults(host, results)
		if err != nil {
			log.Printf("Error saving trace results: %v", err)
		}
	}
	
	return nil
}

// AnalyzeLatency calculates average latency per hop for a target
func (t *Tracer) AnalyzeLatency(host string, db *storage.Database) (map[int]time.Duration, error) {
	results, err := db.GetTraceResults(host)
	if err != nil {
		return nil, err
	}
	
	// Calculate average latency per hop
	latencyMap := make(map[int]time.Duration)
	countMap := make(map[int]int)
	
	for _, result := range results {
		latencyMap[result.Hop] += result.Latency
		countMap[result.Hop]++
	}
	
	// Calculate averages
	for hop, totalLatency := range latencyMap {
		count := countMap[hop]
		if count > 0 {
			latencyMap[hop] = totalLatency / time.Duration(count)
		}
	}
	
	return latencyMap, nil
}
