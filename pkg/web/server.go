package web

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/Samirrahman71/PacketPanther/pkg/storage"
)

// Server handles the web dashboard
type Server struct {
	db        *storage.Database
	templates *template.Template
	server    *http.Server
}

// NewServer creates a new web server
func NewServer(db *storage.Database) (*Server, error) {
	// Get the template directory
	tmplPath := filepath.Join("web", "templates", "*.html")
	
	// Parse templates from filesystem
	tmpl, err := template.ParseGlob(tmplPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %v", err)
	}

	return &Server{
		db:        db,
		templates: tmpl,
	}, nil
}

// Start begins the web server on the specified port
func (s *Server) Start(ctx context.Context, port int) error {
	// Create router
	mux := http.NewServeMux()

	// Register handlers
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/capture", s.handleCapture)
	mux.HandleFunc("/trace", s.handleTrace)
	mux.HandleFunc("/scan", s.handleScan)
	mux.HandleFunc("/snmp", s.handleSNMP)
	mux.HandleFunc("/api/top-talkers", s.handleAPITopTalkers)
	mux.HandleFunc("/api/trace-results", s.handleAPITraceResults)
	mux.HandleFunc("/api/scan-results", s.handleAPIScanResults)
	mux.HandleFunc("/api/snmp-devices", s.handleAPISNMPDevices)

	// Create file server for static files from filesystem
	staticDir := filepath.Join("web", "static")
	fileServer := http.FileServer(http.Dir(staticDir))
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))

	// Create server
	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Web server listening on http://localhost:%d", port)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Web server error: %v", err)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	log.Println("Shutting down web server...")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shutdown server
	return s.server.Shutdown(shutdownCtx)
}

// handleIndex serves the main dashboard page
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data := struct {
		Title    string
		Time     time.Time
		Version  string
		Platform string
	}{
		Title:    "PacketPanther Dashboard",
		Time:     time.Now(),
		Version:  "v0.1.0",
		Platform: "Go 1.22",
	}

	s.render(w, "index.html", data)
}

// handleCapture serves the packet capture page
func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	topTalkers, err := s.db.GetTopTalkers(10)
	if err != nil {
		log.Printf("Error getting top talkers: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Title      string
		TopTalkers map[string]int64
	}{
		Title:      "Packet Capture - PacketPanther",
		TopTalkers: topTalkers,
	}

	s.render(w, "capture.html", data)
}

// handleTrace serves the traceroute page
func (s *Server) handleTrace(w http.ResponseWriter, r *http.Request) {
	s.render(w, "trace.html", nil)
}

// handleScan serves the port scan page
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	s.render(w, "scan.html", nil)
}

// handleSNMP serves the SNMP page
func (s *Server) handleSNMP(w http.ResponseWriter, r *http.Request) {
	s.render(w, "snmp.html", nil)
}

// handleAPITopTalkers serves top talkers data as JSON
func (s *Server) handleAPITopTalkers(w http.ResponseWriter, r *http.Request) {
	topTalkers, err := s.db.GetTopTalkers(10)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"topTalkers":[`)
	
	i := 0
	for host, bytes := range topTalkers {
		if i > 0 {
			fmt.Fprintf(w, ",")
		}
		fmt.Fprintf(w, `{"host":"%s","bytes":%d}`, host, bytes)
		i++
	}
	
	fmt.Fprintf(w, `]}`)
}

// handleAPITraceResults serves traceroute results as JSON
func (s *Server) handleAPITraceResults(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "Target parameter required", http.StatusBadRequest)
		return
	}

	results, err := s.db.GetTraceResults(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"target":"%s","hops":[`, target)
	
	for i, hop := range results {
		if i > 0 {
			fmt.Fprintf(w, ",")
		}
		fmt.Fprintf(w, `{"hop":%d,"address":"%s","hostname":"%s","latency":%d}`,
			hop.Hop, hop.Address, hop.Hostname, hop.Latency.Milliseconds())
	}
	
	fmt.Fprintf(w, `]}`)
}

// handleAPIScanResults serves port scan results as JSON
func (s *Server) handleAPIScanResults(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "Host parameter required", http.StatusBadRequest)
		return
	}

	ports, err := s.db.GetOpenPortsForHost(host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"host":"%s","openPorts":[`, host)
	
	for i, port := range ports {
		if i > 0 {
			fmt.Fprintf(w, ",")
		}
		fmt.Fprintf(w, `%d`, port)
	}
	
	fmt.Fprintf(w, `]}`)
}

// handleAPISNMPDevices serves SNMP device list as JSON
func (s *Server) handleAPISNMPDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.db.GetSNMPDevices()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"devices":[`)
	
	for i, device := range devices {
		if i > 0 {
			fmt.Fprintf(w, ",")
		}
		fmt.Fprintf(w, `"%s"`, device)
	}
	
	fmt.Fprintf(w, `]}`)
}

// render renders a template with the given data
func (s *Server) render(w http.ResponseWriter, name string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Always execute the layout template which will include the specified content template
	if err := s.templates.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
