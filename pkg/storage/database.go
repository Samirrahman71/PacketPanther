package storage

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/glebarez/go-sqlite" // Pure Go SQLite driver, no CGO required
)

// Database handles SQLite storage
type Database struct {
	db *sql.DB
}

// TraceResult represents a traceroute hop result stored in the database
type TraceResult struct {
	Target   string
	Hop      int
	Address  string
	Hostname string
	Latency  time.Duration
	Time     time.Time
}

// ScanResult represents a port scan result stored in the database
type ScanResult struct {
	Host      string
	Port      int
	Open      bool
	Latency   time.Duration
	Timestamp time.Time
}

// SNMPResult represents SNMP data stored in the database
type SNMPResult struct {
	Host        string
	SysName     string
	SysDescr    string
	SysUpTime   string
	SysContact  string
	SysLocation string
	Interfaces  []InterfaceInfo
	Timestamp   time.Time
}

// InterfaceInfo contains information about a network interface
type InterfaceInfo struct {
	Index       int
	Name        string
	Description string
	Type        string
	Speed       uint64
	AdminStatus int
	OperStatus  int
	InOctets    uint64
	OutOctets   uint64
}

// NewDatabase creates a new SQLite database connection
func NewDatabase(dbPath string) (*Database, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}

	database := &Database{
		db: db,
	}

	// Initialize database schema
	if err := database.initSchema(); err != nil {
		db.Close()
		return nil, err
	}

	log.Printf("Database initialized at %s", dbPath)
	return database, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	return d.db.Close()
}

// initSchema creates the database tables if they don't exist
func (d *Database) initSchema() error {
	// Create traffic stats table
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS traffic_stats (
			host TEXT NOT NULL,
			bytes INTEGER NOT NULL,
			timestamp DATETIME NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	// Create traceroute results table
	_, err = d.db.Exec(`
		CREATE TABLE IF NOT EXISTS trace_results (
			target TEXT NOT NULL,
			hop INTEGER NOT NULL,
			address TEXT NOT NULL,
			hostname TEXT,
			latency INTEGER NOT NULL,
			timestamp DATETIME NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	// Create port scan results table
	_, err = d.db.Exec(`
		CREATE TABLE IF NOT EXISTS scan_results (
			host TEXT NOT NULL,
			port INTEGER NOT NULL,
			open BOOLEAN NOT NULL,
			latency INTEGER NOT NULL,
			timestamp DATETIME NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	// Create SNMP devices table
	_, err = d.db.Exec(`
		CREATE TABLE IF NOT EXISTS snmp_devices (
			host TEXT NOT NULL PRIMARY KEY,
			sys_name TEXT,
			sys_descr TEXT,
			sys_uptime TEXT,
			sys_contact TEXT,
			sys_location TEXT,
			timestamp DATETIME NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	// Create SNMP interfaces table
	_, err = d.db.Exec(`
		CREATE TABLE IF NOT EXISTS snmp_interfaces (
			host TEXT NOT NULL,
			if_index INTEGER NOT NULL,
			if_name TEXT,
			if_descr TEXT,
			if_type TEXT,
			if_speed INTEGER,
			if_admin_status INTEGER,
			if_oper_status INTEGER,
			in_octets INTEGER,
			out_octets INTEGER,
			timestamp DATETIME NOT NULL,
			PRIMARY KEY (host, if_index, timestamp)
		)
	`)
	if err != nil {
		return err
	}

	// Create indexes for faster queries
	for _, indexSQL := range []string{
		"CREATE INDEX IF NOT EXISTS idx_traffic_stats_host ON traffic_stats(host)",
		"CREATE INDEX IF NOT EXISTS idx_traffic_stats_timestamp ON traffic_stats(timestamp)",
		"CREATE INDEX IF NOT EXISTS idx_trace_results_target ON trace_results(target)",
		"CREATE INDEX IF NOT EXISTS idx_trace_results_timestamp ON trace_results(timestamp)",
		"CREATE INDEX IF NOT EXISTS idx_scan_results_host ON scan_results(host)",
		"CREATE INDEX IF NOT EXISTS idx_scan_results_port ON scan_results(port)",
		"CREATE INDEX IF NOT EXISTS idx_scan_results_timestamp ON scan_results(timestamp)",
		"CREATE INDEX IF NOT EXISTS idx_snmp_interfaces_host ON snmp_interfaces(host)",
		"CREATE INDEX IF NOT EXISTS idx_snmp_interfaces_timestamp ON snmp_interfaces(timestamp)",
	} {
		if _, err := d.db.Exec(indexSQL); err != nil {
			return err
		}
	}

	return nil
}

// SaveTrafficStats saves traffic statistics to the database
func (d *Database) SaveTrafficStats(stats map[string]int64) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	stmt, err := tx.Prepare(`
		INSERT INTO traffic_stats (host, bytes, timestamp)
		VALUES (?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now()
	for host, bytes := range stats {
		_, err = stmt.Exec(host, bytes, now)
		if err != nil {
			return err
		}
	}

	return nil
}

// SaveTraceResults saves traceroute results to the database
func (d *Database) SaveTraceResults(target string, results []interface{}) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	stmt, err := tx.Prepare(`
		INSERT INTO trace_results (target, hop, address, hostname, latency, timestamp)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range results {
		result, ok := r.(struct {
			Target    string
			Hop       int
			Address   string
			Hostname  string
			Latency   time.Duration
			Timestamp time.Time
		})
		if !ok {
			continue
		}

		_, err = stmt.Exec(
			result.Target,
			result.Hop,
			result.Address,
			result.Hostname,
			result.Latency.Nanoseconds(),
			result.Timestamp,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetTraceResults retrieves traceroute results for a specific target
func (d *Database) GetTraceResults(target string) ([]TraceResult, error) {
	rows, err := d.db.Query(`
		SELECT target, hop, address, hostname, latency, timestamp
		FROM trace_results
		WHERE target = ?
		ORDER BY timestamp DESC, hop ASC
		LIMIT 1000
	`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []TraceResult
	for rows.Next() {
		var r TraceResult
		var latencyNs int64
		var timestamp string

		err := rows.Scan(&r.Target, &r.Hop, &r.Address, &r.Hostname, &latencyNs, &timestamp)
		if err != nil {
			return nil, err
		}

		r.Latency = time.Duration(latencyNs)
		r.Time, _ = time.Parse("2006-01-02 15:04:05", timestamp)
		results = append(results, r)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// SaveScanResults saves port scan results to the database
func (d *Database) SaveScanResults(results []interface{}) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	stmt, err := tx.Prepare(`
		INSERT INTO scan_results (host, port, open, latency, timestamp)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range results {
		result, ok := r.(struct {
			Host      string
			Port      int
			Open      bool
			Latency   time.Duration
			Timestamp time.Time
		})
		if !ok {
			continue
		}

		_, err = stmt.Exec(
			result.Host,
			result.Port,
			result.Open,
			result.Latency.Nanoseconds(),
			result.Timestamp,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetOpenPortsForHost retrieves all open ports found for a specific host
func (d *Database) GetOpenPortsForHost(host string) ([]int, error) {
	rows, err := d.db.Query(`
		SELECT DISTINCT port
		FROM scan_results
		WHERE host = ? AND open = 1
		ORDER BY port ASC
	`, host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []int
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return ports, nil
}

// SaveSNMPResult saves SNMP polling results to the database
func (d *Database) SaveSNMPResult(result interface{}) error {
	snmpResult, ok := result.(struct {
		Host        string
		SysName     string
		SysDescr    string
		SysUpTime   string
		SysContact  string
		SysLocation string
		Interfaces  []struct {
			Index       int
			Name        string
			Description string
			Type        string
			Speed       uint64
			AdminStatus int
			OperStatus  int
			InOctets    uint64
			OutOctets   uint64
		}
		Timestamp time.Time
	})
	if !ok {
		return fmt.Errorf("invalid SNMP result type")
	}

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	// Insert or update device information
	_, err = tx.Exec(`
		INSERT OR REPLACE INTO snmp_devices
		(host, sys_name, sys_descr, sys_uptime, sys_contact, sys_location, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`,
		snmpResult.Host,
		snmpResult.SysName,
		snmpResult.SysDescr,
		snmpResult.SysUpTime,
		snmpResult.SysContact,
		snmpResult.SysLocation,
		snmpResult.Timestamp,
	)
	if err != nil {
		return err
	}

	// Insert interface information
	stmt, err := tx.Prepare(`
		INSERT INTO snmp_interfaces
		(host, if_index, if_name, if_descr, if_type, if_speed, if_admin_status, if_oper_status, in_octets, out_octets, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, iface := range snmpResult.Interfaces {
		_, err = stmt.Exec(
			snmpResult.Host,
			iface.Index,
			iface.Name,
			iface.Description,
			iface.Type,
			iface.Speed,
			iface.AdminStatus,
			iface.OperStatus,
			iface.InOctets,
			iface.OutOctets,
			snmpResult.Timestamp,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetSNMPDevices retrieves a list of all SNMP devices from the database
func (d *Database) GetSNMPDevices() ([]string, error) {
	rows, err := d.db.Query(`
		SELECT DISTINCT host
		FROM snmp_devices
		ORDER BY host ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return hosts, nil
}

// GetLatestSNMPResult retrieves the latest SNMP result for a specific host
func (d *Database) GetLatestSNMPResult(host string) (*SNMPResult, error) {
	// Get device information
	var result SNMPResult
	err := d.db.QueryRow(`
		SELECT host, sys_name, sys_descr, sys_uptime, sys_contact, sys_location, timestamp
		FROM snmp_devices
		WHERE host = ?
		ORDER BY timestamp DESC
		LIMIT 1
	`, host).Scan(
		&result.Host,
		&result.SysName,
		&result.SysDescr,
		&result.SysUpTime,
		&result.SysContact,
		&result.SysLocation,
		&result.Timestamp,
	)
	if err != nil {
		return nil, err
	}

	// Get interfaces
	rows, err := d.db.Query(`
		SELECT if_index, if_name, if_descr, if_type, if_speed, if_admin_status, if_oper_status, in_octets, out_octets
		FROM snmp_interfaces
		WHERE host = ? AND timestamp = ?
		ORDER BY if_index ASC
	`, host, result.Timestamp)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var iface InterfaceInfo
		err := rows.Scan(
			&iface.Index,
			&iface.Name,
			&iface.Description,
			&iface.Type,
			&iface.Speed,
			&iface.AdminStatus,
			&iface.OperStatus,
			&iface.InOctets,
			&iface.OutOctets,
		)
		if err != nil {
			return nil, err
		}
		result.Interfaces = append(result.Interfaces, iface)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetTopTalkers retrieves the top n hosts by traffic volume
func (d *Database) GetTopTalkers(n int) (map[string]int64, error) {
	rows, err := d.db.Query(`
		SELECT host, SUM(bytes) as total_bytes
		FROM traffic_stats
		GROUP BY host
		ORDER BY total_bytes DESC
		LIMIT ?
	`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make(map[string]int64)
	for rows.Next() {
		var host string
		var bytes int64
		if err := rows.Scan(&host, &bytes); err != nil {
			return nil, err
		}
		results[host] = bytes
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// CleanupOldData removes data older than the specified retention period
func (d *Database) CleanupOldData(retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	// Delete old traffic stats
	_, err = tx.Exec("DELETE FROM traffic_stats WHERE timestamp < ?", cutoff)
	if err != nil {
		return err
	}

	// Delete old trace results
	_, err = tx.Exec("DELETE FROM trace_results WHERE timestamp < ?", cutoff)
	if err != nil {
		return err
	}

	// Delete old scan results
	_, err = tx.Exec("DELETE FROM scan_results WHERE timestamp < ?", cutoff)
	if err != nil {
		return err
	}

	// Delete old SNMP interfaces
	_, err = tx.Exec("DELETE FROM snmp_interfaces WHERE timestamp < ?", cutoff)
	if err != nil {
		return err
	}

	// Keep SNMP devices (they're small and useful for history)

	return nil
}
