package snmp

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Samirrahman71/PacketPanther/pkg/storage"
	"github.com/gosnmp/gosnmp"
)

// Poller handles SNMP polling of devices
type Poller struct {
	community string
	version   gosnmp.SnmpVersion
	timeout   time.Duration
	retries   int
}

// SNMPResult represents data collected from an SNMP device
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

// NewPoller creates a new SNMP poller
func NewPoller(community string, version int) *Poller {
	// Map version integer to gosnmp version
	var snmpVersion gosnmp.SnmpVersion
	switch version {
	case 1:
		snmpVersion = gosnmp.Version1
	case 3:
		snmpVersion = gosnmp.Version3
	default:
		snmpVersion = gosnmp.Version2c
	}

	return &Poller{
		community: community,
		version:   snmpVersion,
		timeout:   2 * time.Second,
		retries:   3,
	}
}

// PollHosts polls a list of hosts for SNMP data
func (p *Poller) PollHosts(ctx context.Context, hosts []string, db *storage.Database) {
	for _, host := range hosts {
		select {
		case <-ctx.Done():
			return
		default:
			result, err := p.PollHost(host)
			if err != nil {
				log.Printf("Error polling host %s: %v", host, err)
				continue
			}

			err = db.SaveSNMPResult(result)
			if err != nil {
				log.Printf("Error saving SNMP result for host %s: %v", host, err)
			}

			// Add a short delay between polls
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
				// Continue to the next host
			}
		}
	}
}

// PollHost polls a single host for SNMP data
func (p *Poller) PollHost(host string) (*SNMPResult, error) {
	// Create SNMP client
	client := &gosnmp.GoSNMP{
		Target:    host,
		Port:      161,
		Community: p.community,
		Version:   p.version,
		Timeout:   p.timeout,
		Retries:   p.retries,
	}

	// Connect to the device
	err := client.Connect()
	if err != nil {
		return nil, fmt.Errorf("connect error: %v", err)
	}
	defer client.Conn.Close()

	log.Printf("Connected to %s via SNMP", host)

	// Create result structure
	result := &SNMPResult{
		Host:      host,
		Timestamp: time.Now(),
	}

	// Get system information
	if err := p.getSysInfo(client, result); err != nil {
		return result, fmt.Errorf("error getting system info: %v", err)
	}

	// Get interface information
	if err := p.getInterfaceInfo(client, result); err != nil {
		log.Printf("Warning: error getting interface info for %s: %v", host, err)
		// Continue with partial result
	}

	log.Printf("Successfully polled %s (%s): %d interfaces", host, result.SysName, len(result.Interfaces))

	return result, nil
}

// getSysInfo retrieves system information via SNMP
func (p *Poller) getSysInfo(client *gosnmp.GoSNMP, result *SNMPResult) error {
	oids := []string{
		"1.3.6.1.2.1.1.1.0", // sysDescr
		"1.3.6.1.2.1.1.2.0", // sysObjectID
		"1.3.6.1.2.1.1.3.0", // sysUpTime
		"1.3.6.1.2.1.1.4.0", // sysContact
		"1.3.6.1.2.1.1.5.0", // sysName
		"1.3.6.1.2.1.1.6.0", // sysLocation
	}

	pdu, err := client.Get(oids)
	if err != nil {
		return err
	}

	for _, variable := range pdu.Variables {
		switch variable.Name {
		case "1.3.6.1.2.1.1.1.0":
			result.SysDescr = string(variable.Value.([]byte))
		case "1.3.6.1.2.1.1.3.0":
			result.SysUpTime = fmt.Sprintf("%v", variable.Value)
		case "1.3.6.1.2.1.1.4.0":
			result.SysContact = string(variable.Value.([]byte))
		case "1.3.6.1.2.1.1.5.0":
			result.SysName = string(variable.Value.([]byte))
		case "1.3.6.1.2.1.1.6.0":
			result.SysLocation = string(variable.Value.([]byte))
		}
	}

	return nil
}

// getInterfaceInfo retrieves interface information via SNMP
func (p *Poller) getInterfaceInfo(client *gosnmp.GoSNMP, result *SNMPResult) error {
	// Get interface indexes
	ifIndexes, err := p.getTableColumn(client, "1.3.6.1.2.1.2.2.1.1")
	if err != nil {
		return err
	}

	// For each interface, get details
	for _, v := range ifIndexes {
		ifIndex, ok := v.Value.(int)
		if !ok {
			continue
		}

		intf := InterfaceInfo{
			Index: ifIndex,
		}

		// Get interface details
		ifRow := []string{
			fmt.Sprintf("1.3.6.1.2.1.2.2.1.2.%d", ifIndex),  // ifDescr
			fmt.Sprintf("1.3.6.1.2.1.2.2.1.3.%d", ifIndex),  // ifType
			fmt.Sprintf("1.3.6.1.2.1.2.2.1.5.%d", ifIndex),  // ifSpeed
			fmt.Sprintf("1.3.6.1.2.1.2.2.1.7.%d", ifIndex),  // ifAdminStatus
			fmt.Sprintf("1.3.6.1.2.1.2.2.1.8.%d", ifIndex),  // ifOperStatus
			fmt.Sprintf("1.3.6.1.2.1.2.2.1.10.%d", ifIndex), // ifInOctets
			fmt.Sprintf("1.3.6.1.2.1.2.2.1.16.%d", ifIndex), // ifOutOctets
		}

		pdu, err := client.Get(ifRow)
		if err != nil {
			log.Printf("Error getting interface %d details: %v", ifIndex, err)
			continue
		}

		for _, variable := range pdu.Variables {
			oid := variable.Name
			switch {
			case oid == fmt.Sprintf("1.3.6.1.2.1.2.2.1.2.%d", ifIndex):
				intf.Name = string(variable.Value.([]byte))
			case oid == fmt.Sprintf("1.3.6.1.2.1.2.2.1.3.%d", ifIndex):
				intf.Type = fmt.Sprintf("%v", variable.Value)
			case oid == fmt.Sprintf("1.3.6.1.2.1.2.2.1.5.%d", ifIndex):
				intf.Speed = gosnmp.ToBigInt(variable.Value).Uint64()
			case oid == fmt.Sprintf("1.3.6.1.2.1.2.2.1.7.%d", ifIndex):
				intf.AdminStatus = int(gosnmp.ToBigInt(variable.Value).Int64())
			case oid == fmt.Sprintf("1.3.6.1.2.1.2.2.1.8.%d", ifIndex):
				intf.OperStatus = int(gosnmp.ToBigInt(variable.Value).Int64())
			case oid == fmt.Sprintf("1.3.6.1.2.1.2.2.1.10.%d", ifIndex):
				intf.InOctets = gosnmp.ToBigInt(variable.Value).Uint64()
			case oid == fmt.Sprintf("1.3.6.1.2.1.2.2.1.16.%d", ifIndex):
				intf.OutOctets = gosnmp.ToBigInt(variable.Value).Uint64()
			}
		}

		// Try to get interface description from IF-MIB::ifAlias
		ifDescOid := fmt.Sprintf("1.3.6.1.2.1.31.1.1.1.18.%d", ifIndex)
		ifDescPdu, err := client.Get([]string{ifDescOid})
		if err == nil && len(ifDescPdu.Variables) > 0 {
			if ifDescPdu.Variables[0].Type == gosnmp.OctetString {
				intf.Description = string(ifDescPdu.Variables[0].Value.([]byte))
			}
		}

		result.Interfaces = append(result.Interfaces, intf)
	}

	return nil
}

// getTableColumn retrieves a column from an SNMP table
func (p *Poller) getTableColumn(client *gosnmp.GoSNMP, oid string) ([]gosnmp.SnmpPDU, error) {
	var results []gosnmp.SnmpPDU
	
	err := client.Walk(oid, func(pdu gosnmp.SnmpPDU) error {
		results = append(results, pdu)
		return nil
	})
	
	return results, err
}

// GetSNMPDevices retrieves a list of all SNMP devices from the database
func (p *Poller) GetSNMPDevices(db *storage.Database) ([]string, error) {
	return db.GetSNMPDevices()
}

// GetLatestSNMPResult retrieves the latest SNMP result for a specific host
func (p *Poller) GetLatestSNMPResult(host string, db *storage.Database) (*SNMPResult, error) {
	result, err := db.GetLatestSNMPResult(host)
	if err != nil {
		return nil, err
	}
	
	// Convert storage.SNMPResult to snmp.SNMPResult
	snmpResult := &SNMPResult{
		Host:        result.Host,
		SysName:     result.SysName,
		SysDescr:    result.SysDescr,
		SysUpTime:   result.SysUpTime,
		SysContact:  result.SysContact,
		SysLocation: result.SysLocation,
		Timestamp:   result.Timestamp,
	}
	
	// Convert interfaces
	for _, iface := range result.Interfaces {
		snmpResult.Interfaces = append(snmpResult.Interfaces, InterfaceInfo{
			Index:       iface.Index,
			Name:        iface.Name,
			Description: iface.Description,
			Type:        iface.Type,
			Speed:       iface.Speed,
			AdminStatus: iface.AdminStatus,
			OperStatus:  iface.OperStatus,
			InOctets:    iface.InOctets,
			OutOctets:   iface.OutOctets,
		})
	}
	
	return snmpResult, nil
}
