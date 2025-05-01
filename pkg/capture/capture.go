package capture

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Samirrahman71/PacketPanther/pkg/storage"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Capturer handles packet capture from network interfaces
type Capturer struct {
	interfaces []string
	handles    map[string]*pcap.Handle
	packets    chan gopacket.Packet
	stats      map[string]int64 // host -> bytes
}

// NewCapturer creates a new packet capturer for the specified interfaces
func NewCapturer(interfaces []string) (*Capturer, error) {
	c := &Capturer{
		interfaces: interfaces,
		handles:    make(map[string]*pcap.Handle),
		packets:    make(chan gopacket.Packet, 1000),
		stats:      make(map[string]int64),
	}
	
	return c, nil
}

// Start begins packet capture on all interfaces
func (c *Capturer) Start(ctx context.Context, db *storage.Database) error {
	// Open pcap handles for each interface
	for _, iface := range c.interfaces {
		handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
		if err != nil {
			return fmt.Errorf("error opening interface %s: %v", iface, err)
		}
		c.handles[iface] = handle
		
		// Start packet capture for this interface
		go c.captureInterface(ctx, iface, handle)
	}
	
	// Start packet processing
	go c.processPackets(ctx, db)
	
	// Periodically save stats to database
	go c.persistStats(ctx, db)
	
	return nil
}

// captureInterface captures packets from a specific interface
func (c *Capturer) captureInterface(ctx context.Context, iface string, handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	for {
		select {
		case <-ctx.Done():
			handle.Close()
			return
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return
			}
			c.packets <- packet
		}
	}
}

// processPackets analyzes captured packets and updates stats
func (c *Capturer) processPackets(ctx context.Context, db *storage.Database) {
	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-c.packets:
			// Extract IP layer
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}
			
			ip, _ := ipLayer.(*layers.IPv4)
			
			// Update stats for source and destination
			srcHost := ip.SrcIP.String()
			dstHost := ip.DstIP.String()
			packetLen := int64(len(packet.Data()))
			
			c.stats[srcHost] += packetLen
			c.stats[dstHost] += packetLen
		}
	}
}

// persistStats saves the traffic statistics to the database
func (c *Capturer) persistStats(ctx context.Context, db *storage.Database) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := db.SaveTrafficStats(c.stats)
			if err != nil {
				log.Printf("Error saving traffic stats: %v", err)
			}
			
			// Log top 5 talkers
			log.Println("Top 5 talkers:")
			topHosts := c.getTopHosts(5)
			for i, host := range topHosts {
				log.Printf("%d. %s: %.2f MB", i+1, host, float64(c.stats[host])/(1024*1024))
			}
		}
	}
}

// getTopHosts returns the top n hosts by traffic volume
func (c *Capturer) getTopHosts(n int) []string {
	type hostTraffic struct {
		host    string
		traffic int64
	}
	
	// Convert map to slice for sorting
	var hostList []hostTraffic
	for host, traffic := range c.stats {
		hostList = append(hostList, hostTraffic{host, traffic})
	}
	
	// Sort by traffic (descending)
	for i := 0; i < len(hostList); i++ {
		for j := i + 1; j < len(hostList); j++ {
			if hostList[i].traffic < hostList[j].traffic {
				hostList[i], hostList[j] = hostList[j], hostList[i]
			}
		}
	}
	
	// Extract top n hosts
	result := make([]string, 0, n)
	for i := 0; i < n && i < len(hostList); i++ {
		result = append(result, hostList[i].host)
	}
	
	return result
}

// GetInterfaceList returns a list of available network interfaces
func GetInterfaceList() ([]string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	
	var interfaces []string
	for _, device := range devices {
		interfaces = append(interfaces, device.Name)
	}
	
	return interfaces, nil
}
