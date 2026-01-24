package network

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TrafficStats holds traffic statistics for a specific point in time
type TrafficStats struct {
	Timestamp int64   `json:"timestamp"`
	RxBytes   uint64  `json:"rx_bytes"`
	TxBytes   uint64  `json:"tx_bytes"`
	RxRate    float64 `json:"rx_rate"` // Bytes per second
	TxRate    float64 `json:"tx_rate"` // Bytes per second
}

// TrafficMonitor handles real-time network traffic monitoring
type TrafficMonitor struct {
	interfaceName string
	history       []TrafficStats
	historyLimit  int
	mutex         sync.RWMutex
	stopChan      chan struct{}
	isRunning     bool
}

// NewTrafficMonitor creates a new traffic monitor instance
func NewTrafficMonitor(interfaceName string) *TrafficMonitor {
	return &TrafficMonitor{
		interfaceName: interfaceName,
		history:       make([]TrafficStats, 0),
		historyLimit:  60, // Keep last 60 seconds (1 minute) of history
		stopChan:      make(chan struct{}),
	}
}

// Start begins the monitoring process
func (tm *TrafficMonitor) Start() {
	tm.mutex.Lock()
	if tm.isRunning {
		tm.mutex.Unlock()
		return
	}
	tm.isRunning = true
	tm.mutex.Unlock()

	go tm.monitorLoop()
}

// Stop stops the monitoring process
func (tm *TrafficMonitor) Stop() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	if !tm.isRunning {
		return
	}
	close(tm.stopChan)
	tm.isRunning = false
}

// monitorLoop is the main loop for collecting traffic data
// monitorLoop is the main loop for collecting traffic data
func (tm *TrafficMonitor) monitorLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastRx, lastTx uint64
	var lastTime time.Time

	// Initial reading
	rx, tx, err := tm.readInterfaceStats()
	if err == nil {
		lastRx = rx
		lastTx = tx
		lastTime = time.Now()
	} else {
		// If initial read fails, set lastTime to now anyway to avoid long first interval
		lastTime = time.Now()
	}

	for {
		select {
		case <-tm.stopChan:
			return
		case <-ticker.C:
			rx, tx, err := tm.readInterfaceStats()
			if err != nil {
				fmt.Printf("Error reading interface stats: %v\n", err)
				continue
			}

			now := time.Now()
			duration := now.Sub(lastTime).Seconds()
			
			if duration <= 0 {
				duration = 1.0 // Safety fallback
			}

			// Calculate rates (Bytes/sec)
			rxRate := float64(rx-lastRx) / duration
			txRate := float64(tx-lastTx) / duration

			// Handle counter overflow/reset
			if rx < lastRx {
				rxRate = 0
			}
			if tx < lastTx {
				txRate = 0
			}

			stats := TrafficStats{
				Timestamp: now.Unix(),
				RxBytes:   rx,
				TxBytes:   tx,
				RxRate:    rxRate,
				TxRate:    txRate,
			}

			tm.addStats(stats)

			lastRx = rx
			lastTx = tx
			lastTime = now
		}
	}
}

// readInterfaceStats reads RX and TX bytes from /proc/net/dev
func (tm *TrafficMonitor) readInterfaceStats() (uint64, uint64, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, tm.interfaceName+":") {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				return 0, 0, fmt.Errorf("unexpected format in /proc/net/dev")
			}

			// Format usually is:
			// Inter-|   Receive                                                |  Transmit
			//  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
			//     lo: 1732200   24765    0    0    0     0          0         0  1732200   24765    0    0    0     0       0          0

			// In fields, fields[0] might be "vmbr0:" or "vmbr0" depending on spacing
			// If it's "vmbr0:", then fields[1] is rx_bytes
			// If it's "vmbr0", then fields[1] is ":" (if detached) or part of name.
			// Standard parsing logic: find the interface name, then take next field as rx, and 9th field after that as tx

			// Let's rely on strings.Fields() splitting
			// Example: "  eth0: 1234 56 ..." -> ["eth0:", "1234", "56", ...]
			// RX bytes is index 1, TX bytes is index 9 (1 + 8)

			rxStr := fields[1]
			txStr := fields[9]

			rx, err := strconv.ParseUint(rxStr, 10, 64)
			if err != nil {
				return 0, 0, err
			}

			tx, err := strconv.ParseUint(txStr, 10, 64)
			if err != nil {
				return 0, 0, err
			}

			return rx, tx, nil
		}
	}

	return 0, 0, fmt.Errorf("interface %s not found in /proc/net/dev", tm.interfaceName)
}

// addStats adds a new stats point and maintains history limit
func (tm *TrafficMonitor) addStats(stats TrafficStats) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	tm.history = append(tm.history, stats)
	if len(tm.history) > tm.historyLimit {
		// Remove oldest, keep last N
		tm.history = tm.history[len(tm.history)-tm.historyLimit:]
	}
}

// GetHistory returns the current traffic history
func (tm *TrafficMonitor) GetHistory() []TrafficStats {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	// Return a copy to avoid race conditions
	result := make([]TrafficStats, len(tm.history))
	copy(result, tm.history)
	return result
}

// GetCurrentRate returns the most recent traffic rate
func (tm *TrafficMonitor) GetCurrentRate() (float64, float64) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	if len(tm.history) == 0 {
		return 0, 0
	}

	last := tm.history[len(tm.history)-1]
	return last.RxRate, last.TxRate
}
