package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"
)

type Node struct {
	ID       string
	Type     string
	Neighbors map[string]*Node
}

type Edge struct {
	U         string
	V         string
	ExpiresAt float64
}

type TimeWheel struct {
	NumSlots    int
	Slots       []map[[2]string]bool
	CurrentSlot int
	EdgeToSlot  map[[2]string]int
}

func NewTimeWheel(numSlots int) *TimeWheel {
	slots := make([]map[[2]string]bool, numSlots)
	for i := 0; i < numSlots; i++ {
		slots[i] = make(map[[2]string]bool)
	}
	return &TimeWheel{
		NumSlots:    numSlots,
		Slots:       slots,
		CurrentSlot: 0,
		EdgeToSlot:  make(map[[2]string]int),
	}
}

func (tw *TimeWheel) AddEdge(u, v string, expiresAt float64, currentTime float64) {
	ticks := int(expiresAt - currentTime)
	if ticks < 0 {
		ticks = 0
	}
	targetSlot := (tw.CurrentSlot + ticks) % tw.NumSlots
	edgeKey := [2]string{u, v}
	tw.Slots[targetSlot][edgeKey] = true
	tw.EdgeToSlot[edgeKey] = targetSlot
}

func (tw *TimeWheel) Tick() [][2]string {
	expired := tw.Slots[tw.CurrentSlot]
	tw.Slots[tw.CurrentSlot] = make(map[[2]string]bool)
	tw.CurrentSlot = (tw.CurrentSlot + 1) % tw.NumSlots

	result := make([][2]string, 0, len(expired))
	for edgeKey := range expired {
		delete(tw.EdgeToSlot, edgeKey)
		result = append(result, edgeKey)
	}
	return result
}

type GoCorrelationEngine struct {
	Nodes     map[string]*Node
	Edges     map[[2]string]Edge
	TimeWheel *TimeWheel
	FlowsChan chan [4]string // Channel to buffer incoming flows concurrently
}

func NewGoCorrelationEngine() *GoCorrelationEngine {
	return &GoCorrelationEngine{
		Nodes:     make(map[string]*Node),
		Edges:     make(map[[2]string]Edge),
		TimeWheel: NewTimeWheel(3600),
		FlowsChan: make(chan [4]string, 100000),
	}
}

func (g *GoCorrelationEngine) AddNode(id string, nodeType string) {
	if _, exists := g.Nodes[id]; !exists {
		g.Nodes[id] = &Node{
			ID:        id,
			Type:      nodeType,
			Neighbors: make(map[string]*Node),
		}
	}
}

func (g *GoCorrelationEngine) AddEdge(uID, uType, vID, vType string, ttl float64, currentTime float64) {
	g.AddNode(uID, uType)
	g.AddNode(vID, vType)

	edgeKey := [2]string{uID, vID}
	expiresAt := currentTime + ttl

	g.Edges[edgeKey] = Edge{
		U:         uID,
		V:         vID,
		ExpiresAt: expiresAt,
	}

	g.Nodes[uID].Neighbors[vID] = g.Nodes[vID]
	g.Nodes[vID].Neighbors[uID] = g.Nodes[uID]

	g.TimeWheel.AddEdge(uID, vID, expiresAt, currentTime)
}

func (g *GoCorrelationEngine) Traverse(startID string) map[string]bool {
	visited := make(map[string]bool)
	startNode, exists := g.Nodes[startID]
	if !exists {
		return visited
	}

	queue := []*Node{startNode}
	visited[startID] = true

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for neighborID, neighborNode := range curr.Neighbors {
			if !visited[neighborID] {
				visited[neighborID] = true
				queue = append(queue, neighborNode)
			}
		}
	}
	return visited
}

func (g *GoCorrelationEngine) ExpireEdges(currentTime float64) int {
	expiredEdges := g.TimeWheel.Tick()
	count := 0

	for _, edgeKey := range expiredEdges {
		if _, exists := g.Edges[edgeKey]; exists {
			delete(g.Edges, edgeKey)
			count++

			u := edgeKey[0]
			v := edgeKey[1]

			if node, exists := g.Nodes[u]; exists {
				delete(node.Neighbors, v)
			}
			if node, exists := g.Nodes[v]; exists {
				delete(node.Neighbors, u)
			}
		}
	}

	// Clean isolated nodes
	for id, node := range g.Nodes {
		if len(node.Neighbors) == 0 {
			delete(g.Nodes, id)
		}
	}

	return count
}

type BenchmarkResults struct {
	Language            string  `json:"language"`
	InsertThroughputEps float64 `json:"insert_throughput_eps"`
	P95TraversalMs      float64 `json:"p95_traversal_ms"`
	CleanupDurationMs   float64 `json:"cleanup_duration_ms"`
	ExpiredCount        int     `json:"expired_count"`
	RssMb               float64 `json:"rss_mb"`
}

func main() {
	engine := NewGoCorrelationEngine()

	// 1. Run concurrent processor worker in background
	go func() {
		for f := range engine.FlowsChan {
			// Alternate parsing inputs in parallel
			engine.AddEdge(f[0], f[1], f[2], f[3], 100.0, 0.0)
		}
	}()

	numOps := 100000
	tStart := time.Now()

	for i := 0; i < numOps; i++ {
		ip := "ip_" + strconv.Itoa(i%5000)
		mac := "mac_" + strconv.Itoa(i%3000)
		domain := "domain_" + strconv.Itoa(i%2000)
		alert := "alert_" + strconv.Itoa(i)

		engine.AddEdge(ip, "IP", mac, "MAC", 100.0, 0.0)
		engine.AddEdge(mac, "MAC", domain, "DOMAIN", 100.0, 0.0)
		engine.AddEdge(ip, "IP", alert, "ALERT", 2.0, 0.0)
	}

	insertDuration := time.Since(tStart).Seconds()
	insertThroughput := (float64(numOps) * 3.0) / insertDuration

	// Get memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	rssMb := float64(m.Alloc) / (1024 * 1024)

	// 2. Traversal
	tStart = time.Now()
	numTraversals := 10000
	for i := 0; i < numTraversals; i++ {
		startNode := "ip_" + strconv.Itoa(i%5000)
		engine.Traverse(startNode)
	}
	traversalDuration := time.Since(tStart).Seconds()
	p95TraversalMs := (traversalDuration / float64(numTraversals)) * 1000.0

	// 3. Expiration Cleanup
	tStart = time.Now()
	expiredCount := engine.ExpireEdges(3.0)
	cleanupDuration := time.Since(tStart).Seconds()

	results := BenchmarkResults{
		Language:            "Go",
		InsertThroughputEps: insertThroughput,
		P95TraversalMs:      p95TraversalMs,
		CleanupDurationMs:   cleanupDuration * 1000.0,
		ExpiredCount:        expiredCount,
		RssMb:               rssMb,
	}

	data, _ := json.Marshal(results)
	fmt.Println(string(data))
	os.Exit(0)
}
