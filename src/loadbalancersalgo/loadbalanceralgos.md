# Document 2: Load Balancing Algorithms
## From Simple Round-Robin to Intelligent Routing

> "The algorithm you choose determines not just how traffic is distributed, but how your system behaves under load, handles failures, and scales."

---

## Table of Contents
1. [Algorithm Selection Criteria](#algorithm-selection-criteria)
2. [Round-Robin Family](#round-robin-family)
3. [Connection-Based Algorithms](#connection-based-algorithms)
4. [Performance-Based Algorithms](#performance-based-algorithms)
5. [Hash-Based Algorithms](#hash-based-algorithms)
6. [Advanced Algorithms](#advanced-algorithms)
7. [Algorithm Comparison](#algorithm-comparison)
8. [Practice Problems](#practice-problems)

---

## Algorithm Selection Criteria

Before diving into algorithms, understand what makes a good algorithm:

### Key Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| **Fairness** | Even distribution across servers | Variance < 10% |
| **Server Utilization** | % of capacity used | 70-80% |
| **Latency** | Response time impact | < 1ms added |
| **Adaptability** | Response to changes | < 1 second |
| **Complexity** | Algorithm overhead | O(1) or O(log n) |
| **Stickiness** | Session persistence | Configurable |

### Decision Tree

```
┌─ Stateless service?
│  ├─ Yes → Round-Robin or Random
│  └─ No → Least Connections or Consistent Hash
│
├─ Need session affinity?
│  ├─ Yes → Consistent Hash or IP Hash
│  └─ No → Any algorithm
│
├─ Heterogeneous servers?
│  ├─ Yes → Weighted algorithms or Least Response Time
│  └─ No → Simple algorithms (Round-Robin)
│
├─ Performance critical?
│  ├─ Yes → Least Response Time or Power of Two Choices
│  └─ No → Round-Robin
│
└─ Cache optimization needed?
   ├─ Yes → Consistent Hash
   └─ No → Any algorithm
```

---

## Round-Robin Family

### 1. Simple Round-Robin

**How it works:**
Distribute requests sequentially to servers in a circular order.

```
Servers: [S1, S2, S3]

Request 1 → S1
Request 2 → S2
Request 3 → S3
Request 4 → S1  (loops back)
Request 5 → S2
Request 6 → S3
```

**Algorithm:**
```java
public class RoundRobin {
    private final List<String> servers;
    private final AtomicInteger index;
    
    public RoundRobin(List<String> servers) {
        this.servers = new ArrayList<>(servers);
        this.index = new AtomicInteger(0);
    }
    
    public String getNextServer() {
        int currentIndex = index.getAndUpdate(i -> (i + 1) % servers.size());
        return servers.get(currentIndex);
    }
}

// Usage
RoundRobin lb = new RoundRobin(Arrays.asList("S1", "S2", "S3"));
System.out.println(lb.getNextServer());  // S1
System.out.println(lb.getNextServer());  // S2
System.out.println(lb.getNextServer());  // S3
System.out.println(lb.getNextServer());  // S1

// Thread-safe version for production
public class ThreadSafeRoundRobin {
    private final List<String> servers;
    private final AtomicInteger index = new AtomicInteger(0);
    
    public ThreadSafeRoundRobin(List<String> servers) {
        this.servers = Collections.unmodifiableList(new ArrayList<>(servers));
    }
    
    public String getNextServer() {
        if (servers.isEmpty()) {
            throw new IllegalStateException("No servers available");
        }
        int currentIndex = Math.abs(index.getAndIncrement() % servers.size());
        return servers.get(currentIndex);
    }
}
```

**Time Complexity:** O(1)
**Space Complexity:** O(1)

**Pros:**
- ✅ Simple to implement
- ✅ Fair distribution (equal traffic)
- ✅ No server state needed
- ✅ Low overhead

**Cons:**
- ❌ Ignores server capacity
- ❌ Ignores current load
- ❌ Bad for heterogeneous servers
- ❌ No session affinity

**When to use:**
- Homogeneous servers (same capacity)
- Stateless applications
- Simple deployments
- Low traffic volume

**Real-world example:**
```nginx
upstream backend {
    server srv1.example.com;
    server srv2.example.com;
    server srv3.example.com;
}
```

**Distribution Analysis:**

For 1000 requests with 3 servers:
```
S1: 333 requests (33.3%)
S2: 333 requests (33.3%)
S3: 334 requests (33.4%)

Perfect fairness!
```

### 2. Weighted Round-Robin

**How it works:**
Like round-robin, but servers get different number of requests based on weights.

```
Servers: [S1(weight=3), S2(weight=2), S3(weight=1)]

Sequence: S1, S1, S1, S2, S2, S3
Request 1 → S1
Request 2 → S1
Request 3 → S1
Request 4 → S2
Request 5 → S2
Request 6 → S3
Request 7 → S1  (cycle repeats)
```

**Algorithm (Smooth Weighted Round-Robin - Nginx style):**
```java
public class WeightedRoundRobin {
    
    private static class Server {
        String name;
        int weight;
        int currentWeight;
        int effectiveWeight;
        
        Server(String name, int weight) {
            this.name = name;
            this.weight = weight;
            this.currentWeight = 0;
            this.effectiveWeight = weight;
        }
    }
    
    private final List<Server> servers;
    private final int totalWeight;
    private final Object lock = new Object();
    
    public WeightedRoundRobin(Map<String, Integer> serverWeights) {
        this.servers = new ArrayList<>();
        int sum = 0;
        
        for (Map.Entry<String, Integer> entry : serverWeights.entrySet()) {
            servers.add(new Server(entry.getKey(), entry.getValue()));
            sum += entry.getValue();
        }
        
        this.totalWeight = sum;
    }
    
    public String getNextServer() {
        synchronized (lock) {
            if (servers.isEmpty()) {
                throw new IllegalStateException("No servers available");
            }
            
            // Increase current_weight by effective_weight
            for (Server server : servers) {
                server.currentWeight += server.effectiveWeight;
            }
            
            // Select server with highest current_weight
            Server best = servers.stream()
                .max(Comparator.comparingInt(s -> s.currentWeight))
                .orElseThrow();
            
            // Decrease selected server's current_weight
            best.currentWeight -= totalWeight;
            
            return best.name;
        }
    }
    
    // Mark server as down (reduce effective weight to 0)
    public void markServerDown(String serverName) {
        synchronized (lock) {
            servers.stream()
                .filter(s -> s.name.equals(serverName))
                .findFirst()
                .ifPresent(s -> s.effectiveWeight = 0);
        }
    }
    
    // Restore server (restore original weight)
    public void markServerUp(String serverName) {
        synchronized (lock) {
            servers.stream()
                .filter(s -> s.name.equals(serverName))
                .findFirst()
                .ifPresent(s -> s.effectiveWeight = s.weight);
        }
    }
}

// Usage
Map<String, Integer> serverWeights = new LinkedHashMap<>();
serverWeights.put("S1", 5);
serverWeights.put("S2", 1);
serverWeights.put("S3", 1);

WeightedRoundRobin lb = new WeightedRoundRobin(serverWeights);

// First 14 requests:
for (int i = 0; i < 14; i++) {
    System.out.println(lb.getNextServer());
}
// Output: S1, S1, S2, S1, S3, S1, S1, S1, S1, S2, S1, S3, S1, S1
// Total: S1=11, S2=2, S3=2 (roughly 5:1:1 ratio)
```

**Why "Smooth"?**
Older algorithms would do: S1, S1, S1, S1, S1, S2, S3 (bursty)
Smooth WRR distributes better: S1, S1, S2, S1, S3, S1, S1 (spread out)

**Distribution Analysis:**

For 1000 requests with weights [5, 1, 1]:
```
S1: ~714 requests (71.4%)
S2: ~143 requests (14.3%)
S3: ~143 requests (14.3%)

Matches weight ratios!
```

**Pros:**
- ✅ Handles heterogeneous servers
- ✅ Smooth distribution (not bursty)
- ✅ Configurable load distribution
- ✅ Still O(1) per request

**Cons:**
- ❌ Static weights (manual tuning)
- ❌ Doesn't adapt to current load
- ❌ No session affinity

**When to use:**
- Different server capacities (4-core vs 8-core)
- Gradual rollouts (10% to new version)
- A/B testing with specific ratios
- Canary deployments

**Real-world example (HAProxy):**
```haproxy
backend servers
    balance roundrobin
    server srv1 192.168.1.1:80 weight 5
    server srv2 192.168.1.2:80 weight 1
    server srv3 192.168.1.3:80 weight 1
```

### 3. Random Selection

**How it works:**
Pick a random server for each request.

```java
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class RandomSelection {
    private final List<String> servers;
    
    public RandomSelection(List<String> servers) {
        this.servers = new ArrayList<>(servers);
    }
    
    public String getNextServer() {
        if (servers.isEmpty()) {
            throw new IllegalStateException("No servers available");
        }
        // ThreadLocalRandom is faster than Random in concurrent scenarios
        int index = ThreadLocalRandom.current().nextInt(servers.size());
        return servers.get(index);
    }
}

// Usage
RandomSelection lb = new RandomSelection(Arrays.asList("S1", "S2", "S3"));
System.out.println(lb.getNextServer());  // Random server
```

**Distribution Analysis:**

For 1000 requests with 3 servers:
```
S1: ~333 ± 20 requests
S2: ~333 ± 20 requests  
S3: ~333 ± 20 requests

Good fairness in practice!
```

**Pros:**
- ✅ Simple implementation
- ✅ No state needed
- ✅ Works well at scale
- ✅ No lock contention (truly stateless)

**Cons:**
- ❌ Not deterministic
- ❌ Short-term unfairness
- ❌ No session affinity

**When to use:**
- Very high concurrency (millions of connections)
- Want zero synchronization overhead
- Distribution doesn't need to be perfect

---

## Connection-Based Algorithms

### 1. Least Connections

**How it works:**
Send requests to server with fewest active connections.

```
Current state:
S1: 5 connections
S2: 3 connections  ← Pick this one
S3: 7 connections

New request → S2
```

**Algorithm:**
```java
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class LeastConnections {
    private final Map<String, AtomicInteger> connections;
    
    public LeastConnections(List<String> servers) {
        this.connections = new ConcurrentHashMap<>();
        for (String server : servers) {
            connections.put(server, new AtomicInteger(0));
        }
    }
    
    public String getNextServer() {
        // Find server with minimum connections
        return connections.entrySet().stream()
            .min(Comparator.comparingInt(e -> e.getValue().get()))
            .map(Map.Entry::getKey)
            .orElseThrow(() -> new IllegalStateException("No servers available"));
    }
    
    public void onRequestStart(String server) {
        connections.get(server).incrementAndGet();
    }
    
    public void onRequestEnd(String server) {
        connections.get(server).decrementAndGet();
    }
    
    public int getConnectionCount(String server) {
        return connections.get(server).get();
    }
}

// Usage
LeastConnections lb = new LeastConnections(Arrays.asList("S1", "S2", "S3"));

// Request comes in
String server = lb.getNextServer();  // Returns S1 (0 connections)
lb.onRequestStart(server);           // S1 now has 1 connection

// Request completes
lb.onRequestEnd(server);             // S1 back to 0 connections
```

**Time Complexity:** O(n) - can be optimized to O(log n) with heap

**Optimized Implementation with PriorityQueue:**
```java
import java.util.*;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;

public class LeastConnectionsOptimized {
    
    private static class ServerEntry implements Comparable<ServerEntry> {
        String serverName;
        int connections;
        
        ServerEntry(String serverName, int connections) {
            this.serverName = serverName;
            this.connections = connections;
        }
        
        @Override
        public int compareTo(ServerEntry other) {
            return Integer.compare(this.connections, other.connections);
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof ServerEntry)) return false;
            ServerEntry that = (ServerEntry) o;
            return serverName.equals(that.serverName);
        }
        
        @Override
        public int hashCode() {
            return serverName.hashCode();
        }
    }
    
    private final PriorityBlockingQueue<ServerEntry> heap;
    private final Map<String, Integer> serverConnections;
    private final Object lock = new Object();
    
    public LeastConnectionsOptimized(List<String> servers) {
        this.heap = new PriorityBlockingQueue<>();
        this.serverConnections = new ConcurrentHashMap<>();
        
        for (String server : servers) {
            heap.offer(new ServerEntry(server, 0));
            serverConnections.put(server, 0);
        }
    }
    
    public String getNextServer() {
        synchronized (lock) {
            // Get server with minimum connections
            ServerEntry entry = heap.poll();
            if (entry == null) {
                throw new IllegalStateException("No servers available");
            }
            
            // Increment connection count
            entry.connections++;
            serverConnections.put(entry.serverName, entry.connections);
            
            // Re-add to heap with updated count
            heap.offer(entry);
            
            return entry.serverName;
        }
    }
    
    public void onRequestEnd(String serverName) {
        synchronized (lock) {
            Integer connections = serverConnections.get(serverName);
            if (connections != null && connections > 0) {
                // Remove old entry
                heap.removeIf(e -> e.serverName.equals(serverName));
                
                // Add updated entry
                int newCount = connections - 1;
                serverConnections.put(serverName, newCount);
                heap.offer(new ServerEntry(serverName, newCount));
            }
        }
    }
}

// Production-Ready Version with Try-With-Resources Support
public class LeastConnectionsProduction {
    
    private final Map<String, AtomicInteger> connections;
    private final List<String> servers;
    
    public LeastConnectionsProduction(List<String> servers) {
        this.servers = new ArrayList<>(servers);
        this.connections = new ConcurrentHashMap<>();
        for (String server : servers) {
            connections.put(server, new AtomicInteger(0));
        }
    }
    
    public String getNextServer() {
        return connections.entrySet().stream()
            .min(Comparator.comparingInt(e -> e.getValue().get()))
            .map(Map.Entry::getKey)
            .orElseThrow(() -> new IllegalStateException("No servers available"));
    }
    
    // Returns auto-closeable connection tracker
    public Connection connect() {
        String server = getNextServer();
        connections.get(server).incrementAndGet();
        return new Connection(server, this);
    }
    
    private void onConnectionClose(String server) {
        connections.get(server).decrementAndGet();
    }
    
    // Auto-closeable connection
    public static class Connection implements AutoCloseable {
        private final String server;
        private final LeastConnectionsProduction loadBalancer;
        private boolean closed = false;
        
        Connection(String server, LeastConnectionsProduction lb) {
            this.server = server;
            this.loadBalancer = lb;
        }
        
        public String getServer() {
            return server;
        }
        
        @Override
        public void close() {
            if (!closed) {
                loadBalancer.onConnectionClose(server);
                closed = true;
            }
        }
    }
}

// Usage with try-with-resources
LeastConnectionsProduction lb = new LeastConnectionsProduction(
    Arrays.asList("S1", "S2", "S3")
);

try (LeastConnectionsProduction.Connection conn = lb.connect()) {
    String server = conn.getServer();
    // Process request...
} // Connection automatically decremented
```

**Pros:**
- ✅ Automatically balances load
- ✅ Works well with long-lived connections
- ✅ Adapts to server capacity
- ✅ Good for variable request times

**Cons:**
- ❌ Requires connection tracking
- ❌ More overhead than round-robin
- ❌ Not ideal for short connections
- ❌ Can overload slow servers

**When to use:**
- Long-lived connections (WebSockets, streaming)
- Variable request durations
- Database connection pooling
- gRPC services

**Real-world example (HAProxy):**
```haproxy
backend servers
    balance leastconn
    server srv1 192.168.1.1:80 check
    server srv2 192.168.1.2:80 check
    server srv3 192.168.1.3:80 check
```

### 2. Weighted Least Connections

**How it works:**
Least connections, but considering server weights (capacity).

```
Formula: connections / weight

S1: 10 connections, weight=5 → score = 10/5 = 2.0
S2: 4 connections, weight=2  → score = 4/2 = 2.0
S3: 2 connections, weight=1  → score = 2/1 = 2.0  ← All equal!

S1: 10 connections, weight=5 → score = 10/5 = 2.0
S2: 3 connections, weight=2  → score = 3/2 = 1.5  ← Pick this
S3: 2 connections, weight=1  → score = 2/1 = 2.0
```

**Algorithm:**
```java
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class WeightedLeastConnections {
    
    private static class ServerInfo {
        final int weight;
        final AtomicInteger connections;
        
        ServerInfo(int weight) {
            this.weight = weight;
            this.connections = new AtomicInteger(0);
        }
        
        double getScore() {
            return (double) connections.get() / weight;
        }
    }
    
    private final Map<String, ServerInfo> servers;
    
    public WeightedLeastConnections(Map<String, Integer> serverWeights) {
        this.servers = new ConcurrentHashMap<>();
        for (Map.Entry<String, Integer> entry : serverWeights.entrySet()) {
            servers.put(entry.getKey(), new ServerInfo(entry.getValue()));
        }
    }
    
    public String getNextServer() {
        // Find server with minimum connections/weight ratio
        return servers.entrySet().stream()
            .min(Comparator.comparingDouble(e -> e.getValue().getScore()))
            .map(Map.Entry::getKey)
            .orElseThrow(() -> new IllegalStateException("No servers available"));
    }
    
    public void onRequestStart(String server) {
        ServerInfo info = servers.get(server);
        if (info != null) {
            info.connections.incrementAndGet();
        }
    }
    
    public void onRequestEnd(String server) {
        ServerInfo info = servers.get(server);
        if (info != null) {
            info.connections.decrementAndGet();
        }
    }
    
    public Map<String, Integer> getConnectionCounts() {
        Map<String, Integer> counts = new HashMap<>();
        servers.forEach((name, info) -> 
            counts.put(name, info.connections.get())
        );
        return counts;
    }
    
    public Map<String, Double> getScores() {
        Map<String, Double> scores = new HashMap<>();
        servers.forEach((name, info) -> 
            scores.put(name, info.getScore())
        );
        return scores;
    }
}

// Usage
Map<String, Integer> serverWeights = new LinkedHashMap<>();
serverWeights.put("S1", 5);  // High capacity
serverWeights.put("S2", 2);  // Medium capacity
serverWeights.put("S3", 1);  // Low capacity

WeightedLeastConnections lb = new WeightedLeastConnections(serverWeights);

// Simulate requests
String server = lb.getNextServer();  // Returns server with best score
lb.onRequestStart(server);

// Check scores
System.out.println("Current scores: " + lb.getScores());
// Output: {S1=0.2, S2=0.5, S3=1.0}

// Production version with auto-close
public class WeightedLeastConnectionsProduction {
    private final WeightedLeastConnections lb;
    
    public WeightedLeastConnectionsProduction(Map<String, Integer> weights) {
        this.lb = new WeightedLeastConnections(weights);
    }
    
    public Connection connect() {
        String server = lb.getNextServer();
        lb.onRequestStart(server);
        return new Connection(server, lb);
    }
    
    public static class Connection implements AutoCloseable {
        private final String server;
        private final WeightedLeastConnections loadBalancer;
        private boolean closed = false;
        
        Connection(String server, WeightedLeastConnections lb) {
            this.server = server;
            this.loadBalancer = lb;
        }
        
        public String getServer() {
            return server;
        }
        
        @Override
        public void close() {
            if (!closed) {
                loadBalancer.onRequestEnd(server);
                closed = true;
            }
        }
    }
}
```

**Pros:**
- ✅ Best of both worlds (capacity + load)
- ✅ Adapts to heterogeneous servers
- ✅ Prevents overload of weak servers

**Cons:**
- ❌ More complex
- ❌ Need to tune weights
- ❌ Higher overhead

**When to use:**
- Mixed server capacities (4GB vs 32GB RAM)
- Gradual rollouts with load awareness
- Production + canary with different sizes

---

## Performance-Based Algorithms

### 1. Least Response Time

**How it works:**
Send requests to server with lowest average response time.

```
Current state:
S1: avg response = 50ms
S2: avg response = 30ms  ← Pick this one
S3: avg response = 80ms

Some variants combine with connections:
Score = (response_time × active_connections)
```

**Algorithm:**
```python
from collections import deque
import time

class LeastResponseTime:
    def __init__(self, servers, window_size=100):
        self.servers = {
            server: {
                'response_times': deque(maxlen=window_size),
                'avg_response_time': 0,
                'active_connections': 0
            }
            for server in servers
        }
    
    def get_next_server(self):
        # Find server with minimum response time
        server = min(
            self.servers.keys(),
            key=lambda s: self.servers[s]['avg_response_time'] or float('inf')
        )
        self.servers[server]['active_connections'] += 1
        return server
    
    def on_request_complete(self, server, response_time):
        server_info = self.servers[server]
        server_info['response_times'].append(response_time)
        server_info['avg_response_time'] = (
            sum(server_info['response_times']) / 
            len(server_info['response_times'])
        )
        server_info['active_connections'] -= 1

# Usage
lb = LeastResponseTime(['S1', 'S2', 'S3'])

start = time.time()
server = lb.get_next_server()
# ... process request ...
duration = time.time() - start
lb.on_request_complete(server, duration)
```

**Enhanced Version (with connections):**
```python
class LeastResponseTimeWithConnections:
    # ... (similar structure) ...
    
    def get_next_server(self):
        # Score = avg_response_time * (active_connections + 1)
        server = min(
            self.servers.keys(),
            key=lambda s: (
                self.servers[s]['avg_response_time'] * 
                (self.servers[s]['active_connections'] + 1)
            )
        )
        return server
```

**Pros:**
- ✅ Performance-aware routing
- ✅ Adapts to server load automatically
- ✅ Handles heterogeneous servers
- ✅ Routes away from slow servers

**Cons:**
- ❌ Complex implementation
- ❌ Needs response time tracking
- ❌ Can oscillate under load
- ❌ Needs careful tuning (window size)

**When to use:**
- Mixed server generations (old + new hardware)
- Auto-scaling environments
- Databases with variable query times
- Microservices with different SLAs

**Real-world example (AWS ALB):**
```
ALB automatically tracks:
- Target response times
- Request count
- Error rates

Uses this for intelligent routing
```

### 2. Power of Two Choices

**How it works:**
Pick two random servers, choose the one with fewer connections.

```
Request arrives:

1. Randomly pick 2 servers: S2, S5
   S2: 10 connections
   S5: 7 connections  ← Choose this one

2. Send request to S5
```

**Algorithm:**
```java
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

public class PowerOfTwoChoices {
    private final List<String> servers;
    private final Map<String, AtomicInteger> connections;
    
    public PowerOfTwoChoices(List<String> servers) {
        this.servers = new ArrayList<>(servers);
        this.connections = new ConcurrentHashMap<>();
        for (String server : servers) {
            connections.put(server, new AtomicInteger(0));
        }
    }
    
    public String getNextServer() {
        if (servers.size() < 2) {
            return servers.get(0);
        }
        
        // Pick two random servers
        ThreadLocalRandom random = ThreadLocalRandom.current();
        int idx1 = random.nextInt(servers.size());
        int idx2 = random.nextInt(servers.size());
        
        // Ensure we pick two different servers
        while (idx1 == idx2 && servers.size() > 1) {
            idx2 = random.nextInt(servers.size());
        }
        
        String server1 = servers.get(idx1);
        String server2 = servers.get(idx2);
        
        // Choose one with fewer connections
        int conn1 = connections.get(server1).get();
        int conn2 = connections.get(server2).get();
        
        return conn1 <= conn2 ? server1 : server2;
    }
    
    public void onRequestStart(String server) {
        connections.get(server).incrementAndGet();
    }
    
    public void onRequestEnd(String server) {
        connections.get(server).decrementAndGet();
    }
    
    public Map<String, Integer> getConnectionCounts() {
        Map<String, Integer> counts = new HashMap<>();
        connections.forEach((name, count) -> 
            counts.put(name, count.get())
        );
        return counts;
    }
}

// Usage
PowerOfTwoChoices lb = new PowerOfTwoChoices(
    Arrays.asList("S1", "S2", "S3", "S4", "S5")
);

String server = lb.getNextServer();
lb.onRequestStart(server);
// ... process request ...
lb.onRequestEnd(server);

// Production version with auto-close
public class PowerOfTwoChoicesProduction {
    private final PowerOfTwoChoices lb;
    
    public PowerOfTwoChoicesProduction(List<String> servers) {
        this.lb = new PowerOfTwoChoices(servers);
    }
    
    public Connection connect() {
        String server = lb.getNextServer();
        lb.onRequestStart(server);
        return new Connection(server, lb);
    }
    
    public static class Connection implements AutoCloseable {
        private final String server;
        private final PowerOfTwoChoices loadBalancer;
        private boolean closed = false;
        
        Connection(String server, PowerOfTwoChoices lb) {
            this.server = server;
            this.loadBalancer = lb;
        }
        
        public String getServer() {
            return server;
        }
        
        @Override
        public void close() {
            if (!closed) {
                loadBalancer.onRequestEnd(server);
                closed = true;
            }
        }
    }
}

// Benchmark example
public static void benchmarkPowerOfTwo() {
    int numServers = 100;
    int numRequests = 1_000_000;
    
    List<String> servers = new ArrayList<>();
    for (int i = 0; i < numServers; i++) {
        servers.add("server-" + i);
    }
    
    PowerOfTwoChoices lb = new PowerOfTwoChoices(servers);
    
    // Simulate requests
    for (int i = 0; i < numRequests; i++) {
        String server = lb.getNextServer();
        lb.onRequestStart(server);
        // Simulate request processing
        lb.onRequestEnd(server);
    }
    
    // Analyze distribution
    Map<String, Integer> finalCounts = lb.getConnectionCounts();
    IntSummaryStatistics stats = finalCounts.values().stream()
        .mapToInt(Integer::intValue)
        .summaryStatistics();
    
    System.out.println("Distribution stats:");
    System.out.println("Min connections: " + stats.getMin());
    System.out.println("Max connections: " + stats.getMax());
    System.out.println("Average: " + stats.getAverage());
    System.out.println("Imbalance: " + (stats.getMax() - stats.getMin()));
}
```

**Why is this good?**

Mathematical proof shows:
- Random selection: load imbalance = O(log n)
- Power of two: load imbalance = O(log log n)

Huge improvement with minimal overhead!

**Comparison:**

For 10,000 servers with 1M requests:
```
Random:           Max load ~1500, Min load ~500
Power of Two:     Max load ~1100, Min load ~900
Least Connections: Max load ~1020, Min load ~980

Power of Two is 90% as good as Least Connections
with only O(1) complexity instead of O(n)!
```

**Pros:**
- ✅ Near-optimal load balancing
- ✅ O(1) time complexity
- ✅ Simple implementation
- ✅ Low overhead

**Cons:**
- ❌ Non-deterministic
- ❌ Slightly worse than full least connections
- ❌ Requires connection tracking

**When to use:**
- Very large server pools (100+)
- High-throughput systems
- When least connections is too expensive
- Distributed load balancers

**Real-world usage:**
- Used by Google's Maglev
- AWS Network Load Balancer
- Many CDNs

---

## Hash-Based Algorithms

### 1. IP Hash

**How it works:**
Hash client IP to consistently route to same server.

```
Client IP: 192.168.1.100

hash(192.168.1.100) % num_servers = 2

Request → S2 (always)
```

**Algorithm:**
```python
import hashlib

class IPHash:
    def __init__(self, servers):
        self.servers = servers
    
    def get_server(self, client_ip):
        # Hash the IP
        hash_value = int(hashlib.md5(
            client_ip.encode()
        ).hexdigest(), 16)
        
        # Modulo to get server index
        index = hash_value % len(self.servers)
        return self.servers[index]

# Usage
lb = IPHash(['S1', 'S2', 'S3'])
print(lb.get_server('192.168.1.100'))  # Always same server
print(lb.get_server('192.168.1.101'))  # Different server
```

**Pros:**
- ✅ Session affinity (sticky sessions)
- ✅ No cookies or session store needed
- ✅ Simple implementation
- ✅ Deterministic routing

**Cons:**
- ❌ Uneven distribution (some IPs more common)
- ❌ Adding/removing servers breaks affinity
- ❌ Doesn't consider server load
- ❌ Vulnerable to hot spots

**When to use:**
- Need session affinity
- Stateful applications
- Can't use cookies (API clients)
- Cache locality important

**Real-world example (NGINX):**
```nginx
upstream backend {
    ip_hash;
    server srv1.example.com;
    server srv2.example.com;
    server srv3.example.com;
}
```

### 2. Consistent Hashing

**The Problem with Simple Hash:**

```
Initial: 3 servers
hash(key) % 3

Add 1 server → 4 servers total
hash(key) % 4

Almost ALL keys remap to different servers!
Cache invalidation nightmare!
```

**How Consistent Hashing Works:**

Imagine a ring (0 to 2^32):

```
                  0/2^32
                    ↑
        hash(S3) ←  |  → hash(S1)
                    |
                    |
        hash(K2) ← ○ → hash(K1)
                    |
                    |
                hash(S2)

Key goes to next server clockwise on ring
```

**Algorithm:**
```java
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class ConsistentHash<T> {
    
    private final int virtualNodes;
    private final TreeMap<Long, T> ring;
    private final ReadWriteLock lock;
    private final MessageDigest md5;
    
    public ConsistentHash(int virtualNodes) {
        this.virtualNodes = virtualNodes;
        this.ring = new TreeMap<>();
        this.lock = new ReentrantReadWriteLock();
        
        try {
            this.md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 algorithm not found", e);
        }
    }
    
    public ConsistentHash(Collection<T> servers, int virtualNodes) {
        this(virtualNodes);
        for (T server : servers) {
            addServer(server);
        }
    }
    
    // Default constructor with 150 virtual nodes
    public ConsistentHash(Collection<T> servers) {
        this(servers, 150);
    }
    
    private long hash(String key) {
        md5.reset();
        md5.update(key.getBytes(StandardCharsets.UTF_8));
        byte[] digest = md5.digest();
        
        // Convert to long (use first 8 bytes)
        long hash = 0;
        for (int i = 0; i < 8; i++) {
            hash = (hash << 8) | (digest[i] & 0xFF);
        }
        return hash;
    }
    
    public void addServer(T server) {
        lock.writeLock().lock();
        try {
            for (int i = 0; i < virtualNodes; i++) {
                String virtualKey = server.toString() + ":" + i;
                long hashValue = hash(virtualKey);
                ring.put(hashValue, server);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    public void removeServer(T server) {
        lock.writeLock().lock();
        try {
            for (int i = 0; i < virtualNodes; i++) {
                String virtualKey = server.toString() + ":" + i;
                long hashValue = hash(virtualKey);
                ring.remove(hashValue);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    public T getServer(String key) {
        if (ring.isEmpty()) {
            return null;
        }
        
        lock.readLock().lock();
        try {
            long hashValue = hash(key);
            
            // Find the first server clockwise from hash value
            SortedMap<Long, T> tailMap = ring.tailMap(hashValue);
            Long serverHash = tailMap.isEmpty() ? ring.firstKey() : tailMap.firstKey();
            
            return ring.get(serverHash);
        } finally {
            lock.readLock().unlock();
        }
    }
    
    public List<T> getServerList(String key, int count) {
        if (ring.isEmpty()) {
            return Collections.emptyList();
        }
        
        lock.readLock().lock();
        try {
            List<T> servers = new ArrayList<>();
            Set<T> uniqueServers = new LinkedHashSet<>();
            
            long hashValue = hash(key);
            
            SortedMap<Long, T> tailMap = ring.tailMap(hashValue);
            
            // Add servers from tail map
            for (T server : tailMap.values()) {
                uniqueServers.add(server);
                if (uniqueServers.size() >= count) {
                    break;
                }
            }
            
            // Wrap around if needed
            if (uniqueServers.size() < count) {
                for (T server : ring.values()) {
                    uniqueServers.add(server);
                    if (uniqueServers.size() >= count) {
                        break;
                    }
                }
            }
            
            servers.addAll(uniqueServers);
            return servers;
        } finally {
            lock.readLock().unlock();
        }
    }
    
    public int getServerCount() {
        lock.readLock().lock();
        try {
            Set<T> uniqueServers = new HashSet<>(ring.values());
            return uniqueServers.size();
        } finally {
            lock.readLock().unlock();
        }
    }
    
    public Set<T> getAllServers() {
        lock.readLock().lock();
        try {
            return new HashSet<>(ring.values());
        } finally {
            lock.readLock().unlock();
        }
    }
}

// Usage Example
public class ConsistentHashExample {
    public static void main(String[] args) {
        // Create consistent hash with servers
        List<String> servers = Arrays.asList("S1", "S2", "S3");
        ConsistentHash<String> lb = new ConsistentHash<>(servers);
        
        // Keys consistently map to same servers
        System.out.println(lb.getServer("user123"));  // e.g., S2
        System.out.println(lb.getServer("user123"));  // Always S2
        
        // Add server - most keys stay on same servers!
        lb.addServer("S4");
        System.out.println(lb.getServer("user123"));  // Likely still S2
        
        // Get multiple servers for replication
        List<String> replicaServers = lb.getServerList("user123", 3);
        System.out.println("Replicas: " + replicaServers);
        
        // Test distribution
        testDistribution();
    }
    
    public static void testDistribution() {
        List<String> servers = Arrays.asList("S1", "S2", "S3");
        ConsistentHash<String> lb = new ConsistentHash<>(servers, 150);
        
        Map<String, Integer> distribution = new HashMap<>();
        for (String server : servers) {
            distribution.put(server, 0);
        }
        
        // Simulate 10000 keys
        for (int i = 0; i < 10000; i++) {
            String key = "key" + i;
            String server = lb.getServer(key);
            distribution.put(server, distribution.get(server) + 1);
        }
        
        System.out.println("\nDistribution:");
        distribution.forEach((server, count) -> {
            System.out.printf("%s: %d keys (%.1f%%)\n", 
                server, count, count / 100.0);
        });
        
        // Test adding a server
        System.out.println("\nAdding S4...");
        lb.addServer("S4");
        
        Map<String, Integer> newDistribution = new HashMap<>();
        newDistribution.put("S1", 0);
        newDistribution.put("S2", 0);
        newDistribution.put("S3", 0);
        newDistribution.put("S4", 0);
        
        int remapped = 0;
        for (int i = 0; i < 10000; i++) {
            String key = "key" + i;
            String newServer = lb.getServer(key);
            newDistribution.put(newServer, newDistribution.get(newServer) + 1);
            
            // Check if key remapped
            String oldServer = servers.get(i % servers.size());
            // This is simplified - in reality you'd track original assignments
        }
        
        System.out.println("\nNew distribution:");
        newDistribution.forEach((server, count) -> {
            System.out.printf("%s: %d keys (%.1f%%)\n", 
                server, count, count / 100.0);
        });
    }
}

// Thread-Safe Production Version with ConcurrentSkipListMap
public class ConsistentHashConcurrent<T> {
    
    private final int virtualNodes;
    private final ConcurrentSkipListMap<Long, T> ring;
    private final MessageDigest md5;
    
    public ConsistentHashConcurrent(int virtualNodes) {
        this.virtualNodes = virtualNodes;
        this.ring = new ConcurrentSkipListMap<>();
        
        try {
            this.md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 algorithm not found", e);
        }
    }
    
    public ConsistentHashConcurrent(Collection<T> servers, int virtualNodes) {
        this(virtualNodes);
        for (T server : servers) {
            addServer(server);
        }
    }
    
    private long hash(String key) {
        // Thread-safe: MessageDigest.getInstance creates new instance
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(key.getBytes(StandardCharsets.UTF_8));
            byte[] hash = digest.digest();
            
            long result = 0;
            for (int i = 0; i < 8; i++) {
                result = (result << 8) | (hash[i] & 0xFF);
            }
            return result;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    public void addServer(T server) {
        for (int i = 0; i < virtualNodes; i++) {
            String virtualKey = server.toString() + ":" + i;
            long hashValue = hash(virtualKey);
            ring.put(hashValue, server);
        }
    }
    
    public void removeServer(T server) {
        for (int i = 0; i < virtualNodes; i++) {
            String virtualKey = server.toString() + ":" + i;
            long hashValue = hash(virtualKey);
            ring.remove(hashValue);
        }
    }
    
    public T getServer(String key) {
        if (ring.isEmpty()) {
            return null;
        }
        
        long hashValue = hash(key);
        
        // ConcurrentSkipListMap provides thread-safe navigation
        Map.Entry<Long, T> entry = ring.ceilingEntry(hashValue);
        
        if (entry == null) {
            // Wrap around to first entry
            entry = ring.firstEntry();
        }
        
        return entry != null ? entry.getValue() : null;
    }
    
    public List<T> getServerList(String key, int count) {
        if (ring.isEmpty()) {
            return Collections.emptyList();
        }
        
        Set<T> uniqueServers = new LinkedHashSet<>();
        long hashValue = hash(key);
        
        // Get entries starting from hash value
        ConcurrentSkipListMap<Long, T> tailMap = ring.tailMap(hashValue);
        
        for (T server : tailMap.values()) {
            uniqueServers.add(server);
            if (uniqueServers.size() >= count) {
                break;
            }
        }
        
        // Wrap around if needed
        if (uniqueServers.size() < count) {
            for (T server : ring.values()) {
                uniqueServers.add(server);
                if (uniqueServers.size() >= count) {
                    break;
                }
            }
        }
        
        return new ArrayList<>(uniqueServers);
    }
}

// Spring Bean Configuration Example
@Configuration
public class LoadBalancerConfig {
    
    @Bean
    public ConsistentHash<String> serverLoadBalancer() {
        List<String> servers = Arrays.asList(
            "server1.example.com:8080",
            "server2.example.com:8080",
            "server3.example.com:8080"
        );
        return new ConsistentHash<>(servers, 150);
    }
}

@Service
public class CacheService {
    
    @Autowired
    private ConsistentHash<String> loadBalancer;
    
    public String getCacheServer(String cacheKey) {
        return loadBalancer.getServer(cacheKey);
    }
    
    public Object getCachedValue(String key) {
        String server = loadBalancer.getServer(key);
        // Connect to that server and fetch value
        return fetchFromServer(server, key);
    }
    
    private Object fetchFromServer(String server, String key) {
        // Implementation
        return null;
    }
}
```

**Virtual Nodes:**

Why 150 virtual nodes per server?

```
Without virtual nodes:
Adding S4 affects 25% of keys

With 150 virtual nodes:
Adding S4 affects ~7% of keys
Better distribution!
```

**Impact of Adding/Removing Servers:**

```
Initial: 3 servers (S1, S2, S3)
K keys distributed

Add S4:
- Simple hash: 75% keys remap ❌
- Consistent hash: 25% keys remap ✅
- Consistent hash (150 vnodes): ~7% keys remap ✅✅

Remove S2:
- Simple hash: 66% keys remap ❌
- Consistent hash: 33% keys remap ✅
- Consistent hash (150 vnodes): ~10% keys remap ✅✅
```

**Pros:**
- ✅ Minimal key remapping on changes
- ✅ Excellent for caching
- ✅ Scalable
- ✅ Fault-tolerant

**Cons:**
- ❌ Complex implementation
- ❌ Slightly higher overhead
- ❌ Need to tune virtual nodes
- ❌ Doesn't consider server load

**When to use:**
- Distributed caching (Redis, Memcached)
- Sharding databases
- CDN content routing
- Distributed hash tables

**Real-world examples:**
- Amazon DynamoDB (partitioning)
- Cassandra (token ring)
- Memcached clients
- Envoy proxy (subset load balancing)

### 3. URL Hash

**How it works:**
Hash request URL to route to same server.

```
URL: /api/users/123

hash(/api/users/123) % num_servers = 1

Request → S1 (always for this URL)
```

**Algorithm:**
```python
class URLHash:
    def __init__(self, servers):
        self.servers = servers
    
    def get_server(self, url):
        hash_value = int(hashlib.md5(
            url.encode()
        ).hexdigest(), 16)
        index = hash_value % len(self.servers)
        return self.servers[index]
```

**Pros:**
- ✅ Cache affinity (same URLs → same server)
- ✅ Predictable routing

**Cons:**
- ❌ Hot URLs cause imbalance
- ❌ Breaking changes on scale

**When to use:**
- Caching proxies
- CDN origin selection
- Microservices routing

---

## Advanced Algorithms

### 1. Adaptive Load Balancing

**How it works:**
Continuously monitors metrics and adjusts routing in real-time.

```python
class AdaptiveLoadBalancer:
    def __init__(self, servers):
        self.servers = {
            server: {
                'cpu_usage': 0,
                'memory_usage': 0,
                'response_time': 0,
                'error_rate': 0,
                'active_connections': 0,
                'health_score': 100
            }
            for server in servers
        }
    
    def calculate_score(self, server):
        metrics = self.servers[server]
        
        # Composite score (lower is better)
        score = (
            metrics['cpu_usage'] * 0.3 +
            metrics['response_time'] * 0.3 +
            metrics['active_connections'] * 0.2 +
            metrics['error_rate'] * 100 * 0.15 +
            (100 - metrics['health_score']) * 0.05
        )
        
        return score
    
    def get_next_server(self):
        # Route to server with best score
        server = min(
            self.servers.keys(),
            key=self.calculate_score
        )
        return server
    
    def update_metrics(self, server, metrics):
        self.servers[server].update(metrics)
```

**Metrics to consider:**

| Metric | Weight | Why |
|--------|--------|-----|
| CPU usage | 30% | Direct capacity indicator |
| Response time | 30% | User experience |
| Active connections | 20% | Current load |
| Error rate | 15% | Health indicator |
| Health score | 5% | Overall status |

**Pros:**
- ✅ Optimal performance
- ✅ Self-adjusting
- ✅ Handles complex scenarios

**Cons:**
- ❌ Very complex
- ❌ Requires extensive monitoring
- ❌ Can be unstable
- ❌ Hard to debug

**When to use:**
- Mission-critical systems
- Highly variable workloads
- Heterogeneous infrastructure

### 2. Geographic Routing

**How it works:**
Route based on client geographic location.

```
Client in New York → US-East datacenter
Client in London → EU-West datacenter
Client in Tokyo → Asia-Pacific datacenter
```

**Algorithm:**
```python
class GeographicLoadBalancer:
    def __init__(self):
        self.regions = {
            'us-east': {
                'servers': ['us-e-1', 'us-e-2'],
                'latency_threshold': 50,  # ms
                'health': 'healthy'
            },
            'eu-west': {
                'servers': ['eu-w-1', 'eu-w-2'],
                'latency_threshold': 50,
                'health': 'healthy'
            },
            'asia-pac': {
                'servers': ['ap-1', 'ap-2'],
                'latency_threshold': 50,
                'health': 'healthy'
            }
        }
    
    def get_server(self, client_ip, client_location):
        # Get closest region
        region = self.get_closest_region(client_location)
        
        # If region unhealthy, failover
        if self.regions[region]['health'] != 'healthy':
            region = self.get_backup_region(region)
        
        # Round-robin within region
        servers = self.regions[region]['servers']
        return random.choice(servers)
    
    def get_closest_region(self, location):
        # Use geographic distance or measured latency
        # ... implementation ...
        pass
```

**Pros:**
- ✅ Lowest latency for users
- ✅ Data sovereignty compliance
- ✅ Disaster recovery

**Cons:**
- ❌ Complex implementation
- ❌ Requires global infrastructure
- ❌ Data consistency challenges

### 3. Request Property-Based Routing

**How it works:**
Route based on request characteristics.

```python
class PropertyBasedRouter:
    def __init__(self):
        self.routes = {
            # Heavy computation → powerful servers
            'computation': ['gpu-server-1', 'gpu-server-2'],
            # Database queries → db-optimized servers
            'database': ['db-server-1', 'db-server-2'],
            # Static content → cache servers
            'static': ['cache-server-1', 'cache-server-2'],
            # Default → general servers
            'default': ['app-server-1', 'app-server-2']
        }
    
    def get_server(self, request):
        # Analyze request
        if '/api/ml/' in request.path:
            category = 'computation'
        elif '/api/db/' in request.path:
            category = 'database'
        elif request.path.endswith(('.jpg', '.css', '.js')):
            category = 'static'
        else:
            category = 'default'
        
        # Round-robin within category
        servers = self.routes[category]
        return random.choice(servers)
```

**Use cases:**
- ML inference vs regular API
- Read vs write requests
- Premium vs free tier
- Mobile vs desktop clients

---

## Algorithm Comparison

### Performance Comparison

| Algorithm | Complexity | Fairness | Load Awareness | Session Affinity | Best For |
|-----------|-----------|----------|----------------|------------------|----------|
| Round-Robin | O(1) | ⭐⭐⭐⭐⭐ | ❌ | ❌ | Homogeneous servers |
| Weighted RR | O(1) | ⭐⭐⭐⭐ | ❌ | ❌ | Different capacities |
| Random | O(1) | ⭐⭐⭐⭐ | ❌ | ❌ | High concurrency |
| Least Conn | O(n) | ⭐⭐⭐⭐⭐ | ✅ | ❌ | Long connections |
| Weighted LC | O(n) | ⭐⭐⭐⭐⭐ | ✅ | ❌ | Heterogeneous + load |
| Least RT | O(n) | ⭐⭐⭐⭐ | ✅✅ | ❌ | Variable workloads |
| Power of 2 | O(1) | ⭐⭐⭐⭐ | ✅ | ❌ | Large server pools |
| IP Hash | O(1) | ⭐⭐⭐ | ❌ | ✅ | Session affinity |
| Consistent Hash | O(log n) | ⭐⭐⭐⭐ | ❌ | ✅ | Caching, sharding |
| Adaptive | O(n) | ⭐⭐⭐⭐⭐ | ✅✅ | ❌ | Complex systems |

### Scenario Recommendations

| Scenario | Recommended Algorithm | Why |
|----------|----------------------|-----|
| Stateless web app, equal servers | Round-Robin | Simple, efficient |
| Stateless web app, different servers | Weighted Round-Robin | Respects capacity |
| Long-lived WebSocket connections | Least Connections | Balances active load |
| Shopping cart sessions | IP Hash or Consistent Hash | Sticky sessions |
| Distributed cache | Consistent Hash | Minimal remapping |
| Database replicas | Weighted Least Connections | Capacity + load |
| Microservices mesh | Power of Two Choices | Scalable, efficient |
| Global CDN | Geographic + Consistent Hash | Latency + caching |
| ML inference | Adaptive or Least Response Time | Variable workload |
| A/B testing | Weighted Round-Robin | Controlled distribution |

---

## Practice Problems

### Problem 1: Algorithm Selection (15 min)

You have a video streaming service with:
- 10 origin servers (different capacities)
- Videos are cached on servers
- 1M concurrent users
- Popular videos cause hot spots
- Need session continuity for adaptive bitrate

Which algorithm(s) would you use? Why?

**Twist:** How would you handle a viral video?

---

### Problem 2: Implement Hybrid Algorithm (30 min)

Design an algorithm that:
1. Uses consistent hashing for cache affinity
2. Falls back to least connections if server is overloaded
3. Supports weighted servers

Provide pseudocode or Python implementation.

---

### Problem 3: Capacity Planning (20 min)

Given:
- 100K requests per second
- Average request time: 50ms
- Round-robin algorithm
- Servers can handle 2K concurrent connections each

How many servers do you need?

Calculate for:
a) Round-robin
b) Least connections
c) Weighted (servers have 50% capacity difference)

---

### Problem 4: Trade-off Analysis (15 min)

Compare IP Hash vs Consistent Hash for these scenarios:

a) Memcached cluster (frequently adding/removing nodes)
b) Session storage (rarely changes)
c) Database sharding (need to rebalance data)

What are the trade-offs in each case?

---

### Problem 5: Debug Production Issue (20 min)

Your system uses least connections algorithm. You notice:
- Server1: 10K connections, 20% CPU
- Server2: 5K connections, 80% CPU
- Server3: 8K connections, 50% CPU

New requests go to Server2 (least connections).

What's wrong? How do you fix it?

---

## Key Takeaways

1. **No perfect algorithm** - choose based on your requirements
2. **Simple often wins** - round-robin is good enough for many cases
3. **Consider server heterogeneity** - use weighted algorithms
4. **Session affinity needs hashing** - IP or consistent hash
5. **Caching benefits from consistent hashing** - minimal remapping
6. **Load awareness matters** - least connections for variable workloads
7. **Monitor and adapt** - what works at 1K RPS may not work at 1M RPS

---

## Next Steps

✅ You've mastered load balancing algorithms!

**Next:** [Document 3: Health Checks & Failure Detection](./03-health-checks-failure-detection.md)

Learn how to detect and handle server failures gracefully.

**Before moving on:**
- [ ] Implement at least 2 algorithms in code
- [ ] Complete practice problems
- [ ] Draw decision tree for algorithm selection

---

## References

- [NGINX Load Balancing Algorithms](https://nginx.org/en/docs/http/load_balancing.html)
- [HAProxy Algorithm Guide](http://cbonte.github.io/haproxy-dconv/2.4/configuration.html#balance)
- [The Power of Two Choices](https://www.eecs.harvard.edu/~michaelm/postscripts/handbook2001.pdf)
- [Consistent Hashing Paper](https://arxiv.org/abs/1406.2294)
- [Google Maglev](https://research.google/pubs/pub44824/)