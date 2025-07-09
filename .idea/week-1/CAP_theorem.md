# Phase 1, Week 1: Distributed Systems Core - Complete Deep Dive
## From Basics to Advanced - Top 1% Mastery Level

---

## **Introduction: Why These Concepts Matter**

Before diving into implementations, let's understand why these concepts are fundamental to distributed systems. Every major tech company - Google, Amazon, Netflix, Facebook - builds their core systems around these principles. Mastering them means you can:

- Design systems that handle billions of users
- Make the right trade-offs between consistency, availability, and performance
- Debug complex distributed system failures
- Architect solutions that scale globally

---

## **1. CAP Theorem: The Foundation of Distributed System Design**

### **What is CAP Theorem? (Basic Understanding)**

The CAP theorem states that in a distributed system, you can only guarantee **two** of the following three properties:

- **Consistency (C)**: All nodes see the same data at the same time
- **Availability (A)**: System remains operational even if some nodes fail
- **Partition Tolerance (P)**: System continues to operate despite network failures

### **Why This Matters in Practice**

```
Real-world scenario: Your e-commerce app has servers in US and Europe.
Suddenly, the transatlantic cable gets cut (network partition).

Choice 1 (CP): Stop serving European users to maintain consistency
Choice 2 (AP): Let both regions serve users, fix inconsistencies later
```

### **Common Misconception: "Pick 2 of 3"**

This is **incorrect**. Here's the truth:

```
Network partitions WILL happen in any distributed system.
So you're really choosing between:
- CP: Consistency over Availability during partitions
- AP: Availability over Consistency during partitions
```

### **Deep Understanding: CAP is About Partitions**

```java
// This is what happens during normal operation (no partition)
public class NormalOperation {
    public void write(String key, String value) {
        // Can have both consistency AND availability
        primaryNode.write(key, value);
        secondaryNode.replicate(key, value); // Both succeed
    }
}

// This is what happens during partition
public class PartitionScenario {
    public void write(String key, String value) {
        if (canReachAllNodes()) {
            // Normal case - both C and A possible
            writeToAllNodes(key, value);
        } else {
            // Partition detected - must choose
            if (prioritizeConsistency()) {
                // CP choice: reject write to maintain consistency
                throw new ServiceUnavailableException("Cannot ensure consistency");
            } else {
                // AP choice: accept write, handle conflicts later
                writeToAvailableNodes(key, value);
            }
        }
    }
}
```

### **Real-World Examples of CAP Choices**

#### **CP Systems (Consistency over Availability)**

**Example: Banking System**
```java
public class BankingSystem {
    // Money transfers MUST be consistent
    @Transactional(isolation = SERIALIZABLE)
    public void transfer(Account from, Account to, Money amount) {
        // During partition: Better to be unavailable than inconsistent
        if (isNetworkPartitioned()) {
            throw new ServiceUnavailableException("Cannot ensure consistency");
        }
        
        // Atomic operation - both succeed or both fail
        from.debit(amount);  // If this succeeds...
        to.credit(amount);   // ...this must also succeed
        
        // Strong consistency guaranteed
    }
}
```

**Why CP for Banking?**
- Losing money due to inconsistency is unacceptable
- Users prefer temporary unavailability over incorrect balances
- Regulatory requirements demand strict consistency

#### **AP Systems (Availability over Consistency)**

**Example: Social Media Feed**
```java
public class SocialMediaFeed {
    // Users prefer seeing something over seeing nothing
    public List<Post> getFeed(UserId userId) {
        List<Post> posts = new ArrayList<>();
        
        // Try all available data centers
        for (DataCenter dc : availableDataCenters()) {
            try {
                posts.addAll(dc.getUserFeed(userId));
            } catch (PartitionException e) {
                // Continue with partial data - eventual consistency
                logger.warn("Partition detected, serving stale data from {}", dc);
            }
        }
        
        return mergePosts(posts); // May have duplicates/inconsistencies
    }
}
```

**Why AP for Social Media?**
- Users expect the app to always work
- Seeing duplicate posts is better than seeing no posts
- Social interactions can tolerate some inconsistency

### **Advanced CAP: The Spectrum Approach**

Modern systems don't just pick CP or AP - they use **different consistency levels** for different operations:

```java
public class HybridECommerceSystem {
    
    // CP for critical operations
    @ConsistencyLevel(STRONG)
    public void processPayment(PaymentRequest request) {
        // Must be consistent - use CP approach
        if (!canEnsureConsistency()) {
            throw new PaymentUnavailableException();
        }
        paymentProcessor.charge(request);
    }
    
    // AP for user experience
    @ConsistencyLevel(EVENTUAL)
    public ProductCatalog getProductCatalog() {
        // Can be eventually consistent - use AP approach
        return catalogService.getCatalogFromAnyAvailableRegion();
    }
    
    // Different consistency for different operations
    @ConsistencyLevel(SESSION)
    public UserProfile getUserProfile(UserId userId) {
        // User sees their own writes, but may see stale data from others
        return profileService.getProfile(userId, SESSION_CONSISTENCY);
    }
}
```

### **FAANG Interview Questions on CAP**

**Q1: "Design a global chat system. How does CAP theorem apply?"**

**Basic Answer (Surface Level):**
"I'd make it an AP system for availability."

**Top 1% Answer (Deep Understanding):**
```
"I'd design a hybrid system with different CAP choices for different components:

1. Message Delivery: AP System
   - Users can always send messages, even during partitions
   - Messages queue locally and sync when partition heals
   - Better to have delayed delivery than no delivery

2. Message Ordering: Eventually Consistent
   - Use vector clocks for causal ordering
   - Handle concurrent messages with conflict resolution
   - Users see messages in causal order eventually

3. User Presence: AP with Session Consistency
   - Show 'last seen' during partitions
   - Real-time presence when network is healthy
   - Graceful degradation to cached status

4. Message History: CP Subsystem
   - Critical messages stored with strong consistency
   - Use consensus (Raft) for persistent storage
   - Accept reduced availability for data durability

Architecture Example:
```java
public class GlobalChatSystem {
    
    // AP: Message delivery always available
    public void sendMessage(ChatMessage message) {
        try {
            // Try immediate delivery
            messageBroker.publish(message);
        } catch (PartitionException e) {
            // Queue locally during partition
            localQueue.enqueue(message);
            scheduleRetryWhenPartitionHeals();
        }
    }
    
    // CP: Message persistence for important chats
    public void persistMessage(ChatMessage message) {
        if (message.isImportant()) {
            // Use strong consistency for important messages
            persistentStore.writeWithConsensus(message);
        } else {
            // Use eventual consistency for regular messages
            persistentStore.writeEventually(message);
        }
    }
}
```

**Follow-up Q: "What if it's a financial trading chat? Change your approach?"**

**Answer:** "Switch to CP system - trade unavailability for consistency. Use Raft consensus for message ordering, block cross-region messages during partitions, implement strict leader election per chat room. Financial compliance requires audit trails and exact ordering."

---

## **2. Consistency Models: Understanding the Spectrum**

### **What Are Consistency Models? (Basic Understanding)**

Consistency models define **what guarantees** a distributed system provides about when and how updates become visible to different parts of the system.

Think of it like this:
```
You post a photo on social media.
- Strong consistency: Everyone sees it immediately
- Weak consistency: Some friends see it now, others see it later
- Eventual consistency: Everyone will see it eventually
```

### **The Complete Consistency Hierarchy (Strongest to Weakest)**

```java
public enum ConsistencyLevel {
    LINEARIZABLE,      // Strongest - appears instantaneous globally
    SEQUENTIAL,        // Global order exists, but may not match real-time
    CAUSAL,           // Causally related operations are ordered
    EVENTUAL,         // Guarantees convergence eventually
    WEAK              // No ordering guarantees
}
```

### **1. Linearizability (Strongest Consistency)**

**What it means:** Operations appear to take effect instantaneously at some point between their start and completion.

**Real-world analogy:** ATM withdrawals - when you withdraw money, the balance update is immediately visible to everyone.

```java
public class LinearizableRegister<T> {
    private volatile T value;
    private final AtomicLong timestamp = new AtomicLong(0);
    private final Object lock = new Object();
    
    // Linearizable read - must see latest write or concurrent write
    public T read() {
        synchronized(lock) {
            long readTime = getCurrentTime();
            
            // Key insight: In distributed system, need consensus 
            // to determine what "latest" means across all nodes
            return readWithGlobalConsensus(readTime);
        }
    }
    
    // Linearizable write - appears to take effect atomically
    public void write(T newValue) {
        synchronized(lock) {
            long writeTime = getCurrentTime();
            
            // Ensure monotonic timestamps across all nodes
            if (writeTime <= timestamp.get()) {
                writeTime = timestamp.incrementAndGet();
            }
            
            value = newValue;
            timestamp.set(writeTime);
            
            // Critical: Must replicate to ALL nodes before returning
            // This is expensive but provides strongest guarantees
            replicateToAllNodes(newValue, writeTime);
        }
    }
    
    private void replicateToAllNodes(T value, long timestamp) {
        // Use consensus protocol (Raft/Paxos) to ensure linearizability
        ConsensusResult result = consensusProtocol.propose(
            new WriteOperation(value, timestamp)
        );
        
        if (!result.isSuccess()) {
            throw new ConsistencyException("Cannot maintain linearizability");
        }
    }
}
```

**When to use Linearizability:**
- Financial systems (account balances)
- Inventory management (stock counts)
- Leader election
- Any system where "latest" value is critical

**Cost of Linearizability:**
- High latency (consensus required)
- Reduced availability during partitions
- Higher complexity

### **2. Sequential Consistency**

**What it means:** All operations appear to execute in some sequential order, and this order is consistent across all nodes.

**Key difference from Linearizability:** The order doesn't have to match real-time order.

```java
public class SequentiallyConsistentStore {
    private final AtomicLong globalSequenceNumber = new AtomicLong(0);
    private final Map<String, VersionedValue> store = new ConcurrentHashMap<>();
    
    public void write(String key, Object value) {
        // Assign global sequence number
        long seqNum = globalSequenceNumber.incrementAndGet();
        
        VersionedValue versionedValue = new VersionedValue(value, seqNum);
        store.put(key, versionedValue);
        
        // Replicate with sequence number - all nodes will apply in same order
        replicateInOrder(key, versionedValue);
    }
    
    public Object read(String key) {
        VersionedValue value = store.get(key);
        return value != null ? value.getValue() : null;
    }
    
    private void replicateInOrder(String key, VersionedValue value) {
        // All replicas apply operations in sequence number order
        for (Replica replica : replicas) {
            replica.applyInOrder(key, value);
        }
    }
}

// Replica ensures sequential order
public class Replica {
    private long lastAppliedSequence = 0;
    private final Queue<PendingOperation> pendingOps = new PriorityQueue<>();
    
    public void applyInOrder(String key, VersionedValue value) {
        if (value.getSequenceNumber() == lastAppliedSequence + 1) {
            // Can apply immediately
            localStore.put(key, value);
            lastAppliedSequence++;
            
            // Try to apply any pending operations
            applyPendingOperations();
        } else {
            // Buffer until we can apply in order
            pendingOps.offer(new PendingOperation(key, value));
        }
    }
}
```

**Sequential vs Linearizable Example:**
```
Timeline:
Client A: write(x, 1) at time 10:00:00
Client B: write(x, 2) at time 10:00:01

Linearizable: Everyone must see write(x,2) after write(x,1) (respects real-time)
Sequential: Some nodes might see write(x,2) then write(x,1) (same order everywhere, but not necessarily real-time order)
```

### **3. Causal Consistency**

**What it means:** Operations that are causally related are seen in the same order by all nodes.

**Real-world analogy:** Email threads - replies must be seen after the original message, but unrelated emails can be seen in any order.

```java
public class CausalConsistentStore {
    private final Map<String, VersionedValue> store = new ConcurrentHashMap<>();
    private final VectorClock localClock;
    private final String nodeId;
    
    // Vector Clock implementation for tracking causality
    public static class VectorClock {
        private final Map<String, Long> clock = new ConcurrentHashMap<>();
        
        // Increment local time
        public synchronized void tick(String nodeId) {
            clock.merge(nodeId, 1L, Long::sum);
        }
        
        // Update with received vector clock
        public synchronized void update(VectorClock other) {
            // Take maximum of each component
            for (Map.Entry<String, Long> entry : other.clock.entrySet()) {
                clock.merge(entry.getKey(), entry.getValue(), Long::max);
            }
        }
        
        // Check if this clock happens before another
        public boolean happensBefore(VectorClock other) {
            // VC1 < VC2 if all components of VC1 <= VC2 and at least one is strictly less
            boolean allLessEqual = true;
            boolean atLeastOneLess = false;
            
            Set<String> allNodes = new HashSet<>(clock.keySet());
            allNodes.addAll(other.clock.keySet());
            
            for (String node : allNodes) {
                long thisValue = clock.getOrDefault(node, 0L);
                long otherValue = other.clock.getOrDefault(node, 0L);
                
                if (thisValue > otherValue) {
                    allLessEqual = false;
                    break;
                } else if (thisValue < otherValue) {
                    atLeastOneLess = true;
                }
            }
            
            return allLessEqual && atLeastOneLess;
        }
        
        public boolean isConcurrentWith(VectorClock other) {
            return !this.happensBefore(other) && !other.happensBefore(this);
        }
    }
    
    public void write(String key, Object value) {
        // Increment local clock before write
        localClock.tick(nodeId);
        
        VersionedValue versionedValue = new VersionedValue(
            value, 
            localClock.copy(),
            nodeId
        );
        
        store.put(key, versionedValue);
        
        // Replicate with vector clock for causal ordering
        replicateWithCausalOrder(key, versionedValue);
    }
    
    public Object read(String key) {
        VersionedValue value = store.get(key);
        if (value != null) {
            // Update local clock to reflect causality
            localClock.update(value.getClock());
            return value.getValue();
        }
        return null;
    }
    
    private void replicateWithCausalOrder(String key, VersionedValue value) {
        // Send to all replicas - they will buffer until causal dependencies are satisfied
        for (Node replica : replicas) {
            replica.receiveWrite(key, value);
        }
    }
    
    // Replica side: only deliver when causal dependencies are satisfied
    public void receiveWrite(String key, VersionedValue incomingWrite) {
        if (canDeliver(incomingWrite)) {
            // All causal dependencies satisfied - can deliver immediately
            deliverWrite(key, incomingWrite);
        } else {
            // Buffer until dependencies are satisfied
            bufferWrite(key, incomingWrite);
        }
    }
    
    private boolean canDeliver(VersionedValue incomingWrite) {
        VectorClock incomingClock = incomingWrite.getClock();
        
        // Can deliver if all causally preceding writes have been delivered
        for (Map.Entry<String, Long> entry : incomingClock.clock.entrySet()) {
            String nodeId = entry.getKey();
            long requiredTimestamp = entry.getValue();
            
            if (!nodeId.equals(incomingWrite.getNodeId())) {
                // All writes from other nodes up to timestamp must be delivered
                long deliveredTimestamp = localClock.clock.getOrDefault(nodeId, 0L);
                if (deliveredTimestamp < requiredTimestamp) {
                    return false; // Missing causal dependency
                }
            }
        }
        
        return true;
    }
}
```

**Causal Consistency Example:**
```
Timeline:
Alice posts: "Going to the movies" [VC: {Alice:1, Bob:0}]
Bob replies: "Which movie?" [VC: {Alice:1, Bob:1}] (causally depends on Alice's post)
Charlie posts: "Having lunch" [VC: {Alice:0, Bob:0, Charlie:1}] (concurrent with others)

Causal Consistency guarantees:
- Everyone sees Alice's post before Bob's reply
- Charlie's post can be seen in any order relative to the others
```

### **4. Eventual Consistency**

**What it means:** If no new updates are made, eventually all nodes will converge to the same value.

**Real-world analogy:** DNS updates - when you change your website's IP address, it eventually propagates to all DNS servers worldwide.

```java
public class EventuallyConsistentStore {
    private final Map<String, Object> localStore = new ConcurrentHashMap<>();
    private final Set<Node> replicas = new HashSet<>();
    private final ScheduledExecutorService antiEntropyService;
    
    public void write(String key, Object value) {
        // Write locally immediately
        localStore.put(key, value);
        
        // Asynchronously propagate to replicas
        propagateAsync(key, value);
    }
    
    public Object read(String key) {
        // Read from local store - may be stale
        return localStore.get(key);
    }
    
    private void propagateAsync(String key, Object value) {
        // Fire-and-forget replication
        CompletableFuture.runAsync(() -> {
            for (Node replica : replicas) {
                try {
                    replica.update(key, value);
                } catch (Exception e) {
                    // Log error but don't fail the write
                    logger.warn("Failed to replicate to {}: {}", replica, e.getMessage());
                    // Will be fixed by anti-entropy process
                }
            }
        });
    }
    
    // Anti-entropy process to ensure eventual consistency
    @Scheduled(fixedDelay = 60000) // Run every minute
    public void antiEntropyRepair() {
        for (Node replica : replicas) {
            try {
                // Compare state and fix differences
                Map<String, Object> replicaState = replica.getAllData();
                
                for (Map.Entry<String, Object> entry : localStore.entrySet()) {
                    String key = entry.getKey();
                    Object localValue = entry.getValue();
                    Object replicaValue = replicaState.get(key);
                    
                    if (!Objects.equals(localValue, replicaValue)) {
                        // Conflict detected - resolve using timestamp or other strategy
                        Object resolvedValue = resolveConflict(localValue, replicaValue);
                        
                        // Update both local and replica to resolved value
                        localStore.put(key, resolvedValue);
                        replica.update(key, resolvedValue);
                    }
                }
            } catch (Exception e) {
                logger.error("Anti-entropy failed for replica {}: {}", replica, e.getMessage());
            }
        }
    }
    
    private Object resolveConflict(Object localValue, Object replicaValue) {
        // Simple last-writer-wins (in practice, use vector clocks or CRDTs)
        if (localValue instanceof Timestamped && replicaValue instanceof Timestamped) {
            Timestamped local = (Timestamped) localValue;
            Timestamped replica = (Timestamped) replicaValue;
            
            return local.getTimestamp() > replica.getTimestamp() ? localValue : replicaValue;
        }
        
        return localValue; // Default to local value
    }
}
```

### **FAANG Interview Questions on Consistency**

**Q: "Design a collaborative document editor (Google Docs). What consistency model?"**

**Basic Answer:**
"I'd use eventual consistency."

**Top 1% Answer:**
```
"I'd use Causal Consistency with Operational Transformation for conflict resolution:

1. Why Causal Consistency?
   - If user A sees user B's edit, then A's next edit should be ordered after B's
   - Preserves the natural flow of collaborative editing
   - Allows concurrent edits that don't interfere

2. Implementation with Operational Transform:
```java
public class CollaborativeEditor {
    private final CausalConsistentStore store;
    private final OperationalTransform ot;
    
    public void applyEdit(Edit edit, VectorClock timestamp) {
        // Buffer edit until causal dependencies are satisfied
        if (canApplyEdit(edit, timestamp)) {
            Edit transformedEdit = ot.transform(edit, getConcurrentEdits(timestamp));
            store.write(edit.getDocumentId(), transformedEdit);
        } else {
            bufferEdit(edit, timestamp);
        }
    }
    
    // Transform edit based on concurrent operations
    private Edit transformEdit(Edit originalEdit, List<Edit> concurrentEdits) {
        Edit transformed = originalEdit;
        
        for (Edit concurrent : concurrentEdits) {
            if (concurrent.getPosition() <= transformed.getPosition()) {
                // Adjust position based on concurrent edit
                if (concurrent.isInsert()) {
                    transformed = transformed.adjustPosition(concurrent.getLength());
                } else if (concurrent.isDelete()) {
                    transformed = transformed.adjustPosition(-concurrent.getLength());
                }
            }
        }
        
        return transformed;
    }
}
```

3. Conflict Resolution Example:
   User A: Insert "Hello" at position 0
   User B: Insert "World" at position 0 (concurrent)

   Resolution: Transform B's operation -> Insert "World" at position 5
   Result: "HelloWorld" (consistent across all replicas)

4. Why not stronger consistency?
    - Linearizability would require blocking on every keystroke
    - Sequential consistency would create poor user experience
    - Causal + OT provides good UX with eventual convergence"

**Follow-up: "What if it's financial data that can't have conflicts?"**

**Answer:** "Switch to Sequential Consistency with leader-based ordering. All edits go through a leader election system, strong ordering guarantees, sacrifice some availability for absolute consistency. Use techniques like pessimistic locking for critical sections."

---

## **3. ACID vs BASE: Transaction Models**

### **Understanding ACID (Traditional Database Approach)**

ACID represents the traditional approach to database transactions, prioritizing **correctness** over **availability**.

#### **A - Atomicity: All or Nothing**

**Basic Concept:** Either all operations in a transaction succeed, or none do.

**Real-world analogy:** Bank transfer - either money leaves your account AND arrives in the destination account, or neither happens.

```java
public class AtomicTransactionExample {
    
    // Without atomicity (BAD)
    public void transferMoneyBad(Account from, Account to, Money amount) {
        from.debit(amount);        // What if this succeeds...
        // SYSTEM CRASHES HERE
        to.credit(amount);         // ...but this never happens?
        // Result: Money disappears!
    }
    
    // With atomicity (GOOD)
    @Transactional
    public void transferMoneyGood(Account from, Account to, Money amount) {
        try {
            from.debit(amount);
            to.credit(amount);
            // Both succeed - commit transaction
        } catch (Exception e) {
            // Any failure - rollback everything
            throw new TransactionRollbackException("Transfer failed", e);
        }
    }
}
```

#### **C - Consistency: Valid State Transitions**

**Basic Concept:** Database remains in a valid state before and after the transaction.

**Example:** In a banking system, total money in the system should remain constant after transfers.

```java
public class ConsistencyExample {
    
    // Consistency constraint: account balance >= 0
    @PreCondition("from.getBalance() >= amount")
    @PostCondition("from.getBalance() >= 0 && to.getBalance() >= 0")
    public void transfer(Account from, Account to, Money amount) {
        if (from.getBalance() < amount) {
            throw new InsufficientFundsException("Cannot maintain consistency");
        }
        
        from.debit(amount);
        to.credit(amount);
        
        // Consistency maintained: money moved but total unchanged
        assert getTotalMoney() == initialTotalMoney;
    }
}
```

#### **I - Isolation: Concurrent Transactions Don't Interfere**

**Basic Concept:** Concurrent transactions don't see each other's intermediate states.

```java
public class IsolationExample {
    
    // Without isolation (BAD)
    public void concurrentTransferBad() {
        // Transaction 1: A->B (1000)
        // Transaction 2: A->C (1000)
        // Both read A.balance = 2000
        // Both think they can transfer 1000
        // Result: A.balance = 0 (should be impossible!)
    }
    
    // With isolation (GOOD) - using locks
    public void concurrentTransferGood(Account from, Account to, Money amount) {
        synchronized(from) { // Acquire lock on 'from' account
            if (from.getBalance() >= amount) {
                from.debit(amount);
                
                synchronized(to) { // Acquire lock on 'to' account
                    to.credit(amount);
                }
            }
        }
        // Locks released - other transactions can proceed
    }
}
```

**Isolation Levels Explained:**

```java
public enum IsolationLevel {
    READ_UNCOMMITTED {
        // Can see uncommitted changes from other transactions
        // Allows: Dirty reads, non-repeatable reads, phantom reads
        public boolean allowDirtyRead() { return true; }
    },
    
    READ_COMMITTED {
        // Only see committed changes
        // Allows: Non-repeatable reads, phantom reads
        public boolean allowDirtyRead() { return false; }
        
        public void example() {
            // Transaction 1: Read account balance = 1000
            // Transaction 2: Updates and commits balance = 2000
            // Transaction 1: Read account balance = 2000 (different!)
        }
    },
    
    REPEATABLE_READ {
        // Same reads return same values within transaction
        // Allows: Phantom reads
        public boolean allowNonRepeatableRead() { return false; }
        
        public void example() {
            // Transaction 1: Read all accounts with balance > 1000 (finds 5 accounts)
            // Transaction 2: Inserts new account with balance = 1500
            // Transaction 1: Read all accounts with balance > 1000 (finds 6 accounts!)
        }
    },
    
    SERIALIZABLE {
        // Strongest isolation - transactions appear to run serially
        // No concurrency anomalies allowed
        public boolean allowPhantomRead() { return false; }
    }
}
```

#### **D - Durability: Committed Changes Persist**

**Basic Concept:** Once a transaction commits, its changes survive system failures.

```java
public class DurabilityExample {
    private final WriteAheadLog wal;
    
    @Transactional
    public void durableWrite(String key, String value) {
        // 1. Write to WAL first (durability guarantee)
        wal.append(new WriteLogEntry(key, value));
        wal.sync(); // Force to disk
        
        // 2. Update in-memory data
        memoryStore.put(key, value);
        
        // 3. Commit transaction
        wal.append(new CommitLogEntry());
        wal.sync();
        
        // Even if system crashes here, data is recoverable from WAL
    }
    
    public void recoverFromCrash() {
        // Read WAL and replay committed transactions
        for (LogEntry entry : wal.readAll()) {
            if (entry instanceof WriteLogEntry) {
                WriteLogEntry write = (WriteLogEntry) entry;
                memoryStore.put(write.getKey(), write.getValue());
            }
        }
    }
}
```

### **Complete ACID Implementation**

```java
public class ACIDTransactionManager {
    private final WAL writeAheadLog;
    private final LockManager lockManager;
    private final Map<TransactionId, Transaction> activeTransactions;
    
    public class Transaction {
        private final TransactionId id;
        private final List<Operation> operations = new ArrayList<>();
        private final Map<ResourceId, Object> readSet = new HashMap<>();
        private final Map<ResourceId, Object> writeSet = new HashMap<>();
        private TransactionState state = ACTIVE;
        
        public void read(ResourceId resource) {
            // Consistency: Read committed data only
            Object value = readCommittedValue(resource);
            readSet.put(resource, value);
            
            // Isolation: Acquire read lock
            lockManager.acquireReadLock(id, resource);
        }
        
        public void write(ResourceId resource, Object value) {
            writeSet.put(resource, value);
            
            // Isolation: Acquire write lock  
            lockManager.acquireWriteLock(id, resource);
            
            // Durability: Log operation immediately
            writeAheadLog.append(new WriteLogEntry(id, resource, value));
        }
        
        public void commit() throws TransactionException {
            try {
                // Two-Phase Commit Protocol for Atomicity
                if (prepare()) {
                    doCommit();
                } else {
                    abort();
                }
            } catch (Exception e) {
                abort();
                throw new TransactionException("Commit failed", e);
            }
        }
        
        private boolean prepare() {
            // Phase 1: Prepare
            state = PREPARING;
            
            // Validate read set (Consistency check)
            for (Map.Entry<ResourceId, Object> entry : readSet.entrySet()) {
                if (!validateRead(entry.getKey(), entry.getValue())) {
                    return false; // Abort due to consistency violation
                }
            }
            
            // Write to WAL (Durability guarantee)
            writeAheadLog.append(new PrepareLogEntry(id));
            writeAheadLog.sync(); // Force to disk
            
            state = PREPARED;
            return true;
        }
        
        private void doCommit() {
            // Phase 2: Commit
            state = COMMITTING;
            
            // Atomicity: Apply all writes together
            for (Map.Entry<ResourceId, Object> entry : writeSet.entrySet()) {
                applyWrite(entry.getKey(), entry.getValue());
            }
            
            // Durability: Log commit
            writeAheadLog.append(new CommitLogEntry(id));
            writeAheadLog.sync();
            
            // Isolation: Release all locks (end of isolation)
            lockManager.releaseAllLocks(id);
            
            state = COMMITTED;
        }
        
        private void abort() {
            state = ABORTED;
            
            // Atomicity: Undo all operations
            for (Operation op : operations) {
                op.undo();
            }
            
            // Log abort for durability
            writeAheadLog.append(new AbortLogEntry(id));
            writeAheadLog.sync();
            
            // Release all locks
            lockManager.releaseAllLocks(id);
        }
    }
}
```

### **Understanding BASE (Modern Distributed Approach)**

BASE represents the modern approach for distributed systems, prioritizing **availability and scalability** over strict consistency.

**BASE Acronym:**
- **Basically Available**: System remains operational most of the time
- **Soft State**: Data may change over time due to eventual consistency
- **Eventually Consistent**: System will become consistent over time

#### **Basically Available: Graceful Degradation**

**Concept:** System continues to work even when parts fail, possibly with reduced functionality.

```java
public class BasicallyAvailableService {
    private final List<DataCenter> dataCenters;
    private final CircuitBreaker circuitBreaker;
    
    public UserProfile getUserProfile(UserId userId) {
        // Try primary data center first
        try {
            return primaryDataCenter.getUserProfile(userId);
        } catch (DataCenterException e) {
            // Graceful degradation: try backup data centers
            for (DataCenter backup : backupDataCenters) {
                try {
                    UserProfile profile = backup.getUserProfile(userId);
                    // May be stale, but better than nothing
                    profile.markAsStale();
                    return profile;
                } catch (Exception backupException) {
                    // Continue trying other backups
                }
            }
            
            // Last resort: return cached profile
            UserProfile cached = cache.get(userId);
            if (cached != null) {
                cached.markAsStale();
                return cached;
            }
            
            // Still available: return minimal profile
            return UserProfile.createMinimalProfile(userId);
        }
    }
    
    @CircuitBreaker(failureThreshold = 5, timeout = 30000)
    public void updateProfile(UserId userId, UserProfile profile) {
        try {
            primaryDataCenter.updateProfile(userId, profile);
        } catch (Exception e) {
            // Queue for later processing - system remains available
            updateQueue.enqueue(new ProfileUpdate(userId, profile));
            
            // Update cache immediately for read consistency
            cache.put(userId, profile);
        }
    }
}
```

#### **Soft State: Data Changes Over Time**

**Concept:** Unlike ACID systems where data is consistent, BASE systems allow data to be in flux.

```java
public class SoftStateExample {
    // Example: Shopping cart that times out
    public class ShoppingCart {
        private final Map<ProductId, Integer> items = new HashMap<>();
        private final long createdTime = System.currentTimeMillis();
        private final long timeoutMs = 30 * 60 * 1000; // 30 minutes
        
        public boolean isValid() {
            // Soft state: cart expires after timeout
            return System.currentTimeMillis() - createdTime < timeoutMs;
        }
        
        public void addItem(ProductId productId, int quantity) {
            if (!isValid()) {
                throw new CartExpiredException("Cart has expired");
            }
            items.merge(productId, quantity, Integer::sum);
            
            // Soft state: extend timeout on activity
            resetTimeout();
        }
    }
    
    // Example: Cache with TTL
    public class TTLCache<K, V> {
        private final Map<K, TimestampedValue<V>> cache = new ConcurrentHashMap<>();
        private final long ttlMs;
        
        public void put(K key, V value) {
            cache.put(key, new TimestampedValue<>(value, System.currentTimeMillis()));
        }
        
        public Optional<V> get(K key) {
            TimestampedValue<V> timestamped = cache.get(key);
            if (timestamped == null) {
                return Optional.empty();
            }
            
            // Soft state: data becomes invalid over time
            if (System.currentTimeMillis() - timestamped.timestamp > ttlMs) {
                cache.remove(key); // Expired
                return Optional.empty();
            }
            
            return Optional.of(timestamped.value);
        }
    }
}
```

#### **Eventually Consistent: Convergence Over Time**

**Concept:** If no new updates occur, all replicas will eventually have the same data.

```java
public class EventuallyConsistentStore {
    private final Map<String, Object> localStore = new ConcurrentHashMap<>();
    private final Set<Node> replicas = new HashSet<>();
    private final ScheduledExecutorService antiEntropyService;
    
    public void write(String key, Object value) {
        // Write locally immediately
        localStore.put(key, value);
        
        // Asynchronously propagate to replicas (fire-and-forget)
        propagateAsync(key, value);
    }
    
    public Object read(String key) {
        // Read from local store - may be stale but fast
        return localStore.get(key);
    }
    
    private void propagateAsync(String key, Object value) {
        // Non-blocking replication
        CompletableFuture.runAsync(() -> {
            for (Node replica : replicas) {
                try {
                    replica.update(key, value);
                } catch (Exception e) {
                    // Log error but don't fail the write
                    logger.warn("Failed to replicate to {}: {}", replica, e.getMessage());
                    // Anti-entropy will fix this later
                }
            }
        });
    }
    
    // Anti-entropy process ensures eventual consistency
    @Scheduled(fixedDelay = 60000) // Run every minute
    public void antiEntropyRepair() {
        for (Node replica : replicas) {
            try {
                syncWithReplica(replica);
            } catch (Exception e) {
                logger.error("Anti-entropy failed for replica {}", replica, e);
            }
        }
    }
    
    private void syncWithReplica(Node replica) {
        // Merkle tree comparison for efficient sync
        MerkleTree localTree = buildMerkleTree(localStore);
        MerkleTree replicaTree = replica.getMerkleTree();
        
        Set<String> differingKeys = findDifferences(localTree, replicaTree);
        
        for (String key : differingKeys) {
            Object localValue = localStore.get(key);
            Object replicaValue = replica.get(key);
            
            // Resolve conflicts (last-writer-wins, vector clocks, etc.)
            Object resolvedValue = resolveConflict(localValue, replicaValue);
            
            // Update both stores to resolved value
            localStore.put(key, resolvedValue);
            replica.update(key, resolvedValue);
        }
    }
}
```

### **Saga Pattern: Distributed Transactions in BASE Systems**

When you need transaction-like behavior in a BASE system, you use the **Saga pattern**:

```java
public class OrderProcessingSaga {
    private final List<SagaStep> steps;
    private final List<CompensationAction> executedSteps = new ArrayList<>();
    
    public void execute() {
        for (SagaStep step : steps) {
            try {
                CompensationAction compensation = step.execute();
                executedSteps.add(compensation);
            } catch (Exception e) {
                // Compensate all executed steps in reverse order
                compensate();
                throw new SagaException("Saga failed at step: " + step, e);
            }
        }
    }
    
    private void compensate() {
        Collections.reverse(executedSteps);
        for (CompensationAction action : executedSteps) {
            try {
                action.compensate();
            } catch (Exception e) {
                // Log compensation failure - may need manual intervention
                logger.error("Compensation failed: {}", action, e);
                // In production: alert operations team
            }
        }
    }
    
    // Example: E-commerce Order Processing
    public static OrderProcessingSaga createOrderSaga(Order order) {
        return new OrderProcessingSaga(Arrays.asList(
            new ReserveInventoryStep(order),
            new ChargePaymentStep(order),
            new CreateShipmentStep(order),
            new SendConfirmationStep(order)
        ));
    }
}

// Example saga step with compensation
public class ReserveInventoryStep implements SagaStep {
    private final Order order;
    
    @Override
    public CompensationAction execute() {
        // Reserve inventory for the order
        InventoryReservation reservation = inventoryService.reserve(order.getItems());
        
        // Return compensation action
        return () -> inventoryService.release(reservation);
    }
}

public class ChargePaymentStep implements SagaStep {
    private final Order order;
    
    @Override
    public CompensationAction execute() {
        // Charge customer's payment method
        PaymentTransaction transaction = paymentService.charge(
            order.getCustomerId(), 
            order.getTotalAmount()
        );
        
        // Return compensation action
        return () -> paymentService.refund(transaction);
    }
}
```

### **ACID vs BASE: When to Use Which**

```java
public class HybridECommerceSystem {
    
    // ACID for critical operations
    @Transactional(isolation = SERIALIZABLE)
    public void processPayment(PaymentRequest request) {
        // Money operations must be ACID
        Account customerAccount = getAccount(request.getCustomerId());
        Account merchantAccount = getAccount(request.getMerchantId());
        
        // Atomicity: Both operations succeed or both fail
        customerAccount.debit(request.getAmount());
        merchantAccount.credit(request.getAmount());
        
        // Consistency: Total money in system unchanged
        // Isolation: No other transactions see intermediate state
        // Durability: Changes persisted immediately
    }
    
    // BASE for user experience operations
    public void updateRecommendations(UserId userId, PurchaseEvent event) {
        // Use BASE approach for recommendations
        CompletableFuture.runAsync(() -> {
            try {
                // Eventually consistent - ok if recommendations are slightly stale
                recommendationService.updateUserProfile(userId, event);
            } catch (Exception e) {
                // Log error but don't fail the purchase
                logger.warn("Failed to update recommendations for user {}", userId, e);
                // Anti-entropy will fix this later
            }
        });
    }
    
    // BASE for social features
    public void updateActivityFeed(UserId userId, ActivityEvent event) {
        // Basically available - use multiple data centers
        for (DataCenter dc : dataCenters) {
            CompletableFuture.runAsync(() -> {
                try {
                    dc.addToActivityFeed(userId, event);
                } catch (Exception e) {
                    // Continue with other data centers
                    logger.warn("Failed to update activity feed in DC {}", dc.getId(), e);
                }
            });
        }
    }
    
    // Hybrid approach for inventory
    public boolean reserveInventory(ProductId productId, int quantity) {
        // Strong consistency for inventory counts
        return inventoryService.atomicReserve(productId, quantity);
    }
    
    public void updateInventoryRecommendations(ProductId productId) {
        // Eventual consistency for derived data
        CompletableFuture.runAsync(() -> {
            recommendationService.updateProductPopularity(productId);
        });
    }
}
```

### **FAANG Interview Questions on ACID vs BASE**

**Q: "Design order processing for an e-commerce platform. ACID or BASE?"**

**Basic Answer:**
"I'd use ACID for consistency."

**Top 1% Answer:**
```
"I'd use a hybrid approach - different components need different guarantees:

ACID Components (Strong Consistency Required):
1. Payment Processing
   - Money movement must be atomic
   - Isolation prevents double-charging
   - Durability ensures payment persistence
   - Use distributed 2PC or saga pattern

2. Inventory Management
   - Prevent overselling with strong consistency
   - Atomic reservation/release operations
   - Immediate consistency for stock counts

BASE Components (Scale and Availability Priority):
1. Order Status Updates
   - Status changes can propagate asynchronously
   - Customers can see "processing" while backend works
   - Email notifications sent eventually

2. Recommendation Engine
   - Purchase history updates eventually
   - Stale recommendations are acceptable
   - Performance over perfect accuracy

3. Activity Feeds
   - Social features can be eventually consistent
   - Better to show something than nothing

Implementation Strategy:
```java
public class HybridOrderProcessor {
    
    // ACID: Critical business operations
    @Transactional
    public OrderResult processOrder(Order order) {
        // 1. Reserve inventory (ACID)
        InventoryReservation reservation = inventoryService.reserve(order.getItems());
        
        // 2. Charge payment (ACID)
        PaymentResult payment = paymentService.charge(order.getPaymentInfo());
        
        if (payment.isSuccess()) {
            // 3. Create order record (ACID)
            Order savedOrder = orderService.createOrder(order, reservation, payment);
            
            // 4. Trigger BASE operations asynchronously
            triggerEventuallyConsistentUpdates(savedOrder);
            
            return OrderResult.success(savedOrder);
        } else {
            // Atomicity: rollback inventory reservation
            inventoryService.release(reservation);
            return OrderResult.failure("Payment failed");
        }
    }
    
    // BASE: Non-critical operations
    private void triggerEventuallyConsistentUpdates(Order order) {
        eventBus.publish(new OrderCreatedEvent(order)); // Fire and forget
        
        // Multiple handlers will eventually process:
        // - Update recommendation engine
        // - Send confirmation email
        // - Update analytics
        // - Notify social feeds
    }
}
```

Trade-off Analysis:
- ACID ensures critical business invariants
- BASE provides better user experience and scalability
- Hybrid approach gets benefits of both
- Clear separation of concerns by operation criticality"

**Follow-up: "What if inventory and payment are in different databases?"**

**Answer:** "Implement distributed ACID using 2PC coordinator or saga pattern. For 2PC: prepare phase on both databases, commit only if both succeed. For saga: sequence operations with compensation actions. Saga is more resilient to failures but requires careful compensation logic."

---

## **4. Failure Models: Understanding What Can Go Wrong**

### **Why Failure Models Matter**

In distributed systems, **failures are not exceptions - they're the norm**. Understanding failure types helps you:
- Design resilient systems
- Choose appropriate consistency/availability trade-offs
- Implement correct failure detection and recovery

### **Complete Failure Taxonomy**

```java
public enum FailureType {
    // Crash Failures (Benign)
    CRASH_STOP("Node stops completely and doesn't restart"),
    CRASH_RECOVERY("Node stops but restarts with persistent state intact"),
    
    // Omission Failures (Message Loss)
    SEND_OMISSION("Node fails to send some messages"),
    RECEIVE_OMISSION("Node fails to receive some messages"),
    CHANNEL_OMISSION("Network drops/delays/duplicates messages"),
    
    // Timing Failures (Performance)
    SLOW_NODE("Node responds correctly but very slowly"),
    TIMING_VIOLATION("Messages arrive outside expected time bounds"),
    CLOCK_DRIFT("Node's clock diverges from real time"),
    
    // Byzantine Failures (Malicious/Arbitrary)
    ARBITRARY("Node behaves in any arbitrary way"),
    AUTHENTICATION("Messages are forged or tampered with"),
    PROTOCOL_VIOLATION("Node doesn't follow protocol correctly"),
    
    // Network Failures
    NETWORK_PARTITION("Network splits into disconnected components"),
    ASYMMETRIC_PARTITION("A can reach B but B cannot reach A"),
    FLAPPING("Network connection rapidly connects/disconnects"),
    
    // Correlated Failures (Multiple nodes fail together)
    POWER_OUTAGE("Entire datacenter loses power"),
    CONFIGURATION_ERROR("Bad config deployed to all nodes simultaneously"),
    SOFTWARE_BUG("Same bug affects all replicas"),
    CASCADING_FAILURE("Failure in one component causes failures in others"),
    
    // Gray Failures (Partial degradation)
    SLOW_STORAGE("Disk becomes very slow but still functional"),
    HIGH_CPU("CPU saturated, causing timeouts but not crashes"),
    MEMORY_LEAK("Gradual memory exhaustion over time"),
    INTERMITTENT_NETWORK("Network works sometimes, fails other times");
}
```

### **Crash Failures: The "Easy" Case**

**Crash-Stop:** Node fails and never recovers.

```java
public class CrashStopFailureHandling {
    private final Set<NodeId> liveNodes = ConcurrentHashMap.newKeySet();
    private final FailureDetector failureDetector;
    
    public void handleCrashStop(NodeId failedNode) {
        // Remove from live nodes
        liveNodes.remove(failedNode);
        
        // Redistribute workload
        redistributeWorkload(failedNode);
        
        // Update routing tables
        routingTable.removeNode(failedNode);
        
        // No need to worry about recovery - node won't come back
    }
    
    private void redistributeWorkload(NodeId failedNode) {
        List<Task> orphanedTasks = getTasksAssignedTo(failedNode);
        
        for (Task task : orphanedTasks) {
            // Find new node to handle the task
            NodeId newNode = selectLeastLoadedNode();
            reassignTask(task, newNode);
        }
    }
}
```

**Crash-Recovery:** Node fails but can restart with persistent state.

```java
public class CrashRecoverySystem {
    private final PersistentLog persistentLog;
    private volatile boolean recovering = false;
    
    public void handleCrashRecovery() {
        recovering = true;
        
        try {
            // 1. Recover state from persistent storage
            SystemState recoveredState = recoverFromPersistentLog();
            
            // 2. Rejoin cluster
            rejoinCluster(recoveredState);
            
            // 3. Catch up on missed events
            catchUpWithCluster();
            
            recovering = false;
        } catch (Exception e) {
            logger.error("Recovery failed", e);
            // May need manual intervention
        }
    }
    
    private SystemState recoverFromPersistentLog() {
        SystemState state = new SystemState();
        
        // Replay log entries to rebuild state
        for (LogEntry entry : persistentLog.readAll()) {
            if (entry instanceof StateChangeEntry) {
                state.apply((StateChangeEntry) entry);
            }
        }
        
        return state;
    }
    
    private void rejoinCluster(SystemState state) {
        // Announce return to cluster
        ClusterMessage rejoinMessage = new RejoinMessage(nodeId, state.getVersion());
        
        // Other nodes may need to sync state with us
        for (NodeId peer : clusterMembers) {
            peer.send(rejoinMessage);
        }
    }
}
```

### **Network Partitions: The Difficult Case**

**Symmetric Partition:** Nodes can't communicate in either direction.

```java
public class NetworkPartitionHandling {
    private volatile PartitionState partitionState = HEALTHY;
    private final Set<NodeId> reachableNodes = ConcurrentHashMap.newKeySet();
    
    public void detectPartition() {
        Set<NodeId> currentlyReachable = pingAllNodes();
        Set<NodeId> previouslyReachable = new HashSet<>(reachableNodes);
        
        reachableNodes.clear();
        reachableNodes.addAll(currentlyReachable);
        
        if (currentlyReachable.size() < previouslyReachable.size()) {
            handlePartitionDetected(currentlyReachable, previouslyReachable);
        }
    }
    
    private void handlePartitionDetected(Set<NodeId> reachable, Set<NodeId> wasReachable) {
        int totalNodes = wasReachable.size();
        int reachableCount = reachable.size();
        
        if (reachableCount >= totalNodes / 2 + 1) {
            // Majority partition - continue serving
            partitionState = MAJORITY_PARTITION;
            continueNormalOperation();
            
            logger.info("In majority partition with {} of {} nodes", reachableCount, totalNodes);
        } else {
            // Minority partition - stop serving writes to avoid split-brain
            partitionState = MINORITY_PARTITION;
            enterReadOnlyMode();
            
            logger.warn("In minority partition with {} of {} nodes - entering read-only mode", 
                       reachableCount, totalNodes);
        }
    }
    
    private void enterReadOnlyMode() {
        // Reject all write operations
        writeOperationsEnabled = false;
        
        // Continue serving reads from local state
        // May serve stale data, but maintains availability
    }
    
    private void continueNormalOperation() {
        // Can continue serving both reads and writes
        writeOperationsEnabled = true;
        
        // But be prepared for split-brain resolution when partition heals
    }
}
```

**Asymmetric Partition:** A can reach B, but B cannot reach A.

```java
public class AsymmetricPartitionExample {
    // This is particularly tricky because nodes have different views
    
    public void handleAsymmetricPartition() {
        // Node A can send to B, but B cannot send to A
        // A thinks B is alive (sends succeed)
        // B thinks A is dead (no heartbeats received)
        
        // Solution: Use timeouts and explicit acknowledgments
    }
    
    // Robust heartbeat with explicit acks
    public class RobustHeartbeat {
        private final Map<NodeId, Long> lastAckTimes = new ConcurrentHashMap<>();
        
        @Scheduled(fixedDelay = 1000)
        public void sendHeartbeats() {
            for (NodeId peer : peers) {
                HeartbeatMessage hb = new HeartbeatMessage(nodeId, System.currentTimeMillis());
                
                // Send heartbeat and wait for explicit acknowledgment
                CompletableFuture<Void> ackFuture = peer.sendWithAck(hb, ACK_TIMEOUT_MS);
                
                ackFuture.whenComplete((result, exception) -> {
                    if (exception == null) {
                        lastAckTimes.put(peer, System.currentTimeMillis());
                    } else {
                        // No ack received - potential asymmetric partition
                        handleMissingAck(peer);
                    }
                });
            }
        }
        
        private void handleMissingAck(NodeId peer) {
            long lastAck = lastAckTimes.getOrDefault(peer, 0L);
            long timeSinceLastAck = System.currentTimeMillis() - lastAck;
            
            if (timeSinceLastAck > FAILURE_THRESHOLD_MS) {
                // Consider peer failed, even if sends succeed
                markPeerAsFailed(peer);
            }
        }
    }
}
```

### **Byzantine Failures: The Malicious Case**

**Definition:** Node behaves arbitrarily - may send conflicting messages, lie about state, or actively try to disrupt the system.

```java
public class ByzantineFailureHandling {
    private final int totalNodes;
    private final int byzantineThreshold; // f = (n-1)/3 for PBFT
    
    public ByzantineFailureHandling(int totalNodes) {
        this.totalNodes = totalNodes;
        // Can tolerate up to f Byzantine failures where n >= 3f + 1
        this.byzantineThreshold = (totalNodes - 1) / 3;
    }
    
    // Byzantine Fault Tolerant consensus
    public void handleByzantineProposal(Proposal proposal, NodeId sender) {
        // Never trust a single node - require multiple confirmations
        if (!isValidProposal(proposal)) {
            logger.warn("Invalid proposal from {}: {}", sender, proposal);
            return;
        }
        
        // Collect votes from multiple nodes
        Map<NodeId, Vote> votes = collectVotes(proposal);
        
        // Need 2f+1 matching votes to be safe from f Byzantine nodes
        int requiredVotes = 2 * byzantineThreshold + 1;
        
        if (countMatchingVotes(votes) >= requiredVotes) {
            acceptProposal(proposal);
        } else {
            rejectProposal(proposal);
        }
    }
    
    private boolean isValidProposal(Proposal proposal) {
        // Validate cryptographic signature
        if (!verifySignature(proposal)) {
            return false;
        }
        
        // Validate proposal contents
        if (!isValidState(proposal.getProposedState())) {
            return false;
        }
        
        // Check for internal consistency
        return proposal.isInternallyConsistent();
    }
    
    // Detect Byzantine behavior patterns
    public void monitorByzantineBehavior(NodeId suspect) {
        BehaviorPattern pattern = analyzeBehavior(suspect);
        
        if (pattern.isLikelybyzantine()) {
            // Don't immediately exclude - might be false positive
            // Instead, require more confirmations from this node
            increaseValidationRequirement(suspect);
            
            // Alert monitoring systems
            alertPossibleByzantineNode(suspect, pattern);
        }
    }
}
```

### **Gray Failures: The Subtle Case**

**Definition:** Node doesn't completely fail but performance degrades significantly.

```java
public class GrayFailureDetection {
    // Traditional failure detection misses gray failures
    // Need more sophisticated metrics
    
    public class PerformanceBasedFailureDetector {
        private final Map<NodeId, PerformanceMetrics> nodeMetrics = new ConcurrentHashMap<>();
        
        public void recordResponse(NodeId node, long responseTimeMs, boolean success) {
            PerformanceMetrics metrics = nodeMetrics.computeIfAbsent(node, 
                k -> new PerformanceMetrics());
            
            metrics.recordResponse(responseTimeMs, success);
            
            // Check for gray failure patterns
            if (isGrayFailure(metrics)) {
                handleGrayFailure(node, metrics);
            }
        }
        
        private boolean isGrayFailure(PerformanceMetrics metrics) {
            // Multiple indicators of gray failure
            boolean highLatency = metrics.getP99Latency() > LATENCY_THRESHOLD;
            boolean errorRate = metrics.getErrorRate() > ERROR_RATE_THRESHOLD;
            boolean timeouts = metrics.getTimeoutRate() > TIMEOUT_THRESHOLD;
            
            // Gray failure: high latency OR moderate error rate
            // (vs complete failure: all requests fail)
            return highLatency || (errorRate && !metrics.isCompletelyDown());
        }
        
        private void handleGrayFailure(NodeId node, PerformanceMetrics metrics) {
            logger.warn("Gray failure detected on node {}: {}", node, metrics);
            
            // Gradual response - don't immediately remove from service
            if (metrics.getP99Latency() > SEVERE_LATENCY_THRESHOLD) {
                // Severe degradation - reduce traffic
                loadBalancer.reduceTraffic(node, 0.5); // 50% traffic
            } else {
                // Moderate degradation - monitor more closely
                increaseMonitoringFrequency(node);
            }
        }
    }
    
    // Adaptive failure detection - adjust thresholds based on patterns
    public class AdaptiveFailureDetector {
        public void adjustThresholds(NodeId node, PerformanceHistory history) {
            // If node is consistently slow but stable, adjust expectations
            if (history.isConsistentlySlowButStable()) {
                // Increase timeout threshold for this node
                adjustTimeoutThreshold(node, history.getTypicalResponseTime() * 1.5);
            }
            
            // If node has periodic performance issues, predict them
            if (history.hasPeriodicPattern()) {
                schedulePreemptiveTrafficReduction(node, history.getPredictedSlowPeriods());
            }
        }
    }
}
```

### **Sophisticated Failure Detection: Phi Accrual**

Used by Cassandra and other production systems:

```java
public class PhiAccrualFailureDetector {
    private final CircularBuffer<Long> intervalHistory = new CircularBuffer<>(1000);
    private long lastHeartbeatTime = System.currentTimeMillis();
    private final double threshold = 8.0; // Phi threshold
    
    public void heartbeat() {
        long now = System.currentTimeMillis();
        long interval = now - lastHeartbeatTime;
        
        if (lastHeartbeatTime > 0) {
            intervalHistory.add(interval);
        }
        
        lastHeartbeatTime = now;
    }
    
    public boolean isAvailable() {
        return phi() < threshold;
    }
    
    public double phi() {
        if (intervalHistory.size() < 2) return 0.0;
        
        long timeSinceLastHeartbeat = System.currentTimeMillis() - lastHeartbeatTime;
        double mean = intervalHistory.stream().mapToLong(l -> l).average().orElse(0.0);
        double variance = calculateVariance(mean);
        double stddev = Math.sqrt(variance);
        
        // Phi = -log10(probability that heartbeat arrives within time window)
        // Higher phi = less likely node is alive
        double y = (timeSinceLastHeartbeat - mean) / stddev;
        double e = Math.exp(-y * (1.5976 + 0.070566 * y * y));
        
        if (timeSinceLastHeartbeat > mean) {
            return -Math.log10(e / (1.0 + e));
        } else {
            return 0.0;
        }
    }
    
    private double calculateVariance(double mean) {
        return intervalHistory.stream()
            .mapToDouble(interval -> Math.pow(interval - mean, 2))
            .average()
            .orElse(0.0);
    }
}
```

### **FAANG Interview Questions on Failure Models**

**Q: "Your distributed cache suddenly becomes slow. How do you diagnose and handle it?"**

**Basic Answer:**
"I'd check CPU and memory usage."

**Top 1% Answer:**
```
"This is a classic gray failure scenario requiring systematic diagnosis:

1. Immediate Detection & Mitigation:
   - Monitor P99 latency spikes (not just averages)
   - Check error rates and timeout patterns
   - Use phi accrual failure detector for gradual degradation
   - Implement circuit breaker to prevent cascade failures

2. Systematic Root Cause Analysis:
   a) Network Issues:
      - Ping times and packet loss rates
      - Bandwidth utilization and congestion
      - Check for asymmetric network partitions
   
   b) Resource Exhaustion:
      - CPU utilization patterns (not just averages)
      - Memory usage and GC pressure
      - Disk I/O saturation and queue depths
      - File descriptor and connection pool exhaustion
   
   c) Application-Level Issues:
      - Hot key patterns causing load imbalance
      - Lock contention in critical sections
      - Thread pool saturation
      - Memory leaks or inefficient algorithms

3. Handling Strategies by Failure Type:

```java
public class CacheFailureHandler {
    
    // Circuit breaker for immediate protection
    @CircuitBreaker(
        failureThreshold = 5,
        slowCallDurationThreshold = 2000, // 2 seconds
        slowCallRateThreshold = 50 // 50% slow calls
    )
    public Optional<String> getCacheValue(String key) {
        try {
            return cacheService.get(key);
        } catch (TimeoutException e) {
            // Fail fast instead of waiting
            return Optional.empty();
        }
    }
    
    // Adaptive timeout based on recent performance
    public class AdaptiveTimeout {
        private final AtomicReference<Double> currentTimeout = new AtomicReference<>(1000.0);
        
        public void recordResponse(long responseTimeMs) {
            double newTimeout = Math.max(
                responseTimeMs * 1.5,  // 1.5x recent response time
                currentTimeout.get() * 0.95  // Gradually decrease if improving
            );
            currentTimeout.set(Math.min(newTimeout, MAX_TIMEOUT_MS));
        }
        
        public long getCurrentTimeout() {
            return currentTimeout.get().longValue();
        }
    }
    
    // Load shedding for overload protection
    public class LoadShedder {
        private final AtomicDouble dropProbability = new AtomicDouble(0.0);
        
        public boolean shouldProcessRequest(RequestPriority priority) {
            double currentLoad = getCurrentSystemLoad();
            
            if (currentLoad > HIGH_LOAD_THRESHOLD) {
                // Drop low-priority requests first
                if (priority == LOW && Math.random() < 0.5) return false;
                if (priority == MEDIUM && Math.random() < 0.2) return false;
            }
            
            return true;
        }
    }
    
    // Request hedging for improved latency
    public CompletableFuture<String> hedgedGet(String key) {
        // Send request to primary cache
        CompletableFuture<String> primary = cacheNodes.get(0).get(key);
        
        // After delay, send to backup cache too
        CompletableFuture<String> backup = primary.completeOnTimeout(null, 100, MILLISECONDS)
            .thenCompose(result -> {
                if (result == null) {
                    return cacheNodes.get(1).get(key);
                }
                return CompletableFuture.completedFuture(result);
            });
        
        // Return whichever completes first
        return primary.applyToEither(backup, Function.identity());
    }
}
```

4. Monitoring and Alerting:
    - Real-time dashboards showing latency percentiles
    - Automated alerts on trend changes (not just thresholds)
    - Distributed tracing to identify bottlenecks
    - Capacity planning based on growth trends

5. Prevention Strategies:
    - Consistent hashing to prevent hot spots
    - Connection pooling and keep-alive optimization
    - Graceful degradation with multiple cache tiers
    - Chaos engineering to test failure scenarios"

**Follow-up: "What if it's a Byzantine failure - nodes returning wrong data?"**

**Answer:** "Need Byzantine fault tolerance: Use cryptographic signatures for data integrity, implement PBFT consensus requiring 2f+1 confirmations, add data integrity checks with checksums/merkle trees, and implement voting mechanisms to detect conflicting responses from different nodes."

---

## **5. Time & Ordering: The Foundation of Distributed Coordination**

### **Why Time is Hard in Distributed Systems**

In a single-machine system, you can rely on a single clock. In distributed systems:
- **Clocks drift** at different rates
- **Network delays** make "simultaneous" meaningless
- **Relativity matters** - no global "now"
- **Ordering events** becomes the fundamental challenge

### **Physical vs Logical Time**

```java
// Physical time (problematic in distributed systems)
public class PhysicalTimeExample {
    public void badExample() {
        long timestamp1 = System.currentTimeMillis(); // Node A
        // Network delay...
        long timestamp2 = System.currentTimeMillis(); // Node B
        
        // PROBLEM: timestamp1 might be > timestamp2 even if event1 happened first!
        // Clock skew can make causality appear reversed
    }
}

// Logical time (solves ordering problems)
public class LogicalTimeExample {
    public void goodExample() {
        LogicalClock clock = new LamportClock();
        
        // Events are ordered by logical time, not wall clock time
        long logicalTime1 = clock.tick(); // Increment before event
        sendMessage(message, logicalTime1);
        
        // Receiver updates their clock
        long logicalTime2 = clock.update(receivedLogicalTime);
        // Now we have proper causal ordering!
    }
}
```

### **Lamport Logical Clocks: The Simplest Solution**

**Key Insight:** If event A causally affects event B, then timestamp(A) < timestamp(B).

```java
public class LamportClock {
    private final AtomicLong clock = new AtomicLong(0);
    
    // Rule 1: Increment clock before local events
    public long tick() {
        return clock.incrementAndGet();
    }
    
    // Rule 2: Update clock when receiving messages
    public long update(long receivedTimestamp) {
        while (true) {
            long currentTime = clock.get();
            // Take max of local and received time, then increment
            long newTime = Math.max(currentTime, receivedTimestamp) + 1;
            
            if (clock.compareAndSet(currentTime, newTime)) {
                return newTime;
            }
        }
    }
    
    public long getCurrentTime() {
        return clock.get();
    }
}

// Example usage in distributed system
public class DistributedCounter {
    private final LamportClock clock = new LamportClock();
    private final String nodeId;
    private long counterValue = 0;
    
    public void increment() {
        long timestamp = clock.tick();
        counterValue++;
        
        // Broadcast increment to all replicas
        IncrementMessage msg = new IncrementMessage(nodeId, timestamp, 1);
        broadcastToReplicas(msg);
    }
    
    public void handleIncrementMessage(IncrementMessage msg) {
        // Update logical clock first
        long newTimestamp = clock.update(msg.getTimestamp());
        
        // Apply the increment
        counterValue += msg.getIncrement();
        
        logger.info("Applied increment at logical time {}", newTimestamp);
    }
}
```

**Lamport Clock Properties:**
- ✅ **Causal ordering**: If A → B, then timestamp(A) < timestamp(B)
- ❌ **Not total ordering**: Can't distinguish concurrent events
- ❌ **Can't detect concurrency**: timestamp(A) < timestamp(B) doesn't mean A → B

### **Vector Clocks: Complete Causality Tracking**

**Key Insight:** Track logical time for ALL nodes to capture complete causality.

```java
public class VectorClock {
    private final ConcurrentHashMap<String, Long> clock = new ConcurrentHashMap<>();
    private final String nodeId;
    private final Set<String> allNodeIds;
    
    public VectorClock(String nodeId, Set<String> allNodeIds) {
        this.nodeId = nodeId;
        this.allNodeIds = allNodeIds;
        
        // Initialize all nodes to 0
        for (String id : allNodeIds) {
            clock.put(id, 0L);
        }
    }
    
    // Increment local component
    public synchronized VectorClock tick() {
        clock.merge(nodeId, 1L, Long::sum);
        return this.copy();
    }
    
    // Update with received vector clock
    public synchronized VectorClock update(VectorClock other) {
        // Take component-wise maximum
        for (String node : allNodeIds) {
            long thisValue = this.clock.getOrDefault(node, 0L);
            long otherValue = other.clock.getOrDefault(node, 0L);
            clock.put(node, Math.max(thisValue, otherValue));
        }
        
        // Then increment local component
        clock.merge(nodeId, 1L, Long::sum);
        return this.copy();
    }
    
    // Check causality relationships
    public boolean happensBefore(VectorClock other) {
        // VC1 < VC2 iff all components VC1[i] <= VC2[i] and at least one VC1[i] < VC2[i]
        boolean allLessEqual = true;
        boolean atLeastOneLess = false;
        
        for (String node : allNodeIds) {
            long thisValue = this.clock.getOrDefault(node, 0L);
            long otherValue = other.clock.getOrDefault(node, 0L);
            
            if (thisValue > otherValue) {
                allLessEqual = false;
                break;
            } else if (thisValue < otherValue) {
                atLeastOneLess = true;
            }
        }
        
        return allLessEqual && atLeastOneLess;
    }
    
    public boolean isConcurrentWith(VectorClock other) {
        return !this.happensBefore(other) && !other.happensBefore(this);
    }
    
    public boolean isIdentical(VectorClock other) {
        for (String node : allNodeIds) {
            long thisValue = this.clock.getOrDefault(node, 0L);
            long otherValue = other.clock.getOrDefault(node, 0L);
            if (thisValue != otherValue) {
                return false;
            }
        }
        return true;
    }
    
    public VectorClock copy() {
        VectorClock copy = new VectorClock(nodeId, allNodeIds);
        copy.clock.putAll(this.clock);
        return copy;
    }
}

// Example: Collaborative editing with vector clocks
public class CollaborativeDocument {
    private final VectorClock localClock;
    private final List<DocumentOperation> operations = new ArrayList<>();
    private final Queue<BufferedOperation> pendingOps = new ConcurrentLinkedQueue<>();
    
    public void performEdit(String text, int position) {
        // Increment vector clock
        VectorClock timestamp = localClock.tick();
        
        // Create operation
        DocumentOperation op = new InsertOperation(position, text, timestamp);
        operations.add(op);
        
        // Broadcast to other users
        broadcastOperation(op);
    }
    
    public void receiveOperation(DocumentOperation op) {
        if (canApplyOperation(op)) {
            // All causal dependencies satisfied
            applyOperation(op);
            localClock.update(op.getTimestamp());
            
            // Try to apply pending operations
            tryApplyPendingOperations();
        } else {
            // Buffer until dependencies satisfied
            pendingOps.offer(new BufferedOperation(op));
        }
    }
    
    private boolean canApplyOperation(DocumentOperation op) {
        VectorClock opTimestamp = op.getTimestamp();
        
        // Can apply if all causally preceding operations have been applied
        for (String nodeId : getAllNodeIds()) {
            long opTime = opTimestamp.getTime(nodeId);
            long localTime = localClock.getTime(nodeId);
            
            if (nodeId.equals(op.getAuthor())) {
                // From operation author: must be exactly next operation
                if (opTime != localTime + 1) {
                    return false;
                }
            } else {
                // From other nodes: must have applied all operations up to opTime
                if (localTime < opTime) {
                    return false;
                }
            }
        }
        
        return true;
    }
}
```

**Vector Clock Example:**
```
Initial state: A[0,0,0], B[0,0,0], C[0,0,0]

A sends message: A[1,0,0] → B
B receives and sends: B[1,1,0] → C  
C receives and sends: C[1,1,1] → A
A receives: A[2,1,1]

Causality captured:
- A's first event → B's event → C's event → A's second event
- Can detect concurrent events vs causally related events
```

### **Hybrid Logical Clocks: Best of Both Worlds**

**Key Insight:** Combine wall clock time (for human understanding) with logical time (for ordering).

```java
public class HybridLogicalClock {
    private volatile long logicalTime = 0;
    private volatile long wallClockTime = 0;
    
    public synchronized HLCTimestamp now() {
        long currentWallClock = System.currentTimeMillis();
        
        if (currentWallClock > wallClockTime) {
            // Wall clock advanced - reset logical component
            wallClockTime = currentWallClock;
            logicalTime = 0;
        } else {
            // Wall clock same or behind - increment logical component
            logicalTime++;
        }
        
        return new HLCTimestamp(wallClockTime, logicalTime);
    }
    
    public synchronized HLCTimestamp update(HLCTimestamp received) {
        long currentWallClock = System.currentTimeMillis();
        
        // Take maximum of all wall clock times
        long maxWallClock = Math.max(
            Math.max(wallClockTime, received.wallClock), 
            currentWallClock
        );
        
        if (maxWallClock == wallClockTime && maxWallClock == received.wallClock) {
            // Same wall clock time - increment logical
            logicalTime = Math.max(logicalTime, received.logical) + 1;
        } else if (maxWallClock == wallClockTime) {
            // Our wall clock is max
            logicalTime++;
        } else if (maxWallClock == received.wallClock) {
            // Received wall clock is max
            logicalTime = received.logical + 1;
        } else {
            // Current wall clock is max
            logicalTime = 0;
        }
        
        wallClockTime = maxWallClock;
        return new HLCTimestamp(wallClockTime, logicalTime);
    }
    
    public static class HLCTimestamp implements Comparable<HLCTimestamp> {
        public final long wallClock;  // Physical time component
        public final long logical;    // Logical time component
        
        public HLCTimestamp(long wallClock, long logical) {
            this.wallClock = wallClock;
            this.logical = logical;
        }
        
        @Override
        public int compareTo(HLCTimestamp other) {
            // Order by wall clock first, then logical
            int wallClockComp = Long.compare(this.wallClock, other.wallClock);
            if (wallClockComp != 0) return wallClockComp;
            return Long.compare(this.logical, other.logical);
        }
        
        public boolean happensBefore(HLCTimestamp other) {
            return this.compareTo(other) < 0;
        }
        
        // Human-readable timestamp that preserves ordering
        public String toHumanReadable() {
            return new Date(wallClock) + "." + logical;
        }
    }
}

// Example: Database with HLC timestamps
public class HLCDatabase {
    private final HybridLogicalClock hlc = new HybridLogicalClock();
    private final Map<String, VersionedValue> data = new ConcurrentHashMap<>();
    
    public void write(String key, Object value) {
        HLCTimestamp timestamp = hlc.now();
        VersionedValue versionedValue = new VersionedValue(value, timestamp);
        
        data.put(key, versionedValue);
        
        // Replicate with HLC timestamp
        replicateToOtherNodes(key, versionedValue);
    }
    
    public void handleReplicatedWrite(String key, VersionedValue incomingValue) {
        // Update HLC with received timestamp
        hlc.update(incomingValue.getTimestamp());
        
        // Apply write if it's newer
        VersionedValue currentValue = data.get(key);
        if (currentValue == null || 
            incomingValue.getTimestamp().happensBefore(currentValue.getTimestamp())) {
            data.put(key, incomingValue);
        }
    }
    
    public List<VersionedValue> getVersionHistory(String key, long sinceWallClock) {
        // Can efficiently query by wall clock time!
        return versionHistory.get(key).stream()
            .filter(v -> v.getTimestamp().wallClock >= sinceWallClock)
            .sorted(Comparator.comparing(VersionedValue::getTimestamp))
            .collect(Collectors.toList());
    }
}
```

**HLC Advantages:**
- ✅ **Preserves causality** like logical clocks
- ✅ **Close to wall clock time** for human understanding
- ✅ **Efficient queries** by time ranges
- ✅ **Bounded logical component** (won't grow indefinitely)

### **Distributed Ordering Mechanisms**

#### **Total Order Broadcast**

**Goal:** All nodes deliver messages in the same order.

```java
public class TotalOrderBroadcast {
    private final ConsensusProtocol consensus;
    private final AtomicLong sequenceNumber = new AtomicLong(0);
    private final BlockingQueue<OrderedMessage> deliveryQueue = new LinkedBlockingQueue<>();
    
    public void broadcast(byte[] message) {
        // Use consensus to agree on global ordering
        long seq = sequenceNumber.incrementAndGet();
        OrderedMessage orderedMsg = new OrderedMessage(seq, message, System.currentTimeMillis());
        
        // Propose message through consensus (Raft/Paxos)
        consensus.propose(orderedMsg);
    }
    
    // Consensus callback when message order is decided
    public void onConsensusDecision(OrderedMessage message) {
        deliveryQueue.offer(message);
        notifyApplicationLayer(message);
    }
    
    // Application receives messages in total order
    @EventHandler
    public void handleOrderedMessage(OrderedMessage message) {
        // All nodes process messages in same order
        // Guarantees replica consistency
        applyMessageToState(message);
    }
}
```

#### **FIFO Ordering (Per-Sender)**

**Goal:** Messages from each sender are delivered in send order.

```java
public class FIFOOrderBroadcast {
    private final Map<String, AtomicLong> senderSequenceNumbers = new ConcurrentHashMap<>();
    private final Map<String, Long> expectedSequenceNumbers = new ConcurrentHashMap<>();
    private final Map<String, TreeMap<Long, Message>> pendingMessages = new ConcurrentHashMap<>();
    
    public void send(String senderId, byte[] payload) {
        // Assign sequence number for this sender
        long seqNum = senderSequenceNumbers.computeIfAbsent(senderId, k -> new AtomicLong(0))
                                            .incrementAndGet();
        
        FIFOMessage message = new FIFOMessage(senderId, seqNum, payload);
        broadcast(message);
    }
    
    public void onReceive(FIFOMessage message) {
        String senderId = message.getSenderId();
        long seqNum = message.getSequenceNumber();
        
        long expected = expectedSequenceNumbers.getOrDefault(senderId, 1L);
        
        if (seqNum == expected) {
            // Can deliver immediately
            deliverMessage(message);
            expectedSequenceNumbers.put(senderId, expected + 1);
            
            // Check if we can deliver buffered messages
            deliverBufferedMessages(senderId);
        } else if (seqNum > expected) {
            // Buffer for later delivery
            pendingMessages.computeIfAbsent(senderId, k -> new TreeMap<>())
                          .put(seqNum, message);
        }
        // Ignore if seqNum < expected (duplicate/out of order)
    }
    
    private void deliverBufferedMessages(String senderId) {
        TreeMap<Long, Message> pending = pendingMessages.get(senderId);
        if (pending == null) return;
        
        long expected = expectedSequenceNumbers.get(senderId);
        
        while (pending.containsKey(expected)) {
            Message message = pending.remove(expected);
            deliverMessage(message);
            expected++;
        }
        
        expectedSequenceNumbers.put(senderId, expected);
    }
}
```

#### **Causal Ordering**

**Goal:** Causally related messages are delivered in causal order.

```java
public class CausalOrderBroadcast {
    private final VectorClock localClock;
    private final Queue<CausalMessage> pendingMessages = new ConcurrentLinkedQueue<>();
    
    public void send(byte[] payload) {
        VectorClock timestamp = localClock.tick();
        CausalMessage message = new CausalMessage(localClock.getNodeId(), payload, timestamp);
        broadcast(message);
    }
    
    public void onReceive(CausalMessage message) {
        // Can deliver if all causally preceding messages have been delivered
        if (canDeliver(message)) {
            deliverMessage(message);
            localClock.update(message.getTimestamp());
            
            // Try to deliver pending messages
            deliverPendingMessages();
        } else {
            pendingMessages.offer(message);
        }
    }
    
    private boolean canDeliver(CausalMessage message) {
        VectorClock messageClock = message.getTimestamp();
        String senderId = message.getSenderId();
        
        // Check if all causally preceding messages have been delivered
        for (String nodeId : messageClock.getAllNodes()) {
            long messageTime = messageClock.getTime(nodeId);
            long deliveredTime = localClock.getTime(nodeId);
            
            if (nodeId.equals(senderId)) {
                // From sender: must be exactly next message
                if (messageTime != deliveredTime + 1) {
                    return false;
                }
            } else {
                // From other nodes: must have delivered all up to message time
                if (deliveredTime < messageTime) {
                    return false;
                }
            }
        }
        
        return true;
    }
    
    private void deliverPendingMessages() {
        boolean delivered = true;
        while (delivered) {
            delivered = false;
            
            Iterator<CausalMessage> iterator = pendingMessages.iterator();
            while (iterator.hasNext()) {
                CausalMessage message = iterator.next();
                if (canDeliver(message)) {
                    iterator.remove();
                    deliverMessage(message);
                    localClock.update(message.getTimestamp());
                    delivered = true;
                    break; // Start over to maintain order
                }
            }
        }
    }
}
```

### **FAANG Interview Questions on Time & Ordering**

**Q: "Design a distributed log system like Kafka. How do you ensure message ordering?"**

**Basic Answer:**
"Use timestamps for ordering."

**Top 1% Answer:**
```
"Multi-level ordering strategy based on different requirements:

1. Per-Partition Ordering (FIFO):
   - Each partition maintains strict FIFO order
   - Append-only log with monotonic sequence numbers
   - Single writer per partition ensures atomic ordering

2. Cross-Partition Ordering (Total Order when needed):
   - Use consensus (Raft) for leader election
   - Leader assigns global sequence numbers
   - Two-phase commit for multi-partition atomic writes

3. Causal Ordering (for complex event flows):
   - Vector clocks for client operations
   - Delay delivery until causal dependencies satisfied
   - Buffer out-of-order messages

Implementation:
```java
public class DistributedLog {
    
    // Per-partition FIFO ordering
    public class Partition {
        private final AtomicLong offset = new AtomicLong(0);
        private final WAL writeAheadLog;
        
        public long append(byte[] data) {
            long nextOffset = offset.incrementAndGet();
            LogEntry entry = new LogEntry(nextOffset, data, System.currentTimeMillis());
            
            // Atomic append with FIFO guarantee
            writeAheadLog.append(entry);
            return nextOffset;
        }
        
        public List<LogEntry> read(long fromOffset, int maxEntries) {
            // Always returns entries in offset order
            return writeAheadLog.readRange(fromOffset, maxEntries);
        }
    }
    
    // Total ordering across partitions (when needed)
    public class TotalOrderCoordinator {
        private final AtomicLong globalSequence = new AtomicLong(0);
        private final RaftConsensus consensus;
        
        public synchronized GlobalOffset appendWithTotalOrder(
            List<PartitionWrite> writes) {
            
            long globalSeq = globalSequence.incrementAndGet();
            
            // Two-phase commit for atomicity across partitions
            if (prepareAllPartitions(writes, globalSeq)) {
                commitAllPartitions(writes, globalSeq);
                return new GlobalOffset(globalSeq);
            } else {
                abortAllPartitions(writes);
                throw new OrderingException("Failed to maintain total order");
            }
        }
    }
    
    // Consumer with configurable ordering guarantees
    public class OrderedConsumer {
        private final OrderingLevel orderingLevel;
        
        public void consume(OrderingLevel level) {
            switch (level) {
                case PER_PARTITION:
                    consumeWithPartitionOrdering();
                    break;
                case TOTAL_ORDER:
                    consumeWithTotalOrdering();
                    break;
                case CAUSAL:
                    consumeWithCausalOrdering();
                    break;
            }
        }
        
        private void consumeWithCausalOrdering() {
            VectorClock consumerClock = new VectorClock(consumerId, allProducerIds);
            Queue<BufferedMessage> pendingMessages = new LinkedList<>();
            
            while (true) {
                Message msg = pollNextMessage();
                
                if (canDeliverCausally(msg, consumerClock)) {
                    processMessage(msg);
                    consumerClock.update(msg.getVectorClock());
                    processPendingMessages(pendingMessages, consumerClock);
                } else {
                    pendingMessages.offer(msg);
                }
            }
        }
    }
}
```

Design Trade-offs:
- FIFO per partition: High throughput, simple implementation
- Total order: Strong consistency, lower throughput
- Causal order: Good balance, complex conflict resolution
- Hybrid approach: Different guarantees for different topics

Performance Optimizations:
- Batching for higher throughput
- Parallel consumption within ordering constraints
- Efficient conflict detection with bloom filters"

**Follow-up: "What if you need exactly-once delivery across failures?"**

**Answer:** "Implement idempotent producers with producer epochs and sequence numbers, consumer-side deduplication with configurable retention windows, and transactional coordination between producer state and consumer offsets. Use fencing tokens to handle producer failures and maintain exactly-once semantics even during network partitions."

---

## **Week 1 Complete Study Plan & Implementation Guide**

### **Daily Learning Schedule**

#### **Day 1-2: CAP Theorem & Real-World Systems**
**Morning (3 hours):**
- Study CAP theorem fundamentals and misconceptions
- Analyze real systems: DynamoDB (AP), Spanner (CP), Cassandra (tunable)
- Practice explaining trade-offs in concrete scenarios

**Afternoon (2 hours):**
- Implement configurable consistency system
- Build network partition simulator
- Practice CAP-related interview questions

**Assignment:** Build a distributed counter with configurable CAP choices

#### **Day 3-4: Consistency Models Deep Dive**
**Morning (3 hours):**
- Implement all consistency models from scratch
- Study vector clock mathematics and properties
- Analyze when to use each consistency model

**Afternoon (2 hours):**
- Build causal consistency demo with collaborative editing
- Implement conflict resolution strategies
- Practice consistency interview scenarios

**Assignment:** Build Google Docs-like collaborative editor with causal consistency

#### **Day 5-6: ACID vs BASE Systems**
**Morning (3 hours):**
- Implement complete ACID transaction manager
- Build saga pattern for distributed transactions
- Study isolation levels with concrete examples

**Afternoon (2 hours):**
- Implement eventually consistent system with anti-entropy
- Build circuit breakers and bulkheads
- Compare ACID vs BASE for different use cases

**Assignment:** Build e-commerce order processor with hybrid ACID/BASE approach

#### **Day 7: Failure Models & Time/Ordering**
**Morning (3 hours):**
- Implement phi accrual failure detector
- Build Byzantine fault tolerance demo
- Study gray failure patterns and detection

**Afternoon (2 hours):**
- Implement all three clock types (Lamport, Vector, HLC)
- Build total order broadcast system
- Practice time/ordering interview questions

**Assignment:** Build distributed messaging system with multiple ordering guarantees

### **Complete Implementation Assignments**

#### **Assignment 1: Configurable Distributed Register**
```java
public interface ConfigurableRegister<T> {
    // Support multiple consistency levels
    void write(T value, ConsistencyLevel level) throws ConsistencyException;
    T read(ConsistencyLevel level) throws ConsistencyException;
    
    // Handle network partitions gracefully
    void handlePartition(Set<NodeId> availableNodes);
    PartitionStatus getPartitionStatus();
    
    // Monitor and adjust behavior
    void setFailureDetector(FailureDetector detector);
    HealthStatus getNodeHealth(NodeId node);
}

// Implementation requirements:
// 1. Support LINEARIZABLE, SEQUENTIAL, CAUSAL, EVENTUAL consistency
// 2. Implement proper failure detection with phi accrual
// 3. Handle network partitions with configurable behavior
// 4. Include comprehensive testing with partition simulation
// 5. Measure and report performance characteristics
```

#### **Assignment 2: ACID Transaction Manager**
```java
public interface DistributedTxManager {
    TransactionId beginTransaction(IsolationLevel isolation);
    void addParticipant(TransactionId txId, TransactionParticipant participant);
    void commit(TransactionId txId) throws TransactionException;
    void abort(TransactionId txId);
    
    // Recovery and coordination
    void recoverFromFailure(NodeId failedCoordinator);
    TransactionStatus getTransactionStatus(TransactionId txId);
}

// Implementation requirements:
// 1. Full 2PC protocol with proper logging
// 2. Handle coordinator failures with backup coordinators
// 3. Support all isolation levels with proper locking
// 4. Implement deadlock detection and resolution
// 5. Include WAL for durability and recovery
// 6. Performance testing with concurrent transactions
```

#### **Assignment 3: Comprehensive Messaging System**
```java
public interface OrderedMessagingSystem {
    // Multiple ordering guarantees
    void send(Message message, OrderingLevel ordering);
    void subscribe(String topic, MessageHandler handler, OrderingLevel ordering);
    
    // Failure handling and recovery
    void handleNodeFailure(NodeId failedNode);
    void handleNetworkPartition(Set<NodeId> availableNodes);
    
    // Performance and monitoring
    MessageDeliveryStats getDeliveryStats();
    void enableChaosEngineering(ChaosConfig config);
}

// Implementation requirements:
// 1. Support FIFO, CAUSAL, and TOTAL ordering
// 2. Implement vector clocks for causality tracking
// 3. Handle message buffering and out-of-order delivery
// 4. Include failure detection and automatic recovery
// 5. Performance benchmarking with millions of messages
// 6. Chaos engineering tests for partition tolerance