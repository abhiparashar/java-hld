# Security & Authentication Guide - Part 2 of 5

**Topics Covered:**
- S4: API Security (API Keys, Rate Limiting) 🔴 Critical
- S5: HTTPS/TLS/SSL 🟡 Important
- S6: Encryption (At-rest vs In-transit) 🔴 Critical

**For FAANG System Design Interviews**

---

# S4: API Security (API Keys, Rate Limiting)

## 🍕 The Pizza Delivery Analogy

Imagine you own a pizza shop with a phone ordering system:

**Without API Security (Chaos):**
- Anyone can call and place unlimited orders
- Pranksters order 1000 pizzas to random addresses
- Competitors call repeatedly to overwhelm your phone lines
- You can't tell legitimate customers from attackers
- Your business collapses from fake orders and wasted resources

**With API Security:**

**API Keys (Customer Identification):**
- Regular customers get a customer ID card
- Each order, they provide their ID number
- You know: Who's calling, their order history, if they're banned
- "Hello, this is Customer #5847, I'd like to order..."

**Rate Limiting (Order Limits):**
- Regular customers: 5 orders per hour maximum
- New customers: 2 orders per hour until verified
- Premium customers: 20 orders per hour
- If someone exceeds their limit: "Sorry, you've placed too many orders recently. Try again in 30 minutes."

This protects your business from abuse while serving legitimate customers!

---

## Beginner Level: What is API Security?

### Understanding APIs

An API (Application Programming Interface) is how programs talk to each other.

**Real-World Example - Weather App:**

```
Your Phone App → Makes Request → Weather API → Returns Data

Request:  GET https://api.weather.com/forecast?city=Mumbai
Response: {"temperature": 28, "condition": "sunny", "humidity": 65}
```

**The Problem:** Without security, ANYONE can access your API:
- Hackers can steal all your data
- Attackers can overwhelm your servers (DDoS)
- Competitors can scrape your content
- Costs skyrocket from unauthorized usage

### API Keys - The First Line of Defense

An API key is a unique identifier that tracks who's using your API.

**How It Works:**

```
Step 1: Developer signs up
  → System generates unique key: "sk_live_abc123xyz789"

Step 2: Developer stores key securely

Step 3: Every API request includes the key
  GET /api/data
  Header: Authorization: Bearer sk_live_abc123xyz789

Step 4: Server validates key
  → Look up key in database
  → If valid: Process request
  → If invalid: Return 401 Unauthorized
```

**Real Java Implementation:**

```java
// ApiKeyService.java
@Service
public class ApiKeyService {
    
    @Autowired
    private ApiKeyRepository apiKeyRepo;
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    /**
     * Validate API key and check rate limits
     * Used on every incoming API request
     */
    public ApiKeyValidation validateKey(String apiKey) {
        // 1. Check Redis cache first (performance optimization)
        String cachedUserId = redisTemplate.opsForValue()
            .get("apikey:" + apiKey);
        
        if (cachedUserId != null) {
            return ApiKeyValidation.valid(cachedUserId);
        }
        
        // 2. Not in cache, check database
        ApiKey keyData = apiKeyRepo.findByKey(apiKey);
        
        if (keyData == null) {
            return ApiKeyValidation.invalid("API key not found");
        }
        
        // 3. Check if key is active
        if (!keyData.isActive()) {
            return ApiKeyValidation.invalid("API key has been revoked");
        }
        
        // 4. Check expiration
        if (keyData.getExpiresAt() != null && 
            keyData.getExpiresAt().before(new Date())) {
            return ApiKeyValidation.invalid("API key has expired");
        }
        
        // 5. Check IP whitelist if configured
        if (keyData.hasIpWhitelist()) {
            String clientIp = getCurrentRequestIp();
            if (!keyData.isIpAllowed(clientIp)) {
                logSecurityEvent("IP_NOT_WHITELISTED", apiKey, clientIp);
                return ApiKeyValidation.invalid("IP address not authorized");
            }
        }
        
        // 6. Cache the validated key for 5 minutes
        redisTemplate.opsForValue().set(
            "apikey:" + apiKey, 
            keyData.getUserId(),
            5, 
            TimeUnit.MINUTES
        );
        
        return ApiKeyValidation.valid(keyData.getUserId());
    }
    
    /**
     * Generate new API key for user
     */
    public String generateApiKey(String userId, ApiKeyType type) {
        // Generate cryptographically secure random key
        String prefix = type == ApiKeyType.LIVE ? "sk_live_" : "sk_test_";
        String randomPart = generateSecureRandomString(32);
        String apiKey = prefix + randomPart;
        
        // Store in database
        ApiKey keyData = new ApiKey();
        keyData.setKey(apiKey);
        keyData.setUserId(userId);
        keyData.setType(type);
        keyData.setCreatedAt(new Date());
        keyData.setActive(true);
        
        apiKeyRepo.save(keyData);
        
        // Log creation event
        auditLog.log("API_KEY_CREATED", userId, keyData.getId());
        
        return apiKey;
    }
    
    private String generateSecureRandomString(int length) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(bytes);
    }
}
```

**API Key Database Schema:**

```sql
CREATE TABLE api_keys (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    key_value VARCHAR(64) UNIQUE NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    key_type ENUM('live', 'test') NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    last_used_at TIMESTAMP NULL,
    ip_whitelist TEXT NULL,  -- JSON array of allowed IPs
    permissions JSON NULL,    -- Specific API permissions
    INDEX idx_key (key_value),
    INDEX idx_user (user_id),
    INDEX idx_active (is_active, expires_at)
);
```

### Rate Limiting - Preventing Abuse

Rate limiting controls how many requests a client can make in a time window.

**Common Strategies:**

1. **Fixed Window**
```
User can make 100 requests per hour

Hour 1 (12:00-12:59): 100 requests allowed
Hour 2 (13:00-13:59): Counter resets, 100 more allowed

Problem: Burst at boundary
- 12:59: Make 100 requests
- 13:00: Make 100 more requests
- Result: 200 requests in 1 minute!
```

2. **Sliding Window** (Better)
```
User can make 100 requests per hour, counted on sliding basis

At 12:30: Check requests from 11:30-12:30
At 12:45: Check requests from 11:45-12:45

No boundary burst problem!
```

3. **Token Bucket** (Most Common)
```
Bucket holds 100 tokens
Refill rate: 10 tokens per minute
Each request costs 1 token

Burst allowed: Use all 100 tokens quickly if needed
Sustained rate: Limited to 10/min refill rate
```

4. **Leaky Bucket**
```
Requests go into bucket
Processed at fixed rate (10/min)
If bucket full: Request rejected

Smooths out traffic spikes
```

**Java Implementation - Token Bucket with Redis:**

```java
// RateLimiter.java
@Component
public class TokenBucketRateLimiter {
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    /**
     * Check if request is allowed under rate limit
     * Uses Token Bucket algorithm with Redis
     */
    public RateLimitResult checkRateLimit(
            String userId, 
            int maxTokens,      // Bucket capacity
            int refillRate,     // Tokens per second
            int tokensNeeded    // Cost of this request
    ) {
        String key = "ratelimit:" + userId;
        long now = System.currentTimeMillis();
        
        // Execute as Lua script for atomicity
        String luaScript = 
            "local key = KEYS[1]\n" +
            "local max_tokens = tonumber(ARGV[1])\n" +
            "local refill_rate = tonumber(ARGV[2])\n" +
            "local tokens_needed = tonumber(ARGV[3])\n" +
            "local now = tonumber(ARGV[4])\n" +
            "\n" +
            "local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')\n" +
            "local tokens = tonumber(bucket[1])\n" +
            "local last_refill = tonumber(bucket[2])\n" +
            "\n" +
            "if tokens == nil then\n" +
            "    tokens = max_tokens\n" +
            "    last_refill = now\n" +
            "end\n" +
            "\n" +
            "-- Calculate tokens to add based on time passed\n" +
            "local time_passed = (now - last_refill) / 1000.0\n" +
            "local tokens_to_add = time_passed * refill_rate\n" +
            "tokens = math.min(max_tokens, tokens + tokens_to_add)\n" +
            "\n" +
            "local allowed = 0\n" +
            "if tokens >= tokens_needed then\n" +
            "    tokens = tokens - tokens_needed\n" +
            "    allowed = 1\n" +
            "end\n" +
            "\n" +
            "redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)\n" +
            "redis.call('EXPIRE', key, 3600)\n" +
            "\n" +
            "return {allowed, tokens}";
        
        // Execute Lua script
        RedisScript<List> script = RedisScript.of(luaScript, List.class);
        List<Long> result = (List<Long>) redisTemplate.execute(
            script,
            Collections.singletonList(key),
            maxTokens, refillRate, tokensNeeded, now
        );
        
        boolean allowed = result.get(0) == 1;
        long remainingTokens = result.get(1);
        
        return new RateLimitResult(allowed, remainingTokens, maxTokens);
    }
}

// Usage in API Controller
@RestController
@RequestMapping("/api")
public class ApiController {
    
    @Autowired
    private TokenBucketRateLimiter rateLimiter;
    
    @GetMapping("/data")
    public ResponseEntity<?> getData(@RequestHeader("Authorization") String authHeader) {
        String apiKey = extractApiKey(authHeader);
        String userId = validateApiKey(apiKey);
        
        // Check rate limit: 100 requests per hour = 100 tokens, refill at 1.67/sec
        RateLimitResult rateLimitResult = rateLimiter.checkRateLimit(
            userId,
            100,    // max tokens
            2,      // refill 2 tokens per second (~100/min, ~6000/hour)
            1       // this request costs 1 token
        );
        
        if (!rateLimitResult.isAllowed()) {
            return ResponseEntity.status(429)  // 429 Too Many Requests
                .header("X-RateLimit-Limit", "100")
                .header("X-RateLimit-Remaining", "0")
                .header("X-RateLimit-Reset", String.valueOf(getResetTime()))
                .body(Map.of(
                    "error", "rate_limit_exceeded",
                    "message", "Too many requests. Please try again later."
                ));
        }
        
        // Add rate limit headers to response
        return ResponseEntity.ok()
            .header("X-RateLimit-Limit", "100")
            .header("X-RateLimit-Remaining", 
                String.valueOf(rateLimitResult.getRemainingTokens()))
            .header("X-RateLimit-Reset", String.valueOf(getResetTime()))
            .body(getData());
    }
}
```

---

## Intermediate Level: Advanced Patterns

### Multi-Tier Rate Limiting

Different limits for different customer tiers:

```java
@Service
public class TieredRateLimiter {
    
    public enum Tier {
        FREE(100, 60),          // 100 requests per 60 seconds
        BASIC(1000, 60),        // 1000 requests per 60 seconds
        PRO(10000, 60),         // 10K requests per 60 seconds
        ENTERPRISE(100000, 60); // 100K requests per 60 seconds
        
        private final int maxRequests;
        private final int windowSeconds;
        
        Tier(int maxRequests, int windowSeconds) {
            this.maxRequests = maxRequests;
            this.windowSeconds = windowSeconds;
        }
    }
    
    public boolean isAllowed(String userId, Tier tier) {
        String key = "ratelimit:" + tier.name() + ":" + userId;
        long currentWindow = System.currentTimeMillis() / 1000 / tier.windowSeconds;
        String windowKey = key + ":" + currentWindow;
        
        // Increment request count
        Long requestCount = redisTemplate.opsForValue().increment(windowKey);
        
        // Set expiration on first request
        if (requestCount == 1) {
            redisTemplate.expire(windowKey, tier.windowSeconds * 2, TimeUnit.SECONDS);
        }
        
        return requestCount <= tier.maxRequests;
    }
}
```

### API Key Scopes and Permissions

Not all API keys should have full access:

```java
// ApiKey.java
@Entity
public class ApiKey {
    @Id
    private String id;
    
    private String keyValue;
    private String userId;
    
    // Scopes define what this key can do
    @ElementCollection
    private Set<String> scopes;  // {"read:users", "write:orders", "delete:products"}
    
    public boolean hasScope(String requiredScope) {
        return scopes.contains(requiredScope) || scopes.contains("*");
    }
    
    public boolean hasAllScopes(Set<String> requiredScopes) {
        return scopes.contains("*") || scopes.containsAll(requiredScopes);
    }
}

// ApiController with scope checking
@GetMapping("/users/{id}")
@RequireScope("read:users")
public User getUser(@PathVariable String id) {
    return userService.getUser(id);
}

@PostMapping("/orders")
@RequireScope("write:orders")
public Order createOrder(@RequestBody OrderRequest request) {
    return orderService.createOrder(request);
}

// Annotation processor
@Aspect
@Component
public class ScopeCheckAspect {
    
    @Around("@annotation(requireScope)")
    public Object checkScope(ProceedingJoinPoint joinPoint, RequireScope requireScope) {
        String apiKey = getCurrentApiKey();
        ApiKey key = apiKeyService.getKey(apiKey);
        
        if (!key.hasScope(requireScope.value())) {
            throw new InsufficientScopeException(
                "API key missing required scope: " + requireScope.value()
            );
        }
        
        return joinPoint.proceed();
    }
}
```

---

## Advanced Level: Production Patterns

### Distributed Rate Limiting

When you have multiple API servers, rate limiting must be coordinated:

**Problem:**
```
User has limit: 1000 requests/min

With 10 API servers:
- Each server tracks independently
- User can make 1000 requests to EACH server
- Total: 10,000 requests/min (10x the limit!)
```

**Solution: Centralized Rate Limiting with Redis**

```java
@Component
public class DistributedRateLimiter {
    
    @Autowired
    private RedissonClient redisson;
    
    /**
     * Distributed rate limiter using Redisson
     * Works correctly across multiple servers
     */
    public boolean tryAcquire(String userId, int maxRequests, Duration window) {
        String key = "ratelimit:" + userId;
        RRateLimiter rateLimiter = redisson.getRateLimiter(key);
        
        // Configure if not already configured
        if (!rateLimiter.isExists()) {
            rateLimiter.trySetRate(
                RateType.OVERALL,
                maxRequests,
                window.getSeconds(),
                RateIntervalUnit.SECONDS
            );
        }
        
        // Try to acquire permit
        return rateLimiter.tryAcquire(1);
    }
    
    /**
     * Advanced: Different limits for different endpoints
     */
    public boolean tryAcquireForEndpoint(
            String userId, 
            String endpoint,
            EndpointConfig config
    ) {
        // Combine user + endpoint for granular limiting
        String key = "ratelimit:" + endpoint + ":" + userId;
        
        RRateLimiter rateLimiter = redisson.getRateLimiter(key);
        
        if (!rateLimiter.isExists()) {
            rateLimiter.trySetRate(
                RateType.OVERALL,
                config.getMaxRequests(),
                config.getWindow().getSeconds(),
                RateIntervalUnit.SECONDS
            );
        }
        
        return rateLimiter.tryAcquire(config.getCost());
    }
}

// Configuration per endpoint
@Configuration
public class RateLimitConfig {
    
    @Bean
    public Map<String, EndpointConfig> endpointLimits() {
        return Map.of(
            "/api/search", new EndpointConfig(100, Duration.ofMinutes(1), 1),
            "/api/export", new EndpointConfig(10, Duration.ofHours(1), 5),  // Expensive operation
            "/api/users", new EndpointConfig(1000, Duration.ofMinutes(1), 1)
        );
    }
}
```

### Adaptive Rate Limiting

Adjust limits based on system load:

```java
@Component
public class AdaptiveRateLimiter {
    
    @Autowired
    private SystemMetricsService metricsService;
    
    /**
     * Adjust rate limits based on current system load
     */
    public int getEffectiveLimit(String userId, int baseLimit) {
        SystemMetrics metrics = metricsService.getCurrentMetrics();
        
        // If system is under heavy load, reduce limits
        if (metrics.getCpuUsage() > 80) {
            return (int) (baseLimit * 0.5);  // 50% of normal limit
        }
        
        if (metrics.getCpuUsage() > 60) {
            return (int) (baseLimit * 0.75);  // 75% of normal limit
        }
        
        // If system is idle, allow burst capacity
        if (metrics.getCpuUsage() < 30) {
            return (int) (baseLimit * 1.5);  // 150% of normal limit
        }
        
        return baseLimit;
    }
}
```

---

## Real FAANG Examples

### Example 1: AWS API Gateway Rate Limiting

AWS API Gateway implements sophisticated rate limiting:

**How It Works:**

```
AWS API Gateway Rate Limits (per API key):

Steady-State Rate: 10,000 requests per second
Burst Capacity: 5,000 requests

Algorithm: Token Bucket
- Bucket refills at 10,000 tokens/second
- Bucket holds maximum 5,000 tokens
- Each request consumes 1 token

Real-World Scenario:
00:00:00 - Bucket is full (5000 tokens)
00:00:01 - 15,000 requests arrive
           - First 5000: Use burst capacity (bucket emptied)
           - Next 10,000: Use refill rate (10k/sec)
           - Remaining 0: Rejected with 429 status

Next second:
00:00:02 - Bucket refills 10,000 tokens (capped at 5000)
           - Can handle burst again
```

**Configuration:**

```yaml
# API Gateway Usage Plan
UsagePlans:
  FreeIPlan:
    Quota:
      Limit: 10000           # Total requests per month
      Period: MONTH
    Throttle:
      RateLimit: 10          # Requests per second (steady state)
      BurstLimit: 20         # Burst capacity
      
  ProPlan:
    Quota:
      Limit: 1000000         # 1M requests per month
      Period: MONTH
    Throttle:
      RateLimit: 1000        # 1000 req/sec
      BurstLimit: 2000       # 2000 burst
```

**Response Headers:**

```
HTTP/1.1 200 OK
X-Amzn-RateLimit-Limit: 1000
X-Amzn-RateLimit-Remaining: 847
X-Amzn-RateLimit-Reset: 1642598400

HTTP/1.1 429 Too Many Requests
X-Amzn-RateLimit-Limit: 1000
X-Amzn-RateLimit-Remaining: 0
X-Amzn-RateLimit-Reset: 1642598400
Retry-After: 60
```

### Example 2: Stripe API Keys and Rate Limiting

Stripe's API design is considered industry-leading:

**API Key Structure:**

```
Test Keys:
  Secret: sk_test_51H8xGbKJ...  (Full access, server-side only)
  Public: pk_test_51H8xGbKJ...  (Limited operations, client-safe)

Live Keys:
  Secret: sk_live_51H8xGbKJ...  (Real transactions, server-only)
  Public: pk_live_51H8xGbKJ...  (Limited, client-safe)

Restricted Keys:
  rk_live_51H8xGbKJ...
  Scopes: ["read:customers", "write:charges"]
  IP Whitelist: ["52.3.45.67", "52.3.45.68"]
```

**Rate Limiting Strategy:**

```java
// Stripe-style rate limiting implementation

public class StripeRateLimiter {
    
    /**
     * Stripe uses different limits for different API key types
     */
    public enum KeyType {
        SECRET(100, 1),      // 100 req/sec, no burst
        PUBLIC(25, 5),       // 25 req/sec, 5 sec burst window
        RESTRICTED(50, 2);   // 50 req/sec, 2 sec burst
        
        final int requestsPerSecond;
        final int burstWindowSeconds;
    }
    
    /**
     * Stripe returns detailed rate limit info
     */
    public RateLimitResponse checkLimit(String apiKey, KeyType type) {
        String key = "stripe:ratelimit:" + hashKey(apiKey);
        long now = System.currentTimeMillis();
        
        // Sliding window with Redis
        String luaScript = 
            "local key = KEYS[1]\n" +
            "local now = tonumber(ARGV[1])\n" +
            "local window_ms = tonumber(ARGV[2]) * 1000\n" +
            "local max_requests = tonumber(ARGV[3])\n" +
            "\n" +
            "-- Remove old entries outside window\n" +
            "redis.call('ZREMRANGEBYSCORE', key, 0, now - window_ms)\n" +
            "\n" +
            "-- Count requests in current window\n" +
            "local current_requests = redis.call('ZCARD', key)\n" +
            "\n" +
            "if current_requests < max_requests then\n" +
            "    redis.call('ZADD', key, now, now)\n" +
            "    redis.call('EXPIRE', key, math.ceil(window_ms / 1000) + 1)\n" +
            "    return {1, max_requests - current_requests - 1}\n" +
            "else\n" +
            "    return {0, 0}\n" +
            "end";
        
        List<Long> result = executeRedisScript(
            luaScript,
            key,
            now,
            type.burstWindowSeconds,
            type.requestsPerSecond * type.burstWindowSeconds
        );
        
        boolean allowed = result.get(0) == 1;
        long remaining = result.get(1);
        
        return new RateLimitResponse(allowed, remaining);
    }
}
```

**Stripe's Response Headers:**

```
HTTP/1.1 200 OK
Stripe-Version: 2023-10-16
Request-Id: req_abc123xyz789
RateLimit-Limit: 100
RateLimit-Remaining: 87
RateLimit-Reset: 1705843200
```

### Example 3: Twitter API v2 Rate Limits

Twitter implements complex multi-dimensional rate limiting:

**Rate Limit Dimensions:**

```
1. Per User + Per App
   GET /2/tweets/search/recent
   - App: 450 requests per 15 min
   - User: 180 requests per 15 min

2. Per Endpoint
   POST /2/tweets: 200 tweets per 15 min
   GET /2/users/:id: 900 requests per 15 min
   
3. Per Operation Type
   Reads: Generally more permissive
   Writes: More restricted
   Deletes: Most restricted
```

**Java Implementation:**

```java
@Service
public class TwitterStyleRateLimiter {
    
    /**
     * Twitter-style composite rate limiting
     * Checks BOTH user and app limits
     */
    public RateLimitDecision checkCompositeLimit(
            String appId,
            String userId, 
            String endpoint
    ) {
        EndpointConfig config = getEndpointConfig(endpoint);
        
        // Check app-level limit
        RateLimitResult appLimit = checkLimit(
            "app:" + appId + ":" + endpoint,
            config.getAppLimit(),
            config.getWindow()
        );
        
        if (!appLimit.isAllowed()) {
            return RateLimitDecision.denied(
                "App rate limit exceeded",
                "app",
                appLimit.getResetTime()
            );
        }
        
        // Check user-level limit
        RateLimitResult userLimit = checkLimit(
            "user:" + userId + ":" + endpoint,
            config.getUserLimit(),
            config.getWindow()
        );
        
        if (!userLimit.isAllowed()) {
            return RateLimitDecision.denied(
                "User rate limit exceeded",
                "user",
                userLimit.getResetTime()
            );
        }
        
        // Both passed
        return RateLimitDecision.allowed(
            Math.min(appLimit.getRemaining(), userLimit.getRemaining())
        );
    }
}
```

**Twitter's Rate Limit Headers:**

```
HTTP/1.1 200 OK
x-rate-limit-limit: 180
x-rate-limit-remaining: 175
x-rate-limit-reset: 1705843200

// When exceeded:
HTTP/1.1 429 Too Many Requests
x-rate-limit-limit: 180
x-rate-limit-remaining: 0
x-rate-limit-reset: 1705843200
{
  "errors": [{
    "message": "Rate limit exceeded",
    "code": 88
  }]
}
```

### Example 4: Google Cloud API Quotas

Google implements hierarchical quotas:

```
Project-Level Quotas:
├── Compute Engine API
│   ├── Queries per day: 1,000,000
│   ├── Queries per 100 seconds: 5,000
│   └── Queries per 100 seconds per user: 500
│
├── Cloud Storage API
│   ├── Read requests per day: 50,000,000
│   ├── Write requests per day: 10,000,000
│   └── Bandwidth per day: 1 TB
│
└── BigQuery API
    ├── Queries per day: 1,000
    ├── Query data processed per day: 1 TB
    └── Concurrent queries: 100
```

**Implementation:**

```java
@Service
public class HierarchicalQuotaManager {
    
    /**
     * Google-style hierarchical quota checking
     */
    public QuotaCheckResult checkHierarchicalQuota(
            String projectId,
            String apiName,
            String userId,
            QuotaType quotaType
    ) {
        // Level 1: Check project-wide quota
        QuotaCheck projectQuota = checkQuota(
            "project:" + projectId + ":" + apiName,
            quotaType.getProjectLimit(),
            quotaType.getWindow()
        );
        
        if (!projectQuota.isAvailable()) {
            return QuotaCheckResult.exceeded(
                "Project quota exceeded",
                "project",
                projectQuota
            );
        }
        
        // Level 2: Check per-user quota within project
        QuotaCheck userQuota = checkQuota(
            "project:" + projectId + ":" + apiName + ":user:" + userId,
            quotaType.getUserLimit(),
            quotaType.getWindow()
        );
        
        if (!userQuota.isAvailable()) {
            return QuotaCheckResult.exceeded(
                "User quota exceeded",
                "user",
                userQuota
            );
        }
        
        // Both quotas available - consume from both
        return QuotaCheckResult.allowed(projectQuota, userQuota);
    }
}
```

---

## Interview Questions & Answers

### Question 1: Design a rate limiter for a high-traffic API

**Scenario:** You're designing an API that serves 1 million requests per second. Design a rate limiting system that can:
- Limit users to 1000 requests per minute
- Work across 100 API servers
- Have minimal latency impact (<5ms)

**Answer:**

```
Architecture:

1. Centralized Redis Cluster
   ├── 3 master nodes (sharded by user_id hash)
   ├── 3 replica nodes per master
   └── Redis Cluster mode for horizontal scaling

2. Rate Limiting Algorithm: Token Bucket with Lua
   Why Token Bucket?
   - Allows burst traffic (up to bucket capacity)
   - Smooth sustained rate
   - Simple to implement
   - Efficient in Redis

3. Implementation Strategy:

┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│  API Server │         │  API Server │         │  API Server │
│     #1      │         │     #2      │         │     #100    │
└──────┬──────┘         └──────┬──────┘         └──────┬──────┘
       │                       │                        │
       │                       │                        │
       └───────────────────────┼────────────────────────┘
                               │
                               ▼
                    ┌──────────────────┐
                    │   Redis Cluster   │
                    │  (Token Buckets)  │
                    └──────────────────┘
```

**Java Implementation:**

```java
@Service
public class HighPerformanceRateLimiter {
    
    private static final String RATE_LIMIT_SCRIPT =
        "local key = KEYS[1]\n" +
        "local max_tokens = tonumber(ARGV[1])\n" +
        "local refill_rate = tonumber(ARGV[2])\n" +
        "local now = tonumber(ARGV[3])\n" +
        "local requested = tonumber(ARGV[4])\n" +
        "\n" +
        "local state = redis.call('HMGET', key, 'tokens', 'last_update')\n" +
        "local tokens = tonumber(state[1]) or max_tokens\n" +
        "local last_update = tonumber(state[2]) or now\n" +
        "\n" +
        "-- Refill tokens based on time passed\n" +
        "local elapsed = math.max(0, now - last_update)\n" +
        "local new_tokens = math.min(max_tokens, tokens + (elapsed * refill_rate))\n" +
        "\n" +
        "if new_tokens >= requested then\n" +
        "    new_tokens = new_tokens - requested\n" +
        "    redis.call('HMSET', key, 'tokens', new_tokens, 'last_update', now)\n" +
        "    redis.call('EXPIRE', key, 120)\n" +
        "    return {1, new_tokens}\n" +
        "else\n" +
        "    return {0, new_tokens}\n" +
        "end";
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    private RedisScript<List> compiledScript;
    
    @PostConstruct
    public void init() {
        this.compiledScript = RedisScript.of(RATE_LIMIT_SCRIPT, List.class);
    }
    
    /**
     * High-performance rate limit check
     * Target: < 5ms latency
     */
    public boolean isAllowed(String userId, int requestCost) {
        long startTime = System.nanoTime();
        
        try {
            String key = "rl:" + userId;
            long now = System.currentTimeMillis();
            
            // Configuration: 1000 requests per 60 seconds
            int maxTokens = 1000;
            double refillRate = 1000.0 / 60.0;  // ~16.67 tokens per second
            
            // Execute Lua script atomically
            List<Long> result = (List<Long>) redisTemplate.execute(
                compiledScript,
                Collections.singletonList(key),
                String.valueOf(maxTokens),
                String.valueOf(refillRate),
                String.valueOf(now),
                String.valueOf(requestCost)
            );
            
            return result.get(0) == 1;
            
        } finally {
            long duration = System.nanoTime() - startTime;
            metricsService.recordLatency("rate_limit_check", duration / 1_000_000.0);
        }
    }
    
    /**
     * Batch check for better performance
     * Use when processing multiple users in one request
     */
    public Map<String, Boolean> isAllowedBatch(Set<String> userIds, int requestCost) {
        // Pipeline all checks together
        List<Object> results = redisTemplate.executePipelined(
            (RedisCallback<Object>) connection -> {
                for (String userId : userIds) {
                    String key = "rl:" + userId;
                    // Execute script for each user
                    redisTemplate.execute(
                        compiledScript,
                        Collections.singletonList(key),
                        "1000", "16.67", 
                        String.valueOf(System.currentTimeMillis()),
                        String.valueOf(requestCost)
                    );
                }
                return null;
            }
        );
        
        // Parse results
        Map<String, Boolean> resultMap = new HashMap<>();
        int i = 0;
        for (String userId : userIds) {
            List<Long> result = (List<Long>) results.get(i++);
            resultMap.put(userId, result.get(0) == 1);
        }
        
        return resultMap;
    }
}
```

**Performance Optimizations:**

1. **Connection Pooling:**
```java
@Configuration
public class RedisConfig {
    
    @Bean
    public LettuceConnectionFactory redisConnectionFactory() {
        GenericObjectPoolConfig poolConfig = new GenericObjectPoolConfig();
        poolConfig.setMaxTotal(200);      // Max connections
        poolConfig.setMaxIdle(50);        // Idle connections
        poolConfig.setMinIdle(10);        // Min idle
        poolConfig.setTestOnBorrow(true);
        
        LettucePoolingClientConfiguration clientConfig = 
            LettucePoolingClientConfiguration.builder()
                .commandTimeout(Duration.ofMilliseconds(100))
                .poolConfig(poolConfig)
                .build();
        
        RedisStandaloneConfiguration serverConfig = 
            new RedisStandaloneConfiguration("redis-cluster.internal", 6379);
        
        return new LettuceConnectionFactory(serverConfig, clientConfig);
    }
}
```

2. **Local Caching (Negative Cache):**
```java
// Cache denials locally to reduce Redis load
private LoadingCache<String, Boolean> denialCache = CacheBuilder.newBuilder()
    .expireAfterWrite(1, TimeUnit.SECONDS)
    .maximumSize(10000)
    .build(new CacheLoader<String, Boolean>() {
        public Boolean load(String key) {
            return false;  // Not cached
        }
    });

public boolean isAllowedWithCache(String userId) {
    // If recently denied, fail fast without Redis call
    if (denialCache.getIfPresent(userId) != null) {
        return false;
    }
    
    boolean allowed = isAllowed(userId, 1);
    
    if (!allowed) {
        denialCache.put(userId, true);
    }
    
    return allowed;
}
```

3. **Metrics and Monitoring:**
```java
@Component
public class RateLimiterMetrics {
    
    @Autowired
    private MeterRegistry meterRegistry;
    
    public void recordRateLimitCheck(String userId, boolean allowed, long latencyMs) {
        Counter.builder("rate_limit.checks")
            .tag("allowed", String.valueOf(allowed))
            .register(meterRegistry)
            .increment();
        
        DistributionSummary.builder("rate_limit.latency")
            .baseUnit("milliseconds")
            .register(meterRegistry)
            .record(latencyMs);
        
        if (!allowed) {
            Counter.builder("rate_limit.denials")
                .tag("user_id", userId)
                .register(meterRegistry)
                .increment();
        }
    }
}
```

### Question 2: How do you handle API key rotation without downtime?

**Answer:**

```
Strategy: Dual Key System with Grace Period

Phase 1: Issue New Key
├── User requests key rotation
├── System generates new key (key_v2)
├── Old key (key_v1) remains valid
└── Response: "New key issued. Old key valid for 7 days"

Phase 2: Grace Period (7 days)
├── Both key_v1 and key_v2 work
├── System tracks usage of both
├── Alerts sent if key_v1 still in use after day 5
└── Gradual migration

Phase 3: Deprecation
├── key_v1 stops working after 7 days
├── Only key_v2 accepted
└── Audit log of final key_v1 usage
```

**Implementation:**

```java
@Service
public class ApiKeyRotationService {
    
    @Autowired
    private ApiKeyRepository keyRepo;
    
    /**
     * Rotate API key with grace period
     */
    @Transactional
    public KeyRotationResult rotateKey(String userId, String oldKeyValue) {
        // 1. Validate old key
        ApiKey oldKey = keyRepo.findByKeyValue(oldKeyValue);
        if (oldKey == null || !oldKey.getUserId().equals(userId)) {
            throw new UnauthorizedException("Invalid API key");
        }
        
        // 2. Generate new key
        String newKeyValue = generateSecureKey();
        ApiKey newKey = new ApiKey();
        newKey.setKeyValue(newKeyValue);
        newKey.setUserId(userId);
        newKey.setStatus(KeyStatus.ACTIVE);
        newKey.setCreatedAt(Instant.now());
        newKey.setScopes(oldKey.getScopes());  // Copy permissions
        keyRepo.save(newKey);
        
        // 3. Mark old key as rotating (not deleted yet)
        oldKey.setStatus(KeyStatus.ROTATING);
        oldKey.setRotationStartedAt(Instant.now());
        oldKey.setRotationDeadline(Instant.now().plus(7, ChronoUnit.DAYS));
        oldKey.setReplacedByKeyId(newKey.getId());
        keyRepo.save(oldKey);
        
        // 4. Send notification
        notificationService.send(userId, 
            "API key rotation started",
            "Your old key will expire in 7 days. Please update to new key."
        );
        
        // 5. Schedule deprecation job
        deprecationScheduler.scheduleKeyDeprecation(oldKey.getId(), 7);
        
        return new KeyRotationResult(newKeyValue, oldKeyValue, 7);
    }
    
    /**
     * Check if key is valid (handles grace period)
     */
    public KeyValidationResult validateKey(String keyValue) {
        ApiKey key = keyRepo.findByKeyValue(keyValue);
        
        if (key == null) {
            return KeyValidationResult.invalid("Key not found");
        }
        
        switch (key.getStatus()) {
            case ACTIVE:
                return KeyValidationResult.valid(key);
                
            case ROTATING:
                // Still valid but warn user
                long daysRemaining = ChronoUnit.DAYS.between(
                    Instant.now(),
                    key.getRotationDeadline()
                );
                
                if (daysRemaining <= 0) {
                    // Grace period expired
                    return KeyValidationResult.invalid("Key has expired. Please use new key.");
                }
                
                // Log usage of rotating key
                auditLog.warn(
                    "Rotating key still in use",
                    "user_id", key.getUserId(),
                    "key_id", key.getId(),
                    "days_remaining", daysRemaining
                );
                
                return KeyValidationResult.validWithWarning(
                    key,
                    "This key will expire in " + daysRemaining + " days"
                );
                
            case DEPRECATED:
                return KeyValidationResult.invalid("Key has been deprecated");
                
            case REVOKED:
                return KeyValidationResult.invalid("Key has been revoked");
                
            default:
                return KeyValidationResult.invalid("Invalid key status");
        }
    }
    
    /**
     * Background job: Deprecate keys after grace period
     */
    @Scheduled(cron = "0 0 * * * *")  // Every hour
    public void deprecateExpiredKeys() {
        List<ApiKey> expiredKeys = keyRepo.findExpiredRotatingKeys(Instant.now());
        
        for (ApiKey key : expiredKeys) {
            key.setStatus(KeyStatus.DEPRECATED);
            keyRepo.save(key);
            
            // Notify user
            notificationService.send(
                key.getUserId(),
                "API key has expired",
                "Your old API key has been deprecated. Please ensure you're using the new key."
            );
            
            // Alert if still being used
            if (hasRecentUsage(key, Duration.ofHours(24))) {
                alertService.send(
                    AlertLevel.HIGH,
                    "Deprecated key still in use: " + key.getId(),
                    "User: " + key.getUserId()
                );
            }
        }
    }
}
```

**Database Schema:**

```sql
CREATE TABLE api_keys (
    id BIGINT PRIMARY KEY,
    key_value VARCHAR(64) UNIQUE NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    status ENUM('active', 'rotating', 'deprecated', 'revoked'),
    created_at TIMESTAMP NOT NULL,
    
    -- Rotation fields
    rotation_started_at TIMESTAMP NULL,
    rotation_deadline TIMESTAMP NULL,
    replaced_by_key_id BIGINT NULL,
    
    -- Tracking
    last_used_at TIMESTAMP NULL,
    usage_count BIGINT DEFAULT 0,
    
    INDEX idx_user (user_id),
    INDEX idx_status (status),
    INDEX idx_rotation_deadline (rotation_deadline),
    FOREIGN KEY (replaced_by_key_id) REFERENCES api_keys(id)
);
```

---

## Common Pitfalls and Solutions

### Pitfall 1: Storing API Keys in Plain Text

**❌ Wrong:**
```java
@Entity
public class ApiKey {
    private String keyValue;  // Stored as-is in database
}
```

**✅ Correct:**
```java
@Entity
public class ApiKey {
    // Store hash only
    private String keyHash;
    
    // Show key only once at creation
    public String generateAndReturnKey() {
        String key = generateSecureRandom();
        this.keyHash = hash(key);
        return key;  // Return once, never again
    }
    
    public boolean matches(String providedKey) {
        return hash(providedKey).equals(this.keyHash);
    }
    
    private String hash(String key) {
        return BCrypt.hashpw(key, BCrypt.gensalt(12));
    }
}
```

### Pitfall 2: Rate Limiting Only at Application Layer

**❌ Wrong:**
```
Internet → Load Balancer → App Servers (rate limiting) → Database
```
Problem: DDoS attacks overwhelm load balancer before reaching rate limiter

**✅ Correct:**
```
Internet → WAF (rate limit) → Load Balancer → App (rate limit) → DB
         Layer 1: 10k/sec    Layer 2: 1k/sec per user
```

### Pitfall 3: Not Handling Clock Skew in Distributed Systems

**❌ Wrong:**
```java
// Uses local server time
long now = System.currentTimeMillis();
```

Problem: Different servers have different clocks, causing inconsistent rate limiting

**✅ Correct:**
```java
// Use Redis server time
long now = redisTemplate.execute((RedisCallback<Long>) connection -> 
    connection.time()
);
```

### Pitfall 4: No Monitoring or Alerts

Add comprehensive monitoring:

```java
@Component
public class RateLimiterMonitoring {
    
    @Autowired
    private MeterRegistry registry;
    
    @EventListener
    public void onRateLimitExceeded(RateLimitExceededEvent event) {
        // Track which users are being rate limited
        Counter.builder("rate_limit.exceeded")
            .tag("user_id", event.getUserId())
            .tag("endpoint", event.getEndpoint())
            .register(registry)
            .increment();
        
        // Alert if same user exceeds limit frequently
        long recentViolations = getViolationCount(event.getUserId(), Duration.ofMinutes(5));
        if (recentViolations > 10) {
            alertService.send(
                "Potential abuse detected",
                "User " + event.getUserId() + " exceeded rate limit " + recentViolations + " times"
            );
        }
    }
}
```

---

[Continue to next topic: S5 - HTTPS/TLS/SSL...]


---

# S5: HTTPS/TLS/SSL

## 🔒 The Envelope Analogy

Imagine sending a letter through the mail:

**HTTP (No Encryption):**
- You write your credit card number on a postcard
- Everyone who handles the postcard can read it
- Mailman, sorting facility workers, neighbors - all can see it
- Anyone can modify the message
- No way to verify it's really from you

**HTTPS (Encrypted):**
- You write your credit card in a letter
- Seal it in a tamper-evident envelope
- Only the recipient can open and read it
- Anyone who tampers with it leaves evidence
- Envelope has your authentic signature

This is what TLS/SSL does for web traffic!

---

## Beginner Level: What is HTTPS?

### HTTP vs HTTPS

**HTTP (HyperText Transfer Protocol):**
```
Browser                          Server
   |                               |
   |  GET /api/user?id=123        |
   |----------------------------->|
   |                               |
   |  Response: User data          |
   |<-----------------------------|
```
Problem: Everyone between browser and server can see and modify this!

**HTTPS (HTTP Secure):**
```
Browser                          Server
   |                               |
   |  Establish encrypted tunnel   |
   |<========TLS Handshake========>|
   |                               |
   |  🔒 Encrypted Request          |
   |----------------------------->|
   |                               |
   |  🔒 Encrypted Response         |
   |<-----------------------------|
```
All data is encrypted - attackers see only gibberish!

### What TLS/SSL Provides

1. **Confidentiality**: Data cannot be read by third parties
2. **Integrity**: Data cannot be modified without detection
3. **Authentication**: Verify you're talking to the real server (not imposter)

### The Padlock in Your Browser

When you see `https://` and a padlock:
- ✅ Connection is encrypted
- ✅ Server identity is verified by Certificate Authority
- ✅ Data integrity is guaranteed

---

## Intermediate Level: How TLS Works

### The TLS Handshake (Simplified)

```
CLIENT                                    SERVER
  |                                         |
  | 1. ClientHello                          |
  |   "I support TLS 1.3, AES-256, etc"    |
  |---------------------------------------->|
  |                                         |
  | 2. ServerHello                          |
  |   "Let's use TLS 1.3 with AES-256"     |
  |<----------------------------------------|
  |                                         |
  | 3. Server Certificate                   |
  |   [Contains public key + CA signature]  |
  |<----------------------------------------|
  |                                         |
  | 4. Client verifies certificate:         |
  |    - Is it signed by trusted CA?        |
  |    - Is domain name correct?            |
  |    - Is it not expired?                 |
  |                                         |
  | 5. Client generates session key         |
  |    Encrypts with server's public key    |
  |---------------------------------------->|
  |                                         |
  | 6. Both now have same session key       |
  |    All future messages encrypted        |
  |<======== Secure Channel ===============>|
```

### Asymmetric vs Symmetric Encryption

**Asymmetric (Public Key Crypto):**
- Used for handshake only
- Public key (known to everyone) + Private key (secret)
- Encrypt with public key → Decrypt with private key
- Slow but enables key exchange
- Algorithms: RSA, ECDSA

**Symmetric (Session Encryption):**
- Used for actual data transfer
- Same key for encryption and decryption
- Fast and efficient
- Algorithms: AES-256, ChaCha20

### SSL/TLS Versions

```
History:
SSL 1.0 (1994) - Never released (too many flaws)
SSL 2.0 (1995) - Deprecated (insecure)
SSL 3.0 (1996) - Deprecated (POODLE attack)
TLS 1.0 (1999) - Deprecated (weak ciphers)
TLS 1.1 (2006) - Deprecated
TLS 1.2 (2008) - Still widely used ✓
TLS 1.3 (2018) - Current standard ✓✓

Modern systems should ONLY support TLS 1.2 and TLS 1.3
```

---

## Advanced Level: Production Implementation

### Java TLS Configuration

```java
// SSLConfig.java
@Configuration
public class SSLConfig {
    
    /**
     * Configure embedded Tomcat for HTTPS
     */
    @Bean
    public TomcatServletWebServerFactory servletContainer() {
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory() {
            @Override
            protected void postProcessContext(Context context) {
                SecurityConstraint securityConstraint = new SecurityConstraint();
                securityConstraint.setUserConstraint("CONFIDENTIAL");
                SecurityCollection collection = new SecurityCollection();
                collection.addPattern("/*");
                securityConstraint.addCollection(collection);
                context.addConstraint(securityConstraint);
            }
        };
        
        tomcat.addAdditionalTomcatConnectors(redirectConnector());
        return tomcat;
    }
    
    /**
     * Redirect HTTP to HTTPS
     */
    private Connector redirectConnector() {
        Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
        connector.setScheme("http");
        connector.setPort(8080);
        connector.setSecure(false);
        connector.setRedirectPort(8443);
        return connector;
    }
}

// application.yml
server:
  port: 8443
  ssl:
    enabled: true
    key-store: classpath:keystore.p12
    key-store-password: ${SSL_KEYSTORE_PASSWORD}
    key-store-type: PKCS12
    key-alias: tomcat
    
    # Force TLS 1.2 and 1.3 only
    enabled-protocols: TLSv1.2,TLSv1.3
    
    # Strong cipher suites only
    ciphers: >
      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      TLS_AES_256_GCM_SHA384,
      TLS_AES_128_GCM_SHA256
```

### Certificate Management

```java
@Service
public class CertificateManager {
    
    /**
     * Load SSL certificate and validate
     */
    public SSLContext createSSLContext() throws Exception {
        // Load keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream keystoreStream = getClass()
                .getResourceAsStream("/keystore.p12")) {
            keyStore.load(keystoreStream, 
                getKeystorePassword().toCharArray());
        }
        
        // Initialize key manager
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm()
        );
        kmf.init(keyStore, getKeyPassword().toCharArray());
        
        // Initialize trust manager
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm()
        );
        tmf.init(keyStore);
        
        // Create SSL context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(
            kmf.getKeyManagers(),
            tmf.getTrustManagers(),
            new SecureRandom()
        );
        
        return sslContext;
    }
    
    /**
     * Validate certificate expiration
     * Run this daily to get early warning
     */
    @Scheduled(cron = "0 0 9 * * *")  // Every day at 9 AM
    public void checkCertificateExpiration() {
        try {
            KeyStore keyStore = loadKeyStore();
            String alias = "tomcat";
            
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            Date expiry = cert.getNotAfter();
            long daysUntilExpiry = ChronoUnit.DAYS.between(
                Instant.now(),
                expiry.toInstant()
            );
            
            if (daysUntilExpiry <= 0) {
                alertService.critical(
                    "SSL certificate has EXPIRED!",
                    "Immediate action required"
                );
            } else if (daysUntilExpiry <= 7) {
                alertService.high(
                    "SSL certificate expires in " + daysUntilExpiry + " days",
                    "Renew immediately"
                );
            } else if (daysUntilExpiry <= 30) {
                alertService.medium(
                    "SSL certificate expires in " + daysUntilExpiry + " days",
                    "Plan renewal"
                );
            }
            
        } catch (Exception e) {
            alertService.critical(
                "Failed to check SSL certificate",
                "Exception: " + e.getMessage()
            );
        }
    }
}
```

### Client-Side TLS Configuration

```java
@Configuration
public class HttpClientConfig {
    
    /**
     * HTTP client with TLS configuration
     * For making external API calls
     */
    @Bean
    public CloseableHttpClient httpClient() throws Exception {
        // Create SSL context with custom trust store
        SSLContext sslContext = SSLContextBuilder.create()
            .loadTrustMaterial(
                getTrustStore(),
                new TrustSelfSignedStrategy()  // Only for dev!
            )
            .build();
        
        // Configure SSL/TLS
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
            sslContext,
            new String[] { "TLSv1.2", "TLSv1.3" },  // Protocols
            null,  // Cipher suites (use defaults)
            SSLConnectionSocketFactory.getDefaultHostnameVerifier()
        );
        
        // Build HTTP client
        return HttpClients.custom()
            .setSSLSocketFactory(sslsf)
            .setDefaultRequestConfig(
                RequestConfig.custom()
                    .setConnectTimeout(5000)
                    .setSocketTimeout(5000)
                    .build()
            )
            .build();
    }
    
    /**
     * Make HTTPS request with certificate pinning
     */
    public String makeSecureRequest(String url) throws Exception {
        HttpGet request = new HttpGet(url);
        
        try (CloseableHttpResponse response = httpClient().execute(request)) {
            // Verify certificate
            SSLSession sslSession = getSSLSession(response);
            verifyCertificate(sslSession);
            
            // Read response
            return EntityUtils.toString(response.getEntity());
        }
    }
    
    /**
     * Certificate pinning for extra security
     * Prevents MITM even with compromised CA
     */
    private void verifyCertificate(SSLSession session) throws CertificateException {
        Certificate[] peerCerts = session.getPeerCertificates();
        X509Certificate cert = (X509Certificate) peerCerts[0];
        
        // Calculate certificate fingerprint
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        String fingerprint = DatatypeConverter.printHexBinary(digest);
        
        // Compare with pinned fingerprint
        String expectedFingerprint = getExpectedFingerprint(session.getPeerHost());
        
        if (!fingerprint.equals(expectedFingerprint)) {
            throw new CertificateException(
                "Certificate fingerprint mismatch! " +
                "Expected: " + expectedFingerprint + " " +
                "Got: " + fingerprint
            );
        }
    }
}
```

---

## Real FAANG Examples

### Example 1: Google's HTTPS Everywhere Initiative

Google enforces HTTPS across all services:

**Chrome Browser Warnings:**
```
Non-HTTPS site → "Not Secure" warning in address bar
Mixed content (HTTPS page loading HTTP resources) → Blocked
HTTP-only cookies → Not sent
```

**Implementation Requirements:**
```
1. TLS 1.2+ only
2. Perfect Forward Secrecy (PFS) enabled
3. Strong cipher suites
4. HSTS enabled (HTTP Strict Transport Security)
5. Certificate Transparency logs
```

**Java Implementation - HSTS:**

```java
@Component
public class SecurityHeadersFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, 
                        FilterChain chain) throws IOException, ServletException {
        
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        // HSTS: Force HTTPS for 1 year
        httpResponse.setHeader(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload"
        );
        
        // Prevent clickjacking
        httpResponse.setHeader("X-Frame-Options", "DENY");
        
        // Prevent MIME sniffing
        httpResponse.setHeader("X-Content-Type-Options", "nosniff");
        
        // XSS protection
        httpResponse.setHeader("X-XSS-Protection", "1; mode=block");
        
        // Content Security Policy
        httpResponse.setHeader(
            "Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self' data:; " +
            "connect-src 'self'"
        );
        
        chain.doFilter(request, response);
    }
}
```

### Example 2: Facebook's Certificate Pinning

Meta implements certificate pinning in mobile apps:

```java
/**
 * Facebook-style certificate pinning
 * Prevents MITM attacks even with compromised CAs
 */
@Configuration
public class FacebookStylePinning {
    
    // SHA-256 hashes of expected certificates
    private static final Set<String> PINNED_CERTIFICATES = Set.of(
        "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",  // Primary cert
        "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",  // Backup cert
        "sha256/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="   // CA cert
    );
    
    @Bean
    public OkHttpClient secureClient() {
        CertificatePinner pinner = new CertificatePinner.Builder()
            .add("*.facebook.com", PINNED_CERTIFICATES.toArray(new String[0]))
            .add("*.fbcdn.net", PINNED_CERTIFICATES.toArray(new String[0]))
            .build();
        
        return new OkHttpClient.Builder()
            .certificatePinner(pinner)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build();
    }
    
    /**
     * Fallback mechanism if pinned cert changes
     */
    public Response makeRequestWithFallback(String url) {
        try {
            // Try with certificate pinning first
            return secureClient().newCall(
                new Request.Builder().url(url).build()
            ).execute();
            
        } catch (SSLPeerUnverifiedException e) {
            // Certificate doesn't match pins
            log.error("Certificate pinning failed for: " + url);
            
            // Alert security team
            securityAlerts.send(
                "Certificate pinning failure",
                "URL: " + url + ", Error: " + e.getMessage()
            );
            
            // Fallback to normal TLS validation
            // (Only in non-critical scenarios)
            return standardClient().newCall(
                new Request.Builder().url(url).build()
            ).execute();
        }
    }
}
```

### Example 3: Netflix's TLS Optimization

Netflix optimizes TLS for streaming performance:

**Optimizations:**
1. **Session Resumption**: Reuse TLS sessions to avoid handshake overhead
2. **OCSP Stapling**: Server provides certificate revocation status
3. **TLS False Start**: Start sending data during handshake
4. **Zero Round Trip Time (0-RTT)**: TLS 1.3 feature for returning clients

```java
@Configuration
public class NetflixStyleTLSOptimization {
    
    /**
     * Configure TLS with performance optimizations
     */
    @Bean
    public SSLContext optimizedSSLContext() throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        
        // Enable session caching
        SSLSessionContext sessionContext = context.getServerSessionContext();
        sessionContext.setSessionCacheSize(10000);  // Cache 10k sessions
        sessionContext.setSessionTimeout(86400);     // 24 hour timeout
        
        context.init(
            getKeyManagers(),
            getTrustManagers(),
            new SecureRandom()
        );
        
        return context;
    }
    
    /**
     * Track TLS handshake performance
     */
    @Component
    public class TLSPerformanceMonitor {
        
        @Autowired
        private MeterRegistry registry;
        
        public void recordHandshake(boolean sessionResumed, long durationMs) {
            Timer.builder("tls.handshake")
                .tag("resumed", String.valueOf(sessionResumed))
                .register(registry)
                .record(durationMs, TimeUnit.MILLISECONDS);
            
            // Track session resumption rate
            Counter.builder("tls.session")
                .tag("type", sessionResumed ? "resumed" : "full")
                .register(registry)
                .increment();
        }
    }
}
```

### Example 4: AWS Certificate Manager Integration

AWS provides managed SSL/TLS certificates:

```java
@Service
public class AWSCertificateService {
    
    @Autowired
    private AWSCertificateManager acmClient;
    
    /**
     * Request new certificate from AWS ACM
     */
    public String requestCertificate(String domainName, List<String> subjectAltNames) {
        RequestCertificateRequest request = new RequestCertificateRequest()
            .withDomainName(domainName)
            .withSubjectAlternativeNames(subjectAltNames)
            .withValidationMethod(ValidationMethod.DNS)  // DNS validation
            .withOptions(new CertificateOptions()
                .withCertificateTransparencyLoggingPreference(
                    CertificateTransparencyLoggingPreference.ENABLED
                ));
        
        RequestCertificateResult result = acmClient.requestCertificate(request);
        String certificateArn = result.getCertificateArn();
        
        log.info("Requested certificate: " + certificateArn);
        
        // Get DNS validation records
        DescribeCertificateRequest describeRequest = 
            new DescribeCertificateRequest()
                .withCertificateArn(certificateArn);
        
        DescribeCertificateResult describeResult = 
            acmClient.describeCertificate(describeRequest);
        
        // Return DNS records for domain validation
        List<ResourceRecord> validationRecords = describeResult
            .getCertificate()
            .getDomainValidationOptions()
            .stream()
            .map(DomainValidation::getResourceRecord)
            .collect(Collectors.toList());
        
        // User must add these records to DNS
        for (ResourceRecord record : validationRecords) {
            log.info("Add DNS record: " + 
                record.getName() + " " + 
                record.getType() + " " + 
                record.getValue());
        }
        
        return certificateArn;
    }
    
    /**
     * Monitor certificate expiration
     */
    @Scheduled(cron = "0 0 0 * * *")  // Daily
    public void checkCertificates() {
        ListCertificatesResult result = acmClient.listCertificates(
            new ListCertificatesRequest()
        );
        
        for (CertificateSummary cert : result.getCertificateSummaryList()) {
            DescribeCertificateResult details = acmClient.describeCertificate(
                new DescribeCertificateRequest()
                    .withCertificateArn(cert.getCertificateArn())
            );
            
            Certificate certificate = details.getCertificate();
            Date notAfter = certificate.getNotAfter();
            
            long daysUntilExpiry = ChronoUnit.DAYS.between(
                Instant.now(),
                notAfter.toInstant()
            );
            
            if (daysUntilExpiry <= 30) {
                // ACM auto-renews, but alert if renewal fails
                if (!"ISSUED".equals(certificate.getStatus())) {
                    alertService.send(
                        "Certificate renewal issue",
                        "ARN: " + cert.getCertificateArn() + 
                        ", Status: " + certificate.getStatus()
                    );
                }
            }
        }
    }
}
```

---

## Interview Question: Design HTTPS for a Global CDN

**Question:** Design the TLS/SSL architecture for a global CDN serving millions of requests per second across 200 edge locations.

**Requirements:**
- Support custom SSL certificates for customer domains
- Minimize TLS handshake latency
- Handle certificate renewals without downtime
- Protect against SSL/TLS attacks

**Answer:**

```
Architecture:

┌─────────────────────────────────────────────────────────┐
│                    CLIENT (Browser)                      │
└────────────────────┬────────────────────────────────────┘
                     │ TLS Handshake
                     ▼
┌─────────────────────────────────────────────────────────┐
│                    EDGE LOCATION                         │
│  ┌────────────────────────────────────────────────┐    │
│  │  TLS Termination Layer                         │    │
│  │  - Certificate selection based on SNI          │    │
│  │  - Session cache (Redis)                       │    │
│  │  - OCSP stapling                                │    │
│  │  - TLS 1.3 with 0-RTT                          │    │
│  └────────────────────────────────────────────────┘    │
│                        │                                 │
│  ┌────────────────────▼────────────────────────────┐   │
│  │  Edge Cache                                      │   │
│  │  - Encrypted content cache                       │   │
│  │  - Hit rate: 95%+                                │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────┘
                      │ Cache miss
                      ▼
┌─────────────────────────────────────────────────────────┐
│                ORIGIN SERVERS                            │
│  - mTLS between edge and origin                         │
│  - Certificate management system                         │
│  - Automated renewal                                     │
└─────────────────────────────────────────────────────────┘
```

**Implementation Details:**

1. **SNI (Server Name Indication) Routing:**
```java
@Component
public class SNIHandler {
    
    @Autowired
    private CertificateStore certStore;
    
    /**
     * Select certificate based on SNI hostname
     */
    public SSLEngine createSSLEngine(String hostname) {
        SSLContext context = certStore.getSSLContext(hostname);
        SSLEngine engine = context.createSSLEngine();
        
        // Configure for server mode
        engine.setUseClientMode(false);
        
        // Enable TLS 1.2 and 1.3
        engine.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
        
        // Strong ciphers only
        engine.setEnabledCipherSuites(getStrongCiphers());
        
        return engine;
    }
}
```

2. **Session Caching with Redis:**
```java
@Component
public class TLSSessionCache {
    
    @Autowired
    private RedisTemplate<String, byte[]> redis;
    
    private static final String CACHE_PREFIX = "tls:session:";
    private static final int CACHE_TTL_SECONDS = 86400;  // 24 hours
    
    /**
     * Store TLS session for resumption
     */
    public void storeSession(String sessionId, byte[] sessionData) {
        redis.opsForValue().set(
            CACHE_PREFIX + sessionId,
            sessionData,
            CACHE_TTL_SECONDS,
            TimeUnit.SECONDS
        );
    }
    
    /**
     * Retrieve session for resumption
     */
    public byte[] getSession(String sessionId) {
        return redis.opsForValue().get(CACHE_PREFIX + sessionId);
    }
    
    /**
     * Custom SSLSessionContext backed by Redis
     */
    public class RedisSSLSessionContext implements SSLSessionContext {
        
        @Override
        public SSLSession getSession(byte[] sessionId) {
            String id = Base64.getEncoder().encodeToString(sessionId);
            byte[] data = TLSSessionCache.this.getSession(id);
            
            if (data != null) {
                // Deserialize session
                return deserializeSession(data);
            }
            
            return null;
        }
        
        @Override
        public void setSessionTimeout(int seconds) {
            // Handled by Redis TTL
        }
        
        @Override
        public int getSessionTimeout() {
            return CACHE_TTL_SECONDS;
        }
    }
}
```

3. **Automated Certificate Management:**
```java
@Service
public class CertificateLifecycleManager {
    
    @Autowired
    private LetsEncryptClient acmeClient;
    
    @Autowired
    private CertificateStore certStore;
    
    /**
     * Automatically renew certificates 30 days before expiry
     */
    @Scheduled(cron = "0 0 2 * * *")  // Daily at 2 AM
    public void checkAndRenewCertificates() {
        List<Certificate> certificates = certStore.getAllCertificates();
        
        for (Certificate cert : certificates) {
            if (needsRenewal(cert)) {
                renewCertificate(cert);
            }
        }
    }
    
    private boolean needsRenewal(Certificate cert) {
        long daysUntilExpiry = ChronoUnit.DAYS.between(
            Instant.now(),
            cert.getExpiryDate().toInstant()
        );
        return daysUntilExpiry <= 30;
    }
    
    /**
     * Renew certificate using ACME protocol (Let's Encrypt)
     */
    private void renewCertificate(Certificate oldCert) {
        try {
            log.info("Renewing certificate for: " + oldCert.getDomain());
            
            // 1. Request new certificate
            Certificate newCert = acmeClient.requestCertificate(
                oldCert.getDomain(),
                oldCert.getSubjectAltNames()
            );
            
            // 2. Complete domain validation (DNS-01 challenge)
            completeDNSChallenge(newCert);
            
            // 3. Wait for certificate issuance
            newCert = acmeClient.pollForCertificate(newCert.getOrderId());
            
            // 4. Install new certificate (hot reload)
            certStore.addCertificate(newCert);
            
            // 5. Keep old cert active for grace period
            // (Handle in-flight connections)
            scheduler.schedule(
                () -> certStore.removeCertificate(oldCert),
                1,
                TimeUnit.HOURS
            );
            
            log.info("Certificate renewed successfully: " + oldCert.getDomain());
            
        } catch (Exception e) {
            log.error("Failed to renew certificate: " + oldCert.getDomain(), e);
            alertService.critical(
                "Certificate renewal failed",
                "Domain: " + oldCert.getDomain() + 
                ", Error: " + e.getMessage()
            );
        }
    }
}
```

4. **OCSP Stapling:**
```java
@Component
public class OCSPStapler {
    
    /**
     * Fetch and cache OCSP response
     * Reduces client latency by including revocation status
     */
    public byte[] getOCSPResponse(X509Certificate cert) throws Exception {
        // Get OCSP responder URL from certificate
        String ocspUrl = getOCSPUrl(cert);
        if (ocspUrl == null) {
            return null;
        }
        
        // Build OCSP request
        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
        CertificateID certId = new CertificateID(
            new JcaDigestCalculatorProviderBuilder().build()
                .get(CertificateID.HASH_SHA1),
            new JcaX509CertificateHolder(getIssuerCert(cert)),
            cert.getSerialNumber()
        );
        reqBuilder.addRequest(certId);
        OCSPReq request = reqBuilder.build();
        
        // Send request to OCSP responder
        byte[] requestBytes = request.getEncoded();
        HttpPost httpPost = new HttpPost(ocspUrl);
        httpPost.setHeader("Content-Type", "application/ocsp-request");
        httpPost.setEntity(new ByteArrayEntity(requestBytes));
        
        HttpResponse response = httpClient.execute(httpPost);
        byte[] responseBytes = EntityUtils.toByteArray(response.getEntity());
        
        // Cache OCSP response (typically valid for 7 days)
        cacheOCSPResponse(cert.getSerialNumber(), responseBytes, 7);
        
        return responseBytes;
    }
}
```

**Performance Results:**

```
Without optimization:
- Full TLS handshake: 2 round trips = 200ms (100ms RTT)
- Total time to first byte: 200ms + data transfer

With optimization:
- Session resumption: 1 round trip = 100ms
- TLS 1.3 0-RTT: 0 round trips = 0ms (for returning clients)
- OCSP stapling: Saves 1 round trip to CA
- Total time to first byte: 0-100ms + data transfer

Performance gain: 50-100% reduction in latency
```

---

[Continue to next topic: S6 - Encryption...]


# S6: Encryption (At-rest vs In-transit)

## 🏦 The Bank Vault Analogy

Imagine a bank protecting your money:

**Encryption In-Transit (Armored Truck):**
- Money being transported from Branch A to Branch B
- Placed in an armored truck with armed guards
- If robbers attack the truck, money is in a locked safe inside
- Even if they steal the truck, they can't open the safe
- This is like HTTPS - data encrypted while moving across the network

**Encryption At-Rest (Bank Vault):**
- Money stored in the bank's vault
- Multiple layers of physical security
- Even if burglar enters the building, vault is locked
- Need combination + biometrics to open
- This is like database encryption - data encrypted while stored

**Why Both Matter:**
- In-transit: Protects against network eavesdropping
- At-rest: Protects against disk theft, database dumps, backup leaks

---

## Beginner Level: Understanding Encryption

### What is Encryption?

Encryption transforms readable data (plaintext) into unreadable data (ciphertext) using a key.

**Simple Example:**

```
Plaintext:  "user_password: MySecret123"
                    ↓ [Encrypt with key]
Ciphertext: "kJ9#mL2$pQ8@nR4%tY6"
                    ↓ [Decrypt with key]
Plaintext:  "user_password: MySecret123"
```

Without the key, ciphertext is useless random data.

### Encryption In-Transit

Protects data as it moves between:
- Client ↔ Server (user's browser to your API)
- Service ↔ Service (your API to database)
- Service ↔ External API (your system to payment processor)

**Technologies:**
- HTTPS/TLS (web traffic)
- SSH (secure shell)
- VPN (network layer)
- mTLS (service-to-service)

### Encryption At-Rest

Protects data when stored on:
- Hard drives / SSDs
- Database files
- Backups
- Cloud storage (S3, etc.)
- Log files

**Technologies:**
- Database encryption (MySQL, PostgreSQL TDE)
- File system encryption (LUKS, BitLocker)
- Application-level encryption (encrypt before storing)
- Cloud KMS (AWS KMS, Google Cloud KMS)

---

## Intermediate Level: Implementation Patterns

### Pattern 1: Application-Level Encryption

Encrypt sensitive fields before storing in database:

```java
// UserService.java
@Service
public class UserService {
    
    @Autowired
    private FieldEncryptionService encryptionService;
    
    @Autowired
    private UserRepository userRepo;
    
    /**
     * Store user with encrypted sensitive data
     */
    public void createUser(UserRegistration registration) {
        User user = new User();
        user.setUsername(registration.getUsername());
        user.setEmail(registration.getEmail());
        
        // Password: hash (NOT encrypt)
        user.setPasswordHash(bcrypt.hash(registration.getPassword()));
        
        // SSN: encrypt (reversible)
        String encryptedSSN = encryptionService.encrypt(registration.getSSN());
        user.setEncryptedSSN(encryptedSSN);
        
        // Credit card: encrypt with separate key
        String encryptedCC = encryptionService.encryptPCI(
            registration.getCreditCard()
        );
        user.setEncryptedCreditCard(encryptedCC);
        
        userRepo.save(user);
    }
    
    /**
     * Retrieve user with decrypted data
     */
    public UserDTO getUser(Long userId) {
        User user = userRepo.findById(userId)
            .orElseThrow(() -> new NotFoundException("User not found"));
        
        UserDTO dto = new UserDTO();
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        
        // Decrypt sensitive fields
        dto.setSSN(encryptionService.decrypt(user.getEncryptedSSN()));
        dto.setCreditCard(
            encryptionService.decryptPCI(user.getEncryptedCreditCard())
        );
        
        return dto;
    }
}
```

**Encryption Service Implementation:**

```java
// FieldEncryptionService.java
@Service
public class FieldEncryptionService {
    
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;  // 96 bits for GCM
    
    @Autowired
    private KeyManagementService kms;
    
    /**
     * Encrypt sensitive field using AES-256-GCM
     * GCM provides both confidentiality and authenticity
     */
    public String encrypt(String plaintext) {
        try {
            // Get data encryption key (DEK) from KMS
            SecretKey key = kms.getDataEncryptionKey("user-data");
            
            // Generate random IV (Initialization Vector)
            byte[] iv = new byte[IV_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            
            // Initialize cipher
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
            
            // Encrypt
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            
            // Combine IV + ciphertext (IV is not secret, but must be unique)
            byte[] combined = new byte[IV_LENGTH + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, IV_LENGTH);
            System.arraycopy(ciphertext, 0, combined, IV_LENGTH, ciphertext.length);
            
            // Encode as Base64 for storage
            return Base64.getEncoder().encodeToString(combined);
            
        } catch (Exception e) {
            throw new EncryptionException("Failed to encrypt data", e);
        }
    }
    
    /**
     * Decrypt sensitive field
     */
    public String decrypt(String encrypted) {
        try {
            // Decode from Base64
            byte[] combined = Base64.getDecoder().decode(encrypted);
            
            // Extract IV and ciphertext
            byte[] iv = new byte[IV_LENGTH];
            byte[] ciphertext = new byte[combined.length - IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, IV_LENGTH);
            System.arraycopy(combined, IV_LENGTH, ciphertext, 0, ciphertext.length);
            
            // Get key from KMS
            SecretKey key = kms.getDataEncryptionKey("user-data");
            
            // Initialize cipher for decryption
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
            
            // Decrypt
            byte[] plaintext = cipher.doFinal(ciphertext);
            
            return new String(plaintext, StandardCharsets.UTF_8);
            
        } catch (Exception e) {
            throw new EncryptionException("Failed to decrypt data", e);
        }
    }
    
    /**
     * Special handling for PCI data (credit cards)
     * Uses separate key with stricter access controls
     */
    public String encryptPCI(String cardNumber) {
        // Validate card number format first
        if (!isValidCardNumber(cardNumber)) {
            throw new IllegalArgumentException("Invalid card number");
        }
        
        // Use dedicated PCI key
        SecretKey key = kms.getDataEncryptionKey("pci-data");
        
        // Rest is same as regular encryption
        return encryptWithKey(cardNumber, key);
    }
    
    public String decryptPCI(String encrypted) {
        // Audit log access to PCI data
        auditLog.log("PCI_DATA_ACCESS", getCurrentUser());
        
        SecretKey key = kms.getDataEncryptionKey("pci-data");
        return decryptWithKey(encrypted, key);
    }
}
```

**Database Schema:**

```sql
CREATE TABLE users (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(60) NOT NULL,  -- bcrypt hash
    
    -- Encrypted fields (Base64 encoded, ~1.33x original size)
    encrypted_ssn VARCHAR(256) NULL,
    encrypted_credit_card VARCHAR(256) NULL,
    
    -- Metadata for key rotation
    encryption_key_version INT NOT NULL DEFAULT 1,
    encrypted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

### Pattern 2: Database-Level Encryption (TDE)

Transparent Data Encryption encrypts entire database files:

```java
// MySQL TDE Configuration
// application.yml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/mydb?
         useSSL=true&
         requireSSL=true&
         verifyServerCertificate=true
    hikari:
      data-source-properties:
        # Enable encryption at rest
        encrypt: true
        trustCertificateKeyStoreUrl: file:/path/to/truststore.jks
        trustCertificateKeyStorePassword: ${TRUSTSTORE_PASSWORD}
```

```sql
-- MySQL InnoDB Encryption
-- Enable encryption for entire tablespace
ALTER TABLE users ENCRYPTION='Y';

-- Create encrypted table
CREATE TABLE sensitive_data (
    id BIGINT PRIMARY KEY,
    data TEXT
) ENCRYPTION='Y';

-- Check encryption status
SELECT 
    TABLE_SCHEMA, 
    TABLE_NAME, 
    CREATE_OPTIONS 
FROM 
    INFORMATION_SCHEMA.TABLES 
WHERE 
    CREATE_OPTIONS LIKE '%ENCRYPTION%';
```

**PostgreSQL TDE:**

```sql
-- PostgreSQL with pg_crypto extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Encrypt specific column
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50),
    -- Encrypt SSN column
    encrypted_ssn BYTEA DEFAULT pgp_sym_encrypt(
        ssn_plaintext, 
        current_setting('app.encryption_key')
    )
);

-- Decrypt in query
SELECT 
    id,
    username,
    pgp_sym_decrypt(encrypted_ssn, current_setting('app.encryption_key')) AS ssn
FROM users;
```

### Pattern 3: File System Encryption

Encrypt files before storing:

```java
@Service
public class SecureFileStorage {
    
    @Autowired
    private KeyManagementService kms;
    
    @Autowired
    private AmazonS3 s3Client;
    
    /**
     * Upload file to S3 with client-side encryption
     */
    public String uploadEncryptedFile(
            InputStream fileStream, 
            String fileName,
            String bucketName
    ) throws Exception {
        
        // Generate unique data key for this file
        SecretKey dataKey = kms.generateDataKey();
        
        // Encrypt the data key with master key
        byte[] encryptedDataKey = kms.encryptDataKey(dataKey);
        
        // Encrypt file content with data key
        CipherInputStream encryptedStream = encryptStream(fileStream, dataKey);
        
        // Upload encrypted file to S3
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.addUserMetadata("x-amz-key", Base64.getEncoder()
            .encodeToString(encryptedDataKey));
        metadata.addUserMetadata("x-amz-iv", generateIV());
        
        PutObjectRequest request = new PutObjectRequest(
            bucketName,
            fileName,
            encryptedStream,
            metadata
        );
        
        s3Client.putObject(request);
        
        return "s3://" + bucketName + "/" + fileName;
    }
    
    /**
     * Download and decrypt file from S3
     */
    public InputStream downloadEncryptedFile(
            String bucketName, 
            String fileName
    ) throws Exception {
        
        // Get object with metadata
        S3Object s3Object = s3Client.getObject(bucketName, fileName);
        ObjectMetadata metadata = s3Object.getObjectMetadata();
        
        // Extract encrypted data key
        String encryptedKeyBase64 = metadata.getUserMetaDataOf("x-amz-key");
        byte[] encryptedDataKey = Base64.getDecoder().decode(encryptedKeyBase64);
        
        // Decrypt data key using KMS
        SecretKey dataKey = kms.decryptDataKey(encryptedDataKey);
        
        // Decrypt file content
        String iv = metadata.getUserMetaDataOf("x-amz-iv");
        return decryptStream(s3Object.getObjectContent(), dataKey, iv);
    }
    
    /**
     * Encrypt stream using AES-256-GCM
     */
    private CipherInputStream encryptStream(InputStream input, SecretKey key) 
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return new CipherInputStream(input, cipher);
    }
    
    /**
     * Decrypt stream
     */
    private InputStream decryptStream(InputStream input, SecretKey key, String ivBase64) 
            throws Exception {
        byte[] iv = Base64.getDecoder().decode(ivBase64);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return new CipherInputStream(input, cipher);
    }
}
```

---

## Advanced Level: Key Management

### Key Hierarchy (Envelope Encryption)

Never store master key in code. Use multi-layer key hierarchy:

```
┌─────────────────────────────────────────┐
│         Master Key (KMS/HSM)            │  ← Root of trust
│  - Never leaves KMS                      │
│  - Used ONLY to encrypt/decrypt DEKs     │
└────────────────┬────────────────────────┘
                 │ Encrypts
                 ▼
┌─────────────────────────────────────────┐
│     Data Encryption Keys (DEKs)         │  ← Per-tenant or per-file
│  - Encrypted by master key               │
│  - Stored with encrypted data            │
│  - Rotated regularly                     │
└────────────────┬────────────────────────┘
                 │ Encrypts
                 ▼
┌─────────────────────────────────────────┐
│          Actual Data                     │
│  - User records, files, etc.             │
│  - Can be bulk re-encrypted quickly      │
└─────────────────────────────────────────┘
```

**Implementation:**

```java
@Service
public class EnvelopeEncryption {
    
    @Autowired
    private AWSKMSClient kmsClient;
    
    private static final String MASTER_KEY_ID = "arn:aws:kms:us-east-1:123456789:key/abc-123";
    
    /**
     * Encrypt data using envelope encryption
     */
    public EnvelopeEncryptedData encrypt(byte[] plaintext) {
        // 1. Generate unique data key for this data
        GenerateDataKeyRequest dataKeyRequest = new GenerateDataKeyRequest()
            .withKeyId(MASTER_KEY_ID)
            .withKeySpec(DataKeySpec.AES_256);
        
        GenerateDataKeyResult dataKeyResult = kmsClient.generateDataKey(dataKeyRequest);
        
        // plaintext DEK (use this to encrypt data)
        ByteBuffer plaintextKey = dataKeyResult.getPlaintext();
        // encrypted DEK (store this with data)
        ByteBuffer encryptedKey = dataKeyResult.getCiphertextBlob();
        
        // 2. Encrypt data with DEK
        SecretKey key = new SecretKeySpec(
            plaintextKey.array(), 
            "AES"
        );
        byte[] encryptedData = encryptWithAES(plaintext, key);
        
        // 3. Clear plaintext key from memory
        Arrays.fill(plaintextKey.array(), (byte) 0);
        
        // 4. Return encrypted data + encrypted DEK
        return new EnvelopeEncryptedData(
            encryptedData,
            encryptedKey.array()
        );
    }
    
    /**
     * Decrypt envelope-encrypted data
     */
    public byte[] decrypt(EnvelopeEncryptedData encrypted) {
        // 1. Decrypt the DEK using KMS
        DecryptRequest decryptRequest = new DecryptRequest()
            .withCiphertextBlob(ByteBuffer.wrap(encrypted.getEncryptedKey()));
        
        DecryptResult decryptResult = kmsClient.decrypt(decryptRequest);
        ByteBuffer plaintextKey = decryptResult.getPlaintext();
        
        // 2. Decrypt data using DEK
        SecretKey key = new SecretKeySpec(
            plaintextKey.array(),
            "AES"
        );
        byte[] plaintext = decryptWithAES(encrypted.getEncryptedData(), key);
        
        // 3. Clear plaintext key from memory
        Arrays.fill(plaintextKey.array(), (byte) 0);
        
        return plaintext;
    }
}
```

### Key Rotation Strategy

Regular key rotation limits exposure:

```java
@Service
public class KeyRotationService {
    
    @Autowired
    private KeyManagementService kms;
    
    @Autowired
    private UserRepository userRepo;
    
    /**
     * Rotate encryption keys for all users
     * Run this as background job
     */
    @Scheduled(cron = "0 0 3 1 * *")  // 1st of each month at 3 AM
    public void rotateUserEncryptionKeys() {
        log.info("Starting key rotation...");
        
        // Get new key version
        int newKeyVersion = kms.getCurrentKeyVersion() + 1;
        SecretKey newKey = kms.getDataEncryptionKey("user-data", newKeyVersion);
        
        // Process in batches to avoid memory issues
        int batchSize = 1000;
        int offset = 0;
        
        while (true) {
            List<User> users = userRepo.findUsersWithOldKey(
                newKeyVersion - 1,  // Current version
                batchSize,
                offset
            );
            
            if (users.isEmpty()) {
                break;
            }
            
            for (User user : users) {
                try {
                    // Decrypt with old key
                    SecretKey oldKey = kms.getDataEncryptionKey(
                        "user-data",
                        user.getEncryptionKeyVersion()
                    );
                    String ssn = decryptWithKey(user.getEncryptedSSN(), oldKey);
                    String cc = decryptWithKey(user.getEncryptedCreditCard(), oldKey);
                    
                    // Re-encrypt with new key
                    user.setEncryptedSSN(encryptWithKey(ssn, newKey));
                    user.setEncryptedCreditCard(encryptWithKey(cc, newKey));
                    user.setEncryptionKeyVersion(newKeyVersion);
                    user.setEncryptedAt(Instant.now());
                    
                    userRepo.save(user);
                    
                } catch (Exception e) {
                    log.error("Failed to rotate key for user: " + user.getId(), e);
                    alertService.send(
                        "Key rotation failure",
                        "User ID: " + user.getId() + ", Error: " + e.getMessage()
                    );
                }
            }
            
            offset += batchSize;
            
            // Log progress
            log.info("Rotated keys for {} users", offset);
        }
        
        log.info("Key rotation completed");
    }
}
```

---

## Real FAANG Examples

### Example 1: AWS S3 Encryption

AWS S3 provides multiple encryption options:

**Server-Side Encryption (SSE):**

```java
// SSE-S3: Amazon manages keys
PutObjectRequest request = new PutObjectRequest(bucketName, key, file)
    .withServerSideEncryption(ServerSideEncryption.AES256);

// SSE-KMS: AWS KMS manages keys
PutObjectRequest request = new PutObjectRequest(bucketName, key, file)
    .withSSEAwsKeyManagementParams(
        new SSEAwsKeyManagementParams("arn:aws:kms:us-east-1:123456789:key/abc")
    );

// SSE-C: Customer provides key
String base64Key = Base64.getEncoder().encodeToString(customerKey);
String base64KeyMD5 = Base64.getEncoder().encodeToString(
    MessageDigest.getInstance("MD5").digest(customerKey)
);

SSECustomerKey sseKey = new SSECustomerKey(base64Key)
    .withMd5(base64KeyMD5);

PutObjectRequest request = new PutObjectRequest(bucketName, key, file)
    .withSSECustomerKey(sseKey);
```

**Client-Side Encryption:**

```java
// Encrypt before uploading
AmazonS3EncryptionClient encryptionClient = AmazonS3EncryptionClient.builder()
    .withRegion(Regions.US_EAST_1)
    .withCryptoConfiguration(new CryptoConfiguration())
    .withEncryptionMaterials(new KMSEncryptionMaterialsProvider(kmsKeyId))
    .build();

// Upload - automatically encrypted
encryptionClient.putObject(bucketName, key, file);

// Download - automatically decrypted
S3Object object = encryptionClient.getObject(bucketName, key);
```

### Example 2: Google Cloud Storage Encryption

GCS uses envelope encryption automatically:

```java
// Default: Google-managed keys
Storage storage = StorageOptions.getDefaultInstance().getService();
storage.create(BlobInfo.newBuilder(bucketName, objectName).build(), content);

// Customer-managed encryption keys (CMEK)
String kmsKeyName = "projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY";

BlobInfo blobInfo = BlobInfo.newBuilder(bucketName, objectName)
    .setKmsKeyName(kmsKeyName)
    .build();
storage.create(blobInfo, content);

// Customer-supplied encryption keys (CSEK)
String encryptionKey = "your-base64-encoded-256-bit-key";

BlobInfo blobInfo = BlobInfo.newBuilder(bucketName, objectName).build();
storage.create(
    blobInfo,
    content,
    Storage.BlobTargetOption.encryptionKey(encryptionKey)
);
```

### Example 3: Netflix's Encryption Architecture

Netflix encrypts content at multiple layers:

```
Content Encryption Architecture:

1. Master Content (Origin):
   ├── Encrypted with Content Encryption Key (CEK)
   ├── CEK unique per title
   └── CEK encrypted with Key Encryption Key (KEK)

2. Distribution (CDN):
   ├── Encrypted content cached at edge
   ├── TLS for delivery to client
   └── No keys stored at edge

3. Client Playback:
   ├── License server provides decryption keys
   ├── Keys tied to user account + device
   ├── DRM enforces usage rules
   └── Keys never exposed to application
```

**Implementation Pattern:**

```java
@Service
public class ContentEncryptionService {
    
    /**
     * Encrypt video content before CDN upload
     */
    public EncryptedContent encryptContent(
            InputStream videoStream,
            String contentId
    ) {
        // 1. Generate unique content encryption key (CEK)
        SecretKey cek = generateAESKey(256);
        
        // 2. Encrypt video with CEK (using AES-128 CTR mode for streaming)
        InputStream encryptedStream = encryptStreamForStreaming(videoStream, cek);
        
        // 3. Encrypt CEK with key encryption key (KEK) from KMS
        byte[] encryptedCEK = kms.encryptKey(cek, "content-kek");
        
        // 4. Store encrypted CEK in license server
        licenseServer.storeLicense(contentId, encryptedCEK);
        
        // 5. Upload encrypted content to CDN
        String cdnUrl = cdn.upload(encryptedStream, contentId);
        
        return new EncryptedContent(cdnUrl, contentId);
    }
    
    /**
     * Generate playback license for authorized user
     */
    public PlaybackLicense generateLicense(
            String userId,
            String contentId,
            String deviceId
    ) {
        // 1. Verify user has access to content
        if (!accessControl.hasAccess(userId, contentId)) {
            throw new UnauthorizedException("No access to content");
        }
        
        // 2. Retrieve encrypted CEK
        byte[] encryptedCEK = licenseServer.getLicense(contentId);
        
        // 3. Decrypt CEK using KEK
        SecretKey cek = kms.decryptKey(encryptedCEK, "content-kek");
        
        // 4. Re-encrypt CEK with device-specific key
        SecretKey deviceKey = getDeviceKey(userId, deviceId);
        byte[] deviceEncryptedCEK = encryptKey(cek, deviceKey);
        
        // 5. Create time-limited license
        PlaybackLicense license = new PlaybackLicense();
        license.setContentId(contentId);
        license.setEncryptedKey(deviceEncryptedCEK);
        license.setExpiresAt(Instant.now().plus(24, ChronoUnit.HOURS));
        license.setDeviceId(deviceId);
        
        // 6. Sign license to prevent tampering
        String signature = signLicense(license);
        license.setSignature(signature);
        
        return license;
    }
}
```

### Example 4: Meta's End-to-End Encryption (WhatsApp)

WhatsApp uses Signal Protocol for E2E encryption:

```java
/**
 * Simplified version of Signal Protocol encryption
 */
@Service
public class EndToEndEncryption {
    
    /**
     * Initialize session with recipient
     * Uses Double Ratchet Algorithm
     */
    public void initializeSession(String senderId, String recipientId) {
        // 1. Fetch recipient's pre-keys from server
        PreKeyBundle recipientBundle = preKeyServer.getPreKeyBundle(recipientId);
        
        // 2. Generate session keys using X3DH (Extended Triple Diffie-Hellman)
        SessionCipher sessionCipher = SessionBuilder.process(recipientBundle);
        
        // 3. Store session for this conversation
        sessionStore.store(senderId + ":" + recipientId, sessionCipher);
    }
    
    /**
     * Encrypt message
     */
    public EncryptedMessage encryptMessage(
            String senderId,
            String recipientId,
            String plaintext
    ) {
        // 1. Get session cipher
        SessionCipher cipher = sessionStore.get(senderId + ":" + recipientId);
        
        // 2. Encrypt message (generates new ephemeral key each time)
        CiphertextMessage ciphertext = cipher.encrypt(plaintext.getBytes());
        
        // 3. Include ratchet header for key agreement
        return new EncryptedMessage(
            ciphertext.serialize(),
            cipher.getSessionVersion(),
            cipher.getRemoteRegistrationId()
        );
    }
    
    /**
     * Decrypt message
     */
    public String decryptMessage(
            String recipientId,
            String senderId,
            EncryptedMessage encrypted
    ) {
        // 1. Get session cipher
        SessionCipher cipher = sessionStore.get(recipientId + ":" + senderId);
        
        // 2. Decrypt message (automatically updates ratchet state)
        byte[] plaintext = cipher.decrypt(
            new PreKeySignalMessage(encrypted.getCiphertext())
        );
        
        return new String(plaintext, StandardCharsets.UTF_8);
    }
}
```

**Key Properties of E2E Encryption:**
- Only sender and recipient can decrypt messages
- Server cannot read message content
- Forward secrecy: Past messages safe even if key compromised
- Future secrecy: Compromise doesn't affect future messages

---

## Interview Question: Design Encryption for Multi-Tenant SaaS

**Question:** Design encryption architecture for a SaaS platform where:
- 10,000 tenants (companies)
- Each tenant has 100-10,000 users
- Must support per-tenant encryption keys
- Regulatory requirement: Tenant can revoke access to their data
- Must be performant at scale

**Answer:**

```
Architecture:

┌──────────────────────────────────────────────────────┐
│                   Key Hierarchy                       │
├──────────────────────────────────────────────────────┤
│  Platform Master Key (AWS KMS)                       │
│           ↓ encrypts                                  │
│  Tenant Master Key (per tenant)                      │
│           ↓ encrypts                                  │
│  Data Encryption Keys (per data type)                │
│           ↓ encrypts                                  │
│  Actual Data (users, documents, etc.)                │
└──────────────────────────────────────────────────────┘
```

**Implementation:**

```java
@Service
public class MultiTenantEncryption {
    
    @Autowired
    private AWSKMSClient kms;
    
    @Autowired
    private RedisTemplate<String, byte[]> keyCache;
    
    /**
     * Get or create tenant-specific master key
     */
    public String getTenantMasterKey(String tenantId) {
        // Check if tenant already has key
        String alias = "alias/tenant-" + tenantId;
        
        try {
            DescribeKeyRequest request = new DescribeKeyRequest()
                .withKeyId(alias);
            DescribeKeyResult result = kms.describeKey(request);
            return result.getKeyMetadata().getKeyId();
            
        } catch (NotFoundException e) {
            // Create new key for tenant
            CreateKeyRequest createRequest = new CreateKeyRequest()
                .withDescription("Master key for tenant: " + tenantId)
                .withKeyPolicy(getTenantKeyPolicy(tenantId));
            
            CreateKeyResult createResult = kms.createKey(createRequest);
            String keyId = createResult.getKeyMetadata().getKeyId();
            
            // Create alias
            CreateAliasRequest aliasRequest = new CreateAliasRequest()
                .withAliasName(alias)
                .withTargetKeyId(keyId);
            kms.createAlias(aliasRequest);
            
            return keyId;
        }
    }
    
    /**
     * Encrypt data for specific tenant
     */
    public EncryptedData encryptForTenant(String tenantId, byte[] plaintext) {
        // 1. Get tenant's master key
        String tenantKeyId = getTenantMasterKey(tenantId);
        
        // 2. Generate data encryption key using tenant's master key
        GenerateDataKeyRequest dataKeyRequest = new GenerateDataKeyRequest()
            .withKeyId(tenantKeyId)
            .withKeySpec(DataKeySpec.AES_256);
        
        GenerateDataKeyResult dataKeyResult = kms.generateDataKey(dataKeyRequest);
        
        // 3. Encrypt data with DEK
        byte[] encryptedData = encryptAES(
            plaintext,
            dataKeyResult.getPlaintext().array()
        );
        
        // 4. Return encrypted data + encrypted DEK
        return new EncryptedData(
            encryptedData,
            dataKeyResult.getCiphertextBlob().array(),
            tenantId
        );
    }
    
    /**
     * Decrypt data for specific tenant
     */
    public byte[] decryptForTenant(String tenantId, EncryptedData encrypted) {
        // Verify tenant matches
        if (!tenantId.equals(encrypted.getTenantId())) {
            throw new SecurityException("Tenant mismatch");
        }
        
        // 1. Check cache for decrypted DEK
        String cacheKey = "dek:" + tenantId + ":" + 
            Base64.getEncoder().encodeToString(encrypted.getEncryptedKey());
        
        byte[] dek = keyCache.opsForValue().get(cacheKey);
        
        if (dek == null) {
            // 2. Decrypt DEK using KMS (slow operation)
            DecryptRequest decryptRequest = new DecryptRequest()
                .withCiphertextBlob(ByteBuffer.wrap(encrypted.getEncryptedKey()));
            
            DecryptResult decryptResult = kms.decrypt(decryptRequest);
            dek = decryptResult.getPlaintext().array();
            
            // 3. Cache DEK for 5 minutes
            keyCache.opsForValue().set(cacheKey, dek, 5, TimeUnit.MINUTES);
        }
        
        // 4. Decrypt data with DEK
        return decryptAES(encrypted.getData(), dek);
    }
    
    /**
     * Revoke tenant access (regulatory requirement)
     */
    public void revokeTenantAccess(String tenantId) {
        // 1. Disable tenant's master key in KMS
        String alias = "alias/tenant-" + tenantId;
        
        DescribeKeyRequest describeRequest = new DescribeKeyRequest()
            .withKeyId(alias);
        DescribeKeyResult result = kms.describeKey(describeRequest);
        String keyId = result.getKeyMetadata().getKeyId();
        
        // Schedule key deletion (7-30 day waiting period required)
        ScheduleKeyDeletionRequest deleteRequest = 
            new ScheduleKeyDeletionRequest()
                .withKeyId(keyId)
                .withPendingWindowInDays(7);
        kms.scheduleKeyDeletion(deleteRequest);
        
        // 2. Clear cached keys
        keyCache.delete("dek:" + tenantId + ":*");
        
        // 3. Log action for audit
        auditLog.critical(
            "Tenant access revoked",
            "tenant_id", tenantId,
            "kms_key_id", keyId,
            "deletion_date", LocalDate.now().plusDays(7)
        );
        
        // 4. Notify tenant
        notificationService.send(
            tenantId,
            "Data access revoked",
            "Your encryption keys have been scheduled for deletion. " +
            "Data will be permanently inaccessible in 7 days."
        );
    }
}
```

**Performance Optimization:**

```java
/**
 * Batch encryption for better performance
 */
public List<EncryptedData> batchEncrypt(
        String tenantId,
        List<byte[]> plaintexts
) {
    // Generate one DEK for the entire batch
    String tenantKeyId = getTenantMasterKey(tenantId);
    GenerateDataKeyResult dataKeyResult = kms.generateDataKey(
        new GenerateDataKeyRequest()
            .withKeyId(tenantKeyId)
            .withKeySpec(DataKeySpec.AES_256)
    );
    
    byte[] dek = dataKeyResult.getPlaintext().array();
    byte[] encryptedDEK = dataKeyResult.getCiphertextBlob().array();
    
    // Encrypt all plaintexts with same DEK
    return plaintexts.stream()
        .map(plaintext -> new EncryptedData(
            encryptAES(plaintext, dek),
            encryptedDEK,
            tenantId
        ))
        .collect(Collectors.toList());
}
```

**Monitoring and Alerts:**

```java
@Component
public class EncryptionMonitoring {
    
    @Autowired
    private MeterRegistry registry;
    
    public void recordEncryption(String tenantId, long durationMs, boolean success) {
        Timer.builder("encryption.operation")
            .tag("tenant_id", tenantId)
            .tag("success", String.valueOf(success))
            .register(registry)
            .record(durationMs, TimeUnit.MILLISECONDS);
    }
    
    @EventListener
    public void onEncryptionFailure(EncryptionFailureEvent event) {
        Counter.builder("encryption.failures")
            .tag("tenant_id", event.getTenantId())
            .tag("error_type", event.getErrorType())
            .register(registry)
            .increment();
        
        // Alert if failures spike
        long recentFailures = getFailureCount(event.getTenantId(), Duration.ofMinutes(5));
        if (recentFailures > 10) {
            alertService.send(
                "Encryption failure spike",
                "Tenant: " + event.getTenantId() + 
                ", Failures: " + recentFailures
            );
        }
    }
}
```

---

## Summary: Encryption Best Practices

**Critical Rules:**

1. **Encrypt in Transit (HTTPS/TLS)**
    - All external communication must use TLS 1.2+
    - Internal service-to-service: Use mTLS
    - Never send sensitive data over HTTP

2. **Encrypt at Rest**
    - Encrypt sensitive fields in database
    - Use database TDE for additional layer
    - Encrypt backups and logs

3. **Key Management**
    - Never hardcode encryption keys
    - Use KMS (AWS KMS, Google Cloud KMS, HashiCorp Vault)
    - Implement key rotation
    - Use envelope encryption

4. **Algorithm Selection**
    - Symmetric: AES-256-GCM (authenticated encryption)
    - Asymmetric: RSA-2048+ or ECC (elliptic curve)
    - Hashing: bcrypt, scrypt, or Argon2 for passwords

5. **Separation of Concerns**
    - Different keys for different purposes
    - PCI data gets separate key
    - Per-tenant keys for multi-tenant systems

---

**End of Part 2**

Continue to Part 3 for:
- S7: Hashing & Salting (Passwords)
- S8: Single Sign-On (SSO)
- S9: Role-Based Access Control (RBAC)