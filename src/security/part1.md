# Security & Authentication: Complete FAANG Interview Guide

**For System Design Mastery with Java**

---

## Table of Contents

1. [S1: Authentication vs Authorization](#s1-authentication-vs-authorization)
2. [S2: OAuth 2.0 & OpenID Connect](#s2-oauth-20--openid-connect)
3. [S3: JWT vs Session-based Auth](#s3-jwt-vs-session-based-auth)
4. [S4: API Security (API Keys, Rate Limiting)](#s4-api-security-api-keys-rate-limiting)
5. [S5: HTTPS/TLS/SSL](#s5-httpstlsssl)
6. [S6: Encryption (At-rest vs In-transit)](#s6-encryption-at-rest-vs-in-transit)
7. [S7: Hashing & Salting (Passwords)](#s7-hashing--salting-passwords)
8. [S8: Single Sign-On (SSO)](#s8-single-sign-on-sso)
9. [S9: Role-Based Access Control (RBAC)](#s9-role-based-access-control-rbac)
10. [S10: Attribute-Based Access Control (ABAC)](#s10-attribute-based-access-control-abac)
11. [S11: Zero Trust Architecture](#s11-zero-trust-architecture)
12. [S12: Secret Management (Vault)](#s12-secret-management-vault)
13. [S13: SQL Injection, XSS, CSRF Prevention](#s13-sql-injection-xss-csrf-prevention)
14. [S14: DDoS Protection](#s14-ddos-protection)
15. [S15: mTLS (Service-to-Service)](#s15-mtls-service-to-service)

---

# S1: Authentication vs Authorization

## 🏢 The Office Building Analogy

Imagine you're entering a high-security corporate office building:

**Authentication** is like showing your ID badge at the front desk:
- The security guard verifies you are who you claim to be
- They check your photo matches your face
- They verify the badge is legitimate, not fake
- This answers: **"Who are you?"**

**Authorization** is what happens after you're inside:
- Your badge determines which floors you can access
- Some employees can enter the executive suite, others cannot
- Engineers can access the data center, but not HR files
- This answers: **"What are you allowed to do?"**

**Key Insight**: You can't have authorization without authentication. You must prove who you are before the system can determine what you're allowed to do.

---

## Beginner Level: Core Concepts

### What is Authentication?

Authentication is the process of verifying identity. It's proving you are who you claim to be.

**Three Factors of Authentication:**

1. **Knowledge factors** - Something you know
    - Password
    - PIN
    - Security questions

2. **Possession factors** - Something you have
    - Phone (for SMS codes)
    - Security token (YubiKey)
    - Smart card

3. **Inherence factors** - Something you are
    - Fingerprint
    - Face recognition
    - Retina scan

**Example Flow:**
```
User: "I'm John Doe, my password is 'SecurePass123'"
System: *Checks password against stored hash*
System: "Password matches! You are authenticated as John Doe"
```

### What is Authorization?

Authorization is permission checking. After knowing who you are, the system determines what you can access.

**Common Permission Models:**

1. **Read** - View data
2. **Write** - Modify data
3. **Execute** - Perform actions
4. **Delete** - Remove data
5. **Admin** - Manage permissions

**Example Flow:**
```
User (John): "I want to delete this file"
System: "You are John Doe (authenticated ✓)"
System: "Checking permissions... John has 'read' and 'write', but not 'delete'"
System: "Access Denied - insufficient permissions"
```

---

## Intermediate Level: Real-World Implementation

### The Complete Authentication Flow

Let's trace a real login process step-by-step:

```
Step 1: User submits credentials
POST /api/login
{
  "username": "john@example.com",
  "password": "MyPassword123"
}

Step 2: Server validates credentials
- Lookup user by username in database
- Compare password hash (never store plain passwords!)
- Check if account is active/locked

Step 3: Create session or token
- Generate unique session ID
- Store session data (user ID, expiry time)
- Return session token to client

Step 4: Client stores token
- Save in cookie or localStorage
- Include in all subsequent requests

Step 5: Validate on every request
GET /api/profile
Headers: { Authorization: "Bearer abc123..." }
- Server validates token
- Extracts user identity
- Proceeds with authorization check
```

### The Complete Authorization Flow

After authentication, every request goes through authorization:

```
Request: GET /api/documents/12345

Step 1: Extract identity from token
- Parse JWT or lookup session
- Get user_id = 789

Step 2: Load user permissions
- Query database for user roles/permissions
- User 789 has roles: ["employee", "finance"]

Step 3: Check resource permissions
- Document 12345 requires role "finance" to read
- User has "finance" role ✓

Step 4: Apply fine-grained rules
- Check if document belongs to user's department
- Check if document is marked confidential
- Apply any time-based restrictions

Step 5: Grant or deny access
- All checks passed → Return document
- Any check failed → 403 Forbidden
```

---

## Advanced Topics

### Multi-Factor Authentication (MFA)

Combining multiple authentication factors for stronger security.

**Real Attack Scenario Prevented by MFA:**
```
Scenario: Attacker steals password from data breach

Without MFA:
1. Attacker has password → Logs in successfully
2. Account compromised

With MFA:
1. Attacker has password → Enters it
2. System sends OTP to user's phone
3. Attacker doesn't have phone → Cannot proceed
4. User receives unexpected OTP → Knows account is under attack
5. User changes password → Account secured
```

**MFA Methods Ranked by Security:**

1. **Hardware tokens** (Most Secure)
    - YubiKey, RSA SecurID
    - Physically impossible to phish
    - Used by: Google for employees

2. **Authenticator apps**
    - Google Authenticator, Authy
    - Time-based OTP (TOTP)
    - Immune to SIM swapping

3. **SMS codes** (Least Secure)
    - Vulnerable to SIM swapping attacks
    - Still better than no MFA
    - Being phased out by security-conscious companies

### Adaptive Authentication

Modern systems adjust authentication requirements based on risk.

**Google's Approach:**
```
Low Risk Login:
- Known device
- Usual location
- Normal time
→ Password only

Medium Risk Login:
- New device OR new location
→ Password + 2FA code

High Risk Login:
- New device AND new country
- Impossible travel (NYC to Tokyo in 1 hour)
→ Password + 2FA + Email verification + CAPTCHA
```

### Fine-Grained Authorization

Beyond simple yes/no decisions.

**Netflix Example: Content Authorization**
```
User wants to play "Stranger Things S4E1"

Check 1: Subscription tier
- User has "Premium" plan ✓
- Content requires "Standard" or higher ✓

Check 2: Geographic licensing
- User in USA
- Content licensed for USA ✓

Check 3: Parental controls
- Content rated TV-14
- Account set to allow TV-14 ✓

Check 4: Concurrent streams
- User has 3 active streams
- Premium allows 4 streams ✓

Check 5: Device capability
- User on 4K TV
- Premium includes 4K ✓

Result: Authorized to play in 4K quality
```

---

## Real FAANG Examples

### Google: Defense-in-Depth Authentication

Google implements multiple layers of security:

**Layer 1: Password Requirements**
- Minimum 8 characters
- Complexity requirements
- Cannot reuse last 24 passwords
- Expires every 90 days for enterprise accounts

**Layer 2: Two-Step Verification**
```java
// Simplified Google 2SV Flow
public class Google2SVService {
    
    public AuthenticationResult authenticate(LoginRequest request) {
        // Step 1: Verify password
        User user = validatePassword(request.getEmail(), request.getPassword());
        if (user == null) {
            return AuthenticationResult.failed("Invalid credentials");
        }
        
        // Step 2: Check if 2SV is enabled
        if (user.isTwoStepEnabled()) {
            // Generate and send verification code
            String code = generateSecureCode();
            sendVerificationCode(user, code);
            
            // Return pending state - need second factor
            return AuthenticationResult.pending(user.getId(), "2sv_required");
        }
        
        // Create session
        return createAuthenticatedSession(user);
    }
    
    public AuthenticationResult verify2SV(String userId, String code) {
        User user = userRepository.findById(userId);
        
        // Verify code (time-limited, single-use)
        if (!verifyTOTPCode(user.get2SVSecret(), code)) {
            incrementFailedAttempts(userId);
            return AuthenticationResult.failed("Invalid code");
        }
        
        // Mark device as trusted if requested
        if (request.trustDevice()) {
            createTrustedDeviceCookie();
        }
        
        return createAuthenticatedSession(user);
    }
    
    private String generateSecureCode() {
        // 6-digit code, valid for 5 minutes
        SecureRandom random = new SecureRandom();
        int code = 100000 + random.nextInt(900000);
        return String.valueOf(code);
    }
}
```

**Layer 3: Device Recognition**
Google tracks trusted devices:
```java
public class DeviceRecognitionService {
    
    public boolean isTrustedDevice(HttpServletRequest request) {
        String deviceFingerprint = calculateFingerprint(request);
        
        // Fingerprint includes:
        // - User agent
        // - Screen resolution  
        // - Timezone
        // - Installed fonts
        // - Canvas fingerprint
        
        return trustedDevices.contains(deviceFingerprint);
    }
    
    public RiskScore calculateRiskScore(LoginAttempt attempt) {
        int risk = 0;
        
        // Check device
        if (!isTrustedDevice(attempt.getRequest())) {
            risk += 30;
        }
        
        // Check location
        if (isNewLocation(attempt.getIpAddress(), attempt.getUserId())) {
            risk += 20;
        }
        
        // Check for impossible travel
        if (isImpossibleTravel(attempt)) {
            risk += 50; // Last login 1 hour ago from different continent
        }
        
        // Check time of day
        if (isUnusualTime(attempt)) {
            risk += 10; // User never logs in at 3 AM
        }
        
        return new RiskScore(risk);
    }
}
```

**Layer 4: Behavior Analysis**
```java
public class BehaviorAnalyzer {
    
    public boolean analyzeBehavior(User user, LoginAttempt attempt) {
        // Typing pattern analysis
        TypingPattern pattern = analyzeTypingSpeed(attempt.getKeystrokes());
        if (!matchesKnownPattern(user, pattern)) {
            return false;
        }
        
        // Mouse movement analysis
        MousePattern mouse = analyzeMouseMovement(attempt.getMouseData());
        if (!matchesKnownPattern(user, mouse)) {
            return false;
        }
        
        // Login time patterns
        if (!matchesUsualLoginTime(user, attempt.getTimestamp())) {
            return false;
        }
        
        return true;
    }
}
```

### Amazon: IAM (Identity and Access Management)

Amazon's IAM is the gold standard for authorization at scale.

**IAM Core Concepts:**

```java
// IAM Policy Structure
public class IAMPolicy {
    private String version;
    private List<Statement> statements;
    
    @Data
    public static class Statement {
        private Effect effect;        // ALLOW or DENY
        private List<String> actions; // What operations
        private List<String> resources; // On which resources
        private Map<String, Condition> conditions; // Under what circumstances
    }
    
    public enum Effect {
        ALLOW, DENY
    }
}
```

**Real IAM Policy Example:**
```java
// S3 Read-Only Access Policy
public class S3ReadOnlyPolicy {
    
    public IAMPolicy createPolicy() {
        Statement listBucket = Statement.builder()
            .effect(Effect.ALLOW)
            .actions(List.of("s3:ListBucket"))
            .resources(List.of("arn:aws:s3:::company-documents"))
            .build();
            
        Statement getObject = Statement.builder()
            .effect(Effect.ALLOW)
            .actions(List.of("s3:GetObject"))
            .resources(List.of("arn:aws:s3:::company-documents/*"))
            .conditions(Map.of(
                "IpAddress", new Condition("aws:SourceIp", "10.0.0.0/16"), // Corporate network only
                "StringEquals", new Condition("aws:RequestedRegion", "us-east-1") // US region only
            ))
            .build();
            
        return IAMPolicy.builder()
            .version("2012-10-17")
            .statements(List.of(listBucket, getObject))
            .build();
    }
}
```

**IAM Policy Evaluation Logic:**
```java
public class IAMPolicyEvaluator {
    
    public AuthorizationResult evaluate(Principal principal, String action, String resource) {
        // Step 1: Collect all policies attached to principal
        List<IAMPolicy> policies = collectPolicies(principal);
        
        // Step 2: Explicit DENY always wins
        for (IAMPolicy policy : policies) {
            if (hasExplicitDeny(policy, action, resource)) {
                return AuthorizationResult.denied("Explicit deny in policy");
            }
        }
        
        // Step 3: Check for explicit ALLOW
        for (IAMPolicy policy : policies) {
            if (hasExplicitAllow(policy, action, resource)) {
                // Verify conditions
                if (evaluateConditions(policy.getConditions())) {
                    return AuthorizationResult.allowed();
                }
            }
        }
        
        // Step 4: Default deny (implicit)
        return AuthorizationResult.denied("No explicit allow found");
    }
    
    private boolean evaluateConditions(Map<String, Condition> conditions) {
        for (Map.Entry<String, Condition> entry : conditions.entrySet()) {
            String operator = entry.getKey();
            Condition condition = entry.getValue();
            
            switch (operator) {
                case "IpAddress":
                    if (!matchesIpRange(condition.getValue())) return false;
                    break;
                case "StringEquals":
                    if (!matchesString(condition.getKey(), condition.getValue())) return false;
                    break;
                case "DateGreaterThan":
                    if (!isAfterDate(condition.getValue())) return false;
                    break;
                // Many more operators...
            }
        }
        return true;
    }
}
```

**Real-World IAM Usage at Amazon:**

```java
// EC2 Instance Role - Allows EC2 instance to read from S3
public class EC2InstanceRole {
    
    public void setupInstanceRole() {
        // Create role
        Role role = Role.builder()
            .roleName("WebServerRole")
            .assumeRolePolicyDocument(
                "Allow EC2 service to assume this role"
            )
            .build();
            
        // Attach policy
        IAMPolicy policy = IAMPolicy.builder()
            .statements(List.of(
                Statement.builder()
                    .effect(Effect.ALLOW)
                    .actions(List.of(
                        "s3:GetObject",
                        "s3:ListBucket"
                    ))
                    .resources(List.of(
                        "arn:aws:s3:::static-assets/*"
                    ))
                    .build()
            ))
            .build();
            
        attachPolicyToRole(role, policy);
        
        // Launch EC2 with this role
        EC2Instance instance = EC2.launch()
            .instanceType("t3.medium")
            .iamRole(role)
            .build();
            
        // Now this instance can read from S3 without storing credentials
    }
}
```

### Meta (Facebook): Social Graph Authorization

Facebook's authorization is unique because permissions are based on social relationships.

**Friend-Based Authorization:**
```java
public class FacebookAuthorizationService {
    
    public boolean canViewPost(User viewer, Post post) {
        User author = post.getAuthor();
        
        // Step 1: Check post visibility setting
        Visibility visibility = post.getVisibility();
        
        switch (visibility) {
            case PUBLIC:
                return true;
                
            case FRIENDS:
                return areFriends(viewer, author);
                
            case FRIENDS_OF_FRIENDS:
                return areFriendsOfFriends(viewer, author);
                
            case FRIENDS_EXCEPT:
                return areFriends(viewer, author) && 
                       !post.getExceptList().contains(viewer.getId());
                
            case SPECIFIC_FRIENDS:
                return post.getSpecificFriends().contains(viewer.getId());
                
            case ONLY_ME:
                return viewer.getId().equals(author.getId());
        }
        
        return false;
    }
    
    private boolean areFriends(User user1, User user2) {
        // Query graph database
        return graphDB.hasEdge(user1.getId(), user2.getId(), "FRIEND");
    }
    
    private boolean areFriendsOfFriends(User viewer, User author) {
        // BFS search in social graph
        Set<String> authorFriends = graphDB.getNeighbors(author.getId(), "FRIEND");
        Set<String> viewerFriends = graphDB.getNeighbors(viewer.getId(), "FRIEND");
        
        // Check if they have mutual friends
        return !Collections.disjoint(authorFriends, viewerFriends);
    }
}
```

**Advanced Authorization with Blocking:**
```java
public class FacebookBlockingService {
    
    public AuthorizationResult checkAccess(User viewer, User target) {
        // Blocking is bidirectional and absolute
        
        // Check if target blocked viewer
        if (isBlocked(target, viewer)) {
            return AuthorizationResult.denied("You are blocked");
        }
        
        // Check if viewer blocked target  
        if (isBlocked(viewer, target)) {
            return AuthorizationResult.denied("You blocked this user");
        }
        
        // Check if either user is restricted
        if (isRestricted(target, viewer)) {
            return AuthorizationResult.limited("Restricted access");
        }
        
        return AuthorizationResult.allowed();
    }
    
    public boolean canViewPhoto(User viewer, Photo photo) {
        User photoOwner = photo.getOwner();
        
        // Blocking check first
        if (!checkAccess(viewer, photoOwner).isAllowed()) {
            return false;
        }
        
        // Check tag restrictions
        if (photo.getTags().contains(viewer.getId())) {
            // If viewer is tagged, they can see it
            return true;
        }
        
        // Check album privacy
        Album album = photo.getAlbum();
        return canViewPost(viewer, album.asPost());
    }
}
```

**Real-World Optimization: Permission Caching**
```java
public class PermissionCache {
    private final Cache<String, Boolean> cache;
    
    public PermissionCache() {
        // Cache with 15-minute TTL
        this.cache = CacheBuilder.newBuilder()
            .expireAfterWrite(15, TimeUnit.MINUTES)
            .maximumSize(100000)
            .build();
    }
    
    public boolean canView(User viewer, Resource resource) {
        String cacheKey = String.format("%s:%s:%s", 
            viewer.getId(), resource.getType(), resource.getId());
            
        Boolean cached = cache.getIfPresent(cacheKey);
        if (cached != null) {
            return cached;
        }
        
        // Compute permission
        boolean result = computePermission(viewer, resource);
        
        // Cache result
        cache.put(cacheKey, result);
        
        return result;
    }
    
    // Invalidate cache when relationships change
    public void onFriendshipChange(String userId1, String userId2) {
        // Invalidate all cached permissions between these users
        cache.invalidateAll();
    }
}
```

### Netflix: Content Authorization System

Netflix's authorization handles complex content licensing and parental controls.

**Multi-Dimensional Authorization:**
```java
public class NetflixAuthorizationService {
    
    public PlaybackAuthorization authorizePlayback(User user, Content content) {
        AuthorizationBuilder auth = new AuthorizationBuilder();
        
        // Check 1: Subscription tier
        SubscriptionCheck subCheck = checkSubscription(user, content);
        auth.addCheck("subscription", subCheck);
        
        // Check 2: Geographic licensing
        GeoCheck geoCheck = checkGeographicRights(user, content);
        auth.addCheck("geography", geoCheck);
        
        // Check 3: Maturity rating
        MaturityCheck maturityCheck = checkMaturityRating(user, content);
        auth.addCheck("maturity", maturityCheck);
        
        // Check 4: Concurrent streams
        ConcurrencyCheck concurrencyCheck = checkConcurrentStreams(user);
        auth.addCheck("concurrency", concurrencyCheck);
        
        // Check 5: Device capabilities
        DeviceCheck deviceCheck = checkDeviceCapabilities(user.getDevice(), content);
        auth.addCheck("device", deviceCheck);
        
        return auth.build();
    }
    
    private SubscriptionCheck checkSubscription(User user, Content content) {
        Subscription sub = user.getSubscription();
        
        // Basic: SD only
        // Standard: HD
        // Premium: 4K + HDR
        
        if (!sub.isActive()) {
            return SubscriptionCheck.failed("Subscription inactive");
        }
        
        if (content.requires4K() && !sub.isPremium()) {
            return SubscriptionCheck.downgrade("4K requires Premium, streaming in HD");
        }
        
        return SubscriptionCheck.passed();
    }
    
    private GeoCheck checkGeographicRights(User user, Content content) {
        String userCountry = geoIP.getCountry(user.getIpAddress());
        
        // Check licensing rights
        List<String> licensedCountries = licenseDB.getCountries(content.getId());
        
        if (!licensedCountries.contains(userCountry)) {
            return GeoCheck.failed("Content not available in your region");
        }
        
        // Check release windows
        ReleaseWindow window = getReleaseWindow(content, userCountry);
        if (!window.isCurrentlyAvailable()) {
            return GeoCheck.failed(String.format(
                "Available starting %s", window.getStartDate()
            ));
        }
        
        return GeoCheck.passed();
    }
    
    private MaturityCheck checkMaturityRating(User user, Content content) {
        Profile profile = user.getCurrentProfile();
        MaturityRating contentRating = content.getMaturityRating();
        MaturityRating maxAllowed = profile.getMaxMaturityRating();
        
        if (contentRating.exceeds(maxAllowed)) {
            // Check if profile can request PIN override
            if (profile.requiresPinForMature()) {
                return MaturityCheck.pinRequired();
            }
            return MaturityCheck.failed("Content rating exceeds profile limit");
        }
        
        return MaturityCheck.passed();
    }
    
    private ConcurrencyCheck checkConcurrentStreams(User user) {
        int activeStreams = streamTracker.countActiveStreams(user.getAccountId());
        int maxStreams = user.getSubscription().getMaxConcurrentStreams();
        
        // Basic: 1 stream
        // Standard: 2 streams  
        // Premium: 4 streams
        
        if (activeStreams >= maxStreams) {
            return ConcurrencyCheck.failed(String.format(
                "Maximum %d streams already active", maxStreams
            ));
        }
        
        return ConcurrencyCheck.passed(maxStreams - activeStreams);
    }
}
```

**Download Authorization:**
```java
public class DownloadAuthorizationService {
    
    public DownloadResult authorizeDownload(User user, Content content) {
        // Not all content has download rights
        if (!content.isDownloadable()) {
            return DownloadResult.denied("Content not available for download");
        }
        
        // Check device limit
        List<Device> downloadDevices = getDownloadDevices(user);
        if (downloadDevices.size() >= MAX_DOWNLOAD_DEVICES) {
            return DownloadResult.denied(
                "Maximum devices reached. Remove a device to download on a new one."
            );
        }
        
        // Check storage quota
        int totalDownloads = countActiveDownloads(user);
        int maxDownloads = user.getSubscription().getMaxDownloads();
        
        if (totalDownloads >= maxDownloads) {
            return DownloadResult.denied(String.format(
                "Maximum %d downloads reached", maxDownloads
            ));
        }
        
        // Check expiration
        Duration expiryPeriod = content.getDownloadExpiryPeriod();
        Instant expiryTime = Instant.now().plus(expiryPeriod);
        
        return DownloadResult.allowed(expiryTime);
    }
}
```

---

## Production Java Implementation

### Complete Authentication Service

```java
package com.example.auth;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

public class AuthenticationService {
    
    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;
    private final AuditLogger auditLogger;
    private final MetricsCollector metrics;
    
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCKOUT_DURATION_MINUTES = 15;
    private static final int SESSION_DURATION_HOURS = 24;
    
    public AuthenticationService(UserRepository userRepository,
                                  SessionRepository sessionRepository,
                                  AuditLogger auditLogger,
                                  MetricsCollector metrics) {
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.auditLogger = auditLogger;
        this.metrics = metrics;
    }
    
    /**
     * Authenticate user with username and password
     */
    public AuthenticationResult authenticate(String username, String password, HttpServletRequest request) {
        Instant startTime = Instant.now();
        
        try {
            // Step 1: Rate limiting check
            if (isRateLimited(request.getRemoteAddr())) {
                metrics.incrementCounter("auth.rate_limited");
                return AuthenticationResult.failure("Too many attempts. Please try again later.");
            }
            
            // Step 2: Look up user
            User user = userRepository.findByUsername(username);
            if (user == null) {
                // Don't reveal whether username exists (prevent enumeration)
                metrics.incrementCounter("auth.user_not_found");
                auditLogger.logFailedAuth(username, request.getRemoteAddr(), "User not found");
                return AuthenticationResult.failure("Invalid credentials");
            }
            
            // Step 3: Check if account is locked
            if (isAccountLocked(user)) {
                metrics.incrementCounter("auth.account_locked");
                auditLogger.logFailedAuth(username, request.getRemoteAddr(), "Account locked");
                return AuthenticationResult.failure(
                    String.format("Account locked until %s", user.getLockoutExpiry())
                );
            }
            
            // Step 4: Verify password
            boolean passwordValid = verifyPassword(password, user.getPasswordHash(), user.getSalt());
            
            if (!passwordValid) {
                handleFailedAuthentication(user, request);
                return AuthenticationResult.failure("Invalid credentials");
            }
            
            // Step 5: Check if password expired
            if (isPasswordExpired(user)) {
                return AuthenticationResult.passwordExpired(user.getId());
            }
            
            // Step 6: Reset failed attempts
            resetFailedAttempts(user);
            
            // Step 7: Create session
            Session session = createSession(user, request);
            
            // Step 8: Log successful authentication
            auditLogger.logSuccessfulAuth(user.getId(), request.getRemoteAddr());
            metrics.recordTimer("auth.duration", Duration.between(startTime, Instant.now()));
            metrics.incrementCounter("auth.success");
            
            return AuthenticationResult.success(session.getToken(), user);
            
        } catch (Exception e) {
            metrics.incrementCounter("auth.error");
            auditLogger.logError("Authentication error", e);
            return AuthenticationResult.failure("Authentication service error");
        }
    }
    
    /**
     * Verify password against stored hash
     */
    private boolean verifyPassword(String password, String storedHash, byte[] salt) {
        try {
            String computedHash = hashPassword(password, salt);
            return computedHash.equals(storedHash);
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Hash password using PBKDF2 with SHA-256
     */
    private String hashPassword(String password, byte[] salt) 
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        
        int iterations = 100000; // OWASP recommendation
        int keyLength = 256;
        
        PBEKeySpec spec = new PBEKeySpec(
            password.toCharArray(),
            salt,
            iterations,
            keyLength
        );
        
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = factory.generateSecret(spec).getEncoded();
        
        return Base64.getEncoder().encodeToString(hash);
    }
    
    /**
     * Generate cryptographically secure salt
     */
    public byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }
    
    /**
     * Create new session for authenticated user
     */
    private Session createSession(User user, HttpServletRequest request) {
        Session session = Session.builder()
            .id(UUID.randomUUID().toString())
            .userId(user.getId())
            .token(generateSessionToken())
            .createdAt(Instant.now())
            .expiresAt(Instant.now().plus(SESSION_DURATION_HOURS, ChronoUnit.HOURS))
            .ipAddress(request.getRemoteAddr())
            .userAgent(request.getHeader("User-Agent"))
            .build();
            
        sessionRepository.save(session);
        
        // Update user's last login
        user.setLastLoginAt(Instant.now());
        user.setLastLoginIp(request.getRemoteAddr());
        userRepository.save(user);
        
        return session;
    }
    
    /**
     * Generate secure session token
     */
    private String generateSessionToken() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    
    /**
     * Handle failed authentication attempt
     */
    private void handleFailedAuthentication(User user, HttpServletRequest request) {
        int failedAttempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(failedAttempts);
        
        auditLogger.logFailedAuth(
            user.getUsername(),
            request.getRemoteAddr(),
            String.format("Invalid password (attempt %d)", failedAttempts)
        );
        
        if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
            // Lock account
            user.setLockedUntil(
                Instant.now().plus(LOCKOUT_DURATION_MINUTES, ChronoUnit.MINUTES)
            );
            auditLogger.logAccountLocked(user.getUsername(), failedAttempts);
            metrics.incrementCounter("auth.account_locked_auto");
        }
        
        userRepository.save(user);
        metrics.incrementCounter("auth.failed");
    }
    
    /**
     * Reset failed login attempts after successful authentication
     */
    private void resetFailedAttempts(User user) {
        if (user.getFailedLoginAttempts() > 0) {
            user.setFailedLoginAttempts(0);
            user.setLockedUntil(null);
            userRepository.save(user);
        }
    }
    
    /**
     * Check if account is currently locked
     */
    private boolean isAccountLocked(User user) {
        if (user.getLockedUntil() == null) {
            return false;
        }
        
        if (Instant.now().isAfter(user.getLockedUntil())) {
            // Lockout period expired, unlock account
            user.setLockedUntil(null);
            user.setFailedLoginAttempts(0);
            userRepository.save(user);
            return false;
        }
        
        return true;
    }
    
    /**
     * Check if password has expired
     */
    private boolean isPasswordExpired(User user) {
        if (user.getPasswordExpiresAt() == null) {
            return false;
        }
        return Instant.now().isAfter(user.getPasswordExpiresAt());
    }
    
    /**
     * Rate limiting based on IP address
     */
    private boolean isRateLimited(String ipAddress) {
        // Allow 10 attempts per minute per IP
        String key = "ratelimit:auth:" + ipAddress;
        int attempts = rateLimiter.getAttempts(key);
        
        if (attempts >= 10) {
            return true;
        }
        
        rateLimiter.incrementAttempts(key, Duration.ofMinutes(1));
        return false;
    }
}
```

### Complete Authorization Service

```java
package com.example.auth;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

public class AuthorizationService {
    
    private final UserRepository userRepository;
    private final PermissionRepository permissionRepository;
    private final ResourceRepository resourceRepository;
    private final AuditLogger auditLogger;
    private final PermissionCache permissionCache;
    
    public AuthorizationService(UserRepository userRepository,
                                 PermissionRepository permissionRepository,
                                 ResourceRepository resourceRepository,
                                 AuditLogger auditLogger,
                                 PermissionCache permissionCache) {
        this.userRepository = userRepository;
        this.permissionRepository = permissionRepository;
        this.resourceRepository = resourceRepository;
        this.auditLogger = auditLogger;
        this.permissionCache = permissionCache;
    }
    
    /**
     * Check if user has permission to perform action on resource
     */
    public AuthorizationResult authorize(String userId, String action, String resourceId) {
        return authorize(userId, action, resourceId, Collections.emptyMap());
    }
    
    /**
     * Check authorization with context (time, IP, etc.)
     */
    public AuthorizationResult authorize(String userId, 
                                         String action, 
                                         String resourceId,
                                         Map<String, Object> context) {
        
        Instant startTime = Instant.now();
        
        try {
            // Step 1: Check cache
            String cacheKey = buildCacheKey(userId, action, resourceId);
            AuthorizationResult cached = permissionCache.get(cacheKey);
            if (cached != null) {
                metrics.incrementCounter("authz.cache_hit");
                return cached;
            }
            metrics.incrementCounter("authz.cache_miss");
            
            // Step 2: Load user
            User user = userRepository.findById(userId);
            if (user == null) {
                return deny("User not found");
            }
            
            // Step 3: Load resource
            Resource resource = resourceRepository.findById(resourceId);
            if (resource == null) {
                return deny("Resource not found");
            }
            
            // Step 4: Check if user is resource owner (implicit permission)
            if (resource.getOwnerId().equals(userId)) {
                return allow("Resource owner");
            }
            
            // Step 5: Load user's roles
            Set<String> roles = loadUserRoles(userId);
            
            // Step 6: Load user's direct permissions
            Set<Permission> directPermissions = permissionRepository.findByUserId(userId);
            
            // Step 7: Load role-based permissions
            Set<Permission> rolePermissions = permissionRepository.findByRoles(roles);
            
            // Step 8: Combine all permissions
            Set<Permission> allPermissions = new HashSet<>();
            allPermissions.addAll(directPermissions);
            allPermissions.addAll(rolePermissions);
            
            // Step 9: Check for explicit DENY (takes precedence)
            for (Permission permission : allPermissions) {
                if (permission.getEffect() == Effect.DENY &&
                    matchesPermission(permission, action, resourceId)) {
                    
                    AuthorizationResult result = deny("Explicit deny rule");
                    auditLogger.logAuthzDenied(userId, action, resourceId, "explicit_deny");
                    return cacheAndReturn(cacheKey, result);
                }
            }
            
            // Step 10: Check for explicit ALLOW
            for (Permission permission : allPermissions) {
                if (permission.getEffect() == Effect.ALLOW &&
                    matchesPermission(permission, action, resourceId)) {
                    
                    // Step 11: Evaluate conditions
                    if (evaluateConditions(permission.getConditions(), context)) {
                        AuthorizationResult result = allow("Permission granted");
                        auditLogger.logAuthzAllowed(userId, action, resourceId, permission.getId());
                        return cacheAndReturn(cacheKey, result);
                    }
                }
            }
            
            // Step 12: Check resource-level permissions (ACL)
            if (resource.getAcl() != null) {
                ACLEntry aclEntry = resource.getAcl().findEntry(userId, roles);
                if (aclEntry != null && aclEntry.allows(action)) {
                    AuthorizationResult result = allow("Resource ACL");
                    return cacheAndReturn(cacheKey, result);
                }
            }
            
            // Step 13: Default deny (implicit)
            AuthorizationResult result = deny("No matching permission");
            auditLogger.logAuthzDenied(userId, action, resourceId, "default_deny");
            return cacheAndReturn(cacheKey, result);
            
        } finally {
            metrics.recordTimer("authz.duration", Duration.between(startTime, Instant.now()));
        }
    }
    
    /**
     * Check if permission matches action and resource
     */
    private boolean matchesPermission(Permission permission, String action, String resourceId) {
        // Check action match (supports wildcards)
        if (!matchesPattern(permission.getAction(), action)) {
            return false;
        }
        
        // Check resource match (supports wildcards)
        if (!matchesPattern(permission.getResourcePattern(), resourceId)) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Pattern matching with wildcard support
     */
    private boolean matchesPattern(String pattern, String value) {
        // Support * wildcard
        // Example: "documents:*" matches "documents:123", "documents:456", etc.
        
        if (pattern.equals("*")) {
            return true;
        }
        
        if (pattern.contains("*")) {
            String regex = pattern.replace("*", ".*");
            return value.matches(regex);
        }
        
        return pattern.equals(value);
    }
    
    /**
     * Evaluate permission conditions
     */
    private boolean evaluateConditions(List<Condition> conditions, Map<String, Object> context) {
        if (conditions == null || conditions.isEmpty()) {
            return true;
        }
        
        for (Condition condition : conditions) {
            if (!evaluateCondition(condition, context)) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Evaluate single condition
     */
    private boolean evaluateCondition(Condition condition, Map<String, Object> context) {
        Object contextValue = context.get(condition.getKey());
        
        switch (condition.getOperator()) {
            case EQUALS:
                return Objects.equals(contextValue, condition.getValue());
                
            case NOT_EQUALS:
                return !Objects.equals(contextValue, condition.getValue());
                
            case IN:
                List<?> values = (List<?>) condition.getValue();
                return values.contains(contextValue);
                
            case NOT_IN:
                List<?> notInValues = (List<?>) condition.getValue();
                return !notInValues.contains(contextValue);
                
            case GREATER_THAN:
                return compareValues(contextValue, condition.getValue()) > 0;
                
            case LESS_THAN:
                return compareValues(contextValue, condition.getValue()) < 0;
                
            case IP_IN_RANGE:
                String ip = (String) contextValue;
                String cidr = (String) condition.getValue();
                return isIpInRange(ip, cidr);
                
            case TIME_BETWEEN:
                Instant time = (Instant) contextValue;
                TimeRange range = (TimeRange) condition.getValue();
                return time.isAfter(range.getStart()) && time.isBefore(range.getEnd());
                
            default:
                return false;
        }
    }
    
    /**
     * Load all roles for a user (direct and inherited)
     */
    private Set<String> loadUserRoles(String userId) {
        Set<String> roles = new HashSet<>();
        
        // Load direct roles
        roles.addAll(userRepository.getUserRoles(userId));
        
        // Load group memberships
        List<Group> groups = userRepository.getUserGroups(userId);
        for (Group group : groups) {
            roles.addAll(group.getRoles());
        }
        
        return roles;
    }
    
    /**
     * Build cache key for permission check
     */
    private String buildCacheKey(String userId, String action, String resourceId) {
        return String.format("authz:%s:%s:%s", userId, action, resourceId);
    }
    
    /**
     * Cache authorization result
     */
    private AuthorizationResult cacheAndReturn(String cacheKey, AuthorizationResult result) {
        // Cache for 5 minutes
        permissionCache.put(cacheKey, result, Duration.ofMinutes(5));
        return result;
    }
    
    /**
     * Helper methods for result creation
     */
    private AuthorizationResult allow(String reason) {
        return AuthorizationResult.builder()
            .allowed(true)
            .reason(reason)
            .timestamp(Instant.now())
            .build();
    }
    
    private AuthorizationResult deny(String reason) {
        return AuthorizationResult.builder()
            .allowed(false)
            .reason(reason)
            .timestamp(Instant.now())
            .build();
    }
}
```

### Models and DTOs

```java
// User.java
@Data
@Builder
public class User {
    private String id;
    private String username;
    private String email;
    private String passwordHash;
    private byte[] salt;
    private Instant passwordExpiresAt;
    private int failedLoginAttempts;
    private Instant lockedUntil;
    private Instant lastLoginAt;
    private String lastLoginIp;
    private Instant createdAt;
    private Instant updatedAt;
    private boolean active;
}

// Session.java
@Data
@Builder
public class Session {
    private String id;
    private String userId;
    private String token;
    private Instant createdAt;
    private Instant expiresAt;
    private String ipAddress;
    private String userAgent;
    private Map<String, Object> metadata;
}

// Permission.java
@Data
@Builder
public class Permission {
    private String id;
    private Effect effect; // ALLOW or DENY
    private String action; // "read", "write", "documents:*"
    private String resourcePattern; // "documents:123", "users:*"
    private List<Condition> conditions;
    private String grantedBy;
    private Instant createdAt;
    private Instant expiresAt;
}

// Condition.java
@Data
@Builder
public class Condition {
    private String key; // "ip_address", "time", "user_agent"
    private ConditionOperator operator; // EQUALS, IN, GREATER_THAN, etc.
    private Object value;
}

// Resource.java
@Data
@Builder
public class Resource {
    private String id;
    private String type; // "document", "image", "folder"
    private String ownerId;
    private ACL acl; // Access Control List
    private Map<String, Object> metadata;
    private Instant createdAt;
    private Instant updatedAt;
}

// ACL.java
@Data
public class ACL {
    private List<ACLEntry> entries;
    
    public ACLEntry findEntry(String userId, Set<String> roles) {
        for (ACLEntry entry : entries) {
            if (entry.getPrincipalType() == PrincipalType.USER && 
                entry.getPrincipalId().equals(userId)) {
                return entry;
            }
            
            if (entry.getPrincipalType() == PrincipalType.ROLE &&
                roles.contains(entry.getPrincipalId())) {
                return entry;
            }
        }
        return null;
    }
}

// ACLEntry.java
@Data
@Builder
public class ACLEntry {
    private PrincipalType principalType; // USER or ROLE
    private String principalId;
    private Set<String> permissions; // ["read", "write"]
    
    public boolean allows(String action) {
        return permissions.contains(action) || permissions.contains("*");
    }
}

// AuthenticationResult.java
@Data
@Builder
public class AuthenticationResult {
    private boolean success;
    private String token;
    private User user;
    private String errorMessage;
    private AuthenticationStatus status;
    
    public static AuthenticationResult success(String token, User user) {
        return AuthenticationResult.builder()
            .success(true)
            .token(token)
            .user(user)
            .status(AuthenticationStatus.SUCCESS)
            .build();
    }
    
    public static AuthenticationResult failure(String message) {
        return AuthenticationResult.builder()
            .success(false)
            .errorMessage(message)
            .status(AuthenticationStatus.FAILED)
            .build();
    }
    
    public static AuthenticationResult passwordExpired(String userId) {
        return AuthenticationResult.builder()
            .success(false)
            .errorMessage("Password expired")
            .status(AuthenticationStatus.PASSWORD_EXPIRED)
            .build();
    }
}

// AuthorizationResult.java
@Data
@Builder
public class AuthorizationResult {
    private boolean allowed;
    private String reason;
    private Instant timestamp;
    private Map<String, Object> context;
}

// Enums
public enum Effect {
    ALLOW, DENY
}

public enum PrincipalType {
    USER, ROLE, GROUP
}

public enum AuthenticationStatus {
    SUCCESS, FAILED, PASSWORD_EXPIRED, ACCOUNT_LOCKED, MFA_REQUIRED
}

public enum ConditionOperator {
    EQUALS, NOT_EQUALS, IN, NOT_IN, 
    GREATER_THAN, LESS_THAN, 
    IP_IN_RANGE, TIME_BETWEEN, MATCHES_REGEX
}
```

---

## Interview Questions & Answers

### Question 1: Design the authentication system for a banking application

**Interviewer**: "Design the authentication system for a banking app. It needs to be highly secure because users are accessing their financial information."

**Answer**:

```
Step 1: Identify Requirements
- Multi-factor authentication (mandatory)
- Device fingerprinting
- Geo-location verification
- Session timeout (shorter than typical apps)
- Biometric support (fingerprint, face ID)
- Transaction signing

Step 2: High-Level Architecture

┌─────────────┐
│   Client    │
│  (Mobile)   │
└──────┬──────┘
       │
       │ 1. Login Request
       │
┌──────▼──────────────────────────────────┐
│         API Gateway                     │
│  - Rate limiting                        │
│  - DDoS protection                      │
└──────┬──────────────────────────────────┘
       │
       │ 2. Route to Auth Service
       │
┌──────▼──────────────────────────────────┐
│      Authentication Service             │
│  ┌────────────────────────────────┐    │
│  │ 1. Validate credentials         │    │
│  │ 2. Check device fingerprint     │    │
│  │ 3. Verify location              │    │
│  │ 4. Send OTP                     │    │
│  │ 5. Create session               │    │
│  └────────────────────────────────┘    │
└──────┬──────────────────────────────────┘
       │
       ├──────────► User DB (credentials)
       │
       ├──────────► Session Store (Redis)
       │
       ├──────────► Device Registry
       │
       └──────────► Audit Log
```

**Implementation**:

```java
public class BankingAuthenticationService {
    
    public AuthResult authenticateUser(LoginRequest request) {
        // Step 1: Validate credentials
        User user = validateCredentials(request.getUsername(), request.getPassword());
        if (user == null) {
            logSuspiciousActivity(request);
            return AuthResult.failed("Invalid credentials");
        }
        
        // Step 2: Device verification
        DeviceVerification deviceCheck = verifyDevice(user, request.getDeviceInfo());
        if (!deviceCheck.isTrusted()) {
            // New device detected - require additional verification
            sendDeviceVerificationEmail(user);
            return AuthResult.pendingDeviceVerification();
        }
        
        // Step 3: Geo-location check
        GeoLocation location = getLocation(request.getIpAddress());
        if (isUnusualLocation(user, location)) {
            // Unusual location - require OTP
            sendLocationVerificationOTP(user);
            return AuthResult.pendingLocationVerification();
        }
        
        // Step 4: Send OTP (always required for banking)
        String otp = generateOTP();
        sendOTP(user.getPhoneNumber(), otp);
        storeOTPForVerification(user.getId(), otp);
        
        return AuthResult.pendingMFA(user.getId());
    }
    
    public AuthResult verifyMFA(String userId, String otp) {
        // Verify OTP
        if (!validateOTP(userId, otp)) {
            incrementFailedMFAAttempts(userId);
            return AuthResult.failed("Invalid OTP");
        }
        
        // Create session with short timeout (15 minutes for banking)
        Session session = createSession(userId, Duration.ofMinutes(15));
        
        // Require re-authentication for sensitive operations
        session.requiresStepUp(Arrays.asList(
            "transfer_money",
            "add_beneficiary",
            "change_settings"
        ));
        
        return AuthResult.success(session.getToken());
    }
    
    public AuthResult stepUpAuthentication(String userId, String action) {
        // For sensitive actions, require biometric or PIN
        if (requiresStepUp(action)) {
            return AuthResult.requiresBiometric();
        }
        return AuthResult.success();
    }
    
    private boolean isUnusualLocation(User user, GeoLocation location) {
        // Check if user has logged in from this country before
        List<GeoLocation> history = getLocationHistory(user.getId());
        
        if (history.stream().noneMatch(l -> l.getCountry().equals(location.getCountry()))) {
            return true;
        }
        
        // Check for impossible travel
        GeoLocation lastLocation = getLastLocation(user.getId());
        if (lastLocation != null) {
            double distance = calculateDistance(lastLocation, location);
            long timeDiff = getTimeSinceLastLogin(user.getId());
            double speed = distance / timeDiff; // km/hour
            
            if (speed > 900) { // Faster than airplane
                return true;
            }
        }
        
        return false;
    }
}
```

**Key Security Measures**:

1. **Always-on MFA**: OTP required for every login
2. **Device fingerprinting**: Track trusted devices
3. **Geo-location verification**: Detect unusual locations
4. **Step-up authentication**: Extra verification for sensitive actions
5. **Short session timeout**: 15 minutes instead of typical 24 hours
6. **Transaction signing**: Each transaction requires separate auth

### Question 2: How would you prevent account enumeration attacks?

**Interviewer**: "An attacker is trying to find valid usernames by checking if 'user not found' vs 'invalid password' errors differ."

**Answer**:

Account enumeration allows attackers to discover valid usernames, which is the first step in credential stuffing attacks.

**Bad Implementation** (Vulnerable):
```java
// ❌ DON'T DO THIS
public AuthResult login(String username, String password) {
    User user = userRepo.findByUsername(username);
    
    if (user == null) {
        return AuthResult.failed("User not found"); // ⚠️ Reveals username doesn't exist
    }
    
    if (!verifyPassword(password, user.getPasswordHash())) {
        return AuthResult.failed("Invalid password"); // ⚠️ Reveals username exists
    }
    
    return AuthResult.success(token);
}
```

**Good Implementation** (Secure):
```java
// ✓ DO THIS
public AuthResult login(String username, String password) {
    User user = userRepo.findByUsername(username);
    
    // Always return same generic message
    String genericError = "Invalid username or password";
    
    if (user == null) {
        // Perform fake password verification to maintain timing
        performFakePasswordVerification();
        logFailedAttempt(username, "user_not_found");
        return AuthResult.failed(genericError); // Same message
    }
    
    if (!verifyPassword(password, user.getPasswordHash())) {
        logFailedAttempt(username, "invalid_password");
        return AuthResult.failed(genericError); // Same message
    }
    
    return AuthResult.success(token);
}

// Timing attack prevention
private void performFakePasswordVerification() {
    // Perform same hash operation to maintain consistent timing
    String fakePassword = "dummy_password";
    byte[] fakeSalt = new byte[16];
    hashPassword(fakePassword, fakeSalt);
}
```

**Additional Measures**:

```java
public class EnumerationPrevention {
    
    // 1. Rate limiting per IP and per username
    public boolean checkRateLimit(String identifier) {
        String ipKey = "ratelimit:ip:" + getClientIp();
        String usernameKey = "ratelimit:username:" + identifier;
        
        // Allow 5 attempts per 15 minutes per IP
        if (rateLimiter.getAttempts(ipKey) >= 5) {
            return false;
        }
        
        // Allow 3 attempts per 15 minutes per username
        if (rateLimiter.getAttempts(usernameKey) >= 3) {
            return false;
        }
        
        return true;
    }
    
    // 2. CAPTCHA after failed attempts
    public boolean requiresCaptcha(String identifier) {
        int attempts = getFailedAttempts(identifier);
        return attempts >= 3;
    }
    
    // 3. Consistent response time
    public AuthResult loginWithConstantTime(String username, String password) {
        long startTime = System.nanoTime();
        
        AuthResult result = performLogin(username, password);
        
        // Ensure minimum response time of 100ms to prevent timing attacks
        long elapsedTime = System.nanoTime() - startTime;
        long minTime = 100_000_000L; // 100ms in nanoseconds
        
        if (elapsedTime < minTime) {
            try {
                Thread.sleep((minTime - elapsedTime) / 1_000_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        return result;
    }
    
    // 4. Monitor for enumeration patterns
    public void detectEnumerationAttack() {
        // Pattern: Many failed logins with different usernames from same IP
        String ip = getClientIp();
        Set<String> attemptedUsernames = getAttemptedUsernames(ip, Duration.ofMinutes(15));
        
        if (attemptedUsernames.size() > 20) {
            // Likely enumeration attack
            blockIP(ip, Duration.ofHours(24));
            alertSecurityTeam("Enumeration attack detected", ip);
        }
    }
}
```

### Question 3: Design authorization for a document sharing system like Google Drive

**Interviewer**: "Users can create documents, share them with specific people, and create folders. How would you design the authorization system?"

**Answer**:

```
Requirements:
1. Owner has full permissions
2. Can share with specific users (read/write/comment)
3. Can share via link (anyone with link)
4. Folders inherit permissions
5. Can revoke access
6. View-only, comment-only, edit permissions

Architecture:

┌─────────────────────────────────────┐
│         Resource (Document)          │
│  - id: "doc_123"                    │
│  - owner_id: "user_456"             │
│  - parent_folder_id: "folder_789"   │
└─────────────────────────────────────┘
           │
           │ has
           ▼
┌─────────────────────────────────────┐
│         Access Control List          │
│  ┌───────────────────────────────┐  │
│  │ Entry 1: user_111 → "write"   │  │
│  │ Entry 2: user_222 → "read"    │  │
│  │ Entry 3: anyone → "read"      │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

**Implementation**:

```java
public class DocumentAuthorizationService {
    
    public AuthzResult canAccess(String userId, String documentId, String action) {
        Document doc = documentRepo.findById(documentId);
        
        // Step 1: Owner has all permissions
        if (doc.getOwnerId().equals(userId)) {
            return AuthzResult.allowed("owner");
        }
        
        // Step 2: Check direct ACL on document
        ACLEntry directEntry = doc.getAcl().findEntry(userId);
        if (directEntry != null && hasPermission(directEntry, action)) {
            return AuthzResult.allowed("direct_acl");
        }
        
        // Step 3: Check inherited permissions from parent folders
        String folderId = doc.getParentFolderId();
        while (folderId != null) {
            Folder folder = folderRepo.findById(folderId);
            ACLEntry folderEntry = folder.getAcl().findEntry(userId);
            
            if (folderEntry != null && hasPermission(folderEntry, action)) {
                return AuthzResult.allowed("inherited_from_folder");
            }
            
            folderId = folder.getParentFolderId();
        }
        
        // Step 4: Check "anyone with link" permission
        if (doc.isLinkSharingEnabled()) {
            LinkPermission linkPerm = doc.getLinkPermission();
            if (hasPermission(linkPerm, action)) {
                return AuthzResult.allowed("link_sharing");
            }
        }
        
        // Step 5: Check domain sharing (if org document)
        if (doc.getOrganizationId() != null) {
            User user = userRepo.findById(userId);
            if (user.getOrganizationId().equals(doc.getOrganizationId())) {
                DomainPermission domainPerm = doc.getDomainPermission();
                if (domainPerm != null && hasPermission(domainPerm, action)) {
                    return AuthzResult.allowed("domain_sharing");
                }
            }
        }
        
        return AuthzResult.denied("no_permission");
    }
    
    private boolean hasPermission(PermissionEntry entry, String action) {
        switch (entry.getRole()) {
            case OWNER:
                return true; // All permissions
                
            case EDITOR:
                return action.equals("read") || 
                       action.equals("write") || 
                       action.equals("comment");
                
            case COMMENTER:
                return action.equals("read") || 
                       action.equals("comment");
                
            case VIEWER:
                return action.equals("read");
                
            default:
                return false;
        }
    }
    
    public void shareDocument(String documentId, String sharerUserId, 
                              String shareWithUserId, Role role) {
        Document doc = documentRepo.findById(documentId);
        
        // Verify sharer has permission to share
        if (!canAccess(sharerUserId, documentId, "share").isAllowed()) {
            throw new UnauthorizedException("You cannot share this document");
        }
        
        // Add ACL entry
        ACLEntry entry = ACLEntry.builder()
            .principalType(PrincipalType.USER)
            .principalId(shareWithUserId)
            .role(role)
            .grantedBy(sharerUserId)
            .grantedAt(Instant.now())
            .build();
            
        doc.getAcl().addEntry(entry);
        documentRepo.save(doc);
        
        // Send notification
        notificationService.sendShareNotification(shareWithUserId, documentId, sharerUserId);
        
        // Audit log
        auditLogger.log("document_shared", Map.of(
            "document_id", documentId,
            "shared_by", sharerUserId,
            "shared_with", shareWithUserId,
            "role", role.name()
        ));
    }
    
    public void revokeAccess(String documentId, String revokerId, String userId) {
        Document doc = documentRepo.findById(documentId);
        
        // Only owner or the user themselves can revoke
        if (!doc.getOwnerId().equals(revokerId) && !userId.equals(revokerId)) {
            throw new UnauthorizedException("Cannot revoke access");
        }
        
        doc.getAcl().removeEntry(userId);
        documentRepo.save(doc);
        
        // Invalidate cached permissions
        permissionCache.invalidate(userId, documentId);
    }
}
```

**Optimization: Permission Caching**:

```java
public class PermissionCacheService {
    private final Cache<String, AuthzResult> cache;
    
    public PermissionCacheService() {
        this.cache = CacheBuilder.newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .maximumSize(100000)
            .build();
    }
    
    public AuthzResult getCached(String userId, String documentId, String action) {
        String key = String.format("%s:%s:%s", userId, documentId, action);
        return cache.getIfPresent(key);
    }
    
    public void cache(String userId, String documentId, String action, AuthzResult result) {
        String key = String.format("%s:%s:%s", userId, documentId, action);
        cache.put(key, result);
    }
    
    // Invalidate when ACL changes
    public void invalidateDocument(String documentId) {
        cache.invalidateAll();
    }
}
```

---

## Common Pitfalls & How to Avoid Them

### Pitfall 1: Storing Passwords in Plain Text

**Never** store passwords in plain text or reversible encryption.

```java
// ❌ NEVER DO THIS
public void createUser(String username, String password) {
    User user = new User();
    user.setUsername(username);
    user.setPassword(password); // Stored as plain text!
    userRepo.save(user);
}

// ✓ DO THIS
public void createUser(String username, String password) {
    byte[] salt = generateSalt();
    String hashedPassword = hashPassword(password, salt);
    
    User user = new User();
    user.setUsername(username);
    user.setPasswordHash(hashedPassword);
    user.setSalt(salt);
    userRepo.save(user);
}
```

### Pitfall 2: Not Implementing Rate Limiting

Attackers can brute-force passwords without rate limiting.

```java
// ✓ Implement rate limiting
@Component
public class LoginRateLimiter {
    private final RateLimiter<String> limiter;
    
    public LoginRateLimiter() {
        // 5 attempts per 15 minutes per IP
        this.limiter = RateLimiter.<String>builder()
            .maxAttempts(5)
            .window(Duration.ofMinutes(15))
            .build();
    }
    
    public boolean allowLogin(String ipAddress) {
        return limiter.tryAcquire(ipAddress);
    }
}
```

### Pitfall 3: Not Checking Authorization on Every Request

```java
// ❌ DON'T DO THIS
@GetMapping("/documents/{id}")
public Document getDocument(@PathVariable String id) {
    return documentRepo.findById(id); // No authorization check!
}

// ✓ DO THIS
@GetMapping("/documents/{id}")
public Document getDocument(@PathVariable String id, Authentication auth) {
    String userId = auth.getPrincipal().getId();
    
    if (!authzService.canAccess(userId, id, "read").isAllowed()) {
        throw new ForbiddenException();
    }
    
    return documentRepo.findById(id);
}
```

### Pitfall 4: Session Fixation

Attacker sets user's session ID before login.

```java
// ✓ Regenerate session ID after login
public AuthResult login(String username, String password) {
    User user = authenticate(username, password);
    
    // Invalidate old session
    sessionManager.invalidateSession(getCurrentSessionId());
    
    // Create new session with new ID
    Session newSession = sessionManager.createNewSession(user);
    
    return AuthResult.success(newSession.getId());
}
```

### Pitfall 5: Not Implementing Audit Logging

Without audit logs, you can't detect or investigate security incidents.

```java
// ✓ Log all authentication and authorization events
public class SecurityAuditLogger {
    
    public void logLoginAttempt(String username, String ipAddress, boolean success) {
        AuditEvent event = AuditEvent.builder()
            .eventType(success ? "LOGIN_SUCCESS" : "LOGIN_FAILURE")
            .username(username)
            .ipAddress(ipAddress)
            .timestamp(Instant.now())
            .build();
            
        auditRepo.save(event);
    }
    
    public void logAuthorizationDenied(String userId, String action, String resourceId) {
        AuditEvent event = AuditEvent.builder()
            .eventType("AUTHORIZATION_DENIED")
            .userId(userId)
            .action(action)
            .resourceId(resourceId)
            .timestamp(Instant.now())
            .build();
            
        auditRepo.save(event);
    }
}
```

---

## Summary: Authentication vs Authorization

**Authentication** = "Who are you?" (Identity verification)
- Proves user identity
- Methods: passwords, MFA, biometrics
- Happens once at login (or periodically)
- Examples: Google 2SV, Touch ID

**Authorization** = "What can you do?" (Permission verification)
- Checks user permissions
- Happens on every request
- Can be role-based, resource-based, attribute-based
- Examples: AWS IAM, Facebook privacy settings

**Key Principle**: You cannot have authorization without authentication. Must verify identity before granting permissions.

---

# S2: OAuth 2.0 & OpenID Connect

## 🏨 The Hotel Key Card Analogy

Imagine you're staying at a luxury hotel:

**Traditional Authentication** (Username/Password):
- You show your ID at front desk
- They give you a physical key that works everywhere
- If you lose the key, anyone can access your room
- You must share your key with roomservice, valet, etc.

**OAuth 2.0**:
- Front desk gives you a key card (access token)
- Different cards for different services:
    - Room card: Access only your room
    - Gym card: Access gym during certain hours
    - Pool card: Access pool area
- Cards can be time-limited
- Cards can be revoked without changing room lock
- You never share your master key (password)

**Real Example**: When you click "Sign in with Google" on a website:
- Website asks Google: "Can this user access their info?"
- Google asks user: "Allow website to see your profile?"
- User approves
- Google gives website a temporary access card (token)
- Website uses card to fetch your info from Google
- Your password never leaves Google

---

## Beginner Level: OAuth 2.0 Basics

### What Problem Does OAuth 2.0 Solve?

**Scenario**: You want to use a photo printing service that needs access to your Google Photos.

**Bad Solution** (Pre-OAuth):
```
1. Give photo service your Google username and password
2. Service logs into Google as you
3. Downloads your photos

Problems:
❌ Service has full access to your Google account
❌ Can read emails, send emails, delete data
❌ Password shared with third-party
❌ Can't revoke access without changing password
❌ Google can't distinguish between you and the service
```

**OAuth 2.0 Solution**:
```
1. Photo service redirects you to Google
2. Google asks: "Allow photo service to access your photos?"
3. You click "Allow"
4. Google gives service an access token
5. Token only grants permission to read photos (nothing else)
6. Token expires in 1 hour
7. You can revoke anytime from Google settings

Benefits:
✓ Service never sees your password
✓ Limited permissions (read photos only)
✓ Time-limited access
✓ Can revoke without changing password
✓ Google knows it's the service accessing (audit trail)
```

### OAuth 2.0 Roles

**Four Roles in OAuth 2.0**:

1. **Resource Owner** (User)
    - The person who owns the data
    - Example: You (who owns Google Photos)

2. **Client** (Third-party Application)
    - The app requesting access
    - Example: Photo printing service

3. **Authorization Server** (OAuth Provider)
    - Issues access tokens
    - Example: Google's OAuth server (accounts.google.com)

4. **Resource Server** (API)
    - Hosts the protected data
    - Example: Google Photos API (photos.googleapis.com)

### OAuth 2.0 Flow (Authorization Code Grant)

This is the most secure and most commonly used flow:

```
┌──────────┐                                      ┌──────────────┐
│          │                                      │              │
│   User   │                                      │   Browser    │
│          │                                      │              │
└────┬─────┘                                      └───────┬──────┘
     │                                                    │
     │ 1. Click "Sign in with Google"                   │
     │───────────────────────────────────────────────────▶
     │                                                    │
     │                                                    │ 2. Redirect to Google
     │                                                    ├────────────────────┐
     │                                                    │                    │
     │                                                    │                    ▼
     │                                              ┌─────┴──────────────────────┐
     │                                              │  Google Authorization      │
     │                                              │  Server                    │
     │                                              │                            │
     │ 3. User logs in and approves                │  "Allow photo service to   │
     │◀─────────────────────────────────────────────│   access your photos?"     │
     │                                              │                            │
     │ 4. User clicks "Allow"                      │   [Allow] [Deny]           │
     │──────────────────────────────────────────────▶                           │
     │                                              │                            │
     │                                              └─────┬──────────────────────┘
     │                                                    │
     │ 5. Redirect back with authorization code          │
     │◀───────────────────────────────────────────────────┤
     │   callback?code=AUTH_CODE_XYZ                     │
     │                                                    │
     ▼                                                    ▼
┌────────────────────────────────────────────────────────────┐
│                 Photo Printing Service                     │
│                                                            │
│  6. Exchange authorization code for access token          │
│     POST /token                                           │
│     code=AUTH_CODE_XYZ                                    │
│     client_id=photo-service                               │
│     client_secret=SECRET                                  │
└───────────────────────────┬────────────────────────────────┘
                            │
                            │ 7. Return access token
                            ▼
                  ┌─────────────────────┐
                  │  Authorization       │
                  │  Server              │
                  │                      │
                  │  {                   │
                  │    "access_token":   │
                  │    "ya29.a0AfH6S...",│
                  │    "expires_in": 3600│
                  │  }                   │
                  └──────────────────────┘

8. Photo service uses access token to fetch photos from Google Photos API
   GET https://photos.googleapis.com/v1/albums
   Authorization: Bearer ya29.a0AfH6S...
```

**Step-by-Step Breakdown**:

```
Step 1: Initial Request
- User clicks "Sign in with Google" on photo service
- Photo service redirects to: 
  https://accounts.google.com/o/oauth2/auth?
    client_id=photo-service&
    redirect_uri=https://photoservice.com/callback&
    response_type=code&
    scope=https://www.googleapis.com/auth/photoslibrary.readonly

Step 2-4: User Authorization
- Google shows login page (if not logged in)
- Google shows consent screen: "Allow photo service to access your photos?"
- User clicks "Allow"

Step 5: Authorization Code
- Google redirects back to photo service:
  https://photoservice.com/callback?code=AUTH_CODE_XYZ
- This code is single-use and expires in ~10 minutes

Step 6-7: Token Exchange
- Photo service makes backend request to Google:
  POST https://oauth2.googleapis.com/token
  {
    "code": "AUTH_CODE_XYZ",
    "client_id": "photo-service",
    "client_secret": "SECRET_KEY",
    "redirect_uri": "https://photoservice.com/callback",
    "grant_type": "authorization_code"
  }
- Google returns:
  {
    "access_token": "ya29.a0AfH6S...",
    "expires_in": 3600,
    "refresh_token": "1//0gK...",
    "scope": "https://www.googleapis.com/auth/photoslibrary.readonly",
    "token_type": "Bearer"
  }

Step 8: Use Access Token
- Photo service calls Google Photos API:
  GET https://photos.googleapis.com/v1/albums
  Authorization: Bearer ya29.a0AfH6S...
- Google Photos API validates token and returns user's photos
```

---

## Intermediate Level: OAuth 2.0 Grants

OAuth 2.0 has several "grant types" (flows) for different scenarios.

### 1. Authorization Code Grant (Most Secure)

**Use Case**: Web applications with a backend server

**Security**: Highest
- Client secret stored on server (not exposed to browser)
- Access token never exposed to browser
- Authorization code is single-use

**Java Implementation**:

```java
@RestController
@RequestMapping("/auth")
public class OAuth2Controller {
    
    @Value("${oauth2.client-id}")
    private String clientId;
    
    @Value("${oauth2.client-secret}")
    private String clientSecret;
    
    @Value("${oauth2.redirect-uri}")
    private String redirectUri;
    
    private static final String AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth";
    private static final String TOKEN_URL = "https://oauth2.googleapis.com/token";
    
    /**
     * Step 1: Redirect user to authorization server
     */
    @GetMapping("/login")
    public RedirectView initiateOAuth2Flow() {
        // Generate random state for CSRF protection
        String state = UUID.randomUUID().toString();
        
        // Store state in session to verify later
        session.setAttribute("oauth2_state", state);
        
        // Build authorization URL
        String authUrl = UriComponentsBuilder.fromHttpUrl(AUTHORIZATION_URL)
            .queryParam("client_id", clientId)
            .queryParam("redirect_uri", redirectUri)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid email profile")
            .queryParam("state", state)
            .build()
            .toUriString();
            
        return new RedirectView(authUrl);
    }
    
    /**
     * Step 2: Handle callback with authorization code
     */
    @GetMapping("/callback")
    public ResponseEntity<?> handleCallback(
            @RequestParam("code") String code,
            @RequestParam("state") String state) {
        
        // Verify state parameter (CSRF protection)
        String sessionState = (String) session.getAttribute("oauth2_state");
        if (!state.equals(sessionState)) {
            return ResponseEntity.badRequest().body("Invalid state parameter");
        }
        
        try {
            // Exchange authorization code for tokens
            TokenResponse tokens = exchangeCodeForTokens(code);
            
            // Store tokens securely
            storeTokens(tokens);
            
            // Fetch user info
            UserInfo userInfo = getUserInfo(tokens.getAccessToken());
            
            // Create session
            createUserSession(userInfo);
            
            return ResponseEntity.ok(userInfo);
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("OAuth2 flow failed: " + e.getMessage());
        }
    }
    
    /**
     * Exchange authorization code for access token
     */
    private TokenResponse exchangeCodeForTokens(String code) throws IOException {
        HttpClient client = HttpClient.newHttpClient();
        
        // Build request body
        Map<String, String> params = Map.of(
            "code", code,
            "client_id", clientId,
            "client_secret", clientSecret,
            "redirect_uri", redirectUri,
            "grant_type", "authorization_code"
        );
        
        String requestBody = params.entrySet().stream()
            .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .collect(Collectors.joining("&"));
        
        // Make POST request
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(TOKEN_URL))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(requestBody))
            .build();
        
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        
        if (response.statusCode() != 200) {
            throw new IOException("Token exchange failed: " + response.body());
        }
        
        // Parse response
        return objectMapper.readValue(response.body(), TokenResponse.class);
    }
    
    /**
     * Fetch user info using access token
     */
    private UserInfo getUserInfo(String accessToken) throws IOException {
        HttpClient client = HttpClient.newHttpClient();
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://www.googleapis.com/oauth2/v3/userinfo"))
            .header("Authorization", "Bearer " + accessToken)
            .GET()
            .build();
        
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        
        return objectMapper.readValue(response.body(), UserInfo.class);
    }
}

@Data
class TokenResponse {
    @JsonProperty("access_token")
    private String accessToken;
    
    @JsonProperty("refresh_token")
    private String refreshToken;
    
    @JsonProperty("expires_in")
    private int expiresIn;
    
    @JsonProperty("token_type")
    private String tokenType;
    
    private String scope;
}

@Data
class UserInfo {
    private String sub; // Subject (user ID)
    private String email;
    private String name;
    private String picture;
    @JsonProperty("email_verified")
    private boolean emailVerified;
}
```

### 2. Implicit Grant (Deprecated - Don't Use)

**Use Case**: Single-page applications (legacy)

**Security**: LOW - Access token exposed in browser
**Status**: DEPRECATED - Use Authorization Code Grant with PKCE instead

**Why it's insecure**:
```
// ❌ Access token in URL (visible in browser history)
https://myapp.com/#access_token=ya29.a0AfH6S...&token_type=Bearer

Problems:
- Token visible in browser history
- Token visible in server logs
- Token visible in Referer header
- No client authentication
- No refresh token
```

### 3. Authorization Code Grant with PKCE

**Use Case**: Mobile apps and single-page applications

**PKCE** = Proof Key for Code Exchange (pronounced "pixie")

**Problem it solves**: Mobile apps can't securely store client_secret

**How PKCE works**:

```java
public class PKCEOAuth2Service {
    
    /**
     * Step 1: Generate code verifier and challenge
     */
    public PKCEParams generatePKCE() {
        // Generate random code verifier (43-128 characters)
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String codeVerifier = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(bytes);
        
        // Generate code challenge (SHA-256 hash of verifier)
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
        String codeChallenge = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(hash);
        
        return new PKCEParams(codeVerifier, codeChallenge);
    }
    
    /**
     * Step 2: Initiate OAuth flow with code challenge
     */
    public String buildAuthorizationUrl(PKCEParams pkce) {
        // Store code verifier locally (will need it later)
        localStorage.set("code_verifier", pkce.getCodeVerifier());
        
        return UriComponentsBuilder.fromHttpUrl(AUTHORIZATION_URL)
            .queryParam("client_id", clientId)
            .queryParam("redirect_uri", redirectUri)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid email profile")
            .queryParam("code_challenge", pkce.getCodeChallenge())
            .queryParam("code_challenge_method", "S256") // SHA-256
            .build()
            .toUriString();
    }
    
    /**
     * Step 3: Exchange code for token (with code verifier)
     */
    public TokenResponse exchangeCode(String code) throws IOException {
        // Retrieve stored code verifier
        String codeVerifier = localStorage.get("code_verifier");
        
        Map<String, String> params = Map.of(
            "code", code,
            "client_id", clientId,
            "redirect_uri", redirectUri,
            "grant_type", "authorization_code",
            "code_verifier", codeVerifier // Send verifier, not challenge
        );
        
        // Note: NO client_secret needed
        
        return makeTokenRequest(params);
    }
}

@Data
@AllArgsConstructor
class PKCEParams {
    private String codeVerifier;  // Random string (stored locally)
    private String codeChallenge; // SHA256(codeVerifier) (sent to server)
}
```

**Why PKCE is secure**:
```
1. Attacker intercepts authorization code
2. Attacker tries to exchange code for token
3. Server asks for code_verifier
4. Attacker doesn't have code_verifier (it's on legitimate app)
5. Server verifies: SHA256(code_verifier) == code_challenge
6. Verification fails → Token request denied
```

### 4. Client Credentials Grant

**Use Case**: Machine-to-machine communication (no user involved)

**Example**: Your backend service calling another API

```java
public class ClientCredentialsOAuth2Service {
    
    /**
     * Get access token using client credentials
     */
    public String getAccessToken() throws IOException {
        HttpClient client = HttpClient.newHttpClient();
        
        Map<String, String> params = Map.of(
            "grant_type", "client_credentials",
            "client_id", clientId,
            "client_secret", clientSecret,
            "scope", "api.read api.write"
        );
        
        String body = params.entrySet().stream()
            .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .collect(Collectors.joining("&"));
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(TOKEN_URL))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        
        HttpResponse<String> response = client.send(request, 
            HttpResponse.BodyHandlers.ofString());
        
        TokenResponse tokens = objectMapper.readValue(response.body(), TokenResponse.class);
        return tokens.getAccessToken();
    }
    
    /**
     * Use access token to call API
     */
    public String callAPI(String accessToken, String endpoint) throws IOException {
        HttpClient client = HttpClient.newHttpClient();
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(endpoint))
            .header("Authorization", "Bearer " + accessToken)
            .GET()
            .build();
        
        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());
        
        return response.body();
    }
}
```

**When to use Client Credentials**:
- Microservice A calling Microservice B
- Backend job accessing API
- CLI tool accessing API
- No user context needed

---

## Advanced: OpenID Connect (OIDC)

### What is OpenID Connect?

**OAuth 2.0** = Authorization protocol (access resources)
**OpenID Connect** = Authentication protocol built on OAuth 2.0

**Key Difference**:
- OAuth 2.0 tells you what user can access
- OIDC tells you who the user is

### OIDC Adds to OAuth 2.0

1. **ID Token** (JWT) - Contains user identity information
2. **UserInfo Endpoint** - Standardized way to get user info
3. **Standard scopes** - `openid`, `profile`, `email`

### ID Token vs Access Token

```
Access Token:
- Opaque string (random characters)
- Used to access APIs
- Not meant to be read by client
- Example: "ya29.a0AfH6SMfP..."

ID Token (JWT):
- JSON Web Token (readable)
- Contains user identity claims
- Meant to be read by client  
- Example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

Decoded ID Token:
{
  "sub": "10769150350006150715113082367", // User ID
  "name": "John Doe",
  "email": "john@example.com",
  "email_verified": true,
  "picture": "https://lh3.googleusercontent.com/...",
  "iss": "https://accounts.google.com", // Issuer
  "aud": "client_id_12345", // Audience (your app)
  "iat": 1642598400, // Issued at
  "exp": 1642602000 // Expires at
}
```

### Complete OIDC Implementation

```java
@Service
public class OpenIDConnectService {
    
    @Value("${oidc.issuer}")
    private String issuer; // https://accounts.google.com
    
    @Value("${oidc.client-id}")
    private String clientId;
    
    @Value("${oidc.client-secret}")
    private String clientSecret;
    
    private JWKSet jwkSet; // Public keys for verifying ID tokens
    
    @PostConstruct
    public void init() throws IOException {
        // Fetch public keys from OIDC provider
        String jwksUri = discoverJWKSUri();
        this.jwkSet = JWKSet.load(new URL(jwksUri));
    }
    
    /**
     * OIDC Discovery - automatically find endpoints
     */
    private String discoverJWKSUri() throws IOException {
        // OIDC providers expose /.well-known/openid-configuration
        String discoveryUrl = issuer + "/.well-known/openid-configuration";
        
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(discoveryUrl))
            .GET()
            .build();
        
        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());
        
        ObjectNode config = objectMapper.readValue(response.body(), ObjectNode.class);
        return config.get("jwks_uri").asText();
    }
    
    /**
     * Handle OIDC callback
     */
    public OIDCResult handleCallback(String code) throws Exception {
        // Step 1: Exchange code for tokens
        TokenResponse tokens = exchangeCodeForTokens(code);
        
        // Step 2: Validate ID token
        IDToken idToken = validateIDToken(tokens.getIdToken());
        
        // Step 3: Get additional user info if needed
        UserInfo userInfo = getUserInfo(tokens.getAccessToken());
        
        // Step 4: Create local user account
        User user = findOrCreateUser(idToken, userInfo);
        
        return new OIDCResult(user, tokens);
    }
    
    /**
     * Validate ID Token (JWT)
     */
    private IDToken validateIDToken(String idTokenString) throws JOSEException {
        // Parse JWT
        SignedJWT signedJWT = SignedJWT.parse(idTokenString);
        
        // Step 1: Verify signature
        JWSHeader header = signedJWT.getHeader();
        JWK jwk = jwkSet.getKeyByKeyId(header.getKeyID());
        
        JWSVerifier verifier = new RSASSAVerifier((RSAKey) jwk);
        if (!signedJWT.verify(verifier)) {
            throw new SecurityException("Invalid ID token signature");
        }
        
        // Step 2: Validate claims
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        
        // Check issuer
        if (!claims.getIssuer().equals(issuer)) {
            throw new SecurityException("Invalid issuer");
        }
        
        // Check audience (should be your client_id)
        if (!claims.getAudience().contains(clientId)) {
            throw new SecurityException("Invalid audience");
        }
        
        // Check expiration
        if (claims.getExpirationTime().before(new Date())) {
            throw new SecurityException("ID token expired");
        }
        
        // Check issued-at time (not too far in past/future)
        Date issuedAt = claims.getIssueTime();
        long now = System.currentTimeMillis();
        if (Math.abs(now - issuedAt.getTime()) > 600000) { // 10 minutes
            throw new SecurityException("ID token issued at invalid time");
        }
        
        // Extract user info from claims
        IDToken idToken = new IDToken();
        idToken.setSub(claims.getSubject());
        idToken.setEmail(claims.getStringClaim("email"));
        idToken.setName(claims.getStringClaim("name"));
        idToken.setEmailVerified(claims.getBooleanClaim("email_verified"));
        idToken.setPicture(claims.getStringClaim("picture"));
        
        return idToken;
    }
    
    /**
     * Fetch user info from UserInfo endpoint
     */
    private UserInfo getUserInfo(String accessToken) throws IOException {
        HttpClient client = HttpClient.newHttpClient();
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(issuer + "/userinfo"))
            .header("Authorization", "Bearer " + accessToken)
            .GET()
            .build();
        
        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());
        
        return objectMapper.readValue(response.body(), UserInfo.class);
    }
    
    /**
     * Find existing user or create new account
     */
    private User findOrCreateUser(IDToken idToken, UserInfo userInfo) {
        // Look up user by OIDC subject ID
        String oidcSubject = idToken.getSub();
        User user = userRepository.findByOIDCSubject(oidcSubject);
        
        if (user == null) {
            // Create new user account
            user = User.builder()
                .oidcSubject(oidcSubject)
                .email(idToken.getEmail())
                .emailVerified(idToken.isEmailVerified())
                .name(userInfo.getName())
                .picture(userInfo.getPicture())
                .createdAt(Instant.now())
                .build();
                
            userRepository.save(user);
        } else {
            // Update existing user info
            user.setEmail(idToken.getEmail());
            user.setName(userInfo.getName());
            user.setPicture(userInfo.getPicture());
            user.setLastLoginAt(Instant.now());
            
            userRepository.save(user);
        }
        
        return user;
    }
}

@Data
class IDToken {
    private String sub; // Subject (user ID)
    private String email;
    private boolean emailVerified;
    private String name;
    private String picture;
}

@Data
class OIDCResult {
    private User user;
    private TokenResponse tokens;
}
```

---

## Real FAANG Examples

### Google: OAuth 2.0 Provider

Google is one of the largest OAuth 2.0 providers. When you see "Sign in with Google", that's OAuth 2.0 + OIDC.

**Google's OAuth 2.0 Configuration**:

```java
public class GoogleOAuth2Config {
    
    // Endpoints
    public static final String AUTHORIZATION_ENDPOINT = 
        "https://accounts.google.com/o/oauth2/v2/auth";
    
    public static final String TOKEN_ENDPOINT = 
        "https://oauth2.googleapis.com/token";
    
    public static final String USERINFO_ENDPOINT = 
        "https://www.googleapis.com/oauth2/v3/userinfo";
    
    public static final String REVOCATION_ENDPOINT = 
        "https://oauth2.googleapis.com/revoke";
    
    // Scopes
    public static final String SCOPE_OPENID = "openid";
    public static final String SCOPE_EMAIL = "email";
    public static final String SCOPE_PROFILE = "profile";
    public static final String SCOPE_DRIVE = "https://www.googleapis.com/auth/drive";
    public static final String SCOPE_GMAIL = "https://www.googleapis.com/auth/gmail.readonly";
    public static final String SCOPE_CALENDAR = "https://www.googleapis.com/auth/calendar";
    
    /**
     * Register your app at: https://console.cloud.google.com/apis/credentials
     */
    public void registerApplication() {
        /*
        1. Create project in Google Cloud Console
        2. Enable OAuth 2.0
        3. Configure OAuth consent screen
        4. Create OAuth 2.0 Client ID
        5. Add authorized redirect URIs
        6. Get client_id and client_secret
        */
    }
}
```

**Incremental Authorization** - Google's unique feature:

```java
public class GoogleIncrementalAuth {
    
    /**
     * Request basic permissions first (email, profile)
     */
    public String requestBasicPermissions() {
        return UriComponentsBuilder.fromHttpUrl(GoogleOAuth2Config.AUTHORIZATION_ENDPOINT)
            .queryParam("client_id", clientId)
            .queryParam("redirect_uri", redirectUri)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid email profile") // Basic only
            .queryParam("access_type", "offline") // Get refresh token
            .build()
            .toUriString();
    }
    
    /**
     * Later, when user wants to sync calendar, request additional permission
     */
    public String requestAdditionalPermission(String existingAccessToken) {
        return UriComponentsBuilder.fromHttpUrl(GoogleOAuth2Config.AUTHORIZATION_ENDPOINT)
            .queryParam("client_id", clientId)
            .queryParam("redirect_uri", redirectUri)
            .queryParam("response_type", "code")
            .queryParam("scope", "https://www.googleapis.com/auth/calendar") // Additional scope
            .queryParam("include_granted_scopes", "true") // Keep existing permissions
            .queryParam("access_type", "offline")
            .build()
            .toUriString();
    }
}
```

**Why Incremental Authorization?**
- Don't scare users with too many permissions upfront
- Request permissions only when needed
- Better user experience

### Facebook: OAuth 2.0 for Social Login

```java
public class FacebookOAuth2Service {
    
    private static final String AUTH_URL = "https://www.facebook.com/v18.0/dialog/oauth";
    private static final String TOKEN_URL = "https://graph.facebook.com/v18.0/oauth/access_token";
    private static final String GRAPH_API = "https://graph.facebook.com/v18.0";
    
    /**
     * Initiate Facebook Login
     */
    public String buildAuthorizationUrl() {
        return UriComponentsBuilder.fromHttpUrl(AUTH_URL)
            .queryParam("client_id", appId)
            .queryParam("redirect_uri", redirectUri)
            .queryParam("scope", "email,public_profile,user_friends")
            .queryParam("state", generateState())
            .build()
            .toUriString();
    }
    
    /**
     * Exchange code for long-lived token
     */
    public FacebookTokenResponse getToken(String code) throws IOException {
        Map<String, String> params = Map.of(
            "client_id", appId,
            "client_secret", appSecret,
            "code", code,
            "redirect_uri", redirectUri
        );
        
        String tokenResponse = makeRequest(TOKEN_URL, params);
        return objectMapper.readValue(tokenResponse, FacebookTokenResponse.class);
    }
    
    /**
     * Exchange short-lived token for long-lived token (60 days)
     */
    public String getLongLivedToken(String shortLivedToken) throws IOException {
        Map<String, String> params = Map.of(
            "grant_type", "fb_exchange_token",
            "client_id", appId,
            "client_secret", appSecret,
            "fb_exchange_token", shortLivedToken
        );
        
        String response = makeRequest(TOKEN_URL, params);
        JsonNode json = objectMapper.readTree(response);
        return json.get("access_token").asText();
    }
    
    /**
     * Get user profile
     */
    public FacebookUser getUserProfile(String accessToken) throws IOException {
        String url = GRAPH_API + "/me?fields=id,name,email,picture&access_token=" + accessToken;
        
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .GET()
            .build();
        
        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());
        
        return objectMapper.readValue(response.body(), FacebookUser.class);
    }
    
    /**
     * Verify access token is valid
     */
    public TokenInspection inspectToken(String accessToken) throws IOException {
        String url = GRAPH_API + "/debug_token?" +
            "input_token=" + accessToken +
            "&access_token=" + appAccessToken;
        
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .GET()
            .build();
        
        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());
        
        JsonNode json = objectMapper.readTree(response.body());
        JsonNode data = json.get("data");
        
        return TokenInspection.builder()
            .isValid(data.get("is_valid").asBoolean())
            .appId(data.get("app_id").asText())
            .userId(data.get("user_id").asText())
            .expiresAt(data.get("expires_at").asLong())
            .scopes(extractScopes(data.get("scopes")))
            .build();
    }
}

@Data
class FacebookTokenResponse {
    @JsonProperty("access_token")
    private String accessToken;
    
    @JsonProperty("token_type")
    private String tokenType;
    
    @JsonProperty("expires_in")
    private int expiresIn;
}

@Data
class FacebookUser {
    private String id;
    private String name;
    private String email;
    private Picture picture;
    
    @Data
    public static class Picture {
        private PictureData data;
        
        @Data
        public static class PictureData {
            private String url;
        }
    }
}
```

### GitHub: OAuth 2.0 for Developer Tools

```java
public class GitHubOAuth2Service {
    
    private static final String AUTH_URL = "https://github.com/login/oauth/authorize";
    private static final String TOKEN_URL = "https://github.com/login/oauth/access_token";
    private static final String API_URL = "https://api.github.com";
    
    /**
     * Initiate GitHub OAuth flow
     */
    public String buildAuthorizationUrl() {
        return UriComponentsBuilder.fromHttpUrl(AUTH_URL)
            .queryParam("client_id", clientId)
            .queryParam("redirect_uri", redirectUri)
            .queryParam("scope", "read:user user:email repo") // Request repository access
            .queryParam("state", generateState())
            .build()
            .toUriString();
    }
    
    /**
     * Exchange code for token
     */
    public GitHubTokenResponse getToken(String code) throws IOException {
        HttpClient client = HttpClient.newHttpClient();
        
        Map<String, String> body = Map.of(
            "client_id", clientId,
            "client_secret", clientSecret,
            "code", code,
            "redirect_uri", redirectUri
        );
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(TOKEN_URL))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)))
            .build();
        
        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());
        
        return objectMapper.readValue(response.body(), GitHubTokenResponse.class);
    }
    
    /**
     * Get authenticated user
     */
    public GitHubUser getAuthenticatedUser(String accessToken) throws IOException {
        return makeAPIRequest("/user", accessToken, GitHubUser.class);
    }
    
    /**
     * List user repositories
     */
    public List<GitHubRepository> getUserRepositories(String accessToken) throws IOException {
        return Arrays.asList(
            makeAPIRequest("/user/repos", accessToken, GitHubRepository[].class)
        );
    }
    
    private <T> T makeAPIRequest(String endpoint, String accessToken, Class<T> responseType) 
            throws IOException {
        HttpClient client = HttpClient.newHttpClient();
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(API_URL + endpoint))
            .header("Authorization", "Bearer " + accessToken)
            .header("Accept", "application/vnd.github.v3+json")
            .GET()
            .build();
        
        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());
        
        return objectMapper.readValue(response.body(), responseType);
    }
}

@Data
class GitHubTokenResponse {
    @JsonProperty("access_token")
    private String accessToken;
    
    @JsonProperty("token_type")
    private String tokenType;
    
    private String scope;
}

@Data
class GitHubUser {
    private Long id;
    private String login;
    private String name;
    private String email;
    @JsonProperty("avatar_url")
    private String avatarUrl;
    private String bio;
}

@Data
class GitHubRepository {
    private Long id;
    private String name;
    @JsonProperty("full_name")
    private String fullName;
    private boolean isPrivate;
    private String description;
}
```

### Netflix: Custom OAuth 2.0 for Content Partners

Netflix uses OAuth 2.0 to allow content partners (studios) to access their dashboard APIs.

```java
public class NetflixPartnerOAuth2 {
    
    /**
     * Content partners use client credentials grant
     * No user involved - machine-to-machine
     */
    public String getPartnerAccessToken(String partnerId, String partnerSecret) 
            throws IOException {
        HttpClient client = HttpClient.newHttpClient();
        
        Map<String, String> params = Map.of(
            "grant_type", "client_credentials",
            "client_id", partnerId,
            "client_secret", partnerSecret,
            "scope", "content.upload content.metadata.read"
        );
        
        String body = params.entrySet().stream()
            .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .collect(Collectors.joining("&"));
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://partner-api.netflix.com/oauth/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        
        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());
        
        JsonNode json = objectMapper.readTree(response.body());
        return json.get("access_token").asText();
    }
    
    /**
     * Upload content metadata
     */
    public void uploadContentMetadata(String accessToken, ContentMetadata metadata) 
            throws IOException {
        HttpClient client = HttpClient.newHttpClient();
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://partner-api.netflix.com/v1/content/metadata"))
            .header("Authorization", "Bearer " + accessToken)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(
                objectMapper.writeValueAsString(metadata)
            ))
            .build();
        
        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());
        
        if (response.statusCode() != 201) {
            throw new IOException("Failed to upload metadata: " + response.body());
        }
    }
}
```

---

## Token Management

### Refresh Tokens

Access tokens are short-lived (1 hour typical). Refresh tokens allow getting new access tokens without user interaction.

```java
public class TokenRefreshService {
    
    private final TokenRepository tokenRepository;
    
    /**
     * Refresh access token using refresh token
     */
    public TokenResponse refreshAccessToken(String refreshToken) throws IOException {
        // Validate refresh token
        RefreshToken storedToken = tokenRepository.findByToken(refreshToken);
        
        if (storedToken == null) {
            throw new UnauthorizedException("Invalid refresh token");
        }
        
        if (storedToken.isExpired()) {
            throw new UnauthorizedException("Refresh token expired");
        }
        
        if (storedToken.isRevoked()) {
            // Potential token theft - revoke all tokens for this user
            revokeAllUserTokens(storedToken.getUserId());
            throw new SecurityException("Refresh token has been revoked");
        }
        
        // Request new access token from OAuth provider
        TokenResponse newTokens = requestNewTokens(refreshToken);
        
        // Update stored refresh token if provider issued new one
        if (newTokens.getRefreshToken() != null) {
            storedToken.setToken(newTokens.getRefreshToken());
            storedToken.setUpdatedAt(Instant.now());
            tokenRepository.save(storedToken);
        }
        
        return newTokens;
    }
    
    private TokenResponse requestNewTokens(String refreshToken) throws IOException {
        HttpClient client = HttpClient.newHttpClient();
        
        Map<String, String> params = Map.of(
            "grant_type", "refresh_token",
            "refresh_token", refreshToken,
            "client_id", clientId,
            "client_secret", clientSecret
        );
        
        String body = params.entrySet().stream()
            .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .collect(Collectors.joining("&"));
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(TOKEN_URL))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        
        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());
        
        return objectMapper.readValue(response.body(), TokenResponse.class);
    }
    
    /**
     * Revoke all tokens for user (security incident)
     */
    private void revokeAllUserTokens(String userId) {
        List<RefreshToken> userTokens = tokenRepository.findByUserId(userId);
        
        for (RefreshToken token : userTokens) {
            token.setRevoked(true);
            tokenRepository.save(token);
        }
        
        // Alert user
        securityAlertService.sendTokenRevokedAlert(userId);
    }
}
```

### Token Rotation (Security Best Practice)

```java
public class TokenRotationService {
    
    /**
     * Rotate refresh token on every use (highest security)
     */
    public TokenResponse refreshWithRotation(String oldRefreshToken) throws IOException {
        // Get new tokens
        TokenResponse newTokens = oauthClient.refresh(oldRefreshToken);
        
        // Immediately revoke old refresh token
        RefreshToken oldToken = tokenRepository.findByToken(oldRefreshToken);
        oldToken.setRevoked(true);
        oldToken.setRevokedAt(Instant.now());
        tokenRepository.save(oldToken);
        
        // Store new refresh token
        RefreshToken newToken = RefreshToken.builder()
            .token(newTokens.getRefreshToken())
            .userId(oldToken.getUserId())
            .expiresAt(Instant.now().plus(30, ChronoUnit.DAYS))
            .createdAt(Instant.now())
            .parentTokenId(oldToken.getId()) // Track token family
            .build();
        tokenRepository.save(newToken);
        
        return newTokens;
    }
    
    /**
     * Detect token replay attack
     */
    public void detectReplayAttack(String refreshToken) {
        RefreshToken token = tokenRepository.findByToken(refreshToken);
        
        if (token.isRevoked()) {
            // This token was already used and should not be reused
            // Potential replay attack - revoke entire token family
            revokeTokenFamily(token.getId());
            
            alertSecurityTeam(
                "Token replay detected",
                token.getUserId(),
                token.getId()
            );
        }
    }
    
    private void revokeTokenFamily(String tokenId) {
        // Find all descendants of this token
        List<RefreshToken> family = tokenRepository.findTokenFamily(tokenId);
        
        for (RefreshToken token : family) {
            token.setRevoked(true);
            tokenRepository.save(token);
        }
    }
}
```

---

## Security Best Practices

### 1. State Parameter (CSRF Protection)

```java
public class OAuth2StateManager {
    
    private final Cache<String, StateInfo> stateCache;
    
    /**
     * Generate state parameter
     */
    public String generateState(HttpServletRequest request) {
        // Generate random state
        String state = UUID.randomUUID().toString();
        
        // Store state with metadata
        StateInfo info = StateInfo.builder()
            .state(state)
            .createdAt(Instant.now())
            .ipAddress(request.getRemoteAddr())
            .userAgent(request.getHeader("User-Agent"))
            .build();
        
        // Cache for 10 minutes
        stateCache.put(state, info, Duration.ofMinutes(10));
        
        return state;
    }
    
    /**
     * Validate state parameter
     */
    public boolean validateState(String state, HttpServletRequest request) {
        StateInfo info = stateCache.get(state);
        
        if (info == null) {
            return false; // State not found or expired
        }
        
        // Remove from cache (single-use)
        stateCache.invalidate(state);
        
        // Verify IP and User-Agent match (optional extra security)
        if (!info.getIpAddress().equals(request.getRemoteAddr())) {
            logger.warn("State parameter used from different IP");
            return false;
        }
        
        return true;
    }
}
```

### 2. Redirect URI Validation

```java
public class RedirectURIValidator {
    
    /**
     * Validate redirect URI exactly matches registered URI
     */
    public boolean validateRedirectURI(String providedUri, List<String> registeredUris) {
        // Must match exactly - no wildcards allowed
        return registeredUris.contains(providedUri);
    }
    
    /**
     * Prevent open redirect attacks
     */
    public boolean isSecureRedirect(String redirectUri) {
        try {
            URI uri = new URI(redirectUri);
            
            // Must use HTTPS (except localhost for development)
            if (!"https".equals(uri.getScheme())) {
                if (!"localhost".equals(uri.getHost()) && 
                    !"127.0.0.1".equals(uri.getHost())) {
                    return false;
                }
            }
            
            // Must not redirect to IP address (except localhost)
            if (uri.getHost().matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                if (!"127.0.0.1".equals(uri.getHost())) {
                    return false;
                }
            }
            
            return true;
            
        } catch (URISyntaxException e) {
            return false;
        }
    }
}
```

### 3. Token Storage (Client Side)

```java
/**
 * ❌ DON'T store tokens in localStorage
 * Vulnerable to XSS attacks
 */
localStorage.setItem('access_token', token); // BAD

/**
 * ✓ Store in HttpOnly cookie
 * Immune to XSS, vulnerable only to CSRF (which we prevent)
 */
@GetMapping("/callback")
public ResponseEntity<?> handleCallback(@RequestParam("code") String code,
                                        HttpServletResponse response) {
    TokenResponse tokens = oauth2Service.exchangeCode(code);
    
    // Store access token in HttpOnly cookie
    Cookie accessTokenCookie = new Cookie("access_token", tokens.getAccessToken());
    accessTokenCookie.setHttpOnly(true); // Not accessible via JavaScript
    accessTokenCookie.setSecure(true); // Only sent over HTTPS
    accessTokenCookie.setPath("/");
    accessTokenCookie.setMaxAge(3600); // 1 hour
    accessTokenCookie.setSameSite("Strict"); // CSRF protection
    response.addCookie(accessTokenCookie);
    
    // Store refresh token in even more secure cookie
    Cookie refreshTokenCookie = new Cookie("refresh_token", tokens.getRefreshToken());
    refreshTokenCookie.setHttpOnly(true);
    refreshTokenCookie.setSecure(true);
    refreshTokenCookie.setPath("/auth/refresh"); // Only accessible to refresh endpoint
    refreshTokenCookie.setMaxAge(2592000); // 30 days
    refreshTokenCookie.setSameSite("Strict");
    response.addCookie(refreshTokenCookie);
    
    return ResponseEntity.ok().build();
}
```

---

## Interview Questions & Answers

### Question 1: Explain OAuth 2.0 flow to a non-technical person

**Answer**:

"Imagine you're at a hotel. OAuth 2.0 is like getting different access cards for different hotel services.

When you check in, you get your room key card. But if you want to use the gym, you need a gym pass. For the pool, you need a pool pass. Each pass gives you access to specific areas, and you can always go back to the front desk to get or cancel any pass.

In the tech world:
- The hotel is like Google or Facebook
- Your room key is your password (you never share this)
- The gym pass is an access token (you can share this with a fitness app)
- The front desk is the authorization server

When a fitness app wants to see your Google Fit data, it doesn't ask for your Google password. Instead, it sends you to Google (the front desk), you approve it, and Google gives the app a special pass (token) that only lets it read your fitness data - nothing else.

If you don't like the app anymore, you can revoke the pass from Google's settings. The app stops working, but your Google account is still safe and you don't need to change your password."

### Question 2: Why can't we use OAuth 2.0 for authentication?

**Interviewer**: "I've seen apps using OAuth 2.0 for 'Sign in with Google'. But you said OAuth 2.0 is for authorization, not authentication. What's going on?"

**Answer**:

"Great question! This is a common confusion. OAuth 2.0 alone is NOT sufficient for authentication, but it's often combined with OpenID Connect (OIDC) for authentication.

Here's the problem with using OAuth 2.0 alone for authentication:

**Scenario**:
```
1. User clicks "Sign in with Google"
2. App redirects to Google
3. User approves
4. App gets access token
5. App thinks: "I have a token, so user is authenticated" ❌ WRONG

Problem: Who is the user?
- Token proves app can access data
- Token does NOT prove user identity
- Two different users could grant access to the same resource
```

**Real Attack**:
```
Attacker's goal: Login to victim's account

1. Attacker starts OAuth flow for victim's account
2. Attacker gets authorization code
3. Attacker tricks victim into using this code
4. Victim's data gets linked to attacker's account
5. Now attacker can access victim's data through the app
```

**Correct Solution - OpenID Connect**:
```
1. Use OIDC (built on OAuth 2.0)
2. Request 'openid' scope
3. Get ID token (JWT) in addition to access token
4. ID token contains user identity claims:
   {
     "sub": "user_id_12345",  // WHO the user is
     "email": "user@example.com",
     "email_verified": true
   }
5. Verify ID token signature
6. Now you know WHO is logging in ✓
```

**Summary**:
- OAuth 2.0 alone: 'What can I access?' (Authorization)
- OpenID Connect: 'Who am I?' (Authentication) + OAuth 2.0
- Modern 'Sign in with Google' uses OIDC, not just OAuth 2.0"

### Question 3: Design OAuth 2.0 for a mobile app

**Interviewer**: "Design how a mobile banking app would implement OAuth 2.0 to access a user's transactions from a third-party financial service."

**Answer**:

```
Architecture:

┌──────────────────┐
│   Mobile App     │  iOS/Android Banking App
└────────┬─────────┘
         │
         │ 1. Initiate OAuth with PKCE
         │
         ▼
┌──────────────────────────────┐
│   Financial Service API      │
│   (e.g., Plaid)              │
│                              │
│   OAuth 2.0 + PKCE Provider  │
└────────┬─────────────────────┘
         │
         │ 2. User authorizes
         │
         ▼
┌──────────────────────────────┐
│   Your Backend API           │
│                              │
│   - Token storage            │
│   - Token refresh            │
│   - Transaction proxy        │
└──────────────────────────────┘

Key Decisions:

1. Use Authorization Code Flow with PKCE
   Why: Mobile apps can't securely store client_secret
   
2. Use custom URL scheme for redirect
   Redirect URI: mybank://oauth/callback
   
3. Store tokens in backend, not on device
   Why: More secure, easier token refresh
   
4. Use biometric authentication
   Required before starting OAuth flow
```

**Implementation**:

```java
// Mobile App (Android/iOS)
public class MobileOAuthClient {
    
    /**
     * Step 1: Generate PKCE parameters
     */
    public PKCEParams generatePKCE() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        
        String codeVerifier = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(bytes);
        
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
        String codeChallenge = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(hash);
        
        // Store code verifier in secure enclave (iOS) or KeyStore (Android)
        secureStorage.set("code_verifier", codeVerifier);
        
        return new PKCEParams(codeVerifier, codeChallenge);
    }
    
    /**
     * Step 2: Open authorization URL in browser
     */
    public void initiateOAuthFlow() {
        PKCEParams pkce = generatePKCE();
        
        String authUrl = "https://financial-service.com/oauth/authorize?" +
            "client_id=" + clientId +
            "&redirect_uri=mybank://oauth/callback" +
            "&response_type=code" +
            "&scope=transactions:read accounts:read" +
            "&code_challenge=" + pkce.getCodeChallenge() +
            "&code_challenge_method=S256" +
            "&state=" + generateState();
        
        // Open in system browser (more secure than WebView)
        openInBrowser(authUrl);
    }
    
    /**
     * Step 3: Handle redirect back to app
     */
    public void handleCallback(Uri uri) {
        String code = uri.getQueryParameter("code");
        String state = uri.getQueryParameter("state");
        
        // Validate state
        if (!validateState(state)) {
            showError("Invalid state");
            return;
        }
        
        // Get stored code verifier
        String codeVerifier = secureStorage.get("code_verifier");
        
        // Send code and verifier to your backend
        backendAPI.exchangeCode(code, codeVerifier, new Callback() {
            @Override
            public void onSuccess(TokenResponse tokens) {
                // Backend stores tokens, returns session ID
                saveSessionId(tokens.getSessionId());
                navigateToHome();
            }
            
            @Override
            public void onError(Error error) {
                showError("OAuth failed: " + error.getMessage());
            }
        });
    }
}

// Your Backend API
@RestController
@RequestMapping("/api/oauth")
public class BankingOAuthController {
    
    /**
     * Exchange code for tokens (mobile app calls this)
     */
    @PostMapping("/exchange")
    public ResponseEntity<?> exchangeCode(@RequestBody ExchangeRequest request) {
        try {
            // Verify code verifier format
            if (!isValidCodeVerifier(request.getCodeVerifier())) {
                return ResponseEntity.badRequest().body("Invalid code verifier");
            }
            
            // Exchange with financial service
            TokenResponse tokens = exchangeWithFinancialService(
                request.getCode(),
                request.getCodeVerifier()
            );
            
            // Store tokens securely in database
            String sessionId = storeTokens(tokens);
            
            // Return only session ID to mobile app
            return ResponseEntity.ok(Map.of("session_id", sessionId));
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Token exchange failed");
        }
    }
    
    /**
     * Fetch transactions (using stored tokens)
     */
    @GetMapping("/transactions")
    public ResponseEntity<?> getTransactions(@RequestHeader("Session-ID") String sessionId) {
        // Get tokens from database
        StoredTokens tokens = tokenRepository.findBySessionId(sessionId);
        
        if (tokens == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        // Check if access token expired
        if (tokens.isAccessTokenExpired()) {
            // Refresh token
            tokens = refreshAccessToken(tokens);
        }
        
        // Call financial service API
        List<Transaction> transactions = financialServiceClient.getTransactions(
            tokens.getAccessToken()
        );
        
        return ResponseEntity.ok(transactions);
    }
    
    private TokenResponse exchangeWithFinancialService(String code, String codeVerifier) 
            throws IOException {
        HttpClient client = HttpClient.newHttpClient();
        
        Map<String, String> params = Map.of(
            "grant_type", "authorization_code",
            "code", code,
            "code_verifier", codeVerifier,
            "client_id", clientId,
            "redirect_uri", "mybank://oauth/callback"
        );
        
        String body = params.entrySet().stream()
            .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .collect(Collectors.joining("&"));
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://financial-service.com/oauth/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        
        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());
        
        return objectMapper.readValue(response.body(), TokenResponse.class);
    }
    
    private String storeTokens(TokenResponse tokens) {
        String sessionId = UUID.randomUUID().toString();
        
        StoredTokens stored = StoredTokens.builder()
            .sessionId(sessionId)
            .accessToken(encryptToken(tokens.getAccessToken()))
            .refreshToken(encryptToken(tokens.getRefreshToken()))
            .expiresAt(Instant.now().plusSeconds(tokens.getExpiresIn()))
            .createdAt(Instant.now())
            .build();
        
        tokenRepository.save(stored);
        
        return sessionId;
    }
}
```

**Security Considerations**:

1. **PKCE is mandatory** - Mobile apps cannot keep secrets
2. **Use system browser** - More secure than WebView, supports biometrics
3. **Custom URL scheme** - Deep link back to app
4. **Store tokens on backend** - Not on device
5. **Encrypt tokens** - Even in database
6. **Biometric before OAuth** - Verify user before starting flow

---

## Summary: OAuth 2.0 & OpenID Connect

**OAuth 2.0**:
- Authorization protocol
- Grants limited access to resources
- Issues access tokens
- Use cases: Third-party API access

**OpenID Connect**:
- Authentication protocol built on OAuth 2.0
- Proves user identity
- Issues ID tokens (JWT)
- Use cases: "Sign in with..." flows

**Grant Types**:
- Authorization Code: Web apps with backend (most secure)
- Authorization Code + PKCE: Mobile apps, SPAs
- Client Credentials: Machine-to-machine
- Implicit: Deprecated (don't use)

**Key Concepts**:
- Access Token: Proves permission to access resources
- Refresh Token: Gets new access token without user interaction
- ID Token: Contains user identity (OIDC only)
- Scope: Requested permissions
- State: CSRF protection

# S3: JWT vs Session-based Auth