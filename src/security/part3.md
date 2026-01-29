# Security & Authentication Guide - Part 3 of 5

**Topics Covered:**
- S7: Hashing & Salting (Passwords) 🔴 Critical
- S8: Single Sign-On (SSO) 🟡 Important
- S9: Role-Based Access Control (RBAC) 🔴 Critical

**For FAANG System Design Interviews**

---

# S7: Hashing & Salting (Passwords)

## 🍳 The Recipe Analogy

Imagine you're a chef with a secret sauce recipe:

**Plain Text Password (Bad Chef):**
- Recipe written on paper: "Mix tomatoes, garlic, olive oil"
- Anyone who sees the paper knows the exact recipe
- If paper is stolen, recipe is compromised
- Can easily recreate the sauce

**Hashed Password (Smart Chef):**
- You blend all ingredients together irreversibly
- Result: "Red smooth liquid with specific taste"
- Even if someone tastes it, they can't unblend to get original ingredients
- They can TRY to recreate it, but it takes forever to guess the right proportions

**Salted + Hashed (Master Chef):**
- Before blending, you add a unique secret ingredient (salt) to EACH batch
- Same recipe + different salt = different final product
- Even if two customers order same sauce, results look different
- Attacker must figure out BOTH the recipe AND the unique salt per user

This is how password hashing works!

---

## Beginner Level: Why Never Store Passwords

### The Nightmare Scenario

```
Database gets hacked
passwords table leaked:

id | email              | password
1  | john@email.com     | password123
2  | sarah@email.com    | qwerty456
3  | mike@email.com     | admin2024

Result:
✗ All passwords exposed
✗ Attackers can login as any user
✗ Users who reuse passwords compromised on OTHER sites too
✗ Company faces lawsuits, fines, reputation damage
✗ GDPR fine: Up to 4% of annual revenue
```

**NEVER STORE PASSWORDS IN PLAIN TEXT!**

### What is Hashing?

Hashing is a **one-way** function: Easy to go forward, impossible to reverse.

```
Input:  "MyPassword123"
         ↓ [Hash Function]
Output: "5f4dcc3b5aa765d61d8327deb882cf99"

You CANNOT do:
"5f4dcc3b5aa765d61d8327deb882cf99"
         ↓ [Reverse?]
"MyPassword123"  ← IMPOSSIBLE
```

**Properties of Good Hash:**
1. **Deterministic**: Same input → Always same output
2. **Fast to compute**: Milliseconds to hash
3. **One-way**: Cannot reverse
4. **Avalanche effect**: Tiny change in input → Completely different output
5. **Collision resistant**: Hard to find two inputs with same hash

### Common Hash Functions

```
Password: "Hello123"

MD5:     "68053af2923e00204c3ca7c6a3150cf7"
SHA-1:   "d3d61e24" 57e12a1c...
SHA-256: "3845dec81..." (64 hex chars)
bcrypt:  "$2a$12$N3g..." (includes salt!)
```

**DO NOT USE for passwords:**
- ❌ MD5 (broken, too fast)
- ❌ SHA-1 (broken, too fast)
- ❌ SHA-256 (too fast - allows brute force)

**USE for passwords:**
- ✅ bcrypt (industry standard)
- ✅ scrypt (memory-hard)
- ✅ Argon2 (winner of password hashing competition)

### The Rainbow Table Attack

**Problem with simple hashing:**

```
Attacker pre-computes common passwords:

password      →  5f4dcc3b5aa765d61d8327deb882cf99
123456        →  e10adc3949ba59abbe56e057f20f883e
qwerty        →  d8578edf8458ce06fbc5bb76a58c5ca4
...
(Billions of passwords pre-computed)

Database leaked:
user1: 5f4dcc3b5aa765d61d8327deb882cf99
       ↓ [Lookup in rainbow table]
       "password" found instantly!
```

**Solution: SALT**

---

## Intermediate Level: Salting

### What is a Salt?

A salt is a **random** string added to password before hashing.

```
Without Salt:
hash("password") → same hash for everyone using "password"

With Salt:
hash("password" + "random_salt_1") → unique hash
hash("password" + "random_salt_2") → different hash!

Even if two users have same password, hashes are different
```

### How Salting Works

**Registration Flow:**

```
1. User creates account with password: "MyPass123"

2. System generates random salt: "a4f9k2m8p5"

3. Combine: "MyPass123" + "a4f9k2m8p5" = "MyPass123a4f9k2m8p5"

4. Hash the combination:
   bcrypt("MyPass123a4f9k2m8p5") = "$2a$12$a4f9k2m8p5.../encrypted..."

5. Store in database:
   user_id: 1
   password_hash: "$2a$12$a4f9k2m8p5.../encrypted..."
   (Salt is embedded in the hash!)
```

**Login Flow:**

```
1. User enters password: "MyPass123"

2. Retrieve stored hash: "$2a$12$a4f9k2m8p5.../encrypted..."

3. Extract salt from hash: "a4f9k2m8p5"

4. Combine entered password + salt: "MyPass123a4f9k2m8p5"

5. Hash it: bcrypt("MyPass123a4f9k2m8p5")

6. Compare:
   Stored:   "$2a$12$a4f9k2m8p5.../encrypted..."
   Computed: "$2a$12$a4f9k2m8p5.../encrypted..."
   Match? → Login successful ✓
```

### Java Implementation with BCrypt

```java
// PasswordService.java
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Service
public class PasswordService {
    
    // BCrypt with strength 12 (2^12 = 4096 rounds)
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    
    /**
     * Hash password with bcrypt
     * Automatically generates salt and includes it in output
     */
    public String hashPassword(String plainPassword) {
        // Validate password strength first
        validatePasswordStrength(plainPassword);
        
        // BCrypt handles salt generation internally
        String hashedPassword = encoder.encode(plainPassword);
        
        // Result looks like:
        // $2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
        //  ^   ^  ^                           ^
        //  |   |  |                           |
        //  |   |  Salt (22 chars)             Hash (31 chars)
        //  |   Cost factor (2^12)
        //  Algorithm version
        
        return hashedPassword;
    }
    
    /**
     * Verify password against stored hash
     */
    public boolean verifyPassword(String plainPassword, String hashedPassword) {
        try {
            return encoder.matches(plainPassword, hashedPassword);
        } catch (IllegalArgumentException e) {
            // Invalid hash format
            return false;
        }
    }
    
    /**
     * Check if password needs rehashing (cost factor increased)
     */
    public boolean needsRehash(String hashedPassword) {
        // Extract cost factor from hash
        String[] parts = hashedPassword.split("\\$");
        if (parts.length < 3) {
            return true;  // Invalid format
        }
        
        int storedCost = Integer.parseInt(parts[2]);
        int currentCost = 12;  // Our current setting
        
        return storedCost < currentCost;
    }
    
    /**
     * Validate password meets security requirements
     */
    private void validatePasswordStrength(String password) {
        if (password == null || password.length() < 8) {
            throw new WeakPasswordException("Password must be at least 8 characters");
        }
        
        boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
        boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSpecial = password.chars().anyMatch(ch -> 
            "!@#$%^&*()_+-=[]{}|;:,.<>?".indexOf(ch) >= 0
        );
        
        int strength = 0;
        if (hasUpper) strength++;
        if (hasLower) strength++;
        if (hasDigit) strength++;
        if (hasSpecial) strength++;
        
        if (strength < 3) {
            throw new WeakPasswordException(
                "Password must contain at least 3 of: uppercase, lowercase, digit, special char"
            );
        }
        
        // Check against common passwords
        if (isCommonPassword(password)) {
            throw new WeakPasswordException("Password is too common");
        }
    }
    
    /**
     * Check against list of common passwords
     */
    private boolean isCommonPassword(String password) {
        Set<String> commonPasswords = Set.of(
            "password", "123456", "password123", "admin", 
            "welcome", "monkey", "dragon", "master",
            "qwerty", "abc123", "letmein", "trustno1"
        );
        
        return commonPasswords.contains(password.toLowerCase());
    }
}
```

### Complete Registration & Login Flow

```java
// AuthController.java
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    @Autowired
    private PasswordService passwordService;
    
    @Autowired
    private UserRepository userRepo;
    
    @Autowired
    private SessionService sessionService;
    
    /**
     * User registration
     */
    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(
            @RequestBody @Valid RegisterRequest request
    ) {
        // 1. Check if user already exists
        if (userRepo.existsByEmail(request.getEmail())) {
            return ResponseEntity.badRequest()
                .body(new RegisterResponse("Email already registered"));
        }
        
        // 2. Hash password (salt is automatic with bcrypt)
        String hashedPassword = passwordService.hashPassword(request.getPassword());
        
        // 3. Create user
        User user = new User();
        user.setEmail(request.getEmail());
        user.setPasswordHash(hashedPassword);
        user.setCreatedAt(Instant.now());
        
        userRepo.save(user);
        
        // 4. Return success (do NOT return the hash!)
        return ResponseEntity.ok(new RegisterResponse("Registration successful"));
    }
    
    /**
     * User login
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @RequestBody @Valid LoginRequest request,
            HttpServletRequest httpRequest
    ) {
        // 1. Find user by email
        User user = userRepo.findByEmail(request.getEmail())
            .orElse(null);
        
        if (user == null) {
            // Don't reveal if email exists or not (security)
            rateLimitFailedLogin(request.getEmail(), getClientIP(httpRequest));
            return ResponseEntity.status(401)
                .body(new LoginResponse("Invalid credentials"));
        }
        
        // 2. Verify password
        boolean passwordMatches = passwordService.verifyPassword(
            request.getPassword(),
            user.getPasswordHash()
        );
        
        if (!passwordMatches) {
            // Log failed attempt
            logFailedLogin(user.getId(), getClientIP(httpRequest));
            rateLimitFailedLogin(request.getEmail(), getClientIP(httpRequest));
            
            return ResponseEntity.status(401)
                .body(new LoginResponse("Invalid credentials"));
        }
        
        // 3. Check if account is locked
        if (user.isLocked()) {
            return ResponseEntity.status(403)
                .body(new LoginResponse("Account is locked. Contact support."));
        }
        
        // 4. Check if password needs rehashing (cost factor increased)
        if (passwordService.needsRehash(user.getPasswordHash())) {
            // Opportunistic rehashing
            String newHash = passwordService.hashPassword(request.getPassword());
            user.setPasswordHash(newHash);
            userRepo.save(user);
        }
        
        // 5. Create session
        String sessionToken = sessionService.createSession(user.getId());
        
        // 6. Update last login
        user.setLastLoginAt(Instant.now());
        user.setFailedLoginAttempts(0);  // Reset counter
        userRepo.save(user);
        
        return ResponseEntity.ok(new LoginResponse(sessionToken));
    }
    
    /**
     * Rate limit failed login attempts
     */
    private void rateLimitFailedLogin(String email, String ipAddress) {
        String key = "failed_login:" + email + ":" + ipAddress;
        Long attempts = redisTemplate.opsForValue().increment(key);
        
        if (attempts == 1) {
            // Set expiration on first attempt
            redisTemplate.expire(key, 15, TimeUnit.MINUTES);
        }
        
        if (attempts > 5) {
            // Too many failed attempts
            User user = userRepo.findByEmail(email).orElse(null);
            if (user != null) {
                user.setLocked(true);
                user.setLockedUntil(Instant.now().plus(30, ChronoUnit.MINUTES));
                userRepo.save(user);
                
                // Send alert
                alertService.send(
                    "Account locked due to failed login attempts",
                    "User: " + email + ", IP: " + ipAddress
                );
            }
        }
    }
}
```

---

## Advanced Level: Production Patterns

### Pattern 1: Argon2 (Modern Alternative)

Argon2 is the winner of Password Hashing Competition (2015):

```java
// Argon2PasswordService.java
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

@Service
public class Argon2PasswordService {
    
    private final Argon2 argon2 = Argon2Factory.create(
        Argon2Factory.Argon2Types.ARGON2id,  // Hybrid mode (best)
        32,    // Salt length
        64     // Hash length
    );
    
    /**
     * Hash password with Argon2
     */
    public String hashPassword(String plainPassword) {
        // Parameters:
        // iterations: 3 (time cost)
        // memory: 65536 KB (64 MB) (memory cost)
        // parallelism: 4 (number of threads)
        return argon2.hash(
            3,      // iterations
            65536,  // memory in KB
            4,      // parallelism
            plainPassword.toCharArray()
        );
        
        // Result: $argon2id$v=19$m=65536,t=3,p=4$hash...
    }
    
    /**
     * Verify password
     */
    public boolean verifyPassword(String plainPassword, String hash) {
        try {
            return argon2.verify(hash, plainPassword.toCharArray());
        } finally {
            // Clear password from memory
            argon2.wipeArray(plainPassword.toCharArray());
        }
    }
}
```

**Why Argon2?**
- Memory-hard: Resists GPU/ASIC attacks
- Configurable memory, time, parallelism
- Protection against side-channel attacks
- Used by: Bitwarden, 1Password, Signal

### Pattern 2: Pepper (Additional Secret)

Add a server-side secret (pepper) for extra security:

```java
@Service
public class PepperedPasswordService {
    
    @Value("${security.password.pepper}")
    private String pepper;  // Stored in environment variable, not database
    
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    
    /**
     * Hash with pepper
     */
    public String hashPassword(String plainPassword) {
        // Combine password with pepper before hashing
        String peppered = plainPassword + pepper;
        return encoder.encode(peppered);
    }
    
    /**
     * Verify with pepper
     */
    public boolean verifyPassword(String plainPassword, String hash) {
        String peppered = plainPassword + pepper;
        return encoder.matches(peppered, hash);
    }
}
```

**Pepper vs Salt:**
```
Salt:
- Random per user
- Stored WITH the hash
- Prevents rainbow tables

Pepper:
- Same for all users
- Stored SEPARATELY from database (environment variable)
- Protects if database is leaked but app server is not compromised
```

### Pattern 3: Password Breach Detection

Check passwords against known breaches using Have I Been Pwned API:

```java
@Service
public class PasswordBreachChecker {
    
    private static final String HIBP_API = "https://api.pwnedpasswords.com/range/";
    
    /**
     * Check if password has been in a data breach
     */
    public boolean isPasswordBreached(String password) {
        try {
            // 1. Hash password with SHA-1
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            String hashHex = DatatypeConverter.printHexBinary(hash);
            
            // 2. Split hash: first 5 chars + rest
            String prefix = hashHex.substring(0, 5);
            String suffix = hashHex.substring(5);
            
            // 3. Query HIBP API with prefix only (k-anonymity)
            RestTemplate restTemplate = new RestTemplate();
            String response = restTemplate.getForObject(
                HIBP_API + prefix,
                String.class
            );
            
            // 4. Check if suffix appears in response
            return response.contains(suffix);
            
        } catch (Exception e) {
            // If check fails, allow password (availability over security)
            log.error("Failed to check password breach", e);
            return false;
        }
    }
    
    /**
     * Validate password during registration
     */
    public void validatePassword(String password) {
        if (isPasswordBreached(password)) {
            throw new WeakPasswordException(
                "This password has been exposed in a data breach. " +
                "Please choose a different password."
            );
        }
    }
}
```

### Pattern 4: Multi-Factor Authentication

Even with strong password hashing, add MFA:

```java
@Service
public class TwoFactorService {
    
    @Autowired
    private GoogleAuthenticator googleAuth;
    
    /**
     * Generate TOTP secret for user
     */
    public TOTPSetup setupTOTP(Long userId) {
        // Generate secret
        GoogleAuthenticatorKey key = googleAuth.createCredentials();
        String secret = key.getKey();
        
        // Store encrypted secret
        User user = userRepo.findById(userId).orElseThrow();
        user.setTotpSecret(encryptionService.encrypt(secret));
        user.setTotpEnabled(false);  // Not enabled until verified
        userRepo.save(user);
        
        // Generate QR code for Google Authenticator
        String qrCodeUrl = GoogleAuthenticatorQRGenerator.getOtpAuthURL(
            "MyApp",
            user.getEmail(),
            key
        );
        
        return new TOTPSetup(secret, qrCodeUrl);
    }
    
    /**
     * Verify TOTP code
     */
    public boolean verifyTOTP(Long userId, int code) {
        User user = userRepo.findById(userId).orElseThrow();
        
        if (!user.isTotpEnabled()) {
            return false;
        }
        
        String secret = encryptionService.decrypt(user.getTotpSecret());
        return googleAuth.authorize(secret, code);
    }
    
    /**
     * Complete login with MFA
     */
    public String loginWithMFA(String email, String password, Integer totpCode) {
        // 1. Verify password
        User user = userRepo.findByEmail(email).orElseThrow();
        if (!passwordService.verifyPassword(password, user.getPasswordHash())) {
            throw new UnauthorizedException("Invalid credentials");
        }
        
        // 2. If MFA enabled, verify TOTP
        if (user.isTotpEnabled()) {
            if (totpCode == null) {
                throw new MFARequiredException("TOTP code required");
            }
            
            if (!verifyTOTP(user.getId(), totpCode)) {
                throw new UnauthorizedException("Invalid TOTP code");
            }
        }
        
        // 3. Create session
        return sessionService.createSession(user.getId());
    }
}
```

---

## Real FAANG Examples

### Example 1: Google's Password Requirements

Google implements sophisticated password protection:

**Password Strength Meter:**
```java
@Service
public class GoogleStylePasswordStrength {
    
    public enum PasswordStrength {
        VERY_WEAK(0),
        WEAK(1),
        FAIR(2),
        GOOD(3),
        STRONG(4);
        
        public final int score;
        PasswordStrength(int score) { this.score = score; }
    }
    
    /**
     * Calculate password strength score
     */
    public PasswordStrength calculateStrength(String password) {
        int score = 0;
        
        // Length score
        if (password.length() >= 8) score++;
        if (password.length() >= 12) score++;
        if (password.length() >= 16) score++;
        
        // Character variety
        boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
        boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSpecial = password.chars().anyMatch(ch -> 
            !Character.isLetterOrDigit(ch));
        
        int variety = 0;
        if (hasLower) variety++;
        if (hasUpper) variety++;
        if (hasDigit) variety++;
        if (hasSpecial) variety++;
        
        score += Math.min(variety, 2);  // Max 2 points for variety
        
        // Penalty for patterns
        if (hasCommonPatterns(password)) {
            score = Math.max(0, score - 2);
        }
        
        // Penalty for dictionary words
        if (containsDictionaryWord(password)) {
            score = Math.max(0, score - 1);
        }
        
        // Convert score to strength enum
        if (score <= 1) return PasswordStrength.VERY_WEAK;
        if (score == 2) return PasswordStrength.WEAK;
        if (score == 3) return PasswordStrength.FAIR;
        if (score == 4) return PasswordStrength.GOOD;
        return PasswordStrength.STRONG;
    }
    
    private boolean hasCommonPatterns(String password) {
        String lower = password.toLowerCase();
        return lower.contains("123") || 
               lower.contains("abc") || 
               lower.contains("qwerty") ||
               lower.matches(".(.)\\1{2,}.*");  // Repeated chars: aaa, 111
    }
}
```

**Breach Detection:**
```java
// Google checks passwords against known breaches
@Service
public class GoogleBreachDetection {
    
    @Async
    public void checkPasswordBreachAsync(String userId, String password) {
        if (isPasswordBreached(password)) {
            // Send warning notification
            notificationService.send(
                userId,
                "Password Security Alert",
                "Your password has appeared in a data breach. " +
                "Please change it immediately."
            );
            
            // Force password reset on next login
            userRepo.setPasswordResetRequired(userId, true);
        }
    }
}
```

### Example 2: Facebook's Password Security

Meta implements multiple password protection layers:

```java
@Service
public class FacebookStylePasswordSecurity {
    
    /**
     * Check password similarity to username/email
     */
    public void validatePasswordNotSimilar(
            String password, 
            String username, 
            String email
    ) {
        String lowerPassword = password.toLowerCase();
        String lowerUsername = username.toLowerCase();
        String emailLocal = email.split("@")[0].toLowerCase();
        
        // Check if password contains username
        if (lowerPassword.contains(lowerUsername) || 
            lowerUsername.contains(lowerPassword)) {
            throw new WeakPasswordException(
                "Password cannot contain your username"
            );
        }
        
        // Check if password contains email local part
        if (lowerPassword.contains(emailLocal) || 
            emailLocal.contains(lowerPassword)) {
            throw new WeakPasswordException(
                "Password cannot contain your email address"
            );
        }
        
        // Check Levenshtein distance
        int distance = LevenshteinDistance.getDefaultInstance()
            .apply(lowerPassword, lowerUsername);
        
        if (distance < 3) {
            throw new WeakPasswordException(
                "Password is too similar to your username"
            );
        }
    }
    
    /**
     * Check against user's previous passwords
     */
    public void validateNotRecentPassword(Long userId, String newPassword) {
        List<String> recentPasswordHashes = passwordHistoryRepo
            .findRecentPasswords(userId, 5);  // Check last 5 passwords
        
        for (String oldHash : recentPasswordHashes) {
            if (passwordService.verifyPassword(newPassword, oldHash)) {
                throw new WeakPasswordException(
                    "Cannot reuse any of your last 5 passwords"
                );
            }
        }
    }
    
    /**
     * Suspicious login detection
     */
    public void checkSuspiciousLogin(Long userId, String ipAddress, String userAgent) {
        // Get user's typical login locations
        List<String> typicalLocations = getTypicalLoginLocations(userId);
        String currentLocation = geoIP.getLocation(ipAddress);
        
        if (!typicalLocations.contains(currentLocation)) {
            // New location - require additional verification
            String code = generateVerificationCode();
            smsService.send(getUserPhone(userId), 
                "Facebook login code: " + code);
            
            throw new AdditionalVerificationRequiredException(code);
        }
    }
}
```

### Example 3: AWS IAM Password Policy

AWS enforces strict password policies for IAM users:

```java
@Service
public class AWSStylePasswordPolicy {
    
    @Data
    public static class PasswordPolicy {
        private int minimumLength = 14;
        private boolean requireUppercase = true;
        private boolean requireLowercase = true;
        private boolean requireNumbers = true;
        private boolean requireSymbols = true;
        private boolean allowUsersToChangePassword = true;
        private int passwordReusePrevention = 24;  // Remember 24 passwords
        private int maxPasswordAge = 90;  // Days until expiration
        private int hardExpiry = false;  // Hard vs soft expiration
    }
    
    /**
     * Validate password meets policy
     */
    public void validatePasswordPolicy(String password, PasswordPolicy policy) {
        List<String> violations = new ArrayList<>();
        
        if (password.length() < policy.getMinimumLength()) {
            violations.add("Password must be at least " + 
                policy.getMinimumLength() + " characters");
        }
        
        if (policy.isRequireUppercase() && 
            !password.chars().anyMatch(Character::isUpperCase)) {
            violations.add("Password must contain at least one uppercase letter");
        }
        
        if (policy.isRequireLowercase() && 
            !password.chars().anyMatch(Character::isLowerCase)) {
            violations.add("Password must contain at least one lowercase letter");
        }
        
        if (policy.isRequireNumbers() && 
            !password.chars().anyMatch(Character::isDigit)) {
            violations.add("Password must contain at least one number");
        }
        
        if (policy.isRequireSymbols() && 
            !password.chars().anyMatch(ch -> !Character.isLetterOrDigit(ch))) {
            violations.add("Password must contain at least one special character");
        }
        
        if (!violations.isEmpty()) {
            throw new PasswordPolicyViolationException(violations);
        }
    }
    
    /**
     * Check password expiration
     */
    @Scheduled(cron = "0 0 9 * * *")  // Daily at 9 AM
    public void checkPasswordExpiration() {
        PasswordPolicy policy = getPasswordPolicy();
        if (policy.getMaxPasswordAge() == 0) {
            return;  // No expiration policy
        }
        
        Instant expirationThreshold = Instant.now()
            .minus(policy.getMaxPasswordAge(), ChronoUnit.DAYS);
        
        List<User> expiredUsers = userRepo
            .findUsersWithPasswordOlderThan(expirationThreshold);
        
        for (User user : expiredUsers) {
            if (policy.isHardExpiry()) {
                // Hard expiry: Lock account
                user.setLocked(true);
                user.setLockReason("Password expired");
                notificationService.send(user,
                    "Account locked - password expired",
                    "Your password has expired. Please contact administrator.");
            } else {
                // Soft expiry: Force change on next login
                user.setPasswordChangeRequired(true);
                notificationService.send(user,
                    "Password expiration warning",
                    "Your password has expired. You will be required to " +
                    "change it on your next login.");
            }
            
            userRepo.save(user);
        }
    }
}
```

---

## Interview Question: Design Password System for 1 Billion Users

**Question:** Design a password storage and verification system for a global platform with 1 billion users. Handle 1 million login requests per second. Ensure security and performance.

**Answer:**

```
Architecture:

┌──────────────────────────────────────────────────────┐
│                   CLIENT                              │
│  POST /login {email, password, device_id}            │
└────────────────────┬─────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────┐
│             API GATEWAY / LOAD BALANCER              │
│  - Rate limiting (10 attempts / 15 min per IP)       │
│  - DDoS protection                                    │
└────────────────────┬─────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────┐
│          AUTH SERVICE (Stateless, Horizontally       │
│                      Scaled)                          │
│  1. Validate input                                    │
│  2. Check rate limits (Redis)                        │
│  3. Verify password                                   │
└────────┬────────────────────────────┬────────────────┘
         │                             │
         │ Read                        │ Write
         ▼                             ▼
┌───────────────────┐         ┌────────────────────┐
│  PASSWORD CACHE   │         │   AUDIT LOG DB     │
│    (Redis)        │         │  (Failed attempts)  │
│ - Hash cache      │         └────────────────────┘
│ - 5min TTL        │
└───────────────────┘
         │
         │ Cache miss
         ▼
┌──────────────────────────────────────────────────────┐
│          USER DATABASE (Sharded by user_id)          │
│  Shard 1: users 0-250M                               │
│  Shard 2: users 250M-500M                            │
│  Shard 3: users 500M-750M                            │
│  Shard 4: users 750M-1B                              │
└──────────────────────────────────────────────────────┘
```

**Database Schema:**

```sql
CREATE TABLE users (
    id BIGINT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(60) NOT NULL,  -- bcrypt with embedded salt
    password_version INT NOT NULL DEFAULT 1,  -- For cost factor rotation
    password_changed_at TIMESTAMP NOT NULL,
    failed_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL,
    
    INDEX idx_email (email),
    INDEX idx_locked (locked_until)
) PARTITION BY HASH(id) PARTITIONS 4;  -- Horizontal partitioning

CREATE TABLE password_history (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    password_hash VARCHAR(60) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    
    INDEX idx_user_created (user_id, created_at DESC),
    FOREIGN KEY (user_id) REFERENCES users(id)
) PARTITION BY HASH(user_id) PARTITIONS 4;

CREATE TABLE login_attempts (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT NULL,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    attempted_at TIMESTAMP NOT NULL,
    
    INDEX idx_email_time (email, attempted_at DESC),
    INDEX idx_ip_time (ip_address, attempted_at DESC)
) PARTITION BY RANGE (UNIX_TIMESTAMP(attempted_at)) (
    PARTITION p_2024_01 VALUES LESS THAN (UNIX_TIMESTAMP('2024-02-01')),
    PARTITION p_2024_02 VALUES LESS THAN (UNIX_TIMESTAMP('2024-03-01')),
    -- Time-based partitions for easy archival
);
```

**Implementation:**

```java
@Service
public class ScalableAuthService {
    
    @Autowired
    private UserRepository userRepo;
    
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    
    @Autowired
    private RedisTemplate<String, String> redis;
    
    @Autowired
    private RateLimiter rateLimiter;
    
    /**
     * Login with high-performance caching
     */
    public LoginResult login(String email, String password, String ipAddress) {
        // 1. Rate limit check (fast fail)
        if (!rateLimiter.allowLogin(email, ipAddress)) {
            return LoginResult.failure("Too many failed attempts. Try again later.");
        }
        
        // 2. Try to get cached password hash
        String cacheKey = "pwd_hash:" + hashEmail(email);
        String cachedHash = redis.opsForValue().get(cacheKey);
        
        User user;
        String actualHash;
        
        if (cachedHash != null) {
            // Fast path: Use cached hash
            actualHash = cachedHash;
            // We still need user object for other checks
            user = userRepo.findByEmail(email).orElse(null);
            if (user == null) {
                // Cache inconsistency - clear and retry
                redis.delete(cacheKey);
                return login(email, password, ipAddress);  // Recursive call
            }
        } else {
            // Slow path: Database lookup
            user = userRepo.findByEmail(email).orElse(null);
            if (user == null) {
                // Don't reveal if email exists
                // Perform fake hash to prevent timing attacks
                passwordEncoder.encode("fake_password_to_match_timing");
                logFailedAttempt(null, email, ipAddress, "USER_NOT_FOUND");
                return LoginResult.failure("Invalid credentials");
            }
            
            actualHash = user.getPasswordHash();
            
            // Cache the hash for 5 minutes
            redis.opsForValue().set(cacheKey, actualHash, 5, TimeUnit.MINUTES);
        }
        
        // 3. Check if account is locked
        if (user.getLockedUntil() != null && 
            user.getLockedUntil().isAfter(Instant.now())) {
            long minutesRemaining = ChronoUnit.MINUTES.between(
                Instant.now(),
                user.getLockedUntil()
            );
            return LoginResult.failure(
                "Account is locked. Try again in " + minutesRemaining + " minutes."
            );
        }
        
        // 4. Verify password (expensive operation)
        long startTime = System.nanoTime();
        boolean passwordMatches = passwordEncoder.matches(password, actualHash);
        long duration = System.nanoTime() - startTime;
        
        // Log verification time for monitoring
        metricsService.recordPasswordVerification(duration / 1_000_000.0);  // ms
        
        if (!passwordMatches) {
            // Failed login
            incrementFailedAttempts(user, ipAddress);
            logFailedAttempt(user.getId(), email, ipAddress, "WRONG_PASSWORD");
            return LoginResult.failure("Invalid credentials");
        }
        
        // 5. Successful login
        resetFailedAttempts(user);
        logSuccessfulLogin(user.getId(), email, ipAddress);
        
        // 6. Check if password needs rehashing (cost factor increased)
        if (needsRehash(actualHash)) {
            CompletableFuture.runAsync(() -> {
                String newHash = passwordEncoder.encode(password);
                user.setPasswordHash(newHash);
                user.setPasswordVersion(getCurrentPasswordVersion());
                userRepo.save(user);
                // Update cache
                redis.opsForValue().set(cacheKey, newHash, 5, TimeUnit.MINUTES);
            });
        }
        
        // 7. Create session
        String sessionToken = sessionService.createSession(user.getId());
        
        return LoginResult.success(sessionToken, user.getId());
    }
    
    /**
     * Increment failed attempts and lock if needed
     */
    private void incrementFailedAttempts(User user, String ipAddress) {
        int attempts = user.getFailedAttempts() + 1;
        user.setFailedAttempts(attempts);
        
        if (attempts >= 5) {
            // Lock account for 30 minutes
            user.setLockedUntil(Instant.now().plus(30, ChronoUnit.MINUTES));
            
            // Send alert
            notificationService.send(
                user.getEmail(),
                "Account locked due to multiple failed login attempts",
                "If this wasn't you, please reset your password immediately."
            );
            
            // Alert security team
            securityAlerts.send(
                "Multiple failed login attempts",
                "User: " + user.getId() + ", IP: " + ipAddress
            );
        }
        
        userRepo.save(user);
    }
    
    /**
     * Hash email for cache key (don't cache raw emails)
     */
    private String hashEmail(String email) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(email.getBytes(StandardCharsets.UTF_8));
            return DatatypeConverter.printHexBinary(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
```

**Performance Optimizations:**

1. **Hash Caching:**
```java
// Cache password hashes in Redis for 5 minutes
// Reduces database load by 90%+
// 1M logins/sec → 100K DB queries/sec (90% cache hit rate)
```

2. **Database Sharding:**
```java
// Shard by user_id hash
// Each shard handles 250M users
// Distributes load across 4 database servers
```

3. **Read Replicas:**
```java
// Use read replicas for login (reads)
// Master only for registration/password change (writes)
// 10 read replicas → each handles 100K req/sec
```

4. **Async Logging:**
```java
// Don't wait for audit log writes
CompletableFuture.runAsync(() -> {
    auditLogRepo.save(loginAttempt);
});
```

5. **Rate Limiting in Redis:**
```java
// Distributed rate limiting
// Track attempts across all servers
String key = "login_rate:" + ipAddress;
Long attempts = redis.opsForValue().increment(key);
if (attempts == 1) {
    redis.expire(key, 15, TimeUnit.MINUTES);
}
if (attempts > 10) {
    return false;  // Rate limited
}
```

---

[Continue to S8: Single Sign-On (SSO)...]


# S8: Single Sign-On (SSO)

## 🎫 The Theme Park Analogy

Imagine visiting a large theme park resort with multiple parks:

**Without SSO (Pain):**
- Enter Disneyland → Show ID, buy ticket
- Go to California Adventure → Show ID AGAIN, buy another ticket
- Visit water park → Show ID AGAIN, buy another ticket
- Go to hotel → Show ID AGAIN, check-in separately

You prove your identity repeatedly!

**With SSO (Convenience):**
- Buy ONE resort pass at entrance
- Wear wristband with your identity
- Enter any park → Scan wristband → Access granted
- Hotel, restaurants, rides → All use same wristband
- Prove identity ONCE, access everything

This is SSO: Log in once, access multiple applications!

---

## Beginner Level: What is SSO?

### The Problem SSO Solves

Modern users access many applications:
- Email (Gmail)
- Calendar (Google Calendar)
- Storage (Google Drive)
- Docs (Google Docs)
- YouTube
- Google Maps

Without SSO: Login to EACH application separately
- 6 applications = 6 logins
- 6 passwords to remember
- 6 times entering credentials

With SSO: Login ONCE to Google
- All Google services automatically accessible
- One password to remember
- One login session

### How SSO Works (Simple Version)

```
1. User visits App A
   ↓
2. App A: "You're not logged in. Go to login server"
   ↓
3. User redirected to Central Login Server (Identity Provider)
   ↓
4. User logs in at Central Server
   ↓
5. Central Server: "Here's a token proving you're John Smith"
   ↓
6. User returns to App A with token
   ↓
7. App A: "Token valid! Welcome John Smith"
   ↓
8. User visits App B
   ↓
9. App B: "You're not logged in. Go to login server"
   ↓
10. Central Server: "You're already logged in! Here's token for App B"
    ↓
11. User returns to App B with token (NO LOGIN NEEDED!)
    ↓
12. App B: "Token valid! Welcome John Smith"
```

### SSO Protocols

**1. SAML (Security Assertion Markup Language)**
- XML-based
- Enterprise standard
- Complex but powerful
- Used by: Microsoft, Okta, OneLogin

**2. OAuth 2.0 + OpenID Connect**
- JSON-based
- Modern, simple
- Web and mobile friendly
- Used by: Google, Facebook, GitHub

**3. CAS (Central Authentication Service)**
- Ticket-based
- Academic institutions
- Simpler than SAML

---

## Intermediate: SAML Implementation

### SAML Flow

```
┌──────────┐                         ┌─────────────┐                    ┌──────────┐
│  Browser │                         │  Service    │                    │ Identity │
│          │                         │  Provider   │                    │ Provider │
│  (User)  │                         │   (SP)      │                    │   (IdP)  │
└──────────┘                         └─────────────┘                    └──────────┘
     │                                      │                                  │
     │ 1. Access protected resource        │                                  │
     │─────────────────────────────────────>│                                  │
     │                                      │                                  │
     │ 2. Redirect to IdP (SAML Request)    │                                  │
     │<─────────────────────────────────────│                                  │
     │                                      │                                  │
     │ 3. Forward SAML Request              │                                  │
     │────────────────────────────────────────────────────────────────────────>│
     │                                      │                                  │
     │ 4. Login form (if not authenticated) │                                  │
     │<────────────────────────────────────────────────────────────────────────│
     │                                      │                                  │
     │ 5. Submit credentials                │                                  │
     │────────────────────────────────────────────────────────────────────────>│
     │                                      │                                  │
     │ 6. SAML Response (signed assertion)  │                                  │
     │<────────────────────────────────────────────────────────────────────────│
     │                                      │                                  │
     │ 7. Forward SAML Response             │                                  │
     │─────────────────────────────────────>│                                  │
     │                                      │                                  │
     │                                      │ 8. Validate signature &          │
     │                                      │    extract user info             │
     │                                      │                                  │
     │ 9. Set session & redirect to         │                                  │
     │    protected resource                │                                  │
     │<─────────────────────────────────────│                                  │
```

### Java SAML Implementation (Service Provider)

```java
@RestController
@RequestMapping("/saml")
public class SAMLController {
    
    @Autowired
    private SAMLService samlService;
    
    /**
     * Initiate SSO login
     */
    @GetMapping("/login")
    public void initiateSSOLogin(HttpServletResponse response) throws Exception {
        // Generate SAML Authentication Request
        AuthnRequest authnRequest = samlService.buildAuthnRequest();
        
        // Sign the request
        String signedRequest = samlService.signAuthnRequest(authnRequest);
        
        // Encode and redirect to IdP
        String encoded = samlService.encodeRequest(signedRequest);
        String idpUrl = samlService.getIdPSSOUrl();
        
        response.sendRedirect(idpUrl + "?SAMLRequest=" + encoded);
    }
    
    /**
     * Handle SAML Response from IdP
     */
    @PostMapping("/acs")  // Assertion Consumer Service
    public ResponseEntity<?> handleSAMLResponse(
            @RequestParam("SAMLResponse") String samlResponse,
            HttpServletRequest request,
            HttpServletResponse httpResponse
    ) throws Exception {
        
        // 1. Decode SAML Response
        String decodedResponse = samlService.decodeResponse(samlResponse);
        
        // 2. Parse XML
        Response response = samlService.parseResponse(decodedResponse);
        
        // 3. Validate signature
        if (!samlService.validateSignature(response)) {
            return ResponseEntity.status(401).body("Invalid SAML signature");
        }
        
        // 4. Validate assertions
        if (!samlService.validateAssertions(response)) {
            return ResponseEntity.status(401).body("Invalid SAML assertions");
        }
        
        // 5. Extract user attributes
        SAMLUserInfo userInfo = samlService.extractUserInfo(response);
        
        // 6. Create local session
        String sessionToken = sessionService.createSession(
            userInfo.getEmail(),
            userInfo.getAttributes()
        );
        
        // 7. Set session cookie
        Cookie cookie = new Cookie("SESSION", sessionToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(3600);  // 1 hour
        httpResponse.addCookie(cookie);
        
        // 8. Redirect to original resource
        String relayState = request.getParameter("RelayState");
        return ResponseEntity.status(302)
            .header("Location", relayState != null ? relayState : "/dashboard")
            .build();
    }
}

@Service
public class SAMLService {
    
    @Value("${saml.idp.entityId}")
    private String idpEntityId;
    
    @Value("${saml.idp.ssoUrl}")
    private String idpSSOUrl;
    
    @Value("${saml.sp.entityId}")
    private String spEntityId;
    
    @Value("${saml.sp.acsUrl}")
    private String spAcsUrl;
    
    /**
     * Build SAML Authentication Request
     */
    public AuthnRequest buildAuthnRequest() {
        AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();
        
        authnRequest.setID(generateID());
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setDestination(idpSSOUrl);
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        authnRequest.setAssertionConsumerServiceURL(spAcsUrl);
        
        // Set Issuer (Service Provider)
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(spEntityId);
        authnRequest.setIssuer(issuer);
        
        // Request NameID format
        NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
        nameIDPolicy.setFormat(NameIDType.EMAIL);
        nameIDPolicy.setAllowCreate(true);
        authnRequest.setNameIDPolicy(nameIDPolicy);
        
        return authnRequest;
    }
    
    /**
     * Validate SAML Response signature
     */
    public boolean validateSignature(Response response) {
        try {
            // Get IdP certificate
            X509Certificate idpCert = getIdPCertificate();
            
            // Create credential
            BasicX509Credential credential = new BasicX509Credential(idpCert);
            
            // Validate signature
            SignatureValidator validator = new SignatureValidator(credential);
            validator.validate(response.getSignature());
            
            return true;
        } catch (ValidationException e) {
            log.error("SAML signature validation failed", e);
            return false;
        }
    }
    
    /**
     * Extract user info from SAML assertions
     */
    public SAMLUserInfo extractUserInfo(Response response) {
        Assertion assertion = response.getAssertions().get(0);
        
        SAMLUserInfo userInfo = new SAMLUserInfo();
        
        // Extract NameID (usually email)
        String nameID = assertion.getSubject().getNameID().getValue();
        userInfo.setEmail(nameID);
        
        // Extract attributes
        for (AttributeStatement statement : assertion.getAttributeStatements()) {
            for (Attribute attribute : statement.getAttributes()) {
                String name = attribute.getName();
                String value = getAttributeValue(attribute);
                
                switch (name) {
                    case "firstName":
                        userInfo.setFirstName(value);
                        break;
                    case "lastName":
                        userInfo.setLastName(value);
                        break;
                    case "email":
                        userInfo.setEmail(value);
                        break;
                    case "groups":
                        userInfo.setGroups(getAttributeValues(attribute));
                        break;
                    default:
                        userInfo.addAttribute(name, value);
                }
            }
        }
        
        return userInfo;
    }
}
```

---

## Real FAANG Example: Google Workspace SSO

```java
@Service
public class GoogleWorkspaceSSO {
    
    /**
     * Users can use Google Workspace to SSO into third-party apps
     */
    public void configureGoogleSSO() {
        // Google acts as Identity Provider (IdP)
        // Your app is Service Provider (SP)
        
        // Configuration:
        String idpEntityId = "https://accounts.google.com";
        String idpSSOUrl = "https://accounts.google.com/o/saml2/idp?idpid=YOUR_IDP_ID";
        String idpCertificate = getGoogleIDPCertificate();
        
        // User attributes Google provides:
        // - email (primary)
        // - firstName
        // - lastName
        // - groups (Google Groups membership)
    }
}
```

---

# S9: Role-Based Access Control (RBAC)

## 🎭 The Theater Analogy

Imagine a movie theater with different roles:

**Manager Role:**
- Can: Open/close theater, count money, hire/fire staff, set ticket prices
- Cannot: Nothing - they have full access

**Ticket Seller Role:**
- Can: Sell tickets, process refunds, view showtimes
- Cannot: Count daily revenue, hire staff, set prices

**Usher Role:**
- Can: Check tickets, help customers find seats, clean theater
- Cannot: Sell tickets, access cash register, view revenue

**Customer Role:**
- Can: Buy tickets, watch movies, buy snacks
- Cannot: Access staff areas, view other customers' info

This is RBAC: Permissions bundled into roles, roles assigned to users!

---

## Beginner Level: RBAC Basics

### What is RBAC?

Instead of assigning permissions directly to users:
```
❌ Bad (Direct Permissions):
User John → Can read users
User John → Can write users
User John → Can delete users
User John → Can read orders
... (100 permissions per user!)
```

Group permissions into roles:
```
✅ Good (RBAC):
Role "Admin" → Can read users, write users, delete users, ...
User John → Has role "Admin"

Simple! One role assignment instead of 100 permission assignments
```

### Core Components

1. **Users** - People using the system
2. **Roles** - Job functions (Admin, Manager, User)
3. **Permissions** - Actions (read, write, delete)
4. **Resources** - Things being accessed (users, orders, products)

### Database Schema

```sql
CREATE TABLE users (
    id BIGINT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL
);

CREATE TABLE roles (
    id BIGINT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT
);

CREATE TABLE permissions (
    id BIGINT PRIMARY KEY,
    resource VARCHAR(50) NOT NULL,  -- 'users', 'orders', 'products'
    action VARCHAR(20) NOT NULL,    -- 'read', 'write', 'delete'
    UNIQUE KEY (resource, action)
);

CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_by BIGINT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (assigned_by) REFERENCES users(id)
);

CREATE TABLE role_permissions (
    role_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
);
```

### Java Implementation

```java
@Service
public class RBACService {
    
    @Autowired
    private UserRepository userRepo;
    
    @Autowired
    private RoleRepository roleRepo;
    
    /**
     * Check if user has permission
     */
    public boolean hasPermission(Long userId, String resource, String action) {
        // Get user's roles
        List<Role> roles = userRepo.findRoles(userId);
        
        // Check if any role has the required permission
        for (Role role : roles) {
            if (roleHasPermission(role, resource, action)) {
                return true;
            }
        }
        
        return false;
    }
    
    private boolean roleHasPermission(Role role, String resource, String action) {
        return role.getPermissions().stream()
            .anyMatch(p -> p.getResource().equals(resource) && 
                          p.getAction().equals(action));
    }
    
    /**
     * Assign role to user
     */
    public void assignRole(Long userId, Long roleId, Long assignedBy) {
        User user = userRepo.findById(userId).orElseThrow();
        Role role = roleRepo.findById(roleId).orElseThrow();
        
        UserRole userRole = new UserRole();
        userRole.setUserId(userId);
        userRole.setRoleId(roleId);
        userRole.setAssignedBy(assignedBy);
        userRole.setAssignedAt(Instant.now());
        
        userRoleRepo.save(userRole);
        
        // Clear cache
        clearPermissionCache(userId);
    }
}

// Usage in Controller
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @Autowired
    private RBACService rbacService;
    
    @GetMapping("/{id}")
    public ResponseEntity<User> getUser(@PathVariable Long id) {
        Long currentUserId = getCurrentUserId();
        
        // Check permission
        if (!rbacService.hasPermission(currentUserId, "users", "read")) {
            return ResponseEntity.status(403).build();
        }
        
        return ResponseEntity.ok(userService.getUser(id));
    }
    
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        Long currentUserId = getCurrentUserId();
        
        // Check permission
        if (!rbacService.hasPermission(currentUserId, "users", "delete")) {
            return ResponseEntity.status(403)
                .body("You don't have permission to delete users");
        }
        
        userService.deleteUser(id);
        return ResponseEntity.ok().build();
    }
}
```

---

## Summary & Next Steps

**Part 3 Complete:**
- ✅ S7: Hashing & Salting - bcrypt, Argon2, breach detection
- ✅ S8: SSO - SAML, OAuth, enterprise integration
- ✅ S9: RBAC - Roles, permissions, access control

**Continue to Part 4 for:**
- S10: Attribute-Based Access Control (ABAC)
- S11: Zero Trust Architecture
- S12: Secret Management (Vault)

**Continue to Part 5 for:**
- S13: SQL Injection, XSS, CSRF Prevention
- S14: DDoS Protection
- S15: mTLS (Service-to-Service)