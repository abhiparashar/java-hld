# Security & Authentication Guide - Part 4 of 5

**Topics Covered:**
- S10: Attribute-Based Access Control (ABAC) 🟡 Important
- S11: Zero Trust Architecture 🟡 Important
- S12: Secret Management (Vault) 🟡 Important

**For FAANG System Design Interviews with Java Examples**

---

# S10: Attribute-Based Access Control (ABAC)

## 🎫 The Concert Ticket Analogy

Imagine you're at a music festival with different stages and VIP areas:

**Traditional RBAC (Role-Based):**
```
Your Ticket Type: "VIP Pass"
Access: All VIP lounges, backstage, main stage pit
```
Simple but inflexible - everyone with VIP gets the same access.

**ABAC (Attribute-Based):**
```
Your Attributes:
- Ticket Type: VIP
- Age: 28
- Purchase Date: Early Bird (3 months ago)
- Location: General Admission currently
- Time: 8:00 PM
- Band Preference: Rock

Access Decision:
- Main Stage Pit → ✅ (VIP + Rock preference + Time after 6PM)
- Backstage Meet & Greet → ✅ (VIP + Early Bird purchase)
- Bar Area → ✅ (Age > 21)
- EDM Stage VIP → ❌ (No EDM preference tag)
- After-Party → ❌ (Time before 11PM)
```

ABAC makes decisions based on MULTIPLE attributes, not just one role.

---

## Beginner Level: Understanding ABAC

### What is ABAC?

Attribute-Based Access Control makes authorization decisions by evaluating attributes (properties) of:
1. **Subject** - The user/service requesting access
2. **Resource** - What they're trying to access
3. **Action** - What they want to do
4. **Environment** - Context of the request

### RBAC vs ABAC Comparison

**RBAC Example:**
```
User: john_smith
Role: Developer

Permissions:
✅ Read source code
✅ Write source code
✅ Deploy to staging
❌ Deploy to production
❌ Access customer data
```

Problem: What if John needs to deploy to production during an emergency? You'd have to change his role.

**ABAC Example:**
```
User: john_smith
Attributes:
- Role: Developer
- Team: Backend
- Clearance Level: L3
- On-Call: Yes (this week)
- Location: Office Network
- Time: 2:00 AM

Request: Deploy to production

Policy Evaluation:
IF (role = Developer) 
   AND (on_call = Yes) 
   AND (time BETWEEN 00:00 AND 06:00) 
   AND (location = Office OR VPN)
THEN ALLOW production deployment

Result: ✅ ALLOWED (emergency deployment during on-call)
```

### The Four ABAC Components

#### 1. Subject Attributes (Who)
```
User Attributes:
- user_id: "john_smith"
- role: "developer"
- department: "engineering"
- clearance_level: 3
- employment_type: "full-time"
- manager: "sarah_jones"
- hire_date: "2022-01-15"
- certifications: ["AWS", "CISSP"]
```

#### 2. Resource Attributes (What)
```
Document Attributes:
- doc_id: "proj-123-design"
- classification: "confidential"
- owner: "engineering"
- project: "payment-system-v2"
- created_date: "2024-01-10"
- tags: ["finance", "pci-compliance"]
- status: "draft"
```

#### 3. Action Attributes (How)
```
Action: "edit"
Action Attributes:
- operation: "UPDATE"
- risk_level: "medium"
- requires_approval: false
- audit_required: true
```

#### 4. Environment Attributes (When/Where)
```
Context:
- current_time: "2024-01-23T14:30:00Z"
- day_of_week: "Tuesday"
- ip_address: "10.0.50.42"
- network: "corporate"
- device_type: "laptop"
- device_compliance: "compliant"
- geo_location: "USA"
```

---

## Intermediate Level: ABAC Policies

### Policy Structure

An ABAC policy is a rule that evaluates attributes to make access decisions.

**Policy Template:**
```
IF <condition on attributes>
THEN <permit or deny>
```

### Real-World Policy Examples

#### Example 1: Document Access Policy

```
Policy: Engineering Documents Access

PERMIT IF:
  (subject.department = "engineering" OR subject.role = "executive")
  AND resource.classification IN ["public", "internal", "confidential"]
  AND action = "read"
  AND environment.network IN ["corporate", "vpn"]

DENY IF:
  resource.classification = "restricted"
  AND subject.clearance_level < 4

PERMIT IF:
  resource.owner = subject.department
  AND action IN ["read", "write"]
  AND environment.time BETWEEN 06:00 AND 22:00
```

#### Example 2: Database Access Policy

```
Policy: Customer Data Access

PERMIT IF:
  subject.role = "customer_support"
  AND action = "read"
  AND resource.customer_id IN subject.assigned_accounts
  AND environment.ip_address IN approved_ips
  AND environment.time BETWEEN 08:00 AND 20:00

DENY IF:
  action = "delete"
  AND subject.role != "dba_admin"

PERMIT IF:
  subject.role = "data_analyst"
  AND action = "read"
  AND resource.contains_pii = false
  AND subject.has_certification("GDPR")
```

---

## Advanced Level: ABAC Implementation

### Architecture Overview

```
┌─────────────┐
│   Client    │
│ (User/App)  │
└──────┬──────┘
       │ 1. Access Request
       ▼
┌─────────────────────────────────┐
│   Policy Enforcement Point      │
│        (PEP)                     │
│  - Intercepts requests           │
│  - Collects attributes           │
│  - Enforces decisions            │
└──────┬──────────────────────────┘
       │ 2. Authorization Request
       ▼
┌─────────────────────────────────┐
│   Policy Decision Point         │
│        (PDP)                     │
│  - Evaluates policies            │
│  - Makes permit/deny decision    │
└──────┬──────────────────────────┘
       │ 3. Fetch Attributes
       │
    ┌──┴──┐
    ▼     ▼
┌─────┐ ┌──────────┐
│ PIP │ │   PAP    │
│     │ │          │
│Attr │ │ Policies │
└─────┘ └──────────┘

Components:
- PEP: Policy Enforcement Point (interceptor)
- PDP: Policy Decision Point (decision engine)
- PIP: Policy Information Point (attribute source)
- PAP: Policy Administration Point (policy storage)
```

### Java Implementation - Complete ABAC System

#### 1. Attribute Classes

```java
// Subject.java - Represents the requesting user/service
public class Subject {
    private String userId;
    private String role;
    private String department;
    private int clearanceLevel;
    private Set<String> groups;
    private Set<String> certifications;
    private Map<String, Object> customAttributes;
    
    public Subject(String userId) {
        this.userId = userId;
        this.customAttributes = new HashMap<>();
    }
    
    public Object getAttribute(String key) {
        switch(key) {
            case "user_id": return userId;
            case "role": return role;
            case "department": return department;
            case "clearance_level": return clearanceLevel;
            case "groups": return groups;
            case "certifications": return certifications;
            default: return customAttributes.get(key);
        }
    }
    
    public boolean hasGroup(String group) {
        return groups != null && groups.contains(group);
    }
    
    public boolean hasCertification(String cert) {
        return certifications != null && certifications.contains(cert);
    }
    
    // Getters and setters
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
    
    public String getDepartment() { return department; }
    public void setDepartment(String department) { this.department = department; }
    
    public int getClearanceLevel() { return clearanceLevel; }
    public void setClearanceLevel(int level) { this.clearanceLevel = level; }
    
    public Set<String> getGroups() { return groups; }
    public void setGroups(Set<String> groups) { this.groups = groups; }
    
    public Set<String> getCertifications() { return certifications; }
    public void setCertifications(Set<String> certs) { this.certifications = certs; }
}

// Resource.java - Represents what's being accessed
public class Resource {
    private String resourceId;
    private String resourceType;
    private String classification;
    private String owner;
    private Set<String> tags;
    private Map<String, Object> customAttributes;
    
    public Resource(String resourceId, String resourceType) {
        this.resourceId = resourceId;
        this.resourceType = resourceType;
        this.customAttributes = new HashMap<>();
    }
    
    public Object getAttribute(String key) {
        switch(key) {
            case "resource_id": return resourceId;
            case "resource_type": return resourceType;
            case "classification": return classification;
            case "owner": return owner;
            case "tags": return tags;
            default: return customAttributes.get(key);
        }
    }
    
    public boolean hasTag(String tag) {
        return tags != null && tags.contains(tag);
    }
    
    // Getters and setters
    public String getResourceId() { return resourceId; }
    public String getResourceType() { return resourceType; }
    public String getClassification() { return classification; }
    public void setClassification(String classification) { 
        this.classification = classification; 
    }
    public String getOwner() { return owner; }
    public void setOwner(String owner) { this.owner = owner; }
    public Set<String> getTags() { return tags; }
    public void setTags(Set<String> tags) { this.tags = tags; }
}

// Action.java - Represents what action is being performed
public class Action {
    private String operation; // read, write, delete, execute
    private String riskLevel; // low, medium, high
    private boolean requiresApproval;
    
    public Action(String operation) {
        this.operation = operation;
    }
    
    public String getOperation() { return operation; }
    public void setOperation(String operation) { this.operation = operation; }
    
    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String level) { this.riskLevel = level; }
    
    public boolean requiresApproval() { return requiresApproval; }
    public void setRequiresApproval(boolean requires) { 
        this.requiresApproval = requires; 
    }
}

// Environment.java - Represents context of the request
public class Environment {
    private Instant timestamp;
    private String ipAddress;
    private String network;
    private String geoLocation;
    private String deviceType;
    private boolean deviceCompliant;
    private DayOfWeek dayOfWeek;
    private LocalTime time;
    
    public Environment() {
        this.timestamp = Instant.now();
        LocalDateTime ldt = LocalDateTime.now();
        this.dayOfWeek = ldt.getDayOfWeek();
        this.time = ldt.toLocalTime();
    }
    
    public boolean isWithinTimeRange(LocalTime start, LocalTime end) {
        return !time.isBefore(start) && !time.isAfter(end);
    }
    
    public boolean isWeekday() {
        return dayOfWeek != DayOfWeek.SATURDAY && 
               dayOfWeek != DayOfWeek.SUNDAY;
    }
    
    // Getters and setters
    public Instant getTimestamp() { return timestamp; }
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ip) { this.ipAddress = ip; }
    public String getNetwork() { return network; }
    public void setNetwork(String network) { this.network = network; }
    public String getGeoLocation() { return geoLocation; }
    public void setGeoLocation(String location) { this.geoLocation = location; }
    public boolean isDeviceCompliant() { return deviceCompliant; }
    public void setDeviceCompliant(boolean compliant) { 
        this.deviceCompliant = compliant; 
    }
    public LocalTime getTime() { return time; }
    public DayOfWeek getDayOfWeek() { return dayOfWeek; }
}
```

#### 2. Policy Engine

```java
// Policy.java - Represents an ABAC policy
public interface Policy {
    /**
     * Evaluates the policy against the provided context
     * @return AccessDecision (PERMIT, DENY, or NOT_APPLICABLE)
     */
    AccessDecision evaluate(Subject subject, Resource resource, 
                           Action action, Environment environment);
    
    String getPolicyId();
    String getDescription();
    int getPriority(); // Higher priority policies evaluated first
}

// AccessDecision.java
public enum AccessDecision {
    PERMIT,
    DENY,
    NOT_APPLICABLE;
    
    public boolean isPermit() {
        return this == PERMIT;
    }
    
    public boolean isDeny() {
        return this == DENY;
    }
}

// Example Policy Implementation
public class EngineeringDocumentPolicy implements Policy {
    private static final String POLICY_ID = "engineering-doc-access-v1";
    
    @Override
    public String getPolicyId() {
        return POLICY_ID;
    }
    
    @Override
    public String getDescription() {
        return "Controls access to engineering documents based on " +
               "department, classification, and time of day";
    }
    
    @Override
    public int getPriority() {
        return 100;
    }
    
    @Override
    public AccessDecision evaluate(Subject subject, Resource resource,
                                   Action action, Environment environment) {
        
        // Only applies to document resources
        if (!"document".equals(resource.getResourceType())) {
            return AccessDecision.NOT_APPLICABLE;
        }
        
        String classification = resource.getClassification();
        String subjectDept = subject.getDepartment();
        String resourceOwner = resource.getOwner();
        int clearanceLevel = subject.getClearanceLevel();
        
        // Rule 1: Restricted documents require clearance level 4+
        if ("restricted".equals(classification)) {
            if (clearanceLevel < 4) {
                return AccessDecision.DENY;
            }
        }
        
        // Rule 2: Confidential documents require same department or exec
        if ("confidential".equals(classification)) {
            boolean sameDept = resourceOwner.equals(subjectDept);
            boolean isExec = "executive".equals(subject.getRole());
            
            if (!sameDept && !isExec) {
                return AccessDecision.DENY;
            }
        }
        
        // Rule 3: Write operations only during business hours
        if ("write".equals(action.getOperation()) ||
            "delete".equals(action.getOperation())) {
            
            LocalTime businessStart = LocalTime.of(6, 0);
            LocalTime businessEnd = LocalTime.of(22, 0);
            
            if (!environment.isWithinTimeRange(businessStart, businessEnd)) {
                return AccessDecision.DENY;
            }
        }
        
        // Rule 4: Must be on corporate network or VPN
        String network = environment.getNetwork();
        if (!"corporate".equals(network) && !"vpn".equals(network)) {
            return AccessDecision.DENY;
        }
        
        // Rule 5: Engineering department gets read access to all
        if ("engineering".equals(subjectDept) && 
            "read".equals(action.getOperation())) {
            return AccessDecision.PERMIT;
        }
        
        // Rule 6: Document owner gets full access
        if (resourceOwner.equals(subjectDept)) {
            return AccessDecision.PERMIT;
        }
        
        return AccessDecision.NOT_APPLICABLE;
    }
}

// Another example: Customer Data Access Policy
public class CustomerDataPolicy implements Policy {
    private static final String POLICY_ID = "customer-data-access-v1";
    
    @Override
    public String getPolicyId() {
        return POLICY_ID;
    }
    
    @Override
    public String getDescription() {
        return "Controls access to customer PII data";
    }
    
    @Override
    public int getPriority() {
        return 200; // Higher priority than document policy
    }
    
    @Override
    public AccessDecision evaluate(Subject subject, Resource resource,
                                   Action action, Environment environment) {
        
        if (!"customer_data".equals(resource.getResourceType())) {
            return AccessDecision.NOT_APPLICABLE;
        }
        
        String role = subject.getRole();
        String operation = action.getOperation();
        
        // Rule 1: Only specific roles can access customer data
        Set<String> allowedRoles = Set.of(
            "customer_support", "data_analyst", "compliance_officer"
        );
        
        if (!allowedRoles.contains(role)) {
            return AccessDecision.DENY;
        }
        
        // Rule 2: Delete operations require compliance officer
        if ("delete".equals(operation)) {
            if (!"compliance_officer".equals(role)) {
                return AccessDecision.DENY;
            }
        }
        
        // Rule 3: Access only during business hours
        if (!environment.isWeekday()) {
            return AccessDecision.DENY;
        }
        
        LocalTime start = LocalTime.of(8, 0);
        LocalTime end = LocalTime.of(20, 0);
        if (!environment.isWithinTimeRange(start, end)) {
            return AccessDecision.DENY;
        }
        
        // Rule 4: Must have GDPR certification for EU customers
        if (resource.hasTag("eu_customer")) {
            if (!subject.hasCertification("GDPR")) {
                return AccessDecision.DENY;
            }
        }
        
        // Rule 5: Device must be compliant
        if (!environment.isDeviceCompliant()) {
            return AccessDecision.DENY;
        }
        
        return AccessDecision.PERMIT;
    }
}
```

#### 3. Policy Decision Point (PDP)

```java
// PolicyDecisionPoint.java - The core decision engine
public class PolicyDecisionPoint {
    private List<Policy> policies;
    private PolicyCombiningAlgorithm combiningAlgorithm;
    
    public PolicyDecisionPoint() {
        this.policies = new ArrayList<>();
        this.combiningAlgorithm = new DenyOverridesAlgorithm();
    }
    
    public void addPolicy(Policy policy) {
        policies.add(policy);
        // Sort by priority (higher first)
        policies.sort((p1, p2) -> Integer.compare(
            p2.getPriority(), p1.getPriority()
        ));
    }
    
    /**
     * Main authorization decision method
     */
    public AuthorizationResult authorize(Subject subject, Resource resource,
                                        Action action, Environment environment) {
        
        long startTime = System.nanoTime();
        List<PolicyEvaluation> evaluations = new ArrayList<>();
        
        // Evaluate all applicable policies
        for (Policy policy : policies) {
            AccessDecision decision = policy.evaluate(
                subject, resource, action, environment
            );
            
            evaluations.add(new PolicyEvaluation(
                policy.getPolicyId(),
                policy.getDescription(),
                decision
            ));
            
            // Stop if explicit DENY (fail-fast for security)
            if (decision == AccessDecision.DENY) {
                break;
            }
        }
        
        // Combine all decisions using combining algorithm
        AccessDecision finalDecision = combiningAlgorithm.combine(evaluations);
        
        long duration = System.nanoTime() - startTime;
        
        return new AuthorizationResult(
            finalDecision,
            evaluations,
            duration,
            Instant.now()
        );
    }
    
    public void setCombiningAlgorithm(PolicyCombiningAlgorithm algorithm) {
        this.combiningAlgorithm = algorithm;
    }
}

// PolicyCombiningAlgorithm.java - How to combine multiple policy results
public interface PolicyCombiningAlgorithm {
    AccessDecision combine(List<PolicyEvaluation> evaluations);
}

// DenyOverridesAlgorithm.java - Any DENY wins
public class DenyOverridesAlgorithm implements PolicyCombiningAlgorithm {
    @Override
    public AccessDecision combine(List<PolicyEvaluation> evaluations) {
        boolean hasPermit = false;
        
        for (PolicyEvaluation eval : evaluations) {
            if (eval.getDecision() == AccessDecision.DENY) {
                return AccessDecision.DENY; // DENY wins immediately
            }
            if (eval.getDecision() == AccessDecision.PERMIT) {
                hasPermit = true;
            }
        }
        
        // Default deny if no policy permitted
        return hasPermit ? AccessDecision.PERMIT : AccessDecision.DENY;
    }
}

// PermitOverridesAlgorithm.java - Any PERMIT wins
public class PermitOverridesAlgorithm implements PolicyCombiningAlgorithm {
    @Override
    public AccessDecision combine(List<PolicyEvaluation> evaluations) {
        for (PolicyEvaluation eval : evaluations) {
            if (eval.getDecision() == AccessDecision.PERMIT) {
                return AccessDecision.PERMIT; // PERMIT wins immediately
            }
        }
        
        // Default deny if no policy permitted
        return AccessDecision.DENY;
    }
}

// AuthorizationResult.java - Result of authorization
public class AuthorizationResult {
    private AccessDecision decision;
    private List<PolicyEvaluation> policyEvaluations;
    private long durationNanos;
    private Instant timestamp;
    
    public AuthorizationResult(AccessDecision decision,
                              List<PolicyEvaluation> evaluations,
                              long duration, Instant timestamp) {
        this.decision = decision;
        this.policyEvaluations = evaluations;
        this.durationNanos = duration;
        this.timestamp = timestamp;
    }
    
    public boolean isPermitted() {
        return decision == AccessDecision.PERMIT;
    }
    
    public boolean isDenied() {
        return decision == AccessDecision.DENY;
    }
    
    public String getExplanation() {
        StringBuilder sb = new StringBuilder();
        sb.append("Authorization Decision: ").append(decision).append("\n");
        sb.append("Evaluated Policies:\n");
        
        for (PolicyEvaluation eval : policyEvaluations) {
            sb.append("  - ").append(eval.getPolicyId())
              .append(": ").append(eval.getDecision()).append("\n");
        }
        
        sb.append("Duration: ").append(durationNanos / 1_000_000).append(" ms");
        return sb.toString();
    }
    
    // Getters
    public AccessDecision getDecision() { return decision; }
    public List<PolicyEvaluation> getPolicyEvaluations() { 
        return policyEvaluations; 
    }
    public long getDurationNanos() { return durationNanos; }
    public Instant getTimestamp() { return timestamp; }
}

// PolicyEvaluation.java - Result of a single policy evaluation
public class PolicyEvaluation {
    private String policyId;
    private String description;
    private AccessDecision decision;
    
    public PolicyEvaluation(String policyId, String description, 
                           AccessDecision decision) {
        this.policyId = policyId;
        this.description = description;
        this.decision = decision;
    }
    
    public String getPolicyId() { return policyId; }
    public String getDescription() { return description; }
    public AccessDecision getDecision() { return decision; }
}
```

#### 4. Policy Enforcement Point (PEP)

```java
// PolicyEnforcementPoint.java - Spring interceptor that enforces ABAC
@Component
public class PolicyEnforcementPoint implements HandlerInterceptor {
    
    @Autowired
    private PolicyDecisionPoint pdp;
    
    @Autowired
    private AttributeResolver attributeResolver;
    
    @Autowired
    private AuditLogger auditLogger;
    
    @Override
    public boolean preHandle(HttpServletRequest request,
                            HttpServletResponse response,
                            Object handler) throws Exception {
        
        // 1. Extract Subject from authentication
        Subject subject = extractSubject(request);
        
        // 2. Determine Resource being accessed
        Resource resource = extractResource(request);
        
        // 3. Determine Action
        Action action = extractAction(request);
        
        // 4. Collect Environment context
        Environment environment = extractEnvironment(request);
        
        // 5. Enrich attributes
        attributeResolver.enrichSubject(subject);
        attributeResolver.enrichResource(resource);
        
        // 6. Make authorization decision
        AuthorizationResult result = pdp.authorize(
            subject, resource, action, environment
        );
        
        // 7. Log the decision
        auditLogger.logAccess(subject, resource, action, result);
        
        // 8. Enforce decision
        if (result.isPermitted()) {
            // Store result in request for later use
            request.setAttribute("authz_result", result);
            return true; // Allow request to proceed
        } else {
            // Deny access
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write(String.format(
                "{\"error\": \"Access Denied\", \"reason\": \"%s\"}",
                result.getExplanation().replace("\n", " ")
            ));
            return false; // Block request
        }
    }
    
    private Subject extractSubject(HttpServletRequest request) {
        // Get authenticated user from security context
        Authentication auth = SecurityContextHolder.getContext()
                                                    .getAuthentication();
        
        if (auth == null || !auth.isAuthenticated()) {
            throw new UnauthorizedException("Not authenticated");
        }
        
        UserPrincipal principal = (UserPrincipal) auth.getPrincipal();
        
        Subject subject = new Subject(principal.getUserId());
        subject.setRole(principal.getRole());
        subject.setDepartment(principal.getDepartment());
        subject.setClearanceLevel(principal.getClearanceLevel());
        subject.setGroups(principal.getGroups());
        subject.setCertifications(principal.getCertifications());
        
        return subject;
    }
    
    private Resource extractResource(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String resourceId = extractResourceIdFromUri(uri);
        String resourceType = determineResourceType(uri);
        
        Resource resource = new Resource(resourceId, resourceType);
        
        // Will be enriched later by AttributeResolver
        return resource;
    }
    
    private Action extractAction(HttpServletRequest request) {
        String httpMethod = request.getMethod();
        String operation = mapHttpMethodToOperation(httpMethod);
        
        Action action = new Action(operation);
        
        // Determine risk level
        if ("DELETE".equals(httpMethod)) {
            action.setRiskLevel("high");
            action.setRequiresApproval(true);
        } else if ("POST".equals(httpMethod) || "PUT".equals(httpMethod)) {
            action.setRiskLevel("medium");
        } else {
            action.setRiskLevel("low");
        }
        
        return action;
    }
    
    private Environment extractEnvironment(HttpServletRequest request) {
        Environment env = new Environment();
        
        // Extract IP address
        String ipAddress = request.getRemoteAddr();
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null) {
            ipAddress = forwardedFor.split(",")[0].trim();
        }
        env.setIpAddress(ipAddress);
        
        // Determine network
        if (isVPNAddress(ipAddress)) {
            env.setNetwork("vpn");
        } else if (isCorporateAddress(ipAddress)) {
            env.setNetwork("corporate");
        } else {
            env.setNetwork("internet");
        }
        
        // Device info from User-Agent
        String userAgent = request.getHeader("User-Agent");
        env.setDeviceType(parseDeviceType(userAgent));
        
        // Geo-location from IP
        env.setGeoLocation(lookupGeoLocation(ipAddress));
        
        // Device compliance (from custom header or session)
        String compliance = request.getHeader("X-Device-Compliance");
        env.setDeviceCompliant("true".equals(compliance));
        
        return env;
    }
    
    private String mapHttpMethodToOperation(String httpMethod) {
        switch (httpMethod.toUpperCase()) {
            case "GET":
            case "HEAD":
                return "read";
            case "POST":
            case "PUT":
            case "PATCH":
                return "write";
            case "DELETE":
                return "delete";
            default:
                return "execute";
        }
    }
    
    private String extractResourceIdFromUri(String uri) {
        // Parse URI to extract resource ID
        // Example: /api/documents/doc-12345 → doc-12345
        String[] parts = uri.split("/");
        if (parts.length >= 2) {
            return parts[parts.length - 1];
        }
        return uri;
    }
    
    private String determineResourceType(String uri) {
        if (uri.contains("/documents")) return "document";
        if (uri.contains("/customers")) return "customer_data";
        if (uri.contains("/employees")) return "employee_data";
        return "unknown";
    }
    
    private boolean isVPNAddress(String ip) {
        // Check if IP is in VPN range
        return ip.startsWith("10.1.") || ip.startsWith("192.168.100.");
    }
    
    private boolean isCorporateAddress(String ip) {
        // Check if IP is in corporate range
        return ip.startsWith("10.0.") || ip.startsWith("172.16.");
    }
    
    private String parseDeviceType(String userAgent) {
        if (userAgent.contains("Mobile")) return "mobile";
        if (userAgent.contains("Tablet")) return "tablet";
        return "desktop";
    }
    
    private String lookupGeoLocation(String ip) {
        // In production, use MaxMind GeoIP or similar
        return "USA"; // Simplified
    }
}

// AttributeResolver.java - Enriches attributes from various sources
@Service
public class AttributeResolver {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private ResourceRepository resourceRepository;
    
    @Autowired
    private RedisTemplate<String, Object> redis;
    
    /**
     * Enriches subject with additional attributes from database
     */
    public void enrichSubject(Subject subject) {
        // Try cache first
        String cacheKey = "subject:" + subject.getUserId();
        Map<String, Object> cached = (Map<String, Object>) redis.opsForValue()
                                                                  .get(cacheKey);
        
        if (cached != null) {
            applyAttributesToSubject(subject, cached);
            return;
        }
        
        // Fetch from database
        User user = userRepository.findById(subject.getUserId())
                                  .orElseThrow();
        
        subject.setClearanceLevel(user.getClearanceLevel());
        subject.setGroups(user.getGroups());
        subject.setCertifications(user.getCertifications());
        
        // Cache for future requests
        Map<String, Object> toCache = new HashMap<>();
        toCache.put("clearance_level", user.getClearanceLevel());
        toCache.put("groups", user.getGroups());
        toCache.put("certifications", user.getCertifications());
        
        redis.opsForValue().set(cacheKey, toCache, 5, TimeUnit.MINUTES);
    }
    
    /**
     * Enriches resource with additional attributes
     */
    public void enrichResource(Resource resource) {
        String cacheKey = "resource:" + resource.getResourceId();
        Map<String, Object> cached = (Map<String, Object>) redis.opsForValue()
                                                                  .get(cacheKey);
        
        if (cached != null) {
            applyAttributesToResource(resource, cached);
            return;
        }
        
        // Fetch from database
        ResourceEntity entity = resourceRepository.findById(resource.getResourceId())
                                                  .orElse(null);
        
        if (entity != null) {
            resource.setClassification(entity.getClassification());
            resource.setOwner(entity.getOwner());
            resource.setTags(entity.getTags());
            
            // Cache
            Map<String, Object> toCache = new HashMap<>();
            toCache.put("classification", entity.getClassification());
            toCache.put("owner", entity.getOwner());
            toCache.put("tags", entity.getTags());
            
            redis.opsForValue().set(cacheKey, toCache, 5, TimeUnit.MINUTES);
        }
    }
    
    private void applyAttributesToSubject(Subject subject, 
                                         Map<String, Object> attributes) {
        if (attributes.containsKey("clearance_level")) {
            subject.setClearanceLevel((Integer) attributes.get("clearance_level"));
        }
        if (attributes.containsKey("groups")) {
            subject.setGroups((Set<String>) attributes.get("groups"));
        }
        if (attributes.containsKey("certifications")) {
            subject.setCertifications((Set<String>) attributes.get("certifications"));
        }
    }
    
    private void applyAttributesToResource(Resource resource,
                                          Map<String, Object> attributes) {
        if (attributes.containsKey("classification")) {
            resource.setClassification((String) attributes.get("classification"));
        }
        if (attributes.containsKey("owner")) {
            resource.setOwner((String) attributes.get("owner"));
        }
        if (attributes.containsKey("tags")) {
            resource.setTags((Set<String>) attributes.get("tags"));
        }
    }
}
```

#### 5. Complete Usage Example

```java
// Example: Using the ABAC system
public class ABACExample {
    
    public static void main(String[] args) {
        // Initialize PDP
        PolicyDecisionPoint pdp = new PolicyDecisionPoint();
        
        // Register policies
        pdp.addPolicy(new EngineeringDocumentPolicy());
        pdp.addPolicy(new CustomerDataPolicy());
        
        // Scenario 1: Engineer accessing engineering document
        Subject engineer = new Subject("john_doe");
        engineer.setRole("engineer");
        engineer.setDepartment("engineering");
        engineer.setClearanceLevel(3);
        engineer.setGroups(Set.of("backend-team", "on-call"));
        engineer.setCertifications(Set.of("AWS", "Kubernetes"));
        
        Resource doc = new Resource("doc-12345", "document");
        doc.setClassification("confidential");
        doc.setOwner("engineering");
        doc.setTags(Set.of("architecture", "internal"));
        
        Action readAction = new Action("read");
        readAction.setRiskLevel("low");
        
        Environment env = new Environment();
        env.setNetwork("corporate");
        env.setDeviceCompliant(true);
        env.setIpAddress("10.0.50.100");
        
        AuthorizationResult result = pdp.authorize(engineer, doc, 
                                                   readAction, env);
        
        System.out.println("Scenario 1: Engineer reading engineering doc");
        System.out.println(result.getExplanation());
        System.out.println("Permitted: " + result.isPermitted()); // true
        System.out.println();
        
        // Scenario 2: Engineer trying to access HR document
        Resource hrDoc = new Resource("doc-67890", "document");
        hrDoc.setClassification("confidential");
        hrDoc.setOwner("human-resources");
        hrDoc.setTags(Set.of("personnel", "confidential"));
        
        result = pdp.authorize(engineer, hrDoc, readAction, env);
        
        System.out.println("Scenario 2: Engineer trying to access HR doc");
        System.out.println(result.getExplanation());
        System.out.println("Permitted: " + result.isPermitted()); // false
        System.out.println();
        
        // Scenario 3: Customer support accessing customer data
        Subject support = new Subject("jane_support");
        support.setRole("customer_support");
        support.setDepartment("support");
        support.setClearanceLevel(2);
        support.setCertifications(Set.of("GDPR", "SOC2"));
        
        Resource customerData = new Resource("cust-999", "customer_data");
        customerData.setTags(Set.of("us_customer", "active"));
        
        Environment businessHours = new Environment();
        businessHours.setNetwork("corporate");
        businessHours.setDeviceCompliant(true);
        // Simulating business hours (would actually use current time)
        
        result = pdp.authorize(support, customerData, readAction, businessHours);
        
        System.out.println("Scenario 3: Support accessing customer data");
        System.out.println(result.getExplanation());
        System.out.println("Permitted: " + result.isPermitted()); // true
        System.out.println();
        
        // Scenario 4: Same support trying to delete customer data
        Action deleteAction = new Action("delete");
        deleteAction.setRiskLevel("high");
        deleteAction.setRequiresApproval(true);
        
        result = pdp.authorize(support, customerData, deleteAction, businessHours);
        
        System.out.println("Scenario 4: Support trying to delete customer data");
        System.out.println(result.getExplanation());
        System.out.println("Permitted: " + result.isPermitted()); // false
        System.out.println();
        
        // Scenario 5: After-hours access attempt
        Environment afterHours = new Environment();
        // Simulate 11 PM access
        afterHours.setNetwork("vpn");
        afterHours.setDeviceCompliant(true);
        
        result = pdp.authorize(support, customerData, readAction, afterHours);
        
        System.out.println("Scenario 5: After-hours access attempt");
        System.out.println(result.getExplanation());
        System.out.println("Permitted: " + result.isPermitted()); // false
    }
}
```

---

## Real FAANG Examples

### Google: Fine-Grained Access Control with ABAC

Google uses ABAC extensively across its infrastructure. Here's how they implement it:

**Google Cloud IAM Conditions (ABAC):**

```
Resource: Cloud Storage Bucket
Policy: "engineering-data-access"

Conditions:
- request.time < timestamp("2024-12-31T00:00:00Z") (time-bound access)
- resource.name.startsWith("projects/eng-")  (resource pattern)
- request.auth.claims.department == "engineering" (subject attribute)
- origin.ip in ["10.0.0.0/8"] (network restriction)

Decision: ALLOW if ALL conditions met
```

**Real Google Cloud IAM Policy with Conditions:**

```json
{
  "bindings": [
    {
      "role": "roles/storage.objectViewer",
      "members": ["group:engineers@company.com"],
      "condition": {
        "title": "Engineering access during business hours",
        "description": "Allow engineers to read objects during business hours from office",
        "expression": "request.time.getHours() >= 8 && request.time.getHours() <= 18 && origin.ip in ['10.0.0.0/8', '172.16.0.0/12']"
      }
    },
    {
      "role": "roles/storage.objectAdmin",
      "members": ["group:senior-engineers@company.com"],
      "condition": {
        "title": "Senior engineers full access with audit",
        "description": "Senior engineers can modify objects with certification",
        "expression": "has(request.auth.claims.certification) && 'GCP-ARCHITECT' in request.auth.claims.certification && resource.type == 'storage.googleapis.com/Object'"
      }
    }
  ]
}
```

**Google's BigQuery ABAC:**

```sql
-- Row-Level Security using ABAC
CREATE ROW ACCESS POLICY engineering_data_policy
ON project.dataset.customer_table
GRANT TO ('group:engineering@company.com')
FILTER USING (
  -- Engineers can only see data from their region
  customer_region = SESSION_USER.region
  AND
  -- Only during business hours
  EXTRACT(HOUR FROM CURRENT_TIMESTAMP()) BETWEEN 8 AND 18
  AND
  -- Only if they have the right certification
  'DATA_ACCESS_L2' IN UNNEST(SESSION_USER.certifications)
);
```

**Why Google uses ABAC:**
- Manages 2+ billion lines of code with thousands of engineers
- Fine-grained access control without explosion of roles
- Dynamic access based on context (time, location, device)
- Automated compliance with data residency laws

### Netflix: Content Access with ABAC

Netflix uses ABAC to control content delivery based on multiple factors:

**Netflix Content Authorization:**

```java
// Netflix-style content authorization policy
public class NetflixContentPolicy implements Policy {
    
    @Override
    public AccessDecision evaluate(Subject subject, Resource resource,
                                   Action action, Environment environment) {
        
        // Resource: Movie/Show
        String contentId = resource.getResourceId();
        String contentType = (String) resource.getAttribute("content_type");
        String maturityRating = (String) resource.getAttribute("maturity_rating");
        Set<String> availableRegions = (Set<String>) resource.getAttribute("regions");
        boolean isOriginal = (Boolean) resource.getAttribute("is_netflix_original");
        
        // Subject: Netflix user
        String subscriptionTier = (String) subject.getAttribute("subscription_tier");
        String accountRegion = (String) subject.getAttribute("account_region");
        String profileType = (String) subject.getAttribute("profile_type");
        int profileAge = (Integer) subject.getAttribute("profile_age");
        boolean hasParentalPin = (Boolean) subject.getAttribute("has_parental_pin");
        int concurrentStreams = (Integer) subject.getAttribute("active_streams");
        
        // Environment
        String deviceType = (String) environment.getAttribute("device_type");
        String currentRegion = environment.getGeoLocation();
        
        // Rule 1: Geographic licensing
        if (!availableRegions.contains(currentRegion)) {
            return AccessDecision.DENY; // Content not licensed in this region
        }
        
        // Rule 2: Subscription tier (Basic = SD, Standard = HD, Premium = 4K)
        String contentQuality = (String) resource.getAttribute("quality");
        if ("4K".equals(contentQuality) && !"premium".equals(subscriptionTier)) {
            // Downgrade quality instead of denying
            resource.setAttribute("served_quality", "HD");
        }
        if ("HD".equals(contentQuality) && "basic".equals(subscriptionTier)) {
            resource.setAttribute("served_quality", "SD");
        }
        
        // Rule 3: Maturity rating vs profile age/type
        if ("kids".equals(profileType)) {
            Set<String> allowedRatings = Set.of("G", "PG", "TV-Y", "TV-G");
            if (!allowedRatings.contains(maturityRating)) {
                return AccessDecision.DENY;
            }
        } else {
            // Mature content requires parental PIN
            Set<String> matureRatings = Set.of("R", "NC-17", "TV-MA");
            if (matureRatings.contains(maturityRating)) {
                if (profileAge < 18 && !hasParentalPin) {
                    return AccessDecision.DENY;
                }
            }
        }
        
        // Rule 4: Concurrent stream limits
        int maxStreams = getMaxStreams(subscriptionTier);
        if (concurrentStreams >= maxStreams) {
            return AccessDecision.DENY; // Too many streams
        }
        
        // Rule 5: Download restrictions
        if ("download".equals(action.getOperation())) {
            if ("mobile".equals(deviceType) || "tablet".equals(deviceType)) {
                // Check download limit
                int downloads = (Integer) subject.getAttribute("active_downloads");
                int maxDownloads = getMaxDownloads(subscriptionTier);
                if (downloads >= maxDownloads) {
                    return AccessDecision.DENY;
                }
            } else {
                // Can't download on TV/desktop
                return AccessDecision.DENY;
            }
        }
        
        // Rule 6: Regional VPN detection
        boolean vpnDetected = (Boolean) environment.getAttribute("vpn_detected");
        if (vpnDetected && !accountRegion.equals(currentRegion)) {
            // Suspicious - potential region hopping
            return AccessDecision.DENY;
        }
        
        return AccessDecision.PERMIT;
    }
    
    private int getMaxStreams(String tier) {
        switch (tier) {
            case "basic": return 1;
            case "standard": return 2;
            case "premium": return 4;
            default: return 0;
        }
    }
    
    private int getMaxDownloads(String tier) {
        switch (tier) {
            case "basic": return 10;
            case "standard": return 30;
            case "premium": return 100;
            default: return 0;
        }
    }
}
```

**Netflix's Content Authorization Attributes:**

```
Subject Attributes (User):
├── subscription_tier: basic | standard | premium
├── account_region: US | UK | IN | etc.
├── profile_type: adult | teen | kids
├── profile_age: integer
├── has_parental_pin: boolean
├── active_streams: current concurrent streams
├── active_downloads: current downloads
├── viewing_history: for recommendations
└── device_fingerprints: trusted devices

Resource Attributes (Content):
├── content_id: unique identifier
├── content_type: movie | series | documentary
├── maturity_rating: G | PG | PG-13 | R | TV-MA
├── available_regions: [US, CA, UK, ...]
├── quality_available: [SD, HD, 4K, HDR]
├── is_netflix_original: boolean
├── licensing_expires: timestamp
├── download_enabled: boolean
└── languages: [en, es, hi, ...]

Environment Attributes (Context):
├── device_type: mobile | tablet | tv | desktop | browser
├── current_region: from IP geolocation
├── vpn_detected: boolean
├── network_quality: mbps estimate
├── time_of_day: for analytics
└── device_compliance: OS version, security patches
```

**Real-world scenario:**

```
User: premium_subscriber in India
Content: "Stranger Things" (Netflix Original)
Device: iPhone in India
Action: Download episode

Evaluation:
✅ Geographic: Content licensed in India
✅ Subscription: Premium allows 4K
✅ Maturity: User age 28, content is TV-14
✅ Concurrent: 1/4 streams used
✅ Download: Mobile device, 5/100 downloads
✅ VPN: Not detected
➡️ PERMIT (Quality: 4K, Download allowed)

User: basic_subscriber in India
Same content/device
Action: Stream

Evaluation:
✅ Geographic: Content licensed in India
⚠️ Subscription: Basic gets SD only (downgrade from 4K)
✅ Maturity: User age 28, content is TV-14
✅ Concurrent: 0/1 streams used
✅ VPN: Not detected
➡️ PERMIT (Quality: SD - downgraded)

User: kids_profile
Content: "Breaking Bad" (TV-MA)
Device: Tablet
Action: Stream

Evaluation:
❌ Maturity: Kids profile cannot access TV-MA
➡️ DENY (Maturity rating restriction)
```

### Amazon: AWS IAM Identity Center (ABAC at Scale)

Amazon uses ABAC for managing access across thousands of AWS accounts:

**AWS SSO with ABAC:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::project-${aws:PrincipalTag/project}/*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalTag/department": "engineering",
          "aws:PrincipalTag/clearance": "L3"
        },
        "IpAddress": {
          "aws:SourceIp": ["10.0.0.0/8", "172.16.0.0/12"]
        },
        "DateGreaterThan": {
          "aws:CurrentTime": "2024-01-01T00:00:00Z"
        },
        "DateLessThan": {
          "aws:CurrentTime": "2024-12-31T23:59:59Z"
        }
      }
    }
  ]
}
```

**Tag-based access control:**

```
User Tags:
- project: payment-system
- department: engineering  
- clearance: L3
- cost-center: 1234

Resource Tags:
- project: payment-system
- environment: production
- compliance: PCI-DSS
- data-classification: sensitive

Policy Logic:
ALLOW IF:
  user.project == resource.project
  AND user.department == "engineering"
  AND user.clearance >= resource.required_clearance
  AND request.ip IN corporate_ranges
```

**Why Amazon uses ABAC at scale:**

- Manages 200+ AWS services across global infrastructure
- Thousands of development teams with different projects
- Dynamic team membership (joiners/leavers)
- Cross-account access without creating roles in each account
- Automatic access based on tags (join "project-X" → automatically get access to "project-X" resources)

### Meta (Facebook): Social Graph ABAC

Facebook's privacy model is one of the most complex ABAC systems:

**Post Visibility ABAC:**

```java
public class FacebookPostPolicy implements Policy {
    
    @Override
    public AccessDecision evaluate(Subject viewer, Resource post,
                                   Action action, Environment env) {
        
        // Post attributes
        String postId = post.getResourceId();
        String authorId = (String) post.getAttribute("author_id");
        String visibility = (String) post.getAttribute("visibility");
        Set<String> taggedUsers = (Set<String>) post.getAttribute("tagged_users");
        Set<String> blockedUsers = (Set<String>) post.getAttribute("blocked_users");
        Set<String> customList = (Set<String>) post.getAttribute("custom_list");
        String groupId = (String) post.getAttribute("group_id");
        boolean isAdsPost = (Boolean) post.getAttribute("is_ad");
        
        // Viewer attributes
        String viewerId = viewer.getUserId();
        int viewerAge = (Integer) viewer.getAttribute("age");
        String viewerCountry = (String) viewer.getAttribute("country");
        Set<String> viewerGroups = (Set<String>) viewer.getAttribute("groups");
        
        // Relationship attributes (from graph database)
        boolean isFriend = checkFriendship(viewerId, authorId);
        boolean isFollower = checkFollower(viewerId, authorId);
        boolean isBlocked = checkBlocked(viewerId, authorId);
        boolean isFriendOfFriend = checkFriendOfFriend(viewerId, authorId);
        int mutualFriends = countMutualFriends(viewerId, authorId);
        
        // Rule 1: Author can always see their own post
        if (viewerId.equals(authorId)) {
            return AccessDecision.PERMIT;
        }
        
        // Rule 2: Blocked users never see posts
        if (isBlocked || blockedUsers.contains(viewerId)) {
            return AccessDecision.DENY;
        }
        
        // Rule 3: Age-restricted content
        boolean isAdult = (Boolean) post.getAttribute("adult_content");
        if (isAdult && viewerAge < 18) {
            return AccessDecision.DENY;
        }
        
        // Rule 4: Geographic restrictions
        Set<String> blockedCountries = (Set<String>) post.getAttribute("blocked_countries");
        if (blockedCountries != null && blockedCountries.contains(viewerCountry)) {
            return AccessDecision.DENY;
        }
        
        // Rule 5: Visibility settings
        switch (visibility) {
            case "PUBLIC":
                return AccessDecision.PERMIT;
                
            case "FRIENDS":
                return isFriend ? AccessDecision.PERMIT : AccessDecision.DENY;
                
            case "FRIENDS_EXCEPT":
                Set<String> exceptList = (Set<String>) post.getAttribute("except_list");
                if (exceptList.contains(viewerId)) {
                    return AccessDecision.DENY;
                }
                return isFriend ? AccessDecision.PERMIT : AccessDecision.DENY;
                
            case "SPECIFIC_FRIENDS":
                return customList.contains(viewerId) ? 
                       AccessDecision.PERMIT : AccessDecision.DENY;
                
            case "FRIENDS_OF_FRIENDS":
                if (isFriend || isFriendOfFriend) {
                    return AccessDecision.PERMIT;
                }
                return AccessDecision.DENY;
                
            case "ONLY_ME":
                return AccessDecision.DENY; // Already handled author check
                
            case "GROUP":
                if (groupId != null && viewerGroups.contains(groupId)) {
                    return AccessDecision.PERMIT;
                }
                return AccessDecision.DENY;
                
            default:
                return AccessDecision.DENY;
        }
    }
    
    private boolean checkFriendship(String user1, String user2) {
        // Query graph database for friendship
        // SELECT * FROM friendships 
        // WHERE (user1=? AND user2=?) OR (user1=? AND user2=?)
        // AND status='accepted'
        return true; // Simplified
    }
    
    private boolean checkFollower(String follower, String followed) {
        // Query follows table
        return false;
    }
    
    private boolean checkBlocked(String user1, String user2) {
        // Query blocks table (bidirectional)
        return false;
    }
    
    private boolean checkFriendOfFriend(String user1, String user2) {
        // 2-hop graph traversal
        // Find common friends
        return false;
    }
    
    private int countMutualFriends(String user1, String user2) {
        // Count common friends
        return 0;
    }
}
```

**Facebook's ABAC Dimensions:**

```
Subject (Viewer) Attributes:
├── user_id
├── age
├── country
├── friends: [user_ids]
├── followers: [user_ids]
├── groups: [group_ids]
├── pages_liked: [page_ids]
├── account_status: active | restricted | suspended
├── trust_score: 0-100 (anti-spam)
└── privacy_settings: object

Resource (Post) Attributes:
├── post_id
├── author_id
├── visibility: public | friends | custom
├── tagged_users: [user_ids]
├── location: geo coordinates
├── group_id: if posted in group
├── is_ad: boolean
├── adult_content: boolean
├── blocked_countries: [country_codes]
├── created_time: timestamp
└── engagement: likes, comments, shares

Relationship Attributes (Graph):
├── is_friend: boolean
├── is_follower: boolean
├── is_blocked: boolean  
├── is_friend_of_friend: boolean
├── mutual_friends_count: integer
├── relationship_strength: 0-1.0 (algorithm)
└── interaction_frequency: recent interactions

Environment:
├── device_type
├── app_version
├── current_location
└── time_of_day
```

---

## ABAC Performance Optimization

ABAC evaluation can be expensive. Here's how to optimize:

### 1. Caching Strategies

```java
@Service
public class ABACCache {
    
    @Autowired
    private RedisTemplate<String, Object> redis;
    
    /**
     * Cache policy decisions for repeated requests
     */
    public AuthorizationResult getCachedDecision(Subject subject, 
                                                 Resource resource,
                                                 Action action) {
        String cacheKey = buildCacheKey(subject, resource, action);
        return (AuthorizationResult) redis.opsForValue().get(cacheKey);
    }
    
    public void cacheDecision(Subject subject, Resource resource,
                             Action action, AuthorizationResult result) {
        String cacheKey = buildCacheKey(subject, resource, action);
        // Cache for 5 minutes
        redis.opsForValue().set(cacheKey, result, 5, TimeUnit.MINUTES);
    }
    
    private String buildCacheKey(Subject subject, Resource resource, Action action) {
        // Create deterministic cache key
        return String.format("abac:%s:%s:%s:%s",
            subject.getUserId(),
            resource.getResourceId(),
            action.getOperation(),
            // Include relevant environment factors
            getCurrentHour() // Group by hour for time-based policies
        );
    }
    
    private int getCurrentHour() {
        return LocalTime.now().getHour();
    }
    
    /**
     * Cache attribute lookups
     */
    public void cacheAttributes(String key, Map<String, Object> attributes) {
        redis.opsForValue().set("attr:" + key, attributes, 10, TimeUnit.MINUTES);
    }
    
    public Map<String, Object> getCachedAttributes(String key) {
        return (Map<String, Object>) redis.opsForValue().get("attr:" + key);
    }
}
```

### 2. Lazy Attribute Loading

```java
// Only fetch attributes when policy actually needs them
public class LazySubject extends Subject {
    private AttributeResolver resolver;
    private boolean clearanceLoaded = false;
    private boolean groupsLoaded = false;
    
    @Override
    public int getClearanceLevel() {
        if (!clearanceLoaded) {
            int level = resolver.fetchClearanceLevel(getUserId());
            setClearanceLevel(level);
            clearanceLoaded = true;
        }
        return super.getClearanceLevel();
    }
    
    @Override
    public Set<String> getGroups() {
        if (!groupsLoaded) {
            Set<String> groups = resolver.fetchGroups(getUserId());
            setGroups(groups);
            groupsLoaded = true;
        }
        return super.getGroups();
    }
}
```

### 3. Policy Pre-Filtering

```java
// Only evaluate policies that could possibly apply
public class OptimizedPolicyDecisionPoint extends PolicyDecisionPoint {
    
    @Override
    public AuthorizationResult authorize(Subject subject, Resource resource,
                                        Action action, Environment environment) {
        
        // Pre-filter policies based on resource type
        List<Policy> applicablePolicies = policies.stream()
            .filter(p -> p.appliesToResourceType(resource.getResourceType()))
            .filter(p -> p.appliesToAction(action.getOperation()))
            .collect(Collectors.toList());
        
        // Now evaluate only applicable policies
        return super.evaluatePolicies(applicablePolicies, 
                                     subject, resource, action, environment);
    }
}
```

### 4. Parallel Policy Evaluation

```java
// Evaluate independent policies in parallel
public class ParallelPolicyDecisionPoint extends PolicyDecisionPoint {
    
    private ExecutorService executor = Executors.newFixedThreadPool(10);
    
    @Override
    public AuthorizationResult authorize(Subject subject, Resource resource,
                                        Action action, Environment environment) {
        
        // Submit all policy evaluations in parallel
        List<Future<PolicyEvaluation>> futures = new ArrayList<>();
        
        for (Policy policy : policies) {
            Future<PolicyEvaluation> future = executor.submit(() -> {
                AccessDecision decision = policy.evaluate(
                    subject, resource, action, environment
                );
                return new PolicyEvaluation(
                    policy.getPolicyId(),
                    policy.getDescription(),
                    decision
                );
            });
            futures.add(future);
        }
        
        // Collect results
        List<PolicyEvaluation> evaluations = new ArrayList<>();
        for (Future<PolicyEvaluation> future : futures) {
            try {
                PolicyEvaluation eval = future.get(100, TimeUnit.MILLISECONDS);
                evaluations.add(eval);
                
                // Early termination on DENY
                if (eval.getDecision() == AccessDecision.DENY) {
                    break;
                }
            } catch (Exception e) {
                // Handle timeout or error
            }
        }
        
        // Combine decisions
        AccessDecision finalDecision = combiningAlgorithm.combine(evaluations);
        return new AuthorizationResult(finalDecision, evaluations, 
                                      System.nanoTime(), Instant.now());
    }
}
```

### Performance Benchmarks

```
ABAC Decision Latency (P95):

Without Optimization:
- Attribute loading: 50ms (database queries)
- Policy evaluation: 20ms (5 policies)
- Total: 70ms per request

With Caching:
- Attribute loading: 2ms (Redis)
- Policy evaluation: 20ms
- Total: 22ms per request

With All Optimizations:
- Cached decision: 1ms (cache hit)
- Fresh evaluation: 15ms (parallel + lazy loading)
- Total: 1-15ms per request
```

---

## ABAC Interview Questions

### Question 1: Design an ABAC System for GitHub

**Problem:** Design an access control system for GitHub that handles:
- Repository access (public/private)
- Branch protection rules
- Code review requirements
- Organization-level permissions

**Solution:**

```java
// Attributes
Subject: User
- username
- organizations: [org_ids]
- teams: [team_ids]
- two_factor_enabled: boolean
- account_age_days: integer

Resource: Repository
- repo_id
- owner: user or org
- visibility: public | private | internal
- branch_protection_rules: Map<branch, rules>
- required_reviewers: [user_ids]
- allows_force_push: boolean

Action:
- operation: read | push | merge | admin
- branch: main | develop | feature/*
- is_force_push: boolean

Environment:
- ip_address
- git_client_version
- commit_signed: boolean
```

**Policy Examples:**

```java
// Policy 1: Read access
IF resource.visibility == "public" THEN PERMIT read
IF subject IN resource.contributors THEN PERMIT read
IF subject IN resource.owner.members THEN PERMIT read

// Policy 2: Push to main branch
IF action.branch == "main" THEN
  REQUIRE:
    - subject IN resource.maintainers
    - action.is_force_push == false
    - subject.two_factor_enabled == true
    - environment.commit_signed == true

// Policy 3: Merge pull request  
IF action == "merge" AND action.branch == "main" THEN
  REQUIRE:
    - pull_request.approvals >= 2
    - pull_request.approved_by INCLUDES resource.required_reviewers
    - pull_request.ci_passed == true
    - subject IN resource.maintainers
```

### Question 2: Compare RBAC vs ABAC for Netflix

**Question:** When would you use RBAC vs ABAC at Netflix?

**Answer:**

**Use RBAC for:**
- Employee access (engineers, content reviewers, customer support)
- Clear hierarchical roles
- Infrequent changes to permissions

```
Roles:
- content_admin: Can add/edit/delete content
- content_reviewer: Can review/approve content
- engineer: Can access internal tools
- support_agent: Can view customer data

Simple and predictable.
```

**Use ABAC for:**
- Customer content access (subscribers viewing shows)
- Dynamic conditions (region, subscription tier, device, time)
- Personalized experiences

```
Content Access ABAC:
- Geographic licensing (show available in user's country?)
- Subscription tier (4K only for Premium)
- Maturity rating (kids profile restrictions)
- Concurrent streams (tier-based limits)
- Download permissions (device type + tier)

Too many combinations for roles!
```

**Hybrid Approach (Best):**

```java
// Use RBAC for employees
if (user.isEmployee()) {
    return rbacEngine.authorize(user, resource, action);
}

// Use ABAC for customers
if (user.isSubscriber()) {
    return abacEngine.authorize(user, resource, action, context);
}
```

### Question 3: Scale ABAC to 1 Billion Users

**Question:** How would you scale an ABAC system to handle 1 billion users with 100K requests/second?

**Solution:**

**1. Decision Caching:**

```
Cache Key: hash(user_id, resource_id, action, hour_of_day)
TTL: 5-60 minutes (depending on policy volatility)

Hit Rate: 80-90% for repeated access patterns

Cache Tiers:
- L1: Application memory (Caffeine cache) - 10K entries
- L2: Redis cluster - 10M entries
- L3: Policy evaluation (cache miss)

Latency:
- L1 hit: <1ms
- L2 hit: 2-5ms
- L3 miss: 20-50ms
```

**2. Attribute Preloading:**

```java
// At login, preload frequently-used attributes
public class UserSession {
    private Subject subject;
    private Map<String, Object> preloadedAttributes;
    
    public void preloadAttributes() {
        preloadedAttributes.put("subscription_tier", ...);
        preloadedAttributes.put("account_region", ...);
        preloadedAttributes.put("parental_controls", ...);
        // Store in session/JWT for reuse
    }
}
```

**3. Policy Compilation:**

```
Instead of interpreting policies at runtime,
compile them to bytecode for faster execution:

Interpreted: 20ms per evaluation
Compiled: 2ms per evaluation

Use ABAC engines that support compilation:
- Open Policy Agent (OPA)
- AWS Cedar
```

**4. Geo-Distributed Architecture:**

```
User → CDN Edge Location
      ↓
      Edge PDP (Policy Decision Point)
      - Cached decisions
      - Pre-compiled policies
      - Local attribute cache
      ↓ (on cache miss)
      Regional PDP Cluster
      ↓ (on attribute miss)
      Central Attribute Store

Latency: <10ms (99th percentile)
```

**5. Async Attribute Updates:**

```
Don't block authorization on attribute updates.

User subscription changes:
1. Update database
2. Publish event to Kafka
3. Cache invalidation workers consume event
4. Invalidate relevant cache entries

User sees change within 1-5 minutes (eventual consistency)
```

**6. Policy Versioning:**

```
Deploy new policies gradually:

1. Canary: 1% of users get new policy
2. Monitor: denial rate, latency, errors
3. Expand: 10% → 50% → 100%
4. Rollback: instant if issues detected
```

---

## Summary: ABAC Best Practices

**When to Use ABAC:**
✅ Complex authorization logic with many conditions
✅ Dynamic access based on context (time, location, device)
✅ Fine-grained permissions beyond simple roles
✅ Need to scale permissions without role explosion
✅ Compliance requirements (GDPR, HIPAA data access controls)

**When NOT to Use ABAC:**
❌ Simple read/write permissions
❌ Static, rarely-changing permissions
❌ Small teams (<100 users) with clear roles
❌ Performance is absolutely critical (< 1ms latency required)

**Performance Tips:**
1. Cache aggressively (decisions, attributes, policy results)
2. Use lazy attribute loading
3. Pre-filter policies before evaluation
4. Compile policies for faster execution
5. Monitor policy evaluation latency

**Security Tips:**
1. Default DENY (require explicit PERMIT)
2. Use deny-overrides combining algorithm
3. Audit all access decisions
4. Validate attribute sources
5. Regularly review and update policies

---

# S11: Zero Trust Architecture

## 🏰 The Medieval Castle Analogy

Traditional Security (Castle & Moat):

```
           🏰
    ┌──────────────┐
    │   CASTLE     │ <-- Trusted Internal Network
    │   (Corp Network)
    └───────┬──────┘
            │
    ════════════════  <-- MOAT (Firewall)
            │
            │
        [Internet] <-- Untrusted External
```

**Problem:** Once you're inside the castle, you can go anywhere. If an attacker breaches the moat, they have free reign inside.

**Zero Trust (No Castle, Every Door Locked):**

```
    User ──Auth──> Service A ──Auth──> Service B
     ↓                 ↓                  ↓
    [Verify]        [Verify]           [Verify]
     ↓                 ↓                  ↓
    [Policy]        [Policy]           [Policy]

Every request authenticated, authorized, encrypted
No implicit trust based on network location
```

**Core Principle:** "Never trust, always verify"

---

## Beginner Level: Understanding Zero Trust

### What is Zero Trust?

Zero Trust is a security framework that eliminates the concept of a "trusted" network. Instead:

**Traditional Model:**
- Inside corporate network = Trusted
- Outside corporate network = Untrusted
- Once inside, relatively free movement

**Zero Trust Model:**
- NO network is trusted
- EVERY request is verified
- Least privilege access always
- Assume breach has already happened

### The Three Core Principles

#### 1. Verify Explicitly

Always authenticate and authorize based on ALL available data points:
- Identity (who)
- Device state (what)
- Location (where)
- Behavior patterns (how)

```
Request to access customer database:

Traditional: Are you on the VPN? ✓ → Access granted

Zero Trust:
- Who are you? → Verify identity (MFA)
- What device? → Check device compliance
- Where from? → Verify location isn't anomalous
- When? → Check if within allowed time window
- Why? → Verify role permits this access
- How? → Analyze behavior (normal pattern?)

ALL checks must pass → Then grant access
```

#### 2. Least Privilege Access

Grant minimal access needed, nothing more:

```
Traditional:
User joins "Engineering" team
→ Gets access to ALL engineering resources

Zero Trust:
User joins "Backend Team"
→ Gets access ONLY to:
  - backend-service-A (read/write)
  - backend-service-B (read only)
  - shared-docs (read only)
→ Must request access to anything else
→ Access auto-expires after 90 days
→ Requires re-approval
```

#### 3. Assume Breach

Design systems assuming attackers are already inside:

```
Traditional:
Focus on perimeter defense (firewall)
Once inside, lateral movement is easy

Zero Trust:
- Segment everything (microsegmentation)
- Encrypt all traffic (even internal)
- Monitor everything (detect anomalies)
- Limit blast radius (contain breaches)

If attacker compromises Service A:
- Cannot access Service B (separate auth)
- Cannot decrypt traffic (service-to-service mTLS)
- Gets detected quickly (anomaly detection)
- Limited damage (microsegmentation)
```

---

## Intermediate Level: Zero Trust Architecture

### The Five Pillars of Zero Trust

#### 1. Identity

**Problem:** How do we verify "who" in a distributed world?

**Solution:** Strong identity verification for ALL entities:
- Users (employees, contractors, partners)
- Devices (laptops, phones, IoT)
- Services (microservices, APIs)
- Workloads (containers, VMs)

**Implementation:**

```java
// Every request carries verified identity
@RestController
public class CustomerController {
    
    @GetMapping("/customers/{id}")
    public Customer getCustomer(@PathVariable String id,
                                @AuthenticationPrincipal UserPrincipal user) {
        
        // 1. Identity verified by framework (JWT validated)
        String userId = user.getUserId();
        String deviceId = user.getDeviceId();
        
        // 2. Check device posture
        DevicePosture posture = deviceService.checkPosture(deviceId);
        if (!posture.isCompliant()) {
            throw new SecurityException("Device not compliant");
        }
        
        // 3. Verify authorization
        if (!authzService.canAccess(userId, "customer", id)) {
            throw new AccessDeniedException();
        }
        
        // 4. Log access
        auditLog.record(userId, deviceId, "read", "customer", id);
        
        return customerService.get(id);
    }
}
```

#### 2. Devices (Device Posture)

**Problem:** Personal laptops, BYOD, compromised devices

**Solution:** Verify device health before granting access:

```
Device Posture Checks:
✓ OS up-to-date (security patches)
✓ Antivirus installed and active
✓ Disk encryption enabled
✓ Screen lock configured
✓ No jailbreak/root
✓ Trusted device (registered)
✓ Certificate installed

If ANY check fails → Block or limit access
```

**Java Implementation:**

```java
@Service
public class DevicePostureService {
    
    public DevicePosture checkPosture(String deviceId) {
        Device device = deviceRepo.findById(deviceId)
                                  .orElseThrow(() -> new UnknownDeviceException());
        
        DevicePosture posture = new DevicePosture();
        
        // Check 1: Device registered and not revoked
        posture.setRegistered(device.isRegistered());
        posture.setRevoked(device.isRevoked());
        
        // Check 2: Certificate valid
        X509Certificate cert = device.getCertificate();
        posture.setCertificateValid(
            cert != null && 
            !cert.getNotAfter().before(new Date())
        );
        
        // Check 3: Last check-in recent (device still under management)
        Instant lastCheckIn = device.getLastCheckIn();
        Duration sinceLast = Duration.between(lastCheckIn, Instant.now());
        posture.setRecentCheckIn(sinceLast.toHours() < 24);
        
        // Check 4: Security agent reporting healthy
        SecurityAgentReport report = device.getLatestSecurityReport();
        if (report != null) {
            posture.setOsUpdated(report.isOsPatched());
            posture.setAntivirusActive(report.isAntivirusRunning());
            posture.setDiskEncrypted(report.isDiskEncrypted());
            posture.setScreenLockEnabled(report.hasScreenLock());
            posture.setJailbroken(report.isJailbroken());
        }
        
        // Overall compliance
        posture.setCompliant(
            posture.isRegistered() &&
            !posture.isRevoked() &&
            posture.isCertificateValid() &&
            posture.isRecentCheckIn() &&
            posture.isOsUpdated() &&
            posture.isAntivirusActive() &&
            posture.isDiskEncrypted() &&
            !posture.isJailbroken()
        );
        
        return posture;
    }
}

public class DevicePosture {
    private boolean registered;
    private boolean revoked;
    private boolean certificateValid;
    private boolean recentCheckIn;
    private boolean osUpdated;
    private boolean antivirusActive;
    private boolean diskEncrypted;
    private boolean screenLockEnabled;
    private boolean jailbroken;
    private boolean compliant;
    
    // Getters and setters...
}
```

#### 3. Network (Microsegmentation)

**Problem:** Flat networks allow lateral movement

**Solution:** Segment network into tiny zones with strict controls:

```
Traditional Network:
┌─────────────────────────────────────┐
│  Corporate Network (10.0.0.0/8)    │
│                                      │
│  All services can talk to each other│
└─────────────────────────────────────┘

Zero Trust Microsegmentation:
┌──────────┐   ┌──────────┐   ┌──────────┐
│Frontend  │   │Backend   │   │Database  │
│Zone      │   │Zone      │   │Zone      │
└────┬─────┘   └────┬─────┘   └────┬─────┘
     │              │              │
     └──Firewall────┴──Firewall───┘
       Rules:           Rules:
       Frontend→Backend Backend→DB
       HTTPS:443        PostgreSQL:5432
       ONLY             ONLY
```

**Implementation with Service Mesh:**

```yaml
# Istio Authorization Policy - Zero Trust Network
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: backend-service-policy
spec:
  selector:
    matchLabels:
      app: backend-service
  action: ALLOW
  rules:
  # Rule 1: Only frontend can call backend
  - from:
    - source:
        principals: ["cluster.local/ns/default/sa/frontend-service"]
    to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/api/*"]
    when:
    # Must use mTLS
    - key: connection.sni
      values: ["backend-service.default.svc.cluster.local"]
  
  # Rule 2: Only on-call engineers can call admin endpoints
  - from:
    - source:
        principals: ["cluster.local/ns/default/sa/admin-user"]
    to:
    - operation:
        methods: ["POST", "DELETE"]
        paths: ["/admin/*"]
    when:
    # Only from specific IPs (VPN)
    - key: source.ip
      values: ["10.1.0.0/16"]
    # Only during business hours (through custom extension)
    - key: request.headers[X-Business-Hours]
      values: ["true"]
```

#### 4. Applications/Workloads

**Problem:** Applications often over-privileged

**Solution:** Runtime application security:

```
Application-Level Zero Trust:
1. Service identity (not just user identity)
2. Least privilege API access
3. Runtime security monitoring
4. Secrets management (no hardcoded credentials)
```

**Java Example:**

```java
// Service-to-service auth with mutual TLS
@Service
public class PaymentService {
    
    @Autowired
    private RestTemplate restTemplate; // Configured with mTLS
    
    @Autowired
    private VaultClient vault;
    
    public PaymentResult processPayment(PaymentRequest request) {
        // 1. Get database credentials from Vault (not hardcoded)
        DatabaseCredentials creds = vault.getCredentials("database/payment-db");
        
        // 2. Connect to DB with short-lived credentials
        try (Connection conn = DriverManager.getConnection(
                "jdbc:postgresql://payment-db:5432/payments",
                creds.getUsername(),
                creds.getPassword())) {
            
            // Process payment...
            
            // 3. Call external service with mTLS
            String paymentGatewayUrl = vault.getConfig("payment-gateway-url");
            ResponseEntity<GatewayResponse> response = restTemplate.postForEntity(
                paymentGatewayUrl,
                request,
                GatewayResponse.class
            );
            
            // Service-to-service call automatically:
            // - Uses service certificate for mTLS
            // - Validates server certificate
            // - Encrypts traffic
            
            return processResponse(response.getBody());
        }
    }
}

// Configuration for mTLS RestTemplate
@Configuration
public class RestTemplateConfig {
    
    @Bean
    public RestTemplate mtlsRestTemplate() throws Exception {
        // Load service certificate (for client auth)
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(
            new FileInputStream("/etc/certs/service-cert.p12"),
            "changeit".toCharArray()
        );
        
        // Load trusted CA certificates (for server validation)
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(
            new FileInputStream("/etc/certs/truststore.jks"),
            "changeit".toCharArray()
        );
        
        SSLContext sslContext = SSLContexts.custom()
            .loadKeyMaterial(keyStore, "changeit".toCharArray())
            .loadTrustMaterial(trustStore, null)
            .build();
        
        SSLConnectionSocketFactory socketFactory = 
            new SSLConnectionSocketFactory(sslContext);
        
        HttpClient httpClient = HttpClients.custom()
            .setSSLSocketFactory(socketFactory)
            .build();
        
        HttpComponentsClientHttpRequestFactory factory =
            new HttpComponentsClientHttpRequestFactory(httpClient);
        
        return new RestTemplate(factory);
    }
}
```

#### 5. Data

**Problem:** Data breaches are costly

**Solution:** Data-centric security:

```
Data Protection:
- Encryption at rest (database, files)
- Encryption in transit (TLS/mTLS)
- Field-level encryption (sensitive fields)
- Tokenization (credit cards, SSNs)
- Data loss prevention (DLP)
- Access logging (audit trail)
```

**Java Implementation:**

```java
// Field-level encryption for PII
@Entity
@Table(name = "customers")
public class Customer {
    
    @Id
    private String id;
    
    private String name; // Not sensitive
    
    @Encrypted  // Custom annotation for field-level encryption
    @Column(name = "ssn_encrypted")
    private String ssn; // Sensitive - encrypted at field level
    
    @Encrypted
    @Column(name = "credit_card_encrypted")
    private String creditCard;
    
    private String email; // Hashed for lookup, original encrypted
    
    @Column(name = "email_hash")
    private String emailHash;
}

// Encryption interceptor
@Component
public class EncryptionInterceptor implements EntityListener {
    
    @Autowired
    private EncryptionService encryptionService;
    
    @PrePersist
    @PreUpdate
    public void encryptFields(Object entity) {
        Field[] fields = entity.getClass().getDeclaredFields();
        
        for (Field field : fields) {
            if (field.isAnnotationPresent(Encrypted.class)) {
                try {
                    field.setAccessible(true);
                    String plaintext = (String) field.get(entity);
                    
                    if (plaintext != null) {
                        String encrypted = encryptionService.encrypt(plaintext);
                        field.set(entity, encrypted);
                    }
                } catch (Exception e) {
                    throw new EncryptionException("Failed to encrypt field", e);
                }
            }
        }
    }
    
    @PostLoad
    public void decryptFields(Object entity) {
        Field[] fields = entity.getClass().getDeclaredFields();
        
        for (Field field : fields) {
            if (field.isAnnotationPresent(Encrypted.class)) {
                try {
                    field.setAccessible(true);
                    String encrypted = (String) field.get(entity);
                    
                    if (encrypted != null) {
                        String plaintext = encryptionService.decrypt(encrypted);
                        field.set(entity, plaintext);
                    }
                } catch (Exception e) {
                    throw new EncryptionException("Failed to decrypt field", e);
                }
            }
        }
    }
}

@Service
public class EncryptionService {
    
    // Use envelope encryption: DEK encrypted by KEK
    private static final String KEK_ID = "projects/my-project/locations/global/keyRings/app/cryptoKeys/dek-key";
    
    @Autowired
    private CloudKMS kmsClient;
    
    @Autowired
    private RedisTemplate<String, String> redis;
    
    public String encrypt(String plaintext) throws Exception {
        // 1. Get or generate DEK (Data Encryption Key)
        byte[] dek = getOrGenerateDEK();
        
        // 2. Encrypt data with DEK using AES-256-GCM
        SecretKeySpec keySpec = new SecretKeySpec(dek, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12]; // GCM standard IV size
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, parameterSpec);
        
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        
        // 3. Combine IV + ciphertext and encode
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        
        return Base64.getEncoder().encodeToString(combined);
    }
    
    public String decrypt(String encrypted) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encrypted);
        
        // 1. Extract IV and ciphertext
        byte[] iv = new byte[12];
        byte[] ciphertext = new byte[combined.length - 12];
        System.arraycopy(combined, 0, iv, 0, 12);
        System.arraycopy(combined, 12, ciphertext, 0, ciphertext.length);
        
        // 2. Get DEK
        byte[] dek = getOrGenerateDEK();
        
        // 3. Decrypt
        SecretKeySpec keySpec = new SecretKeySpec(dek, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, parameterSpec);
        
        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }
    
    private byte[] getOrGenerateDEK() throws Exception {
        // Try to get cached encrypted DEK
        String encryptedDEK = redis.opsForValue().get("encrypted_dek");
        
        if (encryptedDEK != null) {
            // Decrypt DEK using KMS
            byte[] decryptedDEK = kmsClient.decrypt(KEK_ID, 
                Base64.getDecoder().decode(encryptedDEK)
            );
            return decryptedDEK;
        }
        
        // Generate new DEK
        SecureRandom random = new SecureRandom();
        byte[] dek = new byte[32]; // 256-bit key
        random.nextBytes(dek);
        
        // Encrypt DEK with KMS
        byte[] encryptedDEKBytes = kmsClient.encrypt(KEK_ID, dek);
        String encryptedDEKString = Base64.getEncoder().encodeToString(encryptedDEKBytes);
        
        // Cache encrypted DEK
        redis.opsForValue().set("encrypted_dek", encryptedDEKString, 24, TimeUnit.HOURS);
        
        return dek;
    }
}
```

---

## Advanced Level: Implementing Zero Trust

### Complete Zero Trust Architecture

```
                    ┌─────────────────┐
                    │  Identity       │
                    │  Provider (IdP) │
                    │  - Users        │
                    │  - Devices      │
                    │  - Services     │
                    └────────┬────────┘
                             │
                             │ Authentication
                             ▼
                    ┌─────────────────┐
                    │  Policy Engine  │
                    │  - ABAC/RBAC    │
                    │  - Risk Score   │
                    │  - Device State │
                    └────────┬────────┘
                             │
                             │ Authorization
                             ▼
        ┌────────────────────┴────────────────────┐
        │                                         │
        ▼                                         ▼
┌────────────────┐                      ┌────────────────┐
│  Zero Trust    │                      │  Zero Trust    │
│  Proxy (ZTP)   │                      │  Proxy (ZTP)   │
│  - mTLS        │                      │  - mTLS        │
│  - Encryption  │                      │  - Encryption  │
└───────┬────────┘                      └───────┬────────┘
        │                                       │
        │ Verified Traffic                      │
        ▼                                       ▼
┌────────────────┐                      ┌────────────────┐
│  Service A     │ ─────mTLS────────>  │  Service B     │
│  (Frontend)    │                      │  (Backend)     │
└────────────────┘                      └────────┬────────┘
                                                 │
                                                 │ mTLS
                                                 ▼
                                        ┌────────────────┐
                                        │  Database      │
                                        │  (Encrypted)   │
                                        └────────────────┘

All traffic:
- Authenticated (who)
- Authorized (policy check)
- Encrypted (mTLS)
- Logged (audit)
```

### Real FAANG Implementation: Google's BeyondCorp

**Background:** Google pioneered Zero Trust with BeyondCorp

**Problem Google Solved:**
- 100,000+ employees worldwide
- Contractors and partners need access
- BYOD (personal laptops/phones)
- Work from anywhere (coffee shops, airports, home)
- Traditional VPN doesn't scale

**BeyondCorp Architecture:**

```
User (Anywhere in the world)
  ↓
[Device Certificate Check]
  ↓ (mTLS with device cert)
Access Proxy (Edge PoP worldwide)
  ↓
[Identity Verification] - Google SSO + 2FA
  ↓
[Device Inventory Check] - Is device managed?
  ↓
[Device Posture Check] - Is device secure?
  ↓
[Policy Evaluation] - Can user + device access resource?
  ↓
[Risk-Based Authentication] - Risk score < threshold?
  ↓
Access Control Engine
  ↓
[Application]
```

**Key Components:**

1. **Device Inventory:**
```
Every device has:
- Unique device ID
- Device certificate (issued by Google CA)
- Management agent (reports security posture)
- User assignment (who uses this device)
```

2. **Trust Inference:**
```
Calculate trust score based on:
- Device compliance (OS patched, disk encrypted)
- User behavior (normal location, normal time)
- Resource sensitivity (public vs confidential)
- Network context (managed vs unmanaged network)

Trust Score: 0-100
- > 80: Allow with normal auth
- 60-80: Allow with additional MFA
- < 60: Deny access
```

3. **Access Control Engine:**
```
Policy: Access to production database

ALLOW IF:
  user.role == "sre" OR user.role == "dba"
  AND device.trust_score > 80
  AND device.is_managed == true
  AND device.disk_encrypted == true
  AND user.completed_training("database-access") == true
  AND (
    network == "google_corp"
    OR (network == "internet" AND time.hour >= 8 AND time.hour <= 18)
  )

DENY OTHERWISE
```

**Java Implementation - BeyondCorp-Style Access Proxy:**

```java
@RestController
public class ZeroTrustAccessProxy {
    
    @Autowired
    private IdentityService identityService;
    
    @Autowired
    private DeviceInventoryService deviceInventory;
    
    @Autowired
    private TrustInferenceEngine trustEngine;
    
    @Autowired
    private PolicyEngine policyEngine;
    
    @Autowired
    private AuditLogger auditLogger;
    
    @GetMapping("/access/**")
    public ResponseEntity<?> handleAccessRequest(
            HttpServletRequest request,
            @RequestHeader("X-Device-Certificate") String deviceCert) {
        
        AccessContext context = new AccessContext();
        
        try {
            // Step 1: Extract and verify device certificate
            X509Certificate cert = parseCertificate(deviceCert);
            if (!verifyDeviceCertificate(cert)) {
                return deny("Invalid device certificate");
            }
            
            String deviceId = extractDeviceId(cert);
            context.setDeviceId(deviceId);
            
            // Step 2: Verify device is in inventory
            Device device = deviceInventory.getDevice(deviceId);
            if (device == null || !device.isManaged()) {
                return deny("Unknown or unmanaged device");
            }
            context.setDevice(device);
            
            // Step 3: Verify user identity
            String idToken = request.getHeader("Authorization").replace("Bearer ", "");
            UserIdentity user = identityService.verifyToken(idToken);
            if (user == null) {
                return deny("Invalid user token");
            }
            context.setUser(user);
            
            // Step 4: Check device posture
            DevicePosture posture = deviceInventory.getPosture(deviceId);
            if (!posture.isCompliant()) {
                return deny("Device not compliant: " + posture.getViolations());
            }
            context.setPosture(posture);
            
            // Step 5: Calculate trust score
            int trustScore = trustEngine.calculateTrust(user, device, posture, request);
            context.setTrustScore(trustScore);
            
            if (trustScore < 60) {
                return deny("Trust score too low: " + trustScore);
            }
            
            // Step 6: Determine target resource
            String targetPath = request.getRequestURI().replace("/access", "");
            String targetService = determineTargetService(targetPath);
            context.setTargetService(targetService);
            context.setTargetPath(targetPath);
            
            // Step 7: Policy evaluation
            PolicyDecision decision = policyEngine.evaluate(context);
            
            // Step 8: Log decision
            auditLogger.logAccessAttempt(context, decision);
            
            if (!decision.isAllowed()) {
                return deny("Access denied: " + decision.getReason());
            }
            
            // Step 9: Proxy request to backend with service identity
            return proxyToBackend(context, targetService, targetPath, request);
            
        } catch (Exception e) {
            auditLogger.logError(context, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Access proxy error");
        }
    }
    
    private ResponseEntity<?> deny(String reason) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(Map.of("error", "Access Denied", "reason", reason));
    }
    
    private ResponseEntity<?> proxyToBackend(AccessContext context,
                                            String targetService,
                                            String targetPath,
                                            HttpServletRequest originalRequest) {
        
        // Build request to backend service
        String backendUrl = serviceRegistry.getUrl(targetService) + targetPath;
        
        HttpHeaders headers = new HttpHeaders();
        
        // Add service identity (not user identity)
        String serviceToken = identityService.getServiceToken("access-proxy");
        headers.set("Authorization", "Bearer " + serviceToken);
        
        // Add context headers for backend
        headers.set("X-Original-User", context.getUser().getUserId());
        headers.set("X-Device-Id", context.getDeviceId());
        headers.set("X-Trust-Score", String.valueOf(context.getTrustScore()));
        
        // Forward request with mTLS
        RestTemplate mtlsClient = getMTLSRestTemplate();
        
        try {
            ResponseEntity<String> response = mtlsClient.exchange(
                backendUrl,
                HttpMethod.valueOf(originalRequest.getMethod()),
                new HttpEntity<>(headers),
                String.class
            );
            
            auditLogger.logAccessSuccess(context);
            return response;
            
        } catch (Exception e) {
            auditLogger.logAccessFailure(context, e);
            throw e;
        }
    }
}

@Service
public class TrustInferenceEngine {
    
    public int calculateTrust(UserIdentity user, Device device,
                             DevicePosture posture, HttpServletRequest request) {
        
        int score = 100; // Start optimistic
        
        // Factor 1: Device compliance (30 points)
        if (!posture.isOsUpdated()) score -= 10;
        if (!posture.isAntivirusActive()) score -= 10;
        if (!posture.isDiskEncrypted()) score -= 10;
        
        // Factor 2: Device management (20 points)
        if (!device.isManaged()) score -= 20;
        
        // Factor 3: User behavior (20 points)
        String ipAddress = request.getRemoteAddr();
        String location = geolocate(ipAddress);
        
        if (!isNormalLocation(user.getUserId(), location)) {
            score -= 10; // Unusual location
        }
        
        LocalTime now = LocalTime.now();
        if (!isNormalTime(user.getUserId(), now)) {
            score -= 10; // Unusual time
        }
        
        // Factor 4: Network context (15 points)
        if (!isCorporateNetwork(ipAddress) && !isKnownVPN(ipAddress)) {
            score -= 15; // Unknown network
        }
        
        // Factor 5: Recent authentication (15 points)
        Duration sinceAuth = Duration.between(user.getAuthTime(), Instant.now());
        if (sinceAuth.toMinutes() > 60) {
            score -= 15; // Stale authentication
        }
        
        return Math.max(0, score); // Floor at 0
    }
}
```

### Netflix: Zero Trust for Microservices

Netflix runs 700+ microservices. Traditional perimeter security doesn't work.

**Netflix's Zero Trust Approach:**

```
Service A wants to call Service B:

Traditional (Pre-Zero Trust):
- Both in AWS VPC = Trusted
- HTTP request
- No encryption
- No authentication

Netflix Zero Trust:
1. Service A has unique identity (X.509 certificate)
2. Service B requires mTLS (mutual TLS)
3. Service A proves identity via certificate
4. Service B validates certificate
5. Traffic encrypted
6. Authorization check: Is Service A allowed to call this endpoint?
```

**Implementation:**

```java
// Netflix-style service-to-service auth

@Service
public class PaymentService {
    
    @Autowired
    @Qualifier("serviceRestTemplate")
    private RestTemplate restTemplate; // Configured with mTLS
    
    public OrderResult createOrder(OrderRequest request) {
        // Call inventory service
        String inventoryUrl = "https://inventory-service.netflix.internal/api/reserve";
        
        try {
            // RestTemplate automatically:
            // 1. Presents payment-service certificate (client cert)
            // 2. Validates inventory-service certificate (server cert)
            // 3. Establishes mTLS connection
            // 4. Encrypts all traffic
            
            ResponseEntity<InventoryResponse> response = restTemplate.postForEntity(
                inventoryUrl,
                request.getItems(),
                InventoryResponse.class
            );
            
            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new InventoryException("Failed to reserve inventory");
            }
            
            // Process order...
            return new OrderResult(true, response.getBody());
            
        } catch (RestClientException e) {
            // Could be:
            // - Certificate validation failed
            // - Network error
            // - Service unavailable
            throw new ServiceCommunicationException("Failed to call inventory service", e);
        }
    }
}

// On the receiving side (inventory-service)
@RestController
public class InventoryController {
    
    @PostMapping("/api/reserve")
    public ResponseEntity<InventoryResponse> reserveInventory(
            @RequestBody List<Item> items,
            HttpServletRequest request) {
        
        // Extract client certificate from mTLS connection
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(
            "javax.servlet.request.X509Certificate"
        );
        
        if (certs == null || certs.length == 0) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new InventoryResponse("No client certificate provided"));
        }
        
        X509Certificate clientCert = certs[0];
        
        // Extract service identity from certificate
        String clientCN = clientCert.getSubjectX500Principal().getName();
        // Example CN: "CN=payment-service.netflix.internal"
        
        String serviceId = extractServiceId(clientCN);
        
        // Check if this service is authorized
        if (!isAuthorized(serviceId, "inventory", "reserve")) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new InventoryResponse("Service not authorized"));
        }
        
        // Process reservation...
        InventoryResponse response = inventoryService.reserve(items);
        return ResponseEntity.ok(response);
    }
    
    private boolean isAuthorized(String serviceId, String resource, String action) {
        // Check authorization policy
        // In Netflix, this could be:
        // - Hardcoded whitelist
        // - Policy stored in database
        // - Dynamic policy from policy service
        
        Map<String, Set<String>> authMap = Map.of(
            "payment-service", Set.of("inventory.reserve", "pricing.calculate"),
            "order-service", Set.of("inventory.reserve", "shipping.estimate"),
            "admin-service", Set.of("inventory.*")
        );
        
        Set<String> allowed = authMap.getOrDefault(serviceId, Set.of());
        String permission = resource + "." + action;
        
        return allowed.contains(permission) || 
               allowed.contains(resource + ".*");
    }
}
```

---

## Zero Trust Interview Questions

### Question 1: Design a Zero Trust Architecture for a Banking App

**Problem:** Design zero trust for a mobile banking app with these requirements:
- Mobile app (iOS/Android)
- Backend microservices
- Sensitive customer data
- Regulatory compliance (PCI-DSS, SOC2)

**Solution:**

```
Architecture:

[Mobile App]
    ↓ mTLS + JWT
[API Gateway / Zero Trust Proxy]
    ↓
[Identity Verification]
    - JWT validation
    - Device attestation
    - Biometric confirmation
    ↓
[Policy Engine]
    - Transaction limits
    - Geo-fencing
    - Behavior analysis
    ↓
[Microservices (mTLS between services)]
    - Account Service
    - Transaction Service  
    - Payment Service
    ↓
[Database (Encrypted)]
```

**Key Zero Trust Controls:**

```java
// 1. Device Attestation
public class DeviceAttestationService {
    public boolean attestDevice(String deviceToken) {
        // iOS: DeviceCheck API
        // Android: SafetyNet Attestation
        
        // Verify:
        // - App not tampered
        // - Device not jailbroken/rooted
        // - App signature valid
        // - Device from known manufacturer
        
        return safetyNetClient.verify(deviceToken);
    }
}

// 2. Continuous Authorization
@RestController
public class TransactionController {
    
    @PostMapping("/transfer")
    public ResponseEntity<TransactionResult> transfer(
            @RequestBody TransferRequest request,
            @AuthenticationPrincipal UserPrincipal user) {
        
        // Continuous auth: verify on EVERY request
        
        // Check 1: Recent biometric auth
        Duration sinceLastBiometric = getTimeSinceBiometric(user.getSessionId());
        if (sinceLastBiometric.toMinutes() > 5) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new TransactionResult("Biometric re-auth required"));
        }
        
        // Check 2: Transaction within limits
        if (request.getAmount() > user.getTransactionLimit()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new TransactionResult("Exceeds transaction limit"));
        }
        
        // Check 3: Geo-location check
        String currentLocation = request.getLocation();
        if (!isNormalLocation(user.getUserId(), currentLocation)) {
            // Unusual location - require additional verification
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new TransactionResult("Additional verification required"));
        }
        
        // Check 4: Velocity check (anti-fraud)
        int recentTransactions = getRecentTransactionCount(user.getUserId(), Duration.ofMinutes(10));
        if (recentTransactions > 5) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(new TransactionResult("Too many transactions"));
        }
        
        // All checks passed - process transaction
        return processTransfer(request, user);
    }
}

// 3. Microsegmentation
// Each service can only talk to specific other services
@Configuration
public class NetworkPolicy {
    
    @Bean
    public ServiceMeshConfig serviceMeshConfig() {
        return ServiceMeshConfig.builder()
            .addPolicy(
                Policy.builder()
                    .source("mobile-api-gateway")
                    .destination("account-service")
                    .methods(Set.of("GET", "POST"))
                    .paths(Set.of("/accounts/*"))
                    .requireMTLS(true)
                    .build()
            )
            .addPolicy(
                Policy.builder()
                    .source("account-service")
                    .destination("database")
                    .protocol("postgresql")
                    .port(5432)
                    .requireMTLS(true)
                    .build()
            )
            // All other connections DENIED by default
            .defaultAction(Action.DENY)
            .build();
    }
}
```

### Question 2: Zero Trust vs VPN

**Question:** Why is Zero Trust better than VPN?

**Answer:**

**VPN Problems:**

```
VPN (Traditional):
1. Binary trust: Inside VPN = trusted, Outside = untrusted
2. Lateral movement: Once on VPN, can access everything
3. No device posture checking
4. No per-request authorization
5. All-or-nothing access
6. Assumes "network location = identity"

Attack Scenario:
- Attacker steals employee laptop
- Connects to VPN (if credentials saved)
- Now has access to entire corporate network
- Can move laterally to sensitive systems
- Hard to detect until damage done
```

**Zero Trust Advantages:**

```
Zero Trust:
1. No implicit trust - verify every request
2. Microsegmentation - limited blast radius
3. Device posture required
4. Per-request authorization
5. Least privilege access
6. Identity-based, not network-based

Same Attack Scenario:
- Attacker steals laptop
- Laptop detected as non-compliant (stolen = not checking in)
- Access denied
- Even if attacker gets past initial auth:
  - Each service requires separate authorization
  - Unusual behavior detected
  - Limited to user's actual permissions
  - Audit trail of all access
```

**Comparison Table:**

| Feature | VPN | Zero Trust |
|---------|-----|------------|
| Trust Model | Network-based | Identity-based |
| Access Granularity | All-or-nothing | Per-resource |
| Device Security | None | Posture checked |
| Encryption | VPN tunnel only | End-to-end (mTLS) |
| Monitoring | Limited | Comprehensive |
| Lateral Movement | Easy | Prevented |
| User Experience | Connect/disconnect | Seamless |
| Scalability | Limited | High |

---

## Summary: Zero Trust Best Practices

**Core Principles:**
1. **Never Trust, Always Verify** - No implicit trust
2. **Least Privilege** - Minimal access needed
3. **Assume Breach** - Design for compromise

**Implementation Checklist:**
✅ Strong identity for all entities (users, devices, services)
✅ Device posture checking
✅ Microsegmentation (network + application)
✅ End-to-end encryption (mTLS everywhere)
✅ Continuous authorization (not just login)
✅ Comprehensive logging and monitoring
✅ Risk-based access decisions

**Common Pitfalls:**
❌ Trying to implement "all at once" (gradual migration is better)
❌ Neglecting user experience (make it seamless)
❌ Forgetting about third-parties (contractors, partners)
❌ Not monitoring after deployment
❌ Assuming "zero trust product" = zero trust architecture

**Migration Strategy:**
1. Start with new applications (easier than retrofitting)
2. Pilot with low-risk services
3. Gradually expand coverage
4. Maintain legacy security during transition
5. Educate users and developers

---

# S12: Secret Management (Vault)

## 🔐 The Safe Deposit Box Analogy

Imagine managing secrets in a company:

**Bad Practice (Secrets in Code):**
```
Developer writes down bank account PIN on a sticky note
Attaches it to laptop screen
Anyone walking by can see it
Laptop stolen = PIN compromised
```

**Vault (Proper Secret Management):**
```
Bank Safe Deposit Box:
1. Must authenticate to enter bank (identity)
2. Must present key + signature (authorization)
3. Bank ENDOFFILE
wc -l /mnt/user-data/outputs/Part4_S10-S11-S12_ABAC_ZeroTrust_Secrets_COMPLETE.md tracks who accessed what (audit)
4. Time-limited access (lease expiration)
5. Vault is hardened and monitored

Secrets: Database passwords, API keys, certificates
Vault: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault
```

This is **Secret Management** - centralized, secure, audited secret storage.

---

## Beginner Level: Why Secret Management Matters

### The Problem: Secrets Everywhere

In a typical application, secrets are needed in many places:

```
Application Secrets:
- Database passwords
- API keys (Stripe, Twilio, SendGrid)
- OAuth client secrets
- Encryption keys
- TLS/SSL certificates
- SSH keys
- Service account credentials
- Third-party tokens
```

**Bad Practices (DON'T DO THIS):**

```java
// ❌ TERRIBLE: Hardcoded in source code
public class PaymentService {
    private static final String STRIPE_API_KEY = "sk_live_abc123xyz789";
    private static final String DB_PASSWORD = "MyP@ssw0rd123";
}

Problems:
1. Visible in source code
2. Committed to Git (永久历史记录)
3. Visible to all developers
4. Can't rotate without code deploy
5. Leaked if repo is compromised
```

```properties
# ❌ BAD: In properties file (committed to Git)
db.password=MyP@ssw0rd123
stripe.api.key=sk_live_abc123xyz789
```

```yaml
# ❌ BAD: In Kubernetes ConfigMap (not encrypted)
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  DB_PASSWORD: "MyP@ssw0rd123"
  API_KEY: "sk_live_abc123xyz789"
```

### The Solution: Secret Management System

```
Secret Management System (like HashiCorp Vault):

1. Centralized Storage
   - All secrets in one place
   - Encrypted at rest
   - Access controlled

2. Dynamic Secrets
   - Secrets generated on-demand
   - Short-lived (auto-expire)
   - Unique per requester

3. Encryption as a Service
   - Encrypt data without managing keys
   - Key rotation handled automatically

4. Audit Trail
   - Who accessed what secret
   - When they accessed it
   - What they did with it
```

---

## Intermediate Level: Using HashiCorp Vault

### Vault Architecture

```
┌──────────────┐
│ Application  │
│              │
└───────┬──────┘
        │ 1. Authenticate
        │    (AppRole, JWT, etc.)
        ▼
┌──────────────┐
│ Vault Server │
│              │
│ - Auth       │ ←── 2. Issue token
│ - Secrets    │ ←── 3. Request secret
│ - Encryption │ ←── 4. Return secret
│ - Audit      │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Backend      │
│ Storage      │
│ (Encrypted)  │
└──────────────┘
```

### Basic Vault Usage

#### 1. Setting Up Vault

```bash
# Install Vault
brew install vault  # macOS
# or
wget https://releases.hashicorp.com/vault/1.15.0/vault_1.15.0_linux_amd64.zip

# Start Vault in dev mode (for learning)
vault server -dev

# In another terminal, set Vault address
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'  # Dev mode token

# Check status
vault status
```

#### 2. Storing Secrets

```bash
# Store a database password
vault kv put secret/database/config \
    username=admin \
    password=SuperSecret123

# Store API keys
vault kv put secret/api/stripe \
    api_key=sk_live_abc123xyz789 \
    webhook_secret=whsec_def456

# Store with JSON
vault kv put secret/aws/credentials - <<EOF
{
  "access_key": "AKIAIOSFODNN7EXAMPLE",
  "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "region": "us-west-2"
}
EOF
```

#### 3. Reading Secrets

```bash
# Read secret
vault kv get secret/database/config

# Get specific field
vault kv get -field=password secret/database/config

# Output as JSON
vault kv get -format=json secret/database/config
```

#### 4. Secret Versioning

```bash
# Update secret (creates new version)
vault kv put secret/database/config \
    username=admin \
    password=NewPassword456

# List versions
vault kv metadata get secret/database/config

# Get specific version
vault kv get -version=1 secret/database/config

# Delete latest version
vault kv delete secret/database/config

# Undelete
vault kv undelete -versions=2 secret/database/config

# Permanently destroy
vault kv destroy -versions=1 secret/database/config
```

### Java Integration with Vault

```java
// Maven dependency
/*
<dependency>
    <groupId>com.bettercloud</groupId>
    <artifactId>vault-java-driver</artifactId>
    <version>5.1.0</version>
</dependency>
*/

// VaultConfig.java - Configure Vault client
@Configuration
public class VaultConfig {
    
    @Value("${vault.address}")
    private String vaultAddress;
    
    @Value("${vault.token}")
    private String vaultToken;
    
    @Bean
    public Vault vault() throws VaultException {
        VaultConfig config = new VaultConfig()
            .address(vaultAddress)
            .token(vaultToken)
            .build();
        
        return new Vault(config);
    }
}

// SecretService.java - Service to fetch secrets
@Service
public class SecretService {
    
    @Autowired
    private Vault vault;
    
    /**
     * Get database credentials from Vault
     */
    public DatabaseCredentials getDatabaseCredentials() {
        try {
            // Read from Vault
            LogicalResponse response = vault.logical()
                .read("secret/data/database/config");
            
            Map<String, String> data = response.getData();
            
            return new DatabaseCredentials(
                data.get("username"),
                data.get("password")
            );
            
        } catch (VaultException e) {
            throw new SecretRetrievalException("Failed to get DB credentials", e);
        }
    }
    
    /**
     * Get API key from Vault
     */
    public String getStripeApiKey() {
        try {
            LogicalResponse response = vault.logical()
                .read("secret/data/api/stripe");
            
            return response.getData().get("api_key");
            
        } catch (VaultException e) {
            throw new SecretRetrievalException("Failed to get Stripe API key", e);
        }
    }
    
    /**
     * Write secret to Vault
     */
    public void storeSecret(String path, Map<String, Object> secrets) {
        try {
            vault.logical().write(path, secrets);
        } catch (VaultException e) {
            throw new SecretStorageException("Failed to store secret", e);
        }
    }
}

// Usage in application
@Service
public class PaymentService {
    
    @Autowired
    private SecretService secretService;
    
    private Stripe stripeClient;
    
    @PostConstruct
    public void init() {
        // Get Stripe API key from Vault (not hardcoded!)
        String apiKey = secretService.getStripeApiKey();
        this.stripeClient = new Stripe(apiKey);
    }
    
    public PaymentResult processPayment(PaymentRequest request) {
        // Use Stripe client with secret API key from Vault
        return stripeClient.charge(request);
    }
}

// Database configuration with Vault
@Configuration
public class DatabaseConfig {
    
    @Autowired
    private SecretService secretService;
    
    @Bean
    public DataSource dataSource() {
        // Get credentials from Vault
        DatabaseCredentials creds = secretService.getDatabaseCredentials();
        
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:postgresql://db.example.com:5432/mydb");
        config.setUsername(creds.getUsername());
        config.setPassword(creds.getPassword());
        config.setMaximumPoolSize(10);
        
        return new HikariDataSource(config);
    }
}
```

---

## Advanced Level: Production Vault Setup

### Authentication Methods

#### 1. AppRole (for Applications)

```bash
# Enable AppRole auth
vault auth enable approle

# Create role for payment-service
vault write auth/approle/role/payment-service \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=24h \
    policies="payment-service-policy"

# Get Role ID (can be public)
vault read auth/approle/role/payment-service/role-id

# Generate Secret ID (must be kept secret)
vault write -f auth/approle/role/payment-service/secret-id
```

**Java Implementation:**

```java
@Configuration
public class VaultAppRoleAuth {
    
    @Value("${vault.address}")
    private String vaultAddress;
    
    @Value("${vault.role-id}")
    private String roleId;
    
    @Value("${vault.secret-id}")
    private String secretId;
    
    @Bean
    public Vault vault() throws VaultException {
        // Authenticate with AppRole
        VaultConfig config = new VaultConfig()
            .address(vaultAddress)
            .build();
        
        Vault vault = new Vault(config);
        
        // Login with AppRole
        Map<String, String> credentials = new HashMap<>();
        credentials.put("role_id", roleId);
        credentials.put("secret_id", secretId);
        
        AuthResponse response = vault.auth().loginByAppRole(credentials);
        String token = response.getAuthClientToken();
        
        // Create authenticated Vault client
        VaultConfig authenticatedConfig = new VaultConfig()
            .address(vaultAddress)
            .token(token)
            .build();
        
        return new Vault(authenticatedConfig);
    }
}
```

#### 2. Kubernetes Auth (for Pods)

```bash
# Enable Kubernetes auth
vault auth enable kubernetes

# Configure Kubernetes auth
vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc:443" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    token_reviewer_jwt=@/var/run/secrets/kubernetes.io/serviceaccount/token

# Create role for service account
vault write auth/kubernetes/role/payment-service \
    bound_service_account_names=payment-service \
    bound_service_account_namespaces=production \
    policies=payment-service-policy \
    ttl=1h
```

**Java Implementation in Kubernetes:**

```java
@Configuration
public class VaultKubernetesAuth {
    
    @Value("${vault.address}")
    private String vaultAddress;
    
    @Value("${vault.role}")
    private String vaultRole;
    
    @Bean
    public Vault vault() throws VaultException, IOException {
        // Read Kubernetes service account JWT
        String jwt = new String(Files.readAllBytes(
            Paths.get("/var/run/secrets/kubernetes.io/serviceaccount/token")
        ));
        
        VaultConfig config = new VaultConfig()
            .address(vaultAddress)
            .build();
        
        Vault vault = new Vault(config);
        
        // Authenticate with Kubernetes
        AuthResponse response = vault.auth().loginByKubernetes(vaultRole, jwt);
        String token = response.getAuthClientToken();
        
        // Create authenticated client
        VaultConfig authenticatedConfig = new VaultConfig()
            .address(vaultAddress)
            .token(token)
            .build();
        
        return new Vault(authenticatedConfig);
    }
}
```

### Dynamic Secrets

Instead of storing static secrets, Vault can generate them on-demand.

#### Database Dynamic Secrets

```bash
# Enable database secrets engine
vault secrets enable database

# Configure PostgreSQL connection
vault write database/config/my-postgresql-database \
    plugin_name=postgresql-database-plugin \
    allowed_roles="payment-service-role" \
    connection_url="postgresql://{{username}}:{{password}}@postgres:5432/mydb?sslmode=require" \
    username="vault_admin" \
    password="admin_password"

# Create role that generates credentials
vault write database/roles/payment-service-role \
    db_name=my-postgresql-database \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
        GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"
```

**Java Implementation:**

```java
@Service
public class DynamicDatabaseService {
    
    @Autowired
    private Vault vault;
    
    /**
     * Get dynamic database credentials
     * Vault creates a new user with limited lifetime
     */
    public DatabaseCredentials getDynamicCredentials() {
        try {
            // Request dynamic credentials
            LogicalResponse response = vault.logical()
                .read("database/creds/payment-service-role");
            
            Map<String, String> data = response.getData();
            
            String username = data.get("username");  // e.g., "v-approle-payment-a1b2c3d4"
            String password = data.get("password");  // random generated
            
            // These credentials are valid for 1 hour (default_ttl)
            // Vault will automatically revoke them after expiration
            
            return new DatabaseCredentials(username, password);
            
        } catch (VaultException e) {
            throw new SecretRetrievalException("Failed to get dynamic DB creds", e);
        }
    }
    
    /**
     * Renew lease before expiration
     */
    public void renewLease(String leaseId) {
        try {
            vault.leases().renew(leaseId, 3600); // Renew for another hour
        } catch (VaultException e) {
            // If renewal fails, get new credentials
            getDynamicCredentials();
        }
    }
}

@Configuration
public class DynamicDataSourceConfig {
    
    @Autowired
    private DynamicDatabaseService dbService;
    
    @Bean
    public DataSource dataSource() {
        // Use dynamic credentials
        DatabaseCredentials creds = dbService.getDynamicCredentials();
        
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:postgresql://postgres:5432/mydb");
        config.setUsername(creds.getUsername());
        config.setPassword(creds.getPassword());
        
        // Set connection lifetime shorter than credentials lifetime
        config.setMaxLifetime(50 * 60 * 1000); // 50 minutes (credentials valid for 60)
        
        return new HikariDataSource(config);
    }
    
    // Scheduled task to refresh credentials
    @Scheduled(fixedRate = 45 * 60 * 1000) // Every 45 minutes
    public void refreshCredentials() {
        // Refresh datasource with new credentials
        DatabaseCredentials newCreds = dbService.getDynamicCredentials();
        // Update datasource...
    }
}
```

**Benefits of Dynamic Secrets:**
- No long-lived credentials
- Automatic rotation
- Each application gets unique credentials
- Auto-revocation on expiration
- Audit trail of all credential generation

### Encryption as a Service

Vault can encrypt/decrypt data without your application managing keys.

```bash
# Enable transit secrets engine
vault secrets enable transit

# Create encryption key
vault write -f transit/keys/customer-data
```

**Java Implementation:**

```java
@Service
public class VaultEncryptionService {
    
    @Autowired
    private Vault vault;
    
    private static final String TRANSIT_KEY = "customer-data";
    
    /**
     * Encrypt sensitive data using Vault
     */
    public String encrypt(String plaintext) {
        try {
            // Base64 encode plaintext
            String base64Plaintext = Base64.getEncoder()
                .encodeToString(plaintext.getBytes(StandardCharsets.UTF_8));
            
            // Encrypt via Vault
            LogicalResponse response = vault.logical()
                .write("transit/encrypt/" + TRANSIT_KEY,
                       Map.of("plaintext", base64Plaintext));
            
            // Returns something like: "vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w=="
            return response.getData().get("ciphertext");
            
        } catch (VaultException e) {
            throw new EncryptionException("Failed to encrypt", e);
        }
    }
    
    /**
     * Decrypt data using Vault
     */
    public String decrypt(String ciphertext) {
        try {
            // Decrypt via Vault
            LogicalResponse response = vault.logical()
                .write("transit/decrypt/" + TRANSIT_KEY,
                       Map.of("ciphertext", ciphertext));
            
            // Get base64 plaintext
            String base64Plaintext = response.getData().get("plaintext");
            
            // Decode
            byte[] decoded = Base64.getDecoder().decode(base64Plaintext);
            return new String(decoded, StandardCharsets.UTF_8);
            
        } catch (VaultException e) {
            throw new DecryptionException("Failed to decrypt", e);
        }
    }
    
    /**
     * Rotate encryption key
     * Old ciphertexts can still be decrypted
     * New encryptions use new key version
     */
    public void rotateKey() {
        try {
            vault.logical().write("transit/keys/" + TRANSIT_KEY + "/rotate", null);
        } catch (VaultException e) {
            throw new VaultException("Failed to rotate key", e);
        }
    }
}

// Usage in entity
@Entity
public class Customer {
    
    @Id
    private String id;
    
    private String name;
    
    // SSN stored encrypted via Vault
    @Column(name = "ssn_encrypted")
    private String ssnEncrypted;
    
    @Transient
    private String ssn;
    
    // Helper methods
    @PostLoad
    private void decryptSsn() {
        if (ssnEncrypted != null) {
            VaultEncryptionService encService = 
                SpringContext.getBean(VaultEncryptionService.class);
            this.ssn = encService.decrypt(ssnEncrypted);
        }
    }
    
    @PrePersist
    @PreUpdate
    private void encryptSsn() {
        if (ssn != null) {
            VaultEncryptionService encService = 
                SpringContext.getBean(VaultEncryptionService.class);
            this.ssnEncrypted = encService.encrypt(ssn);
        }
    }
}
```

---

## Real FAANG Examples

### Uber: Secret Rotation at Scale

**Challenge:** Uber has thousands of microservices, each needing secrets (DB passwords, API keys, etc.)

**Solution:** Automated secret rotation with Vault

```
Uber's Secret Rotation:
1. Vault generates new credentials
2. Services fetch new credentials from Vault
3. Services connect to database with new credentials
4. After grace period, old credentials revoked
5. Repeat weekly

Scale:
- 10,000+ services
- Rotating 100,000+ secrets per week
- Zero downtime
```

**Implementation Approach:**

```java
@Service
public class SecretRotationService {
    
    @Autowired
    private Vault vault;
    
    @Autowired
    private DataSource dataSource;
    
    @Scheduled(cron = "0 0 2 * * SUN") // Every Sunday 2 AM
    public void rotateSecrets() {
        try {
            // 1. Get new credentials from Vault
            DatabaseCredentials newCreds = vault.logical()
                .read("database/creds/my-service-role")
                .getData();
            
            // 2. Update DataSource to use both old and new
            // (during grace period, accept both)
            updateDataSourceWithDualCredentials(newCreds);
            
            // 3. Wait for all existing connections to close (max 5 min)
            Thread.sleep(5 * 60 * 1000);
            
            // 4. Switch to new credentials only
            updateDataSourceWithNewCredentials(newCreds);
            
            // 5. Old credentials automatically revoked by Vault after TTL
            
            log.info("Successfully rotated database credentials");
            
        } catch (Exception e) {
            log.error("Failed to rotate credentials", e);
            alertOncall("Secret rotation failed");
        }
    }
}
```

### Google: Key Management Service (Cloud KMS)

Google Cloud KMS is similar to Vault's encryption service:

```java
// Google Cloud KMS usage
@Service
public class GoogleKmsService {
    
    private KeyManagementServiceClient kmsClient;
    
    private static final String KEY_NAME = 
        "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key";
    
    @PostConstruct
    public void init() throws IOException {
        kmsClient = KeyManagementServiceClient.create();
    }
    
    public byte[] encrypt(byte[] plaintext) {
        EncryptRequest request = EncryptRequest.newBuilder()
            .setName(KEY_NAME)
            .setPlaintext(ByteString.copyFrom(plaintext))
            .build();
        
        EncryptResponse response = kmsClient.encrypt(request);
        return response.getCiphertext().toByteArray();
    }
    
    public byte[] decrypt(byte[] ciphertext) {
        DecryptRequest request = DecryptRequest.newBuilder()
            .setName(KEY_NAME)
            .setCiphertext(ByteString.copyFrom(ciphertext))
            .build();
        
        DecryptResponse response = kmsClient.decrypt(request);
        return response.getPlaintext().toByteArray();
    }
    
    // Automatic key rotation (managed by Google)
    // Keys rotated every 90 days automatically
    // Old key versions kept for decryption
}
```

### AWS: Secrets Manager + Parameter Store

Amazon uses two services:

**AWS Secrets Manager:** For secrets that rotate

```java
@Service
public class AwsSecretsService {
    
    private SecretsManagerClient secretsClient;
    
    @PostConstruct
    public void init() {
        secretsClient = SecretsManagerClient.builder()
            .region(Region.US_EAST_1)
            .build();
    }
    
    public DatabaseCredentials getDatabaseCredentials() {
        GetSecretValueRequest request = GetSecretValueRequest.builder()
            .secretId("production/database/credentials")
            .build();
        
        GetSecretValueResponse response = secretsClient.getSecretValue(request);
        
        // Parse JSON response
        String secretString = response.secretString();
        JSONObject json = new JSONObject(secretString);
        
        return new DatabaseCredentials(
            json.getString("username"),
            json.getString("password")
        );
    }
    
    // AWS handles rotation automatically
    // Lambda function triggered every 30 days
    // Creates new password in RDS
    // Updates secret in Secrets Manager
}
```

**AWS Parameter Store:** For configuration

```java
@Service
public class AwsParameterStoreService {
    
    private SsmClient ssmClient;
    
    @PostConstruct
    public void init() {
        ssmClient = SsmClient.builder()
            .region(Region.US_EAST_1)
            .build();
    }
    
    public String getParameter(String name) {
        GetParameterRequest request = GetParameterRequest.builder()
            .name(name)
            .withDecryption(true) // Decrypt if SecureString
            .build();
        
        GetParameterResponse response = ssmClient.getParameter(request);
        return response.parameter().value();
    }
    
    // Usage
    public void configure() {
        String apiKey = getParameter("/myapp/production/stripe/api-key");
        String dbUrl = getParameter("/myapp/production/database/url");
    }
}
```

---

## Secret Management Best Practices

### 1. Never Commit Secrets to Git

```bash
# .gitignore - ALWAYS include these
.env
*.key
*.pem
*.p12
*.jks
secrets.yaml
credentials.json

# Check for leaked secrets
git secrets --scan
# or use
gitleaks detect
```

### 2. Use Environment Variables (Better than Hardcoding)

```java
// ✅ GOOD: Environment variable
String apiKey = System.getenv("STRIPE_API_KEY");

// ❌ BAD: Hardcoded
String apiKey = "sk_live_abc123";
```

### 3. Rotate Secrets Regularly

```
Secret Rotation Schedule:
- Database passwords: Weekly
- API keys: Monthly
- Certificates: Before expiration (90 days)
- Root credentials: Quarterly
- Emergency rotation: Immediately if compromised
```

### 4. Principle of Least Privilege

```
Each service only gets secrets it needs:

Payment Service:
✅ Stripe API key
✅ Payment database credentials
❌ Admin database credentials
❌ AWS root keys
❌ Other services' secrets
```

### 5. Audit Everything

```java
@Aspect
@Component
public class SecretAccessAuditor {
    
    @Around("@annotation(SecretAccess)")
    public Object auditSecretAccess(ProceedingJoinPoint joinPoint) throws Throwable {
        String methodName = joinPoint.getSignature().getName();
        String serviceName = joinPoint.getTarget().getClass().getSimpleName();
        
        log.info("Secret access: {} called {} at {}", 
            serviceName, methodName, Instant.now());
        
        long startTime = System.currentTimeMillis();
        Object result = joinPoint.proceed();
        long duration = System.currentTimeMillis() - startTime;
        
        log.info("Secret retrieved in {}ms", duration);
        
        return result;
    }
}
```

---

## Interview Questions

### Question 1: Design Secret Management for Kubernetes

**Problem:** You have 100 microservices in Kubernetes. Design a secret management system.

**Solution:**

```yaml
# Option 1: Kubernetes Secrets + Sealed Secrets
# 1. Encrypt secrets before committing to Git
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: db-credentials
spec:
  encryptedData:
    username: AgBghY3K9... (encrypted)
    password: AgC7HdV2M... (encrypted)

# 2. Sealed Secrets Controller decrypts and creates K8s Secret
# 3. Pods mount secret as environment variable

# Option 2: External Secrets Operator + Vault
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: vault-secret
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
  target:
    name: db-credentials
  data:
  - secretKey: username
    remoteRef:
      key: secret/data/database
      property: username
  - secretKey: password
    remoteRef:
      key: secret/data/database
      property: password

# Vault stores secrets
# External Secrets Operator syncs to K8s Secrets
# Auto-rotates every hour
```

**Best Approach:**

```
1. Vault for secret storage
2. External Secrets Operator for K8s integration
3. AppRole or Kubernetes auth for pods
4. Init containers to fetch secrets before app starts
5. Sidecar containers to refresh secrets periodically
```

### Question 2: Secret Leaked in Git - What Do You Do?

**Response Plan:**

```
1. IMMEDIATELY rotate the secret (highest priority)
   - Generate new credential
   - Update in Vault
   - Deploy services with new secret
   - Revoke old secret

2. Audit the damage
   - Check logs: Was leaked secret used?
   - By whom? When? From where?
   - What data was accessed?

3. Remove from Git history
   - git filter-branch or BFG Repo-Cleaner
   - Force push (coordinate with team)
   - Not enough alone - assume compromised

4. Post-mortem
   - How did it leak?
   - Update processes to prevent recurrence
   - Add pre-commit hooks
   - Add secret scanning to CI/CD

5. Notify if required
   - Security team
   - Compliance (if PII accessed)
   - Customers (if data breach)
```

---

## Summary: Secret Management

**Key Concepts:**
- Never hardcode secrets
- Use centralized secret management (Vault, AWS Secrets Manager)
- Dynamic secrets > static secrets
- Rotate regularly
- Audit all access
- Principle of least privilege

**Implementation:**
```
Development: Use Vault dev server or .env files
Staging: Use Vault with AppRole auth
Production: Use Vault with dynamic secrets + auto-rotation
```

**Common Tools:**
- HashiCorp Vault (open source, self-hosted)
- AWS Secrets Manager (AWS managed)
- Azure Key Vault (Azure managed)
- Google Cloud KMS (GCP managed)
- Kubernetes Secrets (basic, must encrypt)

**Red Flags:**
❌ Secrets in source code
❌ Secrets in Docker images
❌ Secrets in environment variables (visible in `docker inspect`)
❌ Long-lived credentials
❌ No rotation
❌ No audit logs

**Interview Tips:**
- Always mention Vault or managed service
- Discuss rotation strategy
- Mention dynamic secrets
- Talk about audit/compliance
- Consider disaster recovery (backup keys)