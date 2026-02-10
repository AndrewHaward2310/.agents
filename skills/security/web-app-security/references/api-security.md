# API Security Reference

Covers API security best practices, fuzzing, and vulnerability testing for REST, GraphQL, and SOAP APIs.

## API Reconnaissance

```bash
# Check for API documentation
/swagger.json, /openapi.json, /api-docs, /v1/api-docs, /swagger-ui.html

# API discovery tools
kr scan https://target.com -w routes-large.kite  # Kiterunner
```

## OWASP API Security Top 10

1. **Broken Object Level Authorization (BOLA)** - Verify user can access resource
2. **Broken Authentication** - Strong auth mechanisms
3. **Broken Object Property Level Authorization** - Validate property access
4. **Unrestricted Resource Consumption** - Rate limiting and quotas
5. **Broken Function Level Authorization** - Verify role per function
6. **Unrestricted Access to Sensitive Business Flows** - Protect critical workflows
7. **Server Side Request Forgery (SSRF)** - Validate/sanitize URLs
8. **Security Misconfiguration** - Security headers and best practices
9. **Improper Inventory Management** - Document/secure all endpoints
10. **Unsafe Consumption of APIs** - Validate third-party API data

## Authentication & Authorization

### JWT Security
- Use strong secrets (256-bit minimum)
- Short expiration (1 hour access tokens)
- Implement refresh tokens stored in database
- Validate issuer and audience claims
- Never store sensitive data in JWT payload
- Implement token blacklisting for logout

### Input Validation
```javascript
// Use schema validation (e.g., Zod)
const schema = z.object({
  email: z.string().email(),
  password: z.string().min(8).regex(/[A-Z]/).regex(/[0-9]/),
  name: z.string().min(2).max(100)
});

// Always use parameterized queries or ORM
// Never: `SELECT * FROM users WHERE id = '${userId}'`
// Always: db.query('SELECT * FROM users WHERE id = $1', [userId])
```

### Rate Limiting
- General API: 100 requests per 15 minutes
- Auth endpoints: 5 attempts per 15 minutes
- Expensive operations: 10 per hour
- Return headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

## API Fuzzing & Bug Bounty

### IDOR in APIs
```bash
# Basic IDOR
GET /api/users/1234 → GET /api/users/1235

# IDOR bypass techniques
{"id":111} → {"id":[111]}          # Wrap in array
{"id":111} → {"id":{"id":111}}     # JSON wrap
URL?id=<LEGIT>&id=<VICTIM>          # Parameter pollution
{"user_id":"*"}                      # Wildcard
```

### SQL Injection in JSON
```json
{"id":"56456 AND 1=1#"}   → OK
{"id":"56456 AND 1=2#"}   → OK
{"id":"56456 AND 1=3#"}   → ERROR (vulnerable!)
{"id":"56456 AND sleep(15)#"} → SLEEP
```

### Endpoint Bypass (403/401)
```bash
/api/v1/users/sensitivedata.json
/api/v1/users/sensitivedata?
/api/v1/users/sensitivedata/
/api/v1/users/sensitivedata%20
/api/v1/users/..;/sensitivedata
```

### HTTP Method Testing
```bash
# Try all methods on protected endpoints
GET, POST, PUT, DELETE, PATCH
# Switch content type: application/json → application/xml
```

## GraphQL Security

### Introspection Query
```graphql
{__schema{queryType{name},mutationType{name},types{kind,name,fields(includeDeprecated:true){name,args{name,type{name,kind}}}}}}
```

### GraphQL Attacks
```graphql
# IDOR
query { user(id: "OTHER_USER_ID") { email password } }

# SQL Injection
mutation { login(input:{email:"test' or 1=1--" password:"x"}) { jwt } }

# DoS via nested queries
query { posts { comments { user { posts { comments { user { posts { ... } } } } } } } }

# Rate limit bypass via batching
[{query1},{query2},{query3}]  # Multiple queries in one request
```

### GraphQL Tools

| Tool | Purpose |
|------|---------|
| InQL | Burp extension for GraphQL |
| GraphCrawler | Schema discovery |
| graphw00f | Fingerprinting |
| clairvoyance | Schema reconstruction |
| GraphQLmap | Exploitation |

## API Vulnerability Checklist

| Vulnerability | Test |
|---------------|------|
| IDOR / BOLA | Change user_id parameter |
| SQLi in JSON | `' OR 1=1--` in JSON fields |
| Missing rate limiting | Rapid-fire requests |
| JWT weaknesses | Algorithm confusion, weak signing |
| Exposed tokens | API keys in responses/URLs |
| Undocumented endpoints | Swagger, archive.org, JS files |
| Version gaps | Test /v1, /v2, /v3 separately |
| Content type issues | Switch JSON ↔ XML |
| HTTP method tampering | GET → DELETE/PUT |
| Race conditions | Concurrent requests on sensitive ops |

## Security Best Practices

### Do
- Use HTTPS everywhere
- Validate all inputs server-side
- Implement proper CORS (whitelist origins)
- Use security headers (Helmet.js)
- Log security events (not sensitive data)
- Hash passwords with bcrypt (10+ rounds)
- Keep dependencies updated

### Don't
- Store passwords in plain text
- Use string concatenation for SQL
- Expose stack traces in production
- Store sensitive data in JWT
- Disable CORS completely
- Use default credentials
