# PART VI: APPLICATION SECURITY ENGINEERING, SERVER-SIDE VULNERABILITY ROOT-CAUSE ANALYSIS & REMEDIATION

---

# Chapter 25: Modern Web Application Architecture & HTTP Proxy Analysis

## 25.1 Anatomy of the Modern Multi-Tier Enterprise Web Stack

Before analyzing server-side vulnerabilities or performing secure code reviews, Application Security (AppSec) engineers must understand how an HTTP request traverses a modern production web architecture. Unlike early monolithic web servers where a single daemon parsed HTTP and queried a local database directly, modern cloud-native applications process each request across multiple specialized network and application hops.

```
+-----------------------------------------------------------------------------------+
|                ENTERPRISE MULTI-TIER WEB APPLICATION ARCHITECTURE                 |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [Client Browser / Mobile App]                                                    |
|         |                                                                         |
|         |  TLS 1.3 (HTTPS / HTTP/2 / HTTP/3 QUIC)                                 |
|         v                                                                         |
|  +-----------------------------------------------------------------------------+  |
|  | Tier 1: Edge CDN & Web Application Firewall (Cloudflare / CloudFront / WAF) |  |
|  |  - Anycast DDoS Mitigation, TLS Termination, Bot Management, Edge Caching   |  |
|  +-----------------------------------------------------------------------------+  |
|         |                                                                         |
|         |  Authenticated Origin Pull (mTLS)                                       |
|         v                                                                         |
|  +-----------------------------------------------------------------------------+  |
|  | Tier 2: Cloud Load Balancer & API Gateway (ALB / Envoy / Kong / Nginx)      |  |
|  |  - Path Routing, Rate Limiting, JWT Verification, Header Normalization      |  |
|  +-----------------------------------------------------------------------------+  |
|         |                                                                         |
|         |  HTTP/1.1 or gRPC over Private VPC Mesh                                 |
|         v                                                                         |
|  +-----------------------------------------------------------------------------+  |
|  | Tier 3: Application Runtime Tier (Node.js / Python ASGI / Go / Spring Boot) |  |
|  |  - Business Logic, RBAC/ABAC Authorization, Input Validation, Serialization |  |
|  +-----------------------------------------------------------------------------+  |
|         |                                             |                           |
|         | Cache Lookup / Session State                | Parameterized SQL / Wire  |
|         v                                             v                           |
|  +-----------------------------------+   +-------------------------------------+  |
|  | Tier 4A: In-Memory Data Store     |   | Tier 4B: Primary Persistence Tier   |  |
|  |  - Redis / Memcached Cluster      |   |  - PostgreSQL / MySQL / MongoDB     |  |
|  +-----------------------------------+   +-------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### 25.1.1 Architectural Trust Boundaries and Request Normalization

Every boundary between tiers represents a **Trust Boundary**. A major class of server-side security flaws arises when two tiers interpret the same HTTP request differently (**Semantic Discrepancies**):

1. **Client IP Attribution (`X-Forwarded-For` vs. `Forwarded` - RFC 7239):**
   * When a reverse proxy forwards a client request to an upstream application server, the TCP source IP seen by the application server is the internal IP of the proxy—not the end user. Proxies append the client's IP address to the `X-Forwarded-For` header.
   * **Vulnerability Pattern:** If the backend framework trusts the leftmost IP address in `X-Forwarded-For` without verifying that the request arrived from a trusted proxy interface, any client can send a forged `X-Forwarded-For: 127.0.0.1` header to spoof their source IP and bypass rate limits or IP-based access controls.
   * **Architectural Fix:** Configure the reverse proxy to overwrite or append strictly from the right, and configure the application framework (`trust proxy` in Express, `ProxyHeadersMiddleware` in Uvicorn/FastAPI, `RemoteIpValve` in Tomcat) to trust `X-Forwarded-For` **only** when the immediate TCP peer is within the internal load balancer subnet.

2. **Path Normalization Discrepancies:**
   * A reverse proxy (Nginx/Envoy) may evaluate access control rules on the raw URI path `/api/public/../admin/users` as a public route, while the backend application framework normalizes `..` segments and routes the request to `/api/admin/users`.
   * **Architectural Fix:** Always canonicalize URLs at the edge gateway before applying routing or access control rules, and enforce authorization inside the backend application controller itself (Defense-in-Depth).

3. **HTTP Request Smuggling (`CL.TE` / `TE.CL` / HTTP/2 Downgrade):**
   * RFC 9112 specifies two mechanisms for framing HTTP/1.1 request body lengths: `Content-Length` and `Transfer-Encoding: chunked`. If a front-end proxy and a back-end server disagree on where one pipelined HTTP/1.1 request ends and the next begins—or if an HTTP/2 edge proxy downgrades requests to HTTP/1.1 over a shared backend TCP connection—request boundaries can desynchronize.
   * **Architectural Fix:** Use end-to-end HTTP/2 (or gRPC) between reverse proxies and backend application servers, reject requests containing both `Content-Length` and `Transfer-Encoding` headers per RFC 9112 Section 6.3, and disable HTTP/1.1 connection reuse across distinct clients if legacy backends are present.

---

## 25.2 HTTP/1.1, HTTP/2, and HTTP/3 Protocol Mechanics for AppSec Engineers

### 25.2.1 Structural Evolution of HTTP Versions

| Protocol Attribute | HTTP/1.1 (RFC 9112) | HTTP/2 (RFC 9113) | HTTP/3 (RFC 9114) |
| :--- | :--- | :--- | :--- |
| **Framing Format** | Delimited ASCII text (`\r\n` CRLF) | Binary framing layer (`HEADERS`, `DATA` frames) | Binary frames over QUIC streams |
| **Transport Layer** | TCP (Port 80 / 443) | TCP with mandatory TLS (ALPN `h2`) | UDP with QUIC + built-in TLS 1.3 (`h3`) |
| **Header Representation** | Plaintext `Name: Value` lines | **HPACK** compressed pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`) | **QPACK** out-of-order header compression |
| **Multiplexing** | Sequential per TCP connection (Head-of-Line blocking) | Multiplexed streams over a single TCP connection | Independent QUIC streams (eliminates TCP Head-of-Line blocking) |
| **Security Auditing Implication** | Susceptible to CRLF header injection and `CL`/`TE` desynchronization | Pseudo-headers must be validated when translating `h2` to `HTTP/1.1` backends | Requires UDP port `443/udp` inspection and `Alt-Svc` header validation |

### 25.2.2 Anatomy of an Audited HTTP Request and Response Exchange

During an authorized Application Security assessment (aligned with the **OWASP Web Security Testing Guide / WSTG**), every interaction is analyzed at the raw HTTP message level:

```http
POST /api/v2/transfers/initiate HTTP/1.1
Host: banking.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0yMDI2LTAxIn0...
X-CSRF-Token: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
Content-Length: 94
Connection: close

{"source_account":"ACC-100492","destination_account":"ACC-883920","amount":250.00,"currency":"LKR"}
```

```http
HTTP/1.1 201 Created
Date: Mon, 02 Nov 2026 08:30:00 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 89
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'

{"transfer_id":"txn_01JBM8Z7W3K9P2Q4R6T8V0X2Y4","status":"PENDING_MFA","amount":250.00}
```

---

## 25.3 Intercepting HTTP Proxy Architecture (Burp Suite & OWASP ZAP)

Dynamic Application Security Testing (DAST) and manual penetration testing rely on an **Intercepting HTTP/WebSocket Proxy** (such as **PortSwigger Burp Suite** or **OWASP Zed Attack Proxy / ZAP**) positioned between an isolated test browser and the target staging/test environment.

### 25.3.1 How TLS Interception Works in an Authorized Testing Environment

To inspect HTTPS traffic generated by a local test browser, the intercepting proxy generates a unique, installation-specific **Root Certificate Authority (CA)** keypair on the auditor's workstation:

```
+-------------------+     1. CONNECT app.example.com:443     +------------------------+
| Isolated Test     | -------------------------------------> | Local Intercept Proxy  |
| Browser           |                                        | (127.0.0.1:8080)       |
| (Trusts Proxy CA) | <------------------------------------- | Dynamically signs leaf |
+-------------------+     2. Presents Leaf Cert for          | cert using Local CA    |
                          "app.example.com" signed by        +------------------------+
                          Local Proxy CA                                 |
                                                                         | 3. Upstream TLS 1.3
                                                                         |    Handshake
                                                                         v
                                                             +------------------------+
                                                             | Target Test Server     |
                                                             | (app.example.com:443)  |
                                                             +------------------------+
```

> **Operational Security Note for Auditors:** The local proxy listener (`127.0.0.1:8080`) must bind strictly to the loopback interface (`127.0.0.1`), and the generated Proxy Root CA certificate must only be imported into a dedicated, isolated testing browser profile—never into the host operating system's global trust store.

### 25.3.2 Core Functional Modules of an AppSec Assessment Proxy

| Proxy Module | OWASP ZAP Equivalent | Engineering & Assessment Function |
| :--- | :--- | :--- |
| **Proxy & HTTP History** | Sites Tree & History Tab | Passively records all HTTP/1.1, HTTP/2, and WebSocket messages traversed during normal application walkthroughs; supports scope filtering by hostname, status code, and MIME type. |
| **Repeater** | Manual Request Editor | Enables security engineers to modify individual parameters, headers, or HTTP methods on a single request and observe exact changes in server status codes, headers, and response bodies. |
| **Intruder** | Fuzzer | Automates parameterized testing across one or more insertion points to verify input validation boundaries, rate-limiting enforcement, and access control rules. |
| **Sequencer** | Token / Entropy Analyzer | Performs FIPS 140-2 statistical randomness and character-level entropy tests on session identifiers, CSRF tokens, and password reset tokens to verify cryptographic unpredictability. |
| **Comparer** | Diff Tool | Computes byte-by-byte or word-by-word diffs between two HTTP responses (e.g., comparing an Admin response vs. a Standard User response during authorization testing). |
| **Logger++ / Passive Scanner** | Passive Scan Rules | Continuously evaluates every proxied request/response against security policies (missing `HttpOnly`/`Secure` cookie flags, missing CSP/HSTS headers, CORS misconfigurations). |

### 25.3.3 Parameter Insertion Strategies in Automated Boundary Testing

When configuring automated parameter tests in Burp Intruder or OWASP ZAP to verify input validation across multiple fields, four distinct payload placement strategies exist:

1. **Sniper:** Uses a single list of test inputs and places one test value into one insertion point at a time (cycling through each insertion point sequentially while leaving all other parameters at their baseline values). Ideal for auditing individual parameters for input validation rules.
2. **Battering Ram:** Uses a single list of test inputs and places the *exact same* test value simultaneously into all highlighted insertion points in a single request (e.g., when a parameter appears in both the URL query string and the JSON body).
3. **Pitchfork:** Uses multiple test input lists in parallel (1-to-1 zip mapping: List 1 Item 1 is paired with List 2 Item 1, List 1 Item 2 with List 2 Item 2). Ideal for testing paired identifiers such as `account_id` + ` matching_csrf_token` during multi-user authorization matrix testing.
4. **Cluster Bomb:** Computes the full Cartesian product ($N \times M$) across multiple insertion points and lists. Because request volume grows multiplicatively, it is used sparingly in isolated lab environments to test state combinations.

---

# Chapter 26: Injection Flaws (CWE-89 SQL Injection & NoSQL Injection): Root-Cause Analysis & Remediation

## 26.1 Theoretical Mechanics of Injection Vulnerabilities (CWE-74 / CWE-89)

An **Injection Vulnerability** occurs whenever an application combines **untrusted user-supplied data** with **programmatic command or query syntax** inside a single string buffer and passes that concatenated string to an interpreter (such as a SQL database engine, a NoSQL document engine, an LDAP directory server, or an OS shell).

Because the interpreter receives a flat character stream with no out-of-band boundary separating "developer instructions" from "user data," any special metacharacters present in the user input (`'`, `"`, `;`, `--`, `$ne`) are parsed as **structural tokens in the interpreter's Abstract Syntax Tree (AST)**, altering the semantics of the query itself.

### 26.1.1 How a Relational Database Parses SQL Queries (Lexer -> Parser -> AST -> Optimizer)

When a relational database management system (RDBMS) such as PostgreSQL, MySQL, Microsoft SQL Server, or Oracle receives a SQL statement, it processes the query through four distinct compilation phases:

```
+-----------------------------------------------------------------------------------+
|               SQL COMPILATION PIPELINE: CONCATENATION VS. PARAMETERIZATION        |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  1. Lexical Analysis (Tokenizer):                                                 |
|     Splits raw SQL character stream into keywords, identifiers, operators,        |
|     and literal tokens.                                                           |
|                                                                                   |
|  2. Syntactic Analysis (Parser):                                                  |
|     Constructs an Abstract Syntax Tree (AST) representing the logical structure   |
|     of the WHERE clause and boolean predicates.                                   |
|                                                                                   |
|     - VULNERABLE (String Concatenation):                                          |
|       User input is injected BEFORE Step 1 & Step 2!                              |
|       Input characters can close string literals and add new AST nodes (OR, UNION)|
|                                                                                   |
|     - SECURE (Prepared Statement / Parameterized Query):                          |
|       Step 1, Step 2 (AST construction), and Step 3 (Query Plan Optimization)     |
|       are finalized BEFORE user parameters are bound!                             |
|       User input is bound strictly as a scalar value into a pre-compiled leaf node|
|       and can NEVER alter the AST structure.                                      |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

#### Visualizing the AST Corruption Caused by String Concatenation

Suppose a backend service constructs a query using string interpolation:

```sql
SELECT id, email, role FROM users WHERE username = '$user_input' AND tenant_id = 42;
```

**Expected AST (When `$user_input` is `alice`):**
```
                  [AND]
                 /     \
              [=]       [=]
             /   \     /   \
      username 'alice' tenant_id 42
```

**Corrupted AST (When string concatenation allows untrusted metacharacters to inject an `OR` operator into the syntax tree):**
```
                   [OR]
                  /    \
               [=]      [AND]
              /   \    /     \
             1     1  ...    ...
```
Because the boolean `OR` operator has lower precedence than `AND` in SQL grammar, the injected left branch evaluates to `TRUE` for every row in the table, completely neutralizing the `AND tenant_id = 42` restriction.

---

## 26.2 Taxonomy of SQL Injection Classes & Diagnostic Identification in Code Audits

Security engineers categorize SQL Injection flaws into four primary classes based on how the database engine's response is handled by the application:

| SQLi Classification | Application Behavior | Root Cause in Code | Primary Risk |
| :--- | :--- | :--- | :--- |
| **1. In-Band (Classic / Reflected / UNION)** | Query results are returned directly in the HTTP response body (e.g., search results table or profile view). | Unparameterized variable concatenated into `SELECT`, `ORDER BY`, or `WHERE` clauses whose output columns render in the UI. | Unauthorized reading of rows from current or adjacent database tables; authentication bypass. |
| **2. Error-Based** | The application catches raw database driver exceptions (`PDOException`, `psycopg2.Error`) and prints the SQL error string in the HTTP response. | String concatenation combined with verbose error reporting (`display_errors = On` or returning `str(e)` in JSON responses). | Leakage of database schema structure, table names, and column types via parser error diagnostics. |
| **3. Inferential (Boolean-Based & Time-Based Blind)** | The application suppresses database errors and returns no query rows directly, but exhibits observable differences in HTTP status code, page content, or response latency when the query predicate evaluates to `TRUE` vs `FALSE`. | Unparameterized variable concatenated into a query whose boolean outcome controls conditional branching (`if row_exists:`). | Unauthorized inference of sensitive database state via boolean side-channels or timing differences. |
| **4. Second-Order SQL Injection** | User input is safely parameterized during initial `INSERT` into the database, but a *subsequent* background job or reporting query retrieves that stored value from the database and concatenates it unsafely into a second SQL query. | Developers mistakenly treating data read from their own database tables as "trusted" and concatenating it into dynamic SQL. | Deferred query manipulation inside administrative dashboards, batch processors, or audit logs. |

### 26.2.1 Why Second-Order SQL Injection Happens

Second-order SQL injection highlights why **input escaping/filtering at the perimeter is never a substitute for parameterized queries everywhere**. When data is inserted using a prepared statement, the database stores the exact literal characters provided by the user. If a reporting module later reads `user.display_name` from the `users` table and builds a dynamic query via `f"SELECT * FROM activity_logs WHERE actor = '{user.display_name}'"`, the stored literal characters are parsed as SQL syntax during the second query execution.

**Architectural Rule:** Every SQL statement in the entire codebase must use parameterized queries—regardless of whether the variable came from an HTTP request, a message queue, an internal RPC call, or another database table.

---

## 26.3 Complete Multi-Language Remediation Guide: Parameterized Queries & Prepared Statements

The primary defense against SQL Injection (recommended by the **OWASP SQL Injection Prevention Cheat Sheet** and **CWE-89**) is the strict separation of query code and data via **Parameterized Queries (Prepared Statements)**.

### 26.3.1 Python (`psycopg` / `psycopg2` for PostgreSQL & `SQLAlchemy` ORM)

A frequent mistake in Python database programming is using Python's string formatting operators (`%`, `.format()`, or `f"..."` f-strings) inside `cursor.execute()`. In `psycopg2`/`psycopg`, the `%s` placeholder must be passed inside the query string while the parameters are passed as the **second tuple argument** to `cursor.execute(sql, params)`.

#### Side-by-Side Comparison: Python Database Queries

```python
# ============================================================================
# VULNERABLE PYTHON CODE (DO NOT USE)
# ============================================================================
import psycopg2

def get_user_orders_vulnerable(conn, user_email: str, status_filter: str):
    with conn.cursor() as cur:
        # FLAW: f-string interpolation directly concatenates untrusted strings
        # into the SQL command before sending it to PostgreSQL!
        query = f"""
            SELECT order_id, total_amount, created_at
            FROM orders
            WHERE customer_email = '{user_email}'
              AND order_status = '{status_filter}'
        """
        cur.execute(query)
        return cur.fetchall()
```

```python
# ============================================================================
# REMEDIATED SECURE PYTHON CODE (Parameterized Query & SQLAlchemy 2.0)
# ============================================================================
import psycopg2
from typing import List, Tuple, Any
from sqlalchemy import select, text
from sqlalchemy.orm import Session

# 1. Secure Raw Driver Approach (psycopg2 / PEP 249 DB-API 2.0)
def get_user_orders_secure(
    conn, user_email: str, status_filter: str
) -> List[Tuple[Any, ...]]:
    with conn.cursor() as cur:
        # SECURE: Query structure is static. Placeholders (%s) are bound separately
        # as a tuple in the second argument of cur.execute().
        query = """
            SELECT order_id, total_amount, created_at
            FROM orders
            WHERE customer_email = %s
              AND order_status = %s
        """
        cur.execute(query, (user_email, status_filter))
        return cur.fetchall()


# 2. Secure SQLAlchemy 2.0 ORM Approach
def get_user_orders_orm(session: Session, OrderModel, user_email: str, status_filter: str):
    stmt = (
        select(OrderModel.order_id, OrderModel.total_amount, OrderModel.created_at)
        .where(OrderModel.customer_email == user_email)
        .where(OrderModel.order_status == status_filter)
    )
    return session.execute(stmt).all()


# 3. Secure SQLAlchemy Textual SQL with Bound Parameters (when custom SQL is needed)
def get_user_orders_sqlalchemy_text(session: Session, user_email: str, status_filter: str):
    stmt = text(
        """
        SELECT order_id, total_amount, created_at
        FROM orders
        WHERE customer_email = :email
          AND order_status = :status
        """
    )
    return session.execute(
        stmt, {"email": user_email, "status": status_filter}
    ).all()
```

---

### 26.3.2 Node.js / TypeScript (`pg` node-postgres & `mysql2`)

In JavaScript/TypeScript, ES6 template literals (`` `SELECT ... WHERE id = ${req.query.id}` ``) are a major source of SQL injection flaws when developers confuse template literals with parameterized query builders.

#### Side-by-Side Comparison: Node.js (`pg`) Queries

```typescript
// ============================================================================
// VULNERABLE NODE.JS / TYPESCRIPT CODE (DO NOT USE)
// ============================================================================
import { Pool } from 'pg';
const pool = new Pool();

export async function searchInvoicesVulnerable(tenantId: string, searchTerm: string) {
  // FLAW: ES6 backtick template literal concatenates user input directly into SQL!
  const sql = `
    SELECT invoice_id, amount, due_date
    FROM invoices
    WHERE tenant_id = '${tenantId}'
      AND description ILIKE '%${searchTerm}%'
  `;
  const result = await pool.query(sql);
  return result.rows;
}
```

```typescript
// ============================================================================
// REMEDIATED SECURE NODE.JS / TYPESCRIPT CODE (Parameterized $1, $2 Binding)
// ============================================================================
import { Pool } from 'pg';
const pool = new Pool();

export interface InvoiceRecord {
  invoice_id: string;
  amount: number;
  due_date: Date;
}

export async function searchInvoicesSecure(
  tenantId: string,
  searchTerm: string
): Promise<InvoiceRecord[]> {
  // Escape literal % and _ wildcards inside the search term so user input
  // cannot abuse LIKE pattern matching, then bind via $1 and $2 parameters.
  const sanitizedSearch = searchTerm.replace(/[\\%_]/g, '\\$&');
  const likePattern = `%${sanitizedSearch}%`;

  const sql = `
    SELECT invoice_id, amount, due_date
    FROM invoices
    WHERE tenant_id = $1
      AND description ILIKE $2 ESCAPE '\\'
  `;

  // SECURE: Parameters passed in a separate array; PostgreSQL Extended Query
  // Protocol binds $1 and $2 strictly as scalar data values.
  const result = await pool.query<InvoiceRecord>(sql, [tenantId, likePattern]);
  return result.rows;
}
```

---

### 26.3.3 PHP (`PDO` - PHP Data Objects)

When configuring PHP `PDO`, security engineers must explicitly set `PDO::ATTR_EMULATE_PREPARES => false` so that PHP uses true **native server-side prepared statements** at the MySQL/PostgreSQL wire protocol level rather than emulating string interpolation inside the PHP driver.

#### Side-by-Side Comparison: PHP `PDO` Queries

```php
<?php
// ============================================================================
// VULNERABLE PHP CODE (DO NOT USE)
// ============================================================================
function getAccountByUsernameVulnerable(PDO $pdo, string $username): ?array {
    // FLAW: Direct variable interpolation inside double-quoted SQL string
    $stmt = $pdo->query("SELECT id, username, email, role FROM accounts WHERE username = '$username'");
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ?: null;
}
```

```php
<?php
// ============================================================================
// REMEDIATED SECURE PHP CODE (Hardened PDO with Native Prepared Statements)
// ============================================================================
declare(strict_types=1);

function createHardenedPdoConnection(string $dsn, string $dbUser, string $dbPass): PDO {
    return new PDO($dsn, $dbUser, $dbPass, [
        // 1. Disable emulated prepares so MySQL/PostgreSQL compiles the AST server-side
        PDO::ATTR_EMULATE_PREPARES   => false,
        // 2. Throw exceptions on errors (caught by global RFC 9457 error handler)
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        // 3. Default to associative arrays
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
}

function getAccountByUsernameSecure(PDO $pdo, string $username): ?array {
    // SECURE: Named placeholder :username compiled separately from bound data
    $stmt = $pdo->prepare(
        'SELECT id, username, email, role FROM accounts WHERE username = :username LIMIT 1'
    );
    $stmt->execute(['username' => $username]);
    $row = $stmt->fetch();
    return $row ?: null;
}
```

---

### 26.3.4 Java (`java.sql.PreparedStatement` & Spring Data JPA) and Go (`database/sql`)

#### Side-by-Side Comparison: Java JDBC (`Statement` vs. `PreparedStatement`)

```java
// ============================================================================
// VULNERABLE JAVA CODE (DO NOT USE)
// ============================================================================
public UserRecord findUserVulnerable(Connection conn, String department, String employeeId)
        throws SQLException {
    // FLAW: java.sql.Statement with string concatenation (+)
    String sql = "SELECT emp_id, full_name, salary_grade FROM employees "
               + "WHERE department = '" + department + "' AND emp_id = '" + employeeId + "'";
    try (Statement stmt = conn.createStatement();
         ResultSet rs = stmt.executeQuery(sql)) {
        if (rs.next()) {
            return new UserRecord(rs.getString("emp_id"), rs.getString("full_name"));
        }
        return null;
    }
}

// ============================================================================
// REMEDIATED SECURE JAVA CODE (java.sql.PreparedStatement)
// ============================================================================
public UserRecord findUserSecure(Connection conn, String department, String employeeId)
        throws SQLException {
    String sql = "SELECT emp_id, full_name, salary_grade FROM employees "
               + "WHERE department = ? AND emp_id = ?";
    try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
        pstmt.setString(1, department);
        pstmt.setString(2, employeeId);
        try (ResultSet rs = pstmt.executeQuery()) {
            if (rs.next()) {
                return new UserRecord(rs.getString("emp_id"), rs.getString("full_name"));
            }
            return null;
        }
    }
}
```

#### Secure Go (`database/sql`) Implementation

```go
package repository

import (
	"context"
	"database/sql"
	"time"
)

type AuditLogEntry struct {
	ID        int64
	ActorID   string
	Action    string
	CreatedAt time.Time
}

// GetAuditLogsByActor uses parameterized query binding ($1, $2) via database/sql
func GetAuditLogsByActor(ctx context.Context, db *sql.DB, actorID string, limit int) ([]AuditLogEntry, error) {
	const query = `
		SELECT id, actor_id, action, created_at
		FROM security_audit_logs
		WHERE actor_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`
	rows, err := db.QueryContext(ctx, query, actorID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditLogEntry
	for rows.Next() {
		var e AuditLogEntry
		if err := rows.Scan(&e.ID, &e.ActorID, &e.Action, &e.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
```

---

## 26.4 Safely Handling Dynamic Identifiers (`ORDER BY`, Column Names, and Table Names)

A critical architectural limitation of SQL Prepared Statements is that **bound parameters (`?`, `$1`, `:name`) can only represent scalar literal values** (such as strings, integers, timestamps, or booleans in a `WHERE` or `VALUES` clause). Database engines do **not** allow bound parameters to replace SQL structural identifiers such as:
- Table names (`FROM ?`)
- Column names (`SELECT ?` or `ORDER BY ?`)
- Sort direction keywords (`ASC` / `DESC`)

Because developers discover that `ORDER BY ?` fails or sorts by a constant string literal, they often fall back to string concatenation (`f"ORDER BY {sort_column} {sort_dir}"`), re-introducing SQL Injection in sorting and pagination endpoints!

### 26.4.1 Remediation: Strict Allowlist Mapping for Dynamic SQL Identifiers

To support dynamic sorting or column selection safely, applications must map user-supplied sort parameters against a **hardcoded, immutable server-side dictionary/allowlist** of valid column names and sort directions, and reject any unmapped input:

```python
# SECURE PATTERN: Strict Dictionary Allowlist for Dynamic ORDER BY Clauses
from fastapi import HTTPException

ALLOWED_SORT_COLUMNS = {
    "date": "created_at",
    "amount": "total_amount",
    "status": "order_status",
}

ALLOWED_SORT_DIRECTIONS = {
    "asc": "ASC",
    "desc": "DESC",
}

def list_orders_sorted_secure(
    conn,
    tenant_id: int,
    user_sort_col: str = "date",
    user_sort_dir: str = "desc"
):
    # 1. Resolve column and direction strictly from hardcoded server-side dictionary
    safe_column = ALLOWED_SORT_COLUMNS.get(user_sort_col.lower())
    safe_direction = ALLOWED_SORT_DIRECTIONS.get(user_sort_dir.lower())

    if not safe_column or not safe_direction:
        raise HTTPException(status_code=400, detail="Invalid sort parameter")

    # 2. Only hardcoded dictionary values are interpolated for identifiers;
    #    data values (tenant_id) still use parameterized binding (%s)
    query = f"""
        SELECT order_id, total_amount, order_status, created_at
        FROM orders
        WHERE tenant_id = %s
        ORDER BY {safe_column} {safe_direction}
        LIMIT 50
    """
    with conn.cursor() as cur:
        cur.execute(query, (tenant_id,))
        return cur.fetchall()
```

---

## 26.5 NoSQL Injection (MongoDB) Root-Cause Analysis & Type-Safe Remediation

Document databases such as **MongoDB** do not use SQL strings; instead, they accept structured BSON/JSON query objects. However, **NoSQL Injection** occurs via two primary root causes:

1. **Query Operator Injection via Unvalidated JSON / Query Objects:**
   * In Express.js applications using `express.json()` or `qs` query-string parsing, a parameter expected to be a primitive string (`req.body.password = "secret"`) can instead be submitted by a client as a nested JSON object containing a MongoDB query operator (`{"$ne": null}` or `{"$gt": ""}`).
   * If the backend passes `req.body.password` directly into `db.collection('users').findOne({ username: req.body.username, password: req.body.password })` without verifying that `username` and `password` are strictly primitive strings, MongoDB evaluates the query operator, matching the first document where `password` is not `null`.
2. **Server-Side JavaScript Evaluation (`$where`, `mapReduce`, `$function`):**
   * MongoDB supports a `$where` operator that evaluates arbitrary JavaScript expressions inside the database engine for each document. Concatenating user input into a `$where` JavaScript string allows arbitrary syntax manipulation inside the JavaScript interpreter.

### 26.5.1 Side-by-Side Comparison: Vulnerable vs. Hardened Node.js / MongoDB Code

```typescript
// ============================================================================
// VULNERABLE NODE.JS / MONGODB CODE (DO NOT USE)
// ============================================================================
import { Db } from 'mongodb';
import { Request, Response } from 'express';

export async function lookupCustomerVulnerable(req: Request, res: Response, db: Db) {
  // FLAW 1: req.body.apiKey is not type-checked; if client sends {"apiKey": {"$gt": ""}},
  // MongoDB evaluates the $gt operator instead of comparing a literal string!
  const customer = await db.collection('customers').findOne({
    tenantId: req.body.tenantId,
    apiKey: req.body.apiKey,
  });

  return res.json({ customer });
}
```

```typescript
// ============================================================================
// REMEDIATED SECURE NODE.JS / MONGODB CODE (Strict Schema Validation with Zod)
// ============================================================================
import { Db } from 'mongodb';
import { Request, Response } from 'express';
import { z } from 'zod';

// 1. Define a strict runtime schema enforcing primitive types and lengths
const CustomerLookupSchema = z.object({
  tenantId: z.string().uuid(),
  apiKey: z.string().min(32).max(128),
}).strict();

export async function lookupCustomerSecure(req: Request, res: Response, db: Db) {
  // 2. Validate and parse request body before touching the database
  const parsed = CustomerLookupSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid request payload schema' });
  }

  const { tenantId, apiKey } = parsed.data;

  // 3. Explicitly use $eq operator with verified primitive strings
  const customer = await db.collection('customers').findOne({
    tenantId: { $eq: tenantId },
    apiKey: { $eq: apiKey },
  });

  return res.json({ customer });
}
```

### 26.5.2 Database Least-Privilege Defense-in-Depth

Even when all queries are parameterized, database infrastructure must enforce strict **Principle of Least Privilege**:
1. **Dedicated Application Database Role:** The web application must never connect to the database as `sa` (MSSQL), `postgres` (PostgreSQL superuser), or `root` (MySQL). Create a restricted application user granted only `SELECT`, `INSERT`, `UPDATE`, and (where required) `DELETE` on specific application tables—never `DROP`, `ALTER`, `GRANT`, or superuser file-access privileges (`pg_read_server_files`, `FILE` privilege in MySQL, or `xp_cmdshell` in MSSQL).
2. **Network Isolation:** Place database instances in isolated private database subnets with zero internet egress (`0.0.0.0/0` outbound blocked) and inbound access restricted strictly to the application tier's security group on the database port.


---

# Chapter 27: Authentication, Session Management & JWT Security Architecture

## 27.1 Authentication Architecture, Credential Storage & Account Enumeration Prevention

Authentication is the process of verifying the identity of a user, device, or service principal. In accordance with **OWASP Application Security Verification Standard (ASVS v4.0.3 Chapter V2)** and **NIST SP 800-63B (Digital Identity Guidelines)**, resilient authentication systems must defend against credential stuffing, brute-force attacks, user enumeration, password reset flaws, and multi-factor authentication (MFA) state machine errors.

### 27.1.1 Eliminating Username Enumeration Across Login, Registration & Password Reset Flows

**Username Enumeration (WSTG-IDNT-04)** occurs when an application reveals whether a specific email address or username exists in the database through discrepancies in:
1. **HTTP Response Body / Error Messages:** Returning `"User not found"` vs. `"Incorrect password"` on login, or `"Email address is not registered"` on password reset.
2. **HTTP Status Codes:** Returning `404 Not Found` for non-existent users vs. `401 Unauthorized` for existing users with an invalid password.
3. **Cryptographic Timing Side-Channels:** When a login request arrives for a valid username, the server executes an intentionally slow password-hashing function (`Argon2id` or `bcrypt`, taking ~150–300 ms). When a request arrives for a non-existent username, if the server immediately returns `401` without running a dummy hash comparison (~2 ms), an observer measuring response times can distinguish valid accounts from invalid ones with high accuracy.

#### Side-by-Side Comparison: Vulnerable vs. Constant-Time Authentication Service (Python)

```python
# ============================================================================
# VULNERABLE AUTHENTICATION HANDLER (Discloses Account Existence via Message & Timing)
# ============================================================================
def authenticate_user_vulnerable(db, email: str, password: str) -> dict:
    user = db.find_user_by_email(email)
    if not user:
        # FLAW 1: Distinct error message reveals email is not registered
        # FLAW 2: Returns immediately (~1ms) without executing Argon2id verification!
        raise ValueError("No account found with that email address.")

    if not verify_password(user.password_hash, password):
        raise ValueError("Invalid password for this account.")

    return {"user_id": user.id}
```

```python
# ============================================================================
# REMEDIATED SECURE AUTHENTICATION HANDLER (Constant-Time & Uniform Responses)
# ============================================================================
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Configure Argon2id per OWASP Password Storage Cheat Sheet recommendations:
# memory_cost = 65536 KiB (64 MiB), time_cost = 3 iterations, parallelism = 4
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

# Pre-computed dummy Argon2id hash generated at startup to equalize timing
# when a non-existent email address is queried.
DUMMY_ARGON2_HASH = ph.hash("constant-time-dummy-mitigation-secret-2026")


def authenticate_user_secure(db, email: str, password: str) -> dict:
    user = db.find_user_by_email(email)

    # Always run Argon2id verification regardless of whether user exists
    target_hash = user.password_hash if user is not None else DUMMY_ARGON2_HASH

    try:
        password_matches = ph.verify(target_hash, password)
    except VerifyMismatchError:
        password_matches = False

    if user is None or not password_matches:
        # Uniform error message and HTTP status code (401) for both failure paths
        raise PermissionError("Invalid credentials provided.")

    # Check if hash parameters need upgrading (transparent rehash on login)
    if ph.check_needs_rehash(user.password_hash):
        db.update_password_hash(user.id, ph.hash(password))

    return {"user_id": user.id}
```

---

## 27.2 Password Reset Architecture & Preventing Host Header Poisoning

Self-service password reset flows are among the most security-critical workflows in any web application. A compromised password reset mechanism allows complete account takeover without knowing the user's current password or MFA factor.

### 27.2.1 Root Causes of Password Reset Vulnerabilities

1. **Host Header Poisoning in Reset Emails:**
   * Developers often build the password reset URL dynamically using the incoming HTTP `Host` or `X-Forwarded-Host` header:
     `reset_link = f"https://{request.headers['Host']}/reset-password?token={token}"`
   * If an untrusted client requests a password reset for a target user while supplying a modified header (`Host: untrusted-domain.example` or `X-Forwarded-Host: untrusted-domain.example`), the application emails the victim a valid reset link pointing to the untrusted domain. If the victim clicks the link, their secret reset token is sent directly to the untrusted server.
2. **Insufficient Token Entropy or Predictable Identifiers:**
   * Using `UUIDv1` (which is derived from MAC address and 100-nanosecond timestamp intervals), `Math.random()`, `mt_rand()`, or sequential integers for reset tokens allows token prediction.
3. **Token Leakage via HTTP `Referer` Header:**
   * When a user clicks `https://app.example.com/reset-password?token=secret123` and the reset page loads third-party scripts, analytics, or social media links without `Referrer-Policy: no-referrer`, the browser sends the full URL (including `?token=secret123`) in the `Referer` header to those external third-party domains.
4. **Storing Plaintext Reset Tokens in the Database:**
   * Reset tokens should be treated like passwords: generate a 256-bit cryptographically secure random token (`secrets.token_urlsafe(32)`), send the raw token in the email, and store only its **SHA-256 hash** (`hashlib.sha256(token.encode()).hexdigest()`) in the database with a strict 15-minute expiration timestamp (`expires_at`) and single-use invalidation.

### 27.2.2 Hardened Password Reset Implementation (Python)

```python
import datetime
import hashlib
import secrets

# Immutable server-side configuration (NEVER derived from HTTP Host header!)
CANONICAL_APP_ORIGIN = "https://app.example.com"
RESET_TOKEN_TTL_MINUTES = 15


def create_password_reset_request(db, mailer, user_email: str) -> None:
    user = db.find_user_by_email(user_email)
    if not user:
        # Return silently with identical timing/response so caller cannot enumerate emails
        return

    # 1. Generate 256 bits (32 bytes) of CSPRNG entropy
    raw_token = secrets.token_urlsafe(32)

    # 2. Store ONLY the SHA-256 digest of the token in the database
    token_digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        minutes=RESET_TOKEN_TTL_MINUTES
    )

    # Invalidate any prior unused reset tokens for this user and store the new digest
    db.save_password_reset_token(
        user_id=user.id,
        token_sha256=token_digest,
        expires_at=expires_at,
        used=False,
    )

    # 3. Construct reset URL using immutable CANONICAL_APP_ORIGIN config
    reset_url = f"{CANONICAL_APP_ORIGIN}/auth/reset-password#token={raw_token}"
    mailer.send_password_reset_email(to_email=user.email, reset_url=reset_url)
```

> **Note on URL Fragments (`#token=`):** Placing the token in the URL fragment (`#token=...`) or immediately consuming it via `POST` on an interstitial page with `Referrer-Policy: no-referrer` ensures the token is never transmitted in HTTP `Referer` headers to external origins.

---

## 27.3 Multi-Factor Authentication (MFA) State Machine Security

Many MFA vulnerabilities do not involve breaking the cryptographic TOTP algorithm (**RFC 6238** HMAC-Based One-Time Password) or WebAuthn/FIDO2 itself; rather, they result from **broken state machine transitions** or insufficient rate limiting during the two-step authentication flow.

### 27.3.1 Common Architectural Flaws in MFA Implementations

| MFA Design Flaw | Architectural Root Cause | Remediation Standard |
| :--- | :--- | :--- |
| **Direct Endpoint Browsing (Step-Skipping)** | Step 1 (`/login`) sets the full authenticated session cookie (`role=user`) immediately upon password match, relying on client-side JavaScript to redirect the browser to `/mfa-verify`. | Issue a restricted, short-lived `pre_auth_mfa_pending` session state after Step 1. Only mint the authenticated session token after server-side MFA verification succeeds. |
| **OTP Brute-Forcing via Missing Rate Limits** | A 6-digit TOTP code has only $10^6 = 1,000,000$ possible values. If an endpoint lacks strict per-account lockout and trusts forged `X-Forwarded-For` headers to reset IP rate limits, automated scripts can exhaust the keyspace. | Enforce strict per-account MFA attempt counters (e.g., max 5 failed OTP attempts before invalidating the `pre_auth` session and locking MFA verification for 15 minutes). |
| **TOTP Replay Within Validity Window** | RFC 6238 TOTP codes remain valid for a 30-second time step (often +/- 1 step). If the server does not record the last accepted time-step counter for that user, the same OTP can be replayed multiple times within 30–90 seconds. | Store `last_verified_totp_timestep` on the user record and reject any TOTP code whose time-step counter is $\le$ the last accepted counter. |
| **Unprotected MFA Enrollment / Recovery Flows** | Allowing a user to disable MFA, generate new backup codes, or register a new authenticator device without re-verifying their existing MFA factor (**Step-Up Authentication**). | Require recent re-authentication + current MFA / WebAuthn verification before modifying any security settings, email addresses, or MFA devices. |

---

## 27.4 Stateful Session Management & Cookie Hardening (RFC 6265bis)

When an application uses server-side stateful sessions, the session identifier stored in the browser cookie is bearer credentials equivalent to the user's password and MFA token combined.

### 27.4.1 Preventing Session Fixation (CWE-384)

**Session Fixation** occurs when an application assigns a session ID to an unauthenticated visitor *before* login, and then elevates that *exact same session ID* to an authenticated state when the user logs in without regenerating a fresh session identifier.

**Mandatory Rule:** The server must always **destroy/invalidate the pre-login session ID and issue a newly generated 128-bit+ CSPRNG session ID** upon every authentication state transition (login, MFA completion, privilege elevation, and password change).

### 27.4.2 Hardened `Set-Cookie` Attributes & `__Host-` Cookie Prefixes

```http
Set-Cookie: __Host-sid=8f9d2a7e4b1c6f0e3a5d8c2b9e4f1a6d7c0b3e8f2a5d9c1b4e7f0a3d6c9b2e5f; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=28800
```

| Cookie Attribute / Prefix | Security Function | Attack Mitigated |
| :--- | :--- | :--- |
| **`__Host-` Prefix** | Browsers enforce that a cookie named `__Host-*` MUST have `Secure`, MUST have `Path=/`, and MUST NOT have a `Domain` attribute (locking it strictly to the exact origin hostname). | Prevents subdomain cookie tossing (`Domain=.example.com` overwritten by a compromised sibling subdomain). |
| **`HttpOnly`** | Forbids client-side JavaScript (`document.cookie`) from reading or modifying the cookie. | Prevents session token theft via Cross-Site Scripting (XSS). |
| **`Secure`** | Instructs the browser to transmit the cookie exclusively over encrypted HTTPS connections. | Prevents plaintext session interception on untrusted networks. |
| **`SameSite=Lax` / `Strict`** | Controls whether the cookie is sent on cross-site requests initiated by third-party websites. `Strict` never sends on cross-site requests; `Lax` sends only on top-level safe (`GET`) navigations. | Primary browser-level defense-in-depth against Cross-Site Request Forgery (CSRF). |

---

## 27.5 JSON Web Tokens (JWT - RFC 7519) Security Architecture & Cryptographic Verification

**JSON Web Tokens (JWT, RFC 7519)**, built upon JSON Web Signature (**JWS, RFC 7515**) and JSON Web Encryption (**JWE, RFC 7516**), are compact, URL-safe stateless tokens widely used in OAuth 2.0, OpenID Connect (OIDC), and microservice architectures.

### 27.5.1 Structural Anatomy of a JWS Token

A signed JWT consists of three Base64URL-encoded segments separated by dots (`.`):

$$\text{JWT} = \text{Base64URL}(\text{Header}) \;\text{.}\; \text{Base64URL}(\text{Payload}) \;\text{.}\; \text{Base64URL}(\text{Signature})$$

```
+-----------------------------------------------------------------------------------+
|                        RFC 7519 JSON WEB TOKEN ANATOMY                            |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  1. JOSE Header:                                                                  |
|     {"alg": "RS256", "typ": "JWT", "kid": "auth-key-2026-q4"}                     |
|                                                                                   |
|  2. JWT Claims Payload:                                                           |
|     {                                                                             |
|       "iss": "https://idp.example.com",      // Issuer                            |
|       "sub": "usr_01JBM9A2B3C4D5E6",         // Subject (Immutable User ID)       |
|       "aud": "https://api.example.com",      // Audience (Intended Recipient API) |
|       "exp": 1793610000,                     // Expiration Time (Unix Epoch)      |
|       "nbf": 1793609100,                     // Not Before                        |
|       "iat": 1793609100,                     // Issued At                         |
|       "jti": "9b1deb4d-3b7d-4bad-9bdd-2b0d"  // Unique Token ID (Replay/Revoke)   |
|     }                                                                             |
|                                                                                   |
|  3. Cryptographic Signature:                                                      |
|     RSASSA-PKCS1-v1_5-SHA256(                                                     |
|       privateKey,                                                                 |
|       ASCII(Base64URL(Header) + "." + Base64URL(Payload))                         |
|     )                                                                             |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

> **Critical Design Principle:** A standard JWS token is **signed, not encrypted**. Anyone who possesses the token can Base64URL-decode the Header and Payload and read every claim inside it. Never place sensitive secrets, PII, or session passwords inside a JWS payload unless the token is encrypted using **JWE (RFC 7516)**.

### 27.5.2 Critical JWT Verification Flaws (RFC 8725 - JWT Best Current Practices)

**RFC 8725 (JSON Web Token Best Current Practices)** documents the primary cryptographic implementation vulnerabilities that occur when applications verify JWTs insecurely:

1. **Calling `decode()` Instead of `verify()` / Accepting `alg: "none"`:**
   * The original JWS specification included an `"alg": "none"` header value for unsecured tokens that already had transport-layer integrity. If a backend library trusts the `"alg"` field supplied inside the untrusted token's header without enforcing an explicit server-side algorithm allowlist, a token with `"alg": "none"` and an empty signature passes validation.
2. **Asymmetric-to-Symmetric Algorithm Confusion (`RS256` to `HS256`):**
   * Suppose a server signs tokens using an asymmetric RSA private key (`RS256`) and distributes its corresponding **RSA Public Key** (`pubkey.pem`) so microservices can verify tokens.
   * If the verification code passes `pubkey.pem` into a generic `jwt.verify(token, pubkey_bytes)` function without explicitly restricting `algorithms=["RS256"]`, and an incoming token header specifies `"alg": "HS256"` (HMAC-SHA256), vulnerable libraries treat the publicly known `pubkey.pem` byte string as a **symmetric HMAC shared secret**!
3. **Weak Symmetric HMAC (`HS256`) Secrets:**
   * Unlike interactive login endpoints, a JWT signature can be tested offline at millions of guesses per second on GPUs if signed with a weak, human-chosen passphrase (e.g., `"secret123"`). Symmetric `HS256` keys must always be generated using a CSPRNG with at least **256 bits (32 bytes)** of entropy (`secrets.token_bytes(32)`).
4. **Dynamic Header Parameter Injection (`jku`, `x5u`, `jwk`, `kid`):**
   * **Untrusted `jku` (JWK Set URL) / `x5u` (X.509 URL) / Embedded `jwk`:** If the server fetches the verification public key dynamically from whatever URL is specified in the untrusted token's `jku`/`x5u` header (or uses a public key embedded directly in the token's `jwk` header), any party can sign a token with their own keypair and point `jku` to their own server (also triggering SSRF).
   * **Unsanitized `kid` (Key ID):** The `kid` header selects which key from a key store to use. If the application concatenates `header['kid']` into a filesystem path (`open(f"/keys/{kid}.pem")`) or a SQL query (`SELECT key FROM keys WHERE id = '${kid}'`), it introduces Path Traversal or SQL Injection prior to authentication.
5. **Missing `aud` (Audience) and `iss` (Issuer) Validation (Cross-Service Token Replay):**
   * In a multi-service enterprise where an Identity Provider (IdP) issues tokens for both `https://hr-app.example.com` and `https://payments-api.example.com`, if `payments-api` verifies the IdP's signature and `exp` timestamp but fails to verify `aud == "https://payments-api.example.com"`, a token issued for the low-privilege `hr-app` can be replayed against `payments-api`.

### 27.5.3 Side-by-Side Comparison: Vulnerable vs. RFC 8725 Compliant JWT Verification (Python `PyJWT`)

```python
# ============================================================================
# VULNERABLE JWT VERIFICATION (DO NOT USE)
# ============================================================================
import jwt

def verify_token_vulnerable(token: str, public_key_pem: bytes) -> dict:
    # FLAW 1: Trusts alg from unverified header -> vulnerable to RS256->HS256 confusion!
    # FLAW 2: Does not validate 'aud' (Audience) or 'iss' (Issuer) claims!
    unverified_header = jwt.get_unverified_header(token)
    payload = jwt.decode(
        token,
        key=public_key_pem,
        algorithms=[unverified_header.get("alg", "RS256")],
    )
    return payload
```

```python
# ============================================================================
# REMEDIATED SECURE JWT VERIFICATION (RFC 8725 Compliant with PyJWT)
# ============================================================================
import re
from typing import Dict, Any
import jwt
from jwt.exceptions import InvalidTokenError

# 1. Hardcoded allowlist of trusted asymmetric public keys mapped by strict Key ID (kid)
TRUSTED_PUBLIC_KEYS: Dict[str, bytes] = {
    "auth-key-2026-q4": b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----",
}

KID_FORMAT_REGEX = re.compile(r"^[a-zA-Z0-9\-]{8,32}$")
EXPECTED_ISSUER = "https://idp.example.com"
EXPECTED_AUDIENCE = "https://api.example.com"


def verify_jwt_rfc8725(token: str) -> Dict[str, Any]:
    # 2. Extract kid safely and validate against strict regex + static dictionary
    try:
        header = jwt.get_unverified_header(token)
    except InvalidTokenError as exc:
        raise PermissionError("Malformed JWT header") from exc

    # Reject tokens containing dynamic key headers (jku, x5u, jwk)
    for forbidden_header in ("jku", "x5u", "jwk", "crit"):
        if forbidden_header in header:
            raise PermissionError(f"Forbidden JOSE header parameter: {forbidden_header}")

    kid = header.get("kid")
    if not isinstance(kid, str) or not KID_FORMAT_REGEX.match(kid):
        raise PermissionError("Invalid or missing Key ID (kid)")

    public_key = TRUSTED_PUBLIC_KEYS.get(kid)
    if public_key is None:
        raise PermissionError("Unknown Key ID (kid)")

    # 3. Verify signature with HARDCODED asymmetric algorithm list (["RS256"])
    #    and enforce mandatory registered claims (exp, iat, nbf, iss, aud, sub, jti)
    try:
        claims = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],  # NEVER derive this list from the token header!
            issuer=EXPECTED_ISSUER,
            audience=EXPECTED_AUDIENCE,
            options={
                "require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
            leeway=10,  # 10-second clock skew tolerance
        )
        return claims
    except InvalidTokenError as exc:
        raise PermissionError("JWT verification failed") from exc
```

---

# Chapter 28: Broken Access Control (IDOR, BOLA, BFLA & Mass Assignment)

## 28.1 Access Control Taxonomy: Horizontal, Vertical & Context-Dependent Authorization

**Broken Access Control** ranks as **#1 in the OWASP Top 10 (2021 - A01)** and **#1/#3/#5 in the OWASP API Security Top 10 (2023 - API1: Broken Object Level Authorization, API3: Broken Object Property Level Authorization, API5: Broken Function Level Authorization)**.

While **Authentication** answers *"Who is making this request?"*, **Authorization (Access Control)** answers *"Is this authenticated principal permitted to perform this specific action on this specific resource with these specific fields right now?"*

```
+-----------------------------------------------------------------------------------+
|                    TAXONOMY OF ACCESS CONTROL VIOLATIONS                          |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  1. Horizontal Privilege Escalation (IDOR / BOLA - OWASP API1:2023):              |
|     User A (Role: Customer) accesses or modifies a resource belonging to          |
|     User B (Role: Customer) by changing an object identifier                      |
|     (e.g., GET /api/v1/statements/10492 -> GET /api/v1/statements/10493).         |
|                                                                                   |
|  2. Vertical Privilege Escalation (BFLA - OWASP API5:2023):                       |
|     User A (Role: Customer) invokes an administrative function or endpoint        |
|     reserved for a higher privilege tier (Role: Administrator)                    |
|     (e.g., POST /api/v1/admin/users/promote or DELETE /api/v1/users/99).          |
|                                                                                   |
|  3. Object Property Level Violation (Mass Assignment / BOPLA - OWASP API3:2023):  |
|     User A updates their own legitimate user record, but includes restricted      |
|     internal model properties in the JSON body                                    |
|     (e.g., PATCH /api/v1/profile {"name": "Alice", "role": "admin", "balance":99})|
|                                                                                   |
|  4. Context-Dependent / Workflow Bypass (CWE-841):                                |
|     User A skips a required business state transition                             |
|     (e.g., calling POST /api/v1/orders/42/confirm-shipment before completing      |
|     the payment state).                                                           |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

## 28.2 Root-Cause Analysis of IDOR / BOLA & Why UUIDs Alone Are Not Authorization

### 28.2.1 Why Replacing Sequential IDs with UUIDv4 Does Not Fix Broken Access Control

A widespread misconception in software engineering is that replacing sequential integer primary keys (`id=1042`) with 128-bit random `UUIDv4` identifiers (`id=550e8400-e29b-41d4-a716-446655440000`) eliminates **Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA)** vulnerabilities.

While UUIDv4 prevents trivial numeric guessing (`1042 -> 1043`), **obscurity is not authorization** (CWE-639):
1. **UUIDs are Routinely Exposed by Design:** In multi-user applications, user IDs, organization IDs, document UUIDs, and order UUIDs appear in shared team rosters, public profile URLs, webhook payloads, browser history, referrer logs, and API list endpoints.
2. **Insecure UUIDv1 (RFC 4122 Time-Based UUIDs):** If an application uses `UUIDv1` instead of `UUIDv4`, the UUID is not random—it is deterministically constructed from the server's 48-bit MAC address, a 14-bit clock sequence, and a 60-bit timestamp.
3. **Parameter Pollution and HTTP Method Switching:** Even when an endpoint checks authorization on `GET /api/v1/invoices/:id`, developers frequently forget to apply the same ownership check on `PUT`, `PATCH`, or `DELETE /api/v1/invoices/:id`, or when a GraphQL query resolves nested child edges (`query { organization(id: "...") { billingRecords { ... } } }`).

### 28.2.2 Architectural Solution: Tenant-Scoped Queries & Policy Enforcement Points

To eliminate BOLA/IDOR structurally, authorization must be enforced at two levels:
1. **Service-Layer Policy Enforcement (RBAC + ABAC):** Verify explicit resource ownership and role permissions before executing business logic.
2. **Data-Layer Scoped Queries / PostgreSQL Row-Level Security (RLS):** Every database query that fetches or mutates a tenant-owned or user-owned record must include the authenticated `user_id` or `tenant_id` directly in the SQL `WHERE` clause (derived from the verified server-side session/JWT—never from client request parameters).

#### Side-by-Side Comparison: Vulnerable vs. Hardened Object-Level & Property-Level Authorization (FastAPI / SQLAlchemy)

```python
# ============================================================================
# VULNERABLE API CONTROLLER (Exhibits BOLA/IDOR + Mass Assignment / BOPLA)
# ============================================================================
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

router = APIRouter()

@router.patch("/api/v1/documents/{doc_id}")
def update_document_vulnerable(
    doc_id: str,
    payload: dict,  # FLAW 2 (BOPLA/Mass Assignment): Accepts arbitrary dict keys!
    current_user=Depends(get_authenticated_user),
    db: Session = Depends(get_db),
):
    # FLAW 1 (BOLA/IDOR): Queries document solely by doc_id without verifying
    # that current_user owns the document or belongs to the document's tenant!
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    # FLAW 2: Blindly copies all client-supplied JSON keys onto the ORM model
    # (allows overwriting owner_id, tenant_id, is_confidential, etc.)
    for key, value in payload.items():
        setattr(doc, key, value)

    db.commit()
    return doc  # FLAW 3: Returns raw ORM entity exposing internal columns
```

```python
# ============================================================================
# REMEDIATED SECURE API CONTROLLER (Enforces BOLA, BFLA, and BOPLA Protection)
# ============================================================================
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

router = APIRouter()

# 1. Strict Input DTO (Prevents Mass Assignment / BOPLA):
#    Only title and content can ever be modified by the client; extra fields rejected.
class DocumentUpdateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=200)
    content: str = Field(..., max_length=50000)


# 2. Strict Output DTO (Prevents Excessive Data Exposure):
#    Explicitly defines which fields are serialized back to the client.
class DocumentResponseOutput(BaseModel):
    id: str
    title: str
    content: str
    updated_at: str


@router.patch(
    "/api/v1/documents/{doc_id}",
    response_model=DocumentResponseOutput,
    status_code=status.HTTP_200_OK,
)
def update_document_secure(
    doc_id: str,
    update_dto: DocumentUpdateInput,
    current_user=Depends(get_authenticated_user),
    db: Session = Depends(get_db),
):
    # 3. Function-Level Authorization (BFLA Check):
    if "documents:write" not in current_user.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to modify documents",
        )

    # 4. Object-Level Authorization (BOLA Check):
    #    Scope the SQL query directly by BOTH doc_id AND authenticated tenant_id/owner_id
    stmt = select(Document).where(
        Document.id == doc_id,
        Document.tenant_id == current_user.tenant_id,
        Document.owner_id == current_user.id,
    )
    doc = db.execute(stmt).scalar_one_or_none()

    if doc is None:
        # Return 404 (not 403) so unauthorized callers cannot probe whether doc_id exists
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    # 5. Explicitly update only approved attributes from validated DTO
    doc.title = update_dto.title
    doc.content = update_dto.content
    db.commit()
    db.refresh(doc)

    return DocumentResponseOutput(
        id=str(doc.id),
        title=doc.title,
        content=doc.content,
        updated_at=doc.updated_at.isoformat(),
    )
```

---

## 28.3 Database-Enforced Multi-Tenancy: PostgreSQL Row-Level Security (RLS)

In multi-tenant SaaS architectures, relying solely on developers to remember `.where(Model.tenant_id == current_user.tenant_id)` on every query across hundreds of microservices is error-prone. **PostgreSQL Row-Level Security (RLS)** provides a powerful defense-in-depth guarantee at the database engine layer: even if an application developer forgets a `WHERE` filter in a query, PostgreSQL automatically filters out any row that does not match the current database session's `app.current_tenant_id` context variable.

```sql
-- PostgreSQL Row-Level Security (RLS) Defense-in-Depth Configuration
-- 1. Enable RLS on the multi-tenant table (and enforce it even for the table owner)
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

-- 2. Create a strict tenant isolation policy
CREATE POLICY tenant_isolation_policy ON documents
    AS RESTRICTIVE
    FOR ALL
    TO app_backend_role
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
```

At the start of every HTTP request transaction, the application middleware binds the authenticated user's `tenant_id` to the transaction-local PostgreSQL setting:
```sql
SET LOCAL app.current_tenant_id = '550e8400-e29b-41d4-a716-446655440000';
```

---

## 28.4 Automated Authorization Matrix Verification in CI/CD & Proxy Workflows

### 28.4.1 Using Burp `Autorize` During Interactive Security Assessments

During manual or semi-automated DAST assessments, security engineers use the **Autorize** extension in Burp Suite to systematically verify access controls across every endpoint:
1. The auditor configures **Autorize** with the session header (`Authorization: Bearer <low_privilege_user_b_token>` or `Cookie: __Host-sid=<user_b>`) belonging to a lower-privileged user (User B, or an unauthenticated session).
2. The auditor browses the application normally as **User A (Administrator or Resource Owner)**.
3. For every request sent by User A, Autorize automatically replays the request in the background twice:
   - **Modified Session Replay:** Replaces User A's session token with User B's token (testing Horizontal BOLA and Vertical BFLA).
   - **Unauthenticated Replay:** Strips the session token completely (testing missing authentication).
4. Autorize compares the HTTP status code, response length, and JSON structure against enforcement rules and flags any endpoint where User B receives a `200 OK` containing User A's data.

### 28.4.2 Automated Authorization Matrix Testing in CI/CD (Python `pytest`)

Rather than waiting for manual penetration tests to catch broken access control, engineering teams codify an **Automated Authorization Matrix Test Suite** that runs on every Pull Request:

```python
"""
test_authorization_matrix.py
Automated CI/CD Authorization Matrix Verification Suite.
Verifies that every protected API route enforces Unauthenticated, Cross-Tenant (BOLA),
and Role-Based (BFLA) access controls.
"""

import pytest

# Declarative Authorization Matrix:
# (HTTP Method, Path Template, Required Role, Expected Status for Cross-Tenant User B)
AUTHORIZATION_MATRIX = [
    ("GET",    "/api/v1/documents/{user_a_doc_id}",   "member", 404),
    ("PATCH",  "/api/v1/documents/{user_a_doc_id}",   "member", 404),
    ("DELETE", "/api/v1/documents/{user_a_doc_id}",   "member", 404),
    ("POST",   "/api/v1/admin/tenants/suspend",       "admin",  403),
    ("GET",    "/api/v1/admin/audit-logs",            "admin",  403),
]


@pytest.mark.parametrize("method,path_template,required_role,expected_bola_status", AUTHORIZATION_MATRIX)
def test_endpoint_access_control_matrix(
    test_client,
    seeded_fixtures,
    method: str,
    path_template: str,
    required_role: str,
    expected_bola_status: int,
):
    path = path_template.format(user_a_doc_id=seeded_fixtures.user_a_doc_id)

    # 1. Verify Unauthenticated Request is Rejected (401 Unauthorized)
    unauth_resp = test_client.request(method, path)
    assert unauth_resp.status_code == 401, (
        f"Unauthenticated access permitted on {method} {path}!"
    )

    # 2. Verify Horizontal / Vertical Isolation using User B (Standard Member in Tenant B)
    user_b_headers = {"Authorization": f"Bearer {seeded_fixtures.user_b_member_jwt}"}
    bola_resp = test_client.request(method, path, headers=user_b_headers, json={})
    assert bola_resp.status_code == expected_bola_status, (
        f"Access control violation on {method} {path}: "
        f"expected {expected_bola_status}, got {bola_resp.status_code}"
    )
```


---

# Chapter 29: Server-Side Request Forgery (SSRF), XML External Entities (XXE), Path Traversal & File Upload Security

## 29.1 Server-Side Request Forgery (SSRF - OWASP A10:2021 / CWE-918)

**Server-Side Request Forgery (SSRF)** occurs when a web application accepts a URL or hostname from a client and uses its backend server-side HTTP client (`urllib`, `requests`, `axios`, `fetch`, `HttpClient`, `curl`) to make an outbound network request without strictly validating the target destination, protocol scheme, and resolved IP address.

### 29.1.1 Why SSRF Is Critical in Cloud and Container Environments

Because the backend application server resides inside the trusted corporate VPC or Kubernetes cluster, an unrestricted outbound HTTP client allows an external caller to pivot through the application server to reach internal resources that are inaccessible from the public Internet:

```
+-----------------------------------------------------------------------------------+
|               SERVER-SIDE REQUEST FORGERY (SSRF) TRUST BOUNDARY VIOLATION         |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [External Client]                                                                |
|         |                                                                         |
|         |  POST /api/v1/webhooks/test                                             |
|         |  {"webhook_url": "http://<internal-target>/..."}                        |
|         v                                                                         |
|  +------------------------------+      1. Cloud Instance Metadata Service (IMDS)  |
|  | Public Application Server    | ------> 169.254.169.254 (Link-Local Metadata)   |
|  | (Inside Private Cloud VPC)   |                                                 |
|  |                              |      2. Internal VPC Microservices & Caches     |
|  | Outbound HTTP Client makes   | ------> 10.0.x.x:8080 / 127.0.0.1:6379          |
|  | request from trusted network |                                                 |
|  +------------------------------+      3. Kubernetes Internal Service Mesh        |
|                                   ------> kubernetes.default.svc.cluster.local    |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### 29.1.2 Cloud Instance Metadata Services (IMDSv1 vs. IMDSv2)

Cloud providers expose an **Instance Metadata Service (IMDS)** on the link-local IPv4 address **`169.254.169.254`** (and `fd00:ec2::254` on IPv6) so virtual machines can retrieve instance configuration and temporary IAM role credentials:

1. **Why AWS IMDSv1 Was Vulnerable to SSRF:**
   * IMDSv1 used simple, stateless `GET` requests (`http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`). Any SSRF vulnerability capable of issuing a `GET` request (including image fetchers, PDF generators, or open redirects) could read temporary AWS IAM `AccessKeyId`, `SecretAccessKey`, and `Token` credentials attached to the EC2 instance profile.
2. **How AWS IMDSv2 (Session-Oriented Metadata) Defends Against SSRF:**
   * **IMDSv2** requires the client to first issue an HTTP **`PUT`** request to `/latest/api/token` containing a custom header `X-aws-ec2-metadata-token-ttl-seconds: 21600`, and then pass the returned token in the `X-aws-ec2-metadata-token` header on subsequent `GET` requests.
   * Furthermore, IMDSv2 sets the IP packet **Time-to-Live (TTL) / Hop Limit to `1`** on the response (`http_put_response_hop_limit = 1`) and rejects `PUT` requests containing an `X-Forwarded-For` header, preventing simple `GET`-only SSRFs and reverse-proxy forwarding from obtaining metadata tokens.
3. **GCP and Azure Metadata Hardening:**
   * **Google Cloud Platform** (`metadata.google.internal` / `169.254.169.254`) requires the custom request header `Metadata-Flavor: Google` and forbids `X-Forwarded-For`.
   * **Microsoft Azure** (`169.254.169.254/metadata/instance`) requires the custom request header `Metadata: true` and forbids `X-Forwarded-For`.

#### Enforcing AWS IMDSv2 Mandatory Mode in Terraform

```hcl
# Hardened AWS EC2 Instance Configuration Enforcing IMDSv2 Strictly
resource "aws_instance" "hardened_app_node" {
  ami           = var.hardened_ami_id
  instance_type = "t3.large"
  subnet_id     = aws_subnet.private_app.id

  metadata_options {
    http_endpoint               = "enabled"
    # Disables IMDSv1 completely; requires session-oriented IMDSv2 PUT token
    http_tokens                 = "required"
    # Hop limit of 1 prevents container-bridged forwarding
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }
}
```

### 29.1.3 Why Naive String Blacklists Fail to Prevent SSRF

Attempting to prevent SSRF by matching the URL string against a regex blacklist (e.g., blocking `"localhost"` and `"127.0.0.1"`) fails due to four fundamental network and parser behaviors:

1. **Alternative IP Address Representations:** Standard BSD socket parsers (`inet_aton`) and URL libraries accept loopback and private IPv4 addresses in alternative numerical bases (such as 32-bit decimal integer, hexadecimal, octal, or IPv6-mapped IPv4 `::ffff:127.0.0.1`).
2. **External Wildcard DNS Services:** Public domains can hold `A` or `AAAA` records resolving to internal RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or loopback (`127.0.0.0/8`) IP addresses.
3. **HTTP Redirect Following (`301`/`302`/`307`):** If the HTTP client validates the initial URL (`https://public-site.example/webhook`) as safe, but automatically follows an HTTP `302 Found` redirect (`Location: http://169.254.169.254/...`) without re-validating the redirect target, the second hop reaches the internal network.
4. **DNS Rebinding (Time-of-Check to Time-of-Use / TOCTOU):** If the application resolves the hostname first (receiving a public IP with `TTL=0` that passes validation) and then passes the hostname to `requests.get(url)`, which performs a *second* DNS lookup that returns an internal IP (`127.0.0.1`), the connection is made to the internal IP.

### 29.1.4 Defense-in-Depth SSRF Remediation: Socket-Level IP Validation & Egress Proxies

To eliminate SSRF vulnerabilities in application code that *must* fetch user-supplied URLs (such as webhook delivery engines or OpenGraph link previewers):

1. **Strict Scheme & Port Allowlist:** Permit only `https://` (or `http://` if explicitly required) on port `443` (and `80`). Reject `file://`, `gopher://`, `dict://`, `ftp://`, and non-standard ports.
2. **Disable Automatic Redirects (`allow_redirects=False`):** Either reject redirects outright or manually validate each `Location` target through the exact same SSRF validator up to a max depth of 3 hops.
3. **Resolve Once and Connect to the Verified IP (Preventing DNS Rebinding):** Resolve the hostname via `socket.getaddrinfo()`, verify every returned IPv4/IPv6 address using `ipaddress.ip_address(ip).is_global` (rejecting loopback, private RFC 1918, link-local `169.254.0.0/16`, multicast, and unspecified ranges), and bind the socket directly to the verified IP while preserving TLS SNI.
4. **Network-Layer Isolation (Dedicated Egress Proxy / Smokescreen):** Route all untrusted outbound webhook traffic through a dedicated egress proxy (such as Stripe's `smokescreen`) placed in an isolated DMZ subnet that has **zero network routing path** to internal VPC subnets or cloud metadata endpoints.

#### Production-Grade SSRF-Safe URL Validator & Socket Guard (Python)

```python
#!/usr/bin/env python3
"""
ssrf_safe_client.py
Production-grade SSRF prevention module in Python.
Enforces strict scheme/port allowlists, disables automatic redirects, and validates
resolved IPv4/IPv6 addresses against all non-global ranges (RFC 1918, Loopback,
Link-Local 169.254.0.0/16, CGNAT, and IPv6 equivalents).
"""

import ipaddress
import socket
import urllib.parse
from typing import Tuple, List

ALLOWED_SCHEMES = {"https"}
ALLOWED_PORTS = {443}


class SSRFPolicyViolationError(PermissionError):
    """Raised when a target URL or resolved IP violates outbound SSRF security policy."""


def is_publicly_routable_ip(ip_str: str) -> bool:
    """
    Returns True ONLY if the IP address is a globally routable public unicast IP.
    Strictly rejects loopback (127.0.0.0/8, ::1), private (10/8, 172.16/12, 192.168/16, fc00::/7),
    link-local / cloud IMDS (169.254.0.0/16, fe80::/10), multicast, reserved, and IPv4-mapped private IPs.
    """
    addr = ipaddress.ip_address(ip_str)

    # Unwrap IPv6-mapped IPv4 addresses (e.g., ::ffff:127.0.0.1)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    return (
        addr.is_global
        and not addr.is_private
        and not addr.is_loopback
        and not addr.is_link_local
        and not addr.is_multicast
        and not addr.is_reserved
        and not addr.is_unspecified
    )


def validate_and_resolve_outbound_url(raw_url: str) -> Tuple[str, int, List[str]]:
    """
    Parses a candidate URL, validates scheme and port, resolves DNS records once,
    and verifies that EVERY resolved IP address is globally routable.
    """
    parsed = urllib.parse.urlsplit(raw_url)

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise SSRFPolicyViolationError(f"Disallowed URL scheme: {parsed.scheme}")

    if parsed.username or parsed.password:
        raise SSRFPolicyViolationError("URL userinfo credentials are not permitted")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFPolicyViolationError("Missing hostname in URL")

    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise SSRFPolicyViolationError(f"Disallowed destination port: {port}")

    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFPolicyViolationError("DNS resolution failed for target host") from exc

    resolved_ips = sorted({item[4][0] for item in addr_info})
    if not resolved_ips:
        raise SSRFPolicyViolationError("No IP addresses resolved for target host")

    for ip_str in resolved_ips:
        if not is_publicly_routable_ip(ip_str):
            raise SSRFPolicyViolationError(
                f"Target hostname resolved to non-public IP address: {ip_str}"
            )

    return hostname, port, resolved_ips
```

---

## 29.2 XML External Entity (XXE) Injection (OWASP A05:2021 / CWE-611)

### 29.2.1 How XML Document Type Definitions (DTDs) & External Entities Work

The Extensible Markup Language (XML 1.0 specification) supports **Document Type Definitions (`<!DOCTYPE ...>`)**, which allow XML documents to define reusable macros called **Entities (`<!ENTITY name "value">`)**.

In addition to internal text entities, the XML standard defined **External Entities** using the `SYSTEM` or `PUBLIC` keywords (`<!ENTITY ext SYSTEM "URI">`), which instruct a legacy XML parser to dereference an external URI (such as `file:///...` on the local filesystem or `http://...` on the internal network) and substitute the fetched content directly into the parsed XML tree.

```
+-----------------------------------------------------------------------------------+
|               XML EXTERNAL ENTITY (XXE) PARSER ROOT-CAUSE MECHANICS               |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  1. Untrusted XML Input arrives via SOAP API, SAML assertion, SVG image upload,   |
|     or Office Open XML (.docx / .xlsx / .pptx ZIP archive containing XML files).  |
|                                                                                   |
|  2. Vulnerable XML Parser Configuration:                                          |
|     - DTD Processing (DOCTYPE) is enabled                                         |
|     - External General Entities & External Parameter Entities are enabled         |
|     - XInclude / XSLT external document resolution is enabled                     |
|                                                                                   |
|  3. Risks if Unhardened:                                                          |
|     - Arbitrary Local File Disclosure via file:// URI resolution                  |
|     - Server-Side Request Forgery (SSRF) via http:// / https:// URI resolution    |
|     - Denial of Service via Recursive Entity Expansion ("Billion Laughs" CWE-776) |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

> **Hidden XML Attack Surfaces:** Many developers assume their application does not parse XML because their APIs use JSON. However, XML parsers are invoked implicitly whenever a backend processes:
> - **SVG Images (`.svg`):** Scalable Vector Graphics are pure XML documents.
> - **Office Documents (`.docx`, `.xlsx`, `.pptx`):** ZIP archives containing `word/document.xml`, `[Content_Types].xml`, etc.
> - **SAML 2.0 Single Sign-On Assertions** and **SOAP / XML-RPC integrations**.
> - **RSS / Atom Feeds** and **PDF metadata (XMP)**.

### 29.2.2 Multi-Language Remediation: Disabling DTDs and External Entities

According to the **OWASP XML External Entity Prevention Cheat Sheet**, the definitive defense against both XXE (`CWE-611`) and Recursive Entity Expansion (`CWE-776`) is to **completely disallow `DOCTYPE` declarations (`disallow-doctype-decl`)** or use a safe-by-default parser wrapper (`defusedxml` in Python).

#### 1. Python (`lxml` vs. `defusedxml`)

```python
# ============================================================================
# VULNERABLE PYTHON XML PARSING (lxml.etree default resolve_entities=True)
# ============================================================================
from lxml import etree

def parse_xml_invoice_vulnerable(xml_bytes: bytes):
    # FLAW: Default XMLParser in older lxml configurations resolves external entities!
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
    root = etree.fromstring(xml_bytes, parser=parser)
    return root.findtext("invoice_total")
```

```python
# ============================================================================
# REMEDIATED SECURE PYTHON XML PARSING (defusedxml & Hardened lxml.etree)
# ============================================================================
import defusedxml.ElementTree as SafeET
from lxml import etree

# Approach A (Recommended): Use defusedxml, which blocks DTDs, external entities,
# and recursive entity expansion by default.
def parse_xml_invoice_defused(xml_bytes: bytes) -> str:
    root = SafeET.fromstring(
        xml_bytes,
        forbid_dtd=True,
        forbid_entities=True,
        forbid_external=True,
    )
    return root.findtext("invoice_total", default="0.00")


# Approach B: Explicitly hardened lxml.etree.XMLParser configuration
def parse_xml_invoice_hardened_lxml(xml_bytes: bytes) -> str:
    safe_parser = etree.XMLParser(
        resolve_entities=False,  # Never resolve entities
        no_network=True,         # Forbid all network access from parser
        dtd_validation=False,    # Disable DTD validation
        load_dtd=False,          # Do not load external DTDs
        huge_tree=False,         # Protect against XML memory exhaustion
    )
    root = etree.fromstring(xml_bytes, parser=safe_parser)
    return root.findtext("invoice_total") or "0.00"
```

#### 2. Java (`DocumentBuilderFactory` / `SAXParserFactory` / `XMLInputFactory`)

```java
// ============================================================================
// REMEDIATED SECURE JAVA XML PARSER CONFIGURATION (OWASP Gold Standard)
// ============================================================================
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public final class SecureXmlFactory {
    private SecureXmlFactory() {}

    public static DocumentBuilder createSecureDocumentBuilder()
            throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        // 1. Primary Defense: Completely disallow DOCTYPE declarations
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        // 2. Defense-in-Depth: Disable External General & Parameter Entities
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

        // 3. Disable XInclude and entity reference expansion
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);

        // 4. Enable JAXP Secure Processing & restrict external protocols
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

        return dbf.newDocumentBuilder();
    }
}
```

---

## 29.3 OS Command Injection (CWE-78) Root-Cause Analysis & Elimination

**OS Command Injection (CWE-78)** occurs when an application passes user-controlled input into a function that invokes an operating system command shell (`/bin/sh -c` on Linux/macOS or `cmd.exe /c` on Windows)—such as Python's `os.system()` or `subprocess.run(..., shell=True)`, Node.js `child_process.exec()`, or PHP's `exec()` / `system()` / `shell_exec()`.

### 29.3.1 Why `shell=True` / `child_process.exec()` Is Inherently Dangerous

When an application spawns a subshell (`sh -c "convert input.png output.jpg"`), the POSIX shell parses the command string for shell control operators (`;`, `|`, `||`, `&`, `&&`, `$()`, `` ` ``, `>`, `<`, and newline `\n`). Attempting to strip or escape shell metacharacters with regular expressions is brittle and error-prone.

### 29.3.2 Architectural Remediation: Native Libraries & Parameterized `execve` Argument Arrays

1. **Use Native Language Libraries Instead of Shell Commands:**
   * Instead of shelling out to `ping`, `curl`, `tar`, `zip`, or `openssl`, use native in-process libraries (`urllib`/`httpx`, Python `tarfile`/`zipfile`, `cryptography`).
2. **Pass Arguments as an Array Without a Shell (`shell=False` / `execFile`):**
   * When invoking an external binary is unavoidable (e.g., `ffmpeg` or `wkhtmltopdf`), use OS `execve()` wrappers (`subprocess.run([binary, arg1, arg2], shell=False)` in Python or `child_process.execFile()` in Node.js). When `shell=False` is used, the OS kernel passes the `argv` array directly to the target binary **without invoking `/bin/sh`**, so characters like `;` or `$()` are never interpreted as shell syntax.
3. **Prevent Argument/Flag Injection (`CWE-88`):**
   * Even with `shell=False`, if a user-supplied filename starts with a hyphen (`-o` or `--config=...`), the target CLI binary itself may interpret the string as a command-line option flag! Always validate input against a strict allowlist regex AND insert the POSIX `--` end-of-options delimiter before positional arguments.

#### Side-by-Side Comparison: Vulnerable vs. Remediated Process Execution (Python & Node.js)

```python
# ============================================================================
# VULNERABLE PYTHON SUBPROCESS CODE (DO NOT USE)
# ============================================================================
import subprocess

def verify_domain_dns_vulnerable(domain: str) -> str:
    # FLAW: shell=True invokes /bin/sh -c and interprets shell control characters!
    result = subprocess.run(
        f"dig +short A {domain}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
```

```python
# ============================================================================
# REMEDIATED SECURE PYTHON SUBPROCESS CODE (Strict Regex + shell=False + "--")
# ============================================================================
import re
import subprocess

STRICT_DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def verify_domain_dns_secure(domain: str) -> str:
    # 1. Validate input strictly against a narrow syntactic allowlist
    if not STRICT_DOMAIN_REGEX.match(domain):
        raise ValueError("Invalid domain name format")

    # 2. Pass arguments as a discrete list with shell=False (invokes execve directly,
    #    never spawning /bin/sh) and enforce a strict execution timeout.
    result = subprocess.run(
        ["/usr/bin/dig", "+short", "A", "--", domain],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    return result.stdout
```

---

## 29.4 Path Traversal & Local File Inclusion (CWE-22) Prevention

**Path Traversal (CWE-22)** occurs when an application uses user-controlled input to construct a filesystem path (`open(f"/var/app/reports/{filename}")`) without canonicalizing the path and verifying that the resolved path stays strictly inside the intended base directory.

### 29.4.1 Why Stripping `"../"` (`str.replace("../", "")`) Fails

A common anti-pattern is attempting to sanitize filenames by running a single non-recursive replacement `filename.replace("../", "")`.
- If an input contains nested sequences (`....//`), removing the inner `../` leaves behind a valid `../` sequence!
- Furthermore, symlink traversal or OS-specific path separators (`\` on Windows) can escape directories even without `../` if the real canonical path is not verified.

### 29.4.2 Canonical Path Verification (`Path.resolve()` + `is_relative_to()`)

To read files from a local directory safely:
1. **Best Practice (Indirect Reference Map):** Never pass filenames from the client at all; pass a database UUID (`report_id`) and look up the immutable storage key in the database.
2. **Canonical Path Boundary Verification:** If a filename must be accepted, extract only the basename (`os.path.basename`), resolve the full canonical path on disk (`Path.resolve()`, which resolves all `..` segments and symbolic links), and verify that the resolved path is strictly inside the base directory using `resolved_path.is_relative_to(base_dir)`.

```python
# ============================================================================
# REMEDIATED SECURE FILE DOWNLOAD HANDLER (Canonical Path Containment Check)
# ============================================================================
import re
from pathlib import Path

BASE_REPORTS_DIR = Path("/var/app/storage/reports").resolve()
SAFE_FILENAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,64}\.pdf$")


def read_report_file_secure(requested_filename: str) -> bytes:
    # 1. Validate against strict alphanumeric + .pdf regex (rejects slashes and dots)
    if not SAFE_FILENAME_REGEX.match(requested_filename):
        raise PermissionError("Invalid report filename format")

    # 2. Construct candidate path and resolve all symlinks and relative segments
    candidate_path = (BASE_REPORTS_DIR / requested_filename).resolve()

    # 3. Verify canonical path is strictly inside BASE_REPORTS_DIR
    if not candidate_path.is_relative_to(BASE_REPORTS_DIR):
        raise PermissionError("Path traversal attempt blocked")

    if not candidate_path.is_file():
        raise FileNotFoundError("Requested report does not exist")

    return candidate_path.read_bytes()
```

---

## 29.5 Architecture of Secure File Upload & Archive Extraction Systems

File upload functionality introduces multiple high-severity risks if uploaded files are stored inside the web root or processed unsafely:
1. **Server-Side Code Execution:** Uploading an executable script (`.php`, `.jsp`, `.aspx`, `.py`) or server configuration override (`.htaccess`, `.user.ini`, `web.config`) into a directory where the web server executes scripts.
2. **Stored XSS via Active Content Types:** Uploading `.html`, `.svg` (which can contain `<script onload="...">`), or `.xml` files that are served back from the main application origin with `Content-Type: text/html` or `image/svg+xml`.
3. **Archive Extraction Traversal ("Zip Slip" - CWE-22):** Extracting a `.zip` or `.tar.gz` archive containing entries with `../../` filenames using `zipfile.extractall()`, overwriting files outside the target extraction folder.

### 29.5.1 Seven-Layer Defense-in-Depth for File Uploads

```
+-----------------------------------------------------------------------------------+
|                   SECURE FILE UPLOAD & STORAGE ARCHITECTURE                       |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  1. Size & Rate Limit at Edge Gateway (e.g., client_max_body_size 10m;).          |
|  2. Never Use Client-Supplied Filename: Generate a fresh UUIDv4 storage key.      |
|  3. Strict Extension + Magic Byte / File Parser Validation (e.g., Pillow/libvips).|
|  4. Strip EXIF Metadata & Re-encode Images into a Fresh Buffer.                   |
|  5. Store Outside the Web Root (Ideally in Private Cloud Object Storage / S3).    |
|  6. Serve User Uploads from a Separate Sandbox Domain (e.g., example-usercontent) |
|     with Content-Disposition: attachment and X-Content-Type-Options: nosniff.     |
|  7. Scan Asynchronously with Antivirus / Malware Sandbox (ClamAV / GuardDuty).    |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### 29.5.2 Remediating "Zip Slip" During Archive Extraction (Python)

Never call `zipfile.ZipFile.extractall()` or `tarfile.TarFile.extractall()` on untrusted archives without validating every member's canonical destination path first (or in Python 3.12+, enforcing `filter="data"` on `tarfile`):

```python
import zipfile
from pathlib import Path

MAX_EXTRACTED_TOTAL_BYTES = 50 * 1024 * 1024  # 50 MiB limit against Zip Bombs
MAX_ARCHIVE_FILES = 100


def safe_extract_zip(zip_path: Path, destination_dir: Path) -> None:
    """
    Safely extracts a ZIP archive while preventing both Zip Slip (path traversal)
    and Zip Bomb (decompression exhaustion) attacks.
    """
    dest_root = destination_dir.resolve()
    dest_root.mkdir(parents=True, exist_ok=True)

    total_uncompressed_bytes = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        members = zf.infolist()
        if len(members) > MAX_ARCHIVE_FILES:
            raise ValueError("Archive exceeds maximum allowed file count")

        for member in members:
            # 1. Check cumulative uncompressed size to block Zip Bombs
            total_uncompressed_bytes += member.file_size
            if total_uncompressed_bytes > MAX_EXTRACTED_TOTAL_BYTES:
                raise ValueError("Archive exceeds maximum uncompressed size limit")

            # 2. Reject symlinks inside ZIP archives (POSIX S_IFLNK = 0o120000)
            if (member.external_attr >> 16) & 0o170000 == 0o120000:
                raise PermissionError("Symbolic links inside archives are forbidden")

            # 3. Canonicalize target path and verify containment inside dest_root
            target_path = (dest_root / member.filename).resolve()
            if not target_path.is_relative_to(dest_root):
                raise PermissionError(
                    f"Zip Slip traversal blocked on entry: {member.filename}"
                )

            if member.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
            else:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member, "r") as src, open(target_path, "wb") as dst:
                    dst.write(src.read())
```

---

# Chapter 30: Template Engine Security & Safe Data Serialization

## 30.1 Server-Side Template Injection (SSTI - CWE-1336): Root Cause & Prevention

Web applications use **Server-Side Template Engines**—such as **Jinja2** and **Mako** (Python), **Twig** and **Smarty** (PHP), **Freemarker**, **Velocity**, and **Thymeleaf** (Java), **Handlebars** and **Pug/EJS** (Node.js), and **ERB** (Ruby)—to render dynamic HTML pages or emails by merging a static template file with a data context dictionary.

### 30.1.1 Why Concatenating Input into a Template String Causes SSTI

A **Server-Side Template Injection (SSTI, CWE-1336)** vulnerability occurs when a developer mistakenly concatenates user-controlled input **directly into the template source string itself** prior to compilation, rather than passing the user input as a **named variable inside the template rendering context**.

```
+-----------------------------------------------------------------------------------+
|               TEMPLATE ENGINE COMPILATION: SSTI VS. SAFE CONTEXT BINDING          |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  VULNERABLE PATTERN (User input concatenated into Template Source):               |
|    template_str = f"<h1>Hello {user_input}</h1>"                                  |
|    render_template_string(template_str)                                           |
|    -> Template Lexer parses {{ ... }} or {% ... %} inside user_input as           |
|       executable template expressions!                                            |
|                                                                                   |
|  SECURE PATTERN (Static Template + Bound Data Context + Autoescape):              |
|    template = env.get_template("greeting.html")   # Static: <h1>Hello {{name}}</h1>|
|    template.render(name=user_input)                                               |
|    -> user_input is treated strictly as a string variable, never compiled as      |
|       template syntax, and HTML-escaped automatically!                            |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### 30.1.2 Side-by-Side Comparison: Vulnerable vs. Remediated Jinja2 Template Rendering (Python)

```python
# ============================================================================
# VULNERABLE PYTHON / JINJA2 CODE (DO NOT USE)
# ============================================================================
from jinja2 import Template

def render_email_preview_vulnerable(customer_name: str, order_total: str) -> str:
    # FLAW 1: Python f-string injects untrusted customer_name directly into
    # the Jinja2 template source before Template() compiles it -> SSTI!
    # FLAW 2: Direct Template() constructor has autoescape=False by default -> XSS!
    raw_template = f"""
        <html>
          <body>
            <p>Dear {customer_name},</p>
            <p>Your invoice total is {{{{ order_total }}}}.</p>
          </body>
        </html>
    """
    return Template(raw_template).render(order_total=order_total)
```

```python
# ============================================================================
# REMEDIATED SECURE PYTHON / JINJA2 CODE (Static Template + Autoescape)
# ============================================================================
from jinja2 import Environment, select_autoescape
from jinja2.sandbox import SandboxedEnvironment

# 1. Configure Jinja2 Environment with mandatory HTML/XML autoescaping
jinja_env = Environment(
    autoescape=select_autoescape(["html", "htm", "xml"], default_for_string=True, default=True)
)

STATIC_EMAIL_TEMPLATE = jinja_env.from_string(
    """
    <html>
      <body>
        <p>Dear {{ customer_name }},</p>
        <p>Your invoice total is {{ order_total }}.</p>
      </body>
    </html>
    """
)


def render_email_preview_secure(customer_name: str, order_total: str) -> str:
    # SECURE: Template AST is pre-compiled from a static string.
    # customer_name and order_total are bound strictly as context variables.
    return STATIC_EMAIL_TEMPLATE.render(
        customer_name=customer_name,
        order_total=order_total,
    )
```

### 30.1.3 What If Business Requirements Demand User-Editable Email/Report Templates?

In certain B2B SaaS platforms (such as marketing automation or invoice customization tools), tenant administrators are intentionally allowed to edit email HTML templates containing placeholder variables (`{{ customer_first_name }}`).
If user-authored templates are a business requirement:
1. **Use a Logic-Less Template Engine (`Mustache`):** Unlike Jinja2, Freemarker, or Velocity (which expose full object-oriented reflection or Turing-complete programming constructs), **Mustache** is strictly *logic-less* by specification—it contains no `if/else` statements, no arbitrary method calls, and no object graph traversal.
2. **Enforce Sandboxed Execution (`SandboxedEnvironment` / ` TemplateClassResolver.SAFER_RESOLVER`):** If Freemarker (Java) is used, always set `cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER)` so templates cannot instantiate Java classes (`?new()`).

---

## 30.2 Insecure Deserialization (OWASP A08:2021 / CWE-502): Mechanics & Safe Alternatives

**Serialization** is the process of converting an in-memory object graph or data structure into a linear byte stream or text format (for storage in a cache, transmission over a network, or persistence in a cookie). **Deserialization** is the reverse process of reconstructing the in-memory object from that byte stream.

### 30.2.1 Why Native Object Serializers Are Unsafe on Untrusted Data

Many programming languages include native binary or text serialization formats designed to serialize **arbitrary runtime classes and executable object graphs** rather than pure data structures:

| Language / Ecosystem | Unsafe Native Deserializer | Root Cause of Vulnerability (CWE-502) | Safe Data-Only Alternative |
| :--- | :--- | :--- | :--- |
| **Python** | `pickle.loads()`, `cPickle`, `dill`, `shelve`, `torch.load()` (default), `yaml.load()` (`Loader= yaml.Loader`) | `pickle` is a stack-based virtual machine (`REDUCE` opcode) that imports any Python module and invokes arbitrary callables during reconstruction. `PyYAML` `yaml.load()` supports `!!python/object/apply:` tags. | `json.loads()` + `Pydantic` validation; `yaml.safe_load()`; `safetensors` for ML model weights |
| **PHP** | `unserialize()` (including `phar://` stream metadata) | Reconstructs arbitrary PHP classes in scope and automatically triggers lifecycle **Magic Methods** (`__wakeup()`, `__destruct()`, `__toString()`) before validation occurs. | `json_decode($data, true)` with JSON Schema validation |
| **Java / JVM** | `ObjectInputStream.readObject()`, `XMLDecoder`, `XStream` (unconfigured), `SnakeYAML` default `Constructor` | Streams beginning with magic bytes `0xACED0005` (`rO0AB` in Base64) invoke `readObject()` across any `Serializable` class on the classpath (**Gadget Chains**). | `Jackson` / `Gson` (with Polymorphic Default Typing disabled) or **Protocol Buffers (Protobuf)** + Java `ObjectInputFilter` (JEP 290) |
| **Node.js** | `node-serialize`, `cryo`, `js-yaml` (v3 `.load()`) | Allows serialized functions (`_$$ND_FUNC$$_`) or Immediately Invoked Function Expressions (IIFE) to execute during property hydration. | `JSON.parse()` + `Zod` / `Ajv` schema validation; `js-yaml` v4+ (safe by default) |
| **.NET (C#)** | `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter`, `SoapFormatter` | Reconstructs arbitrary `.NET` types (`TypeNameHandling.All` in `Json.NET`), invoking setter properties during instantiation. | `System.Text.Json` with explicit DTO types |

---

## 30.3 Multi-Language Code Remediation for Safe Deserialization

### 30.3.1 Python: Replacing `pickle` and Unsafe `yaml.load()` with `yaml.safe_load()` & Pydantic

```python
# ============================================================================
# VULNERABLE PYTHON DESERIALIZATION CODE (DO NOT USE)
# ============================================================================
import pickle
import yaml

def load_session_cache_vulnerable(raw_bytes: bytes) -> dict:
    # FLAW 1: pickle.loads() executes arbitrary bytecode instructions!
    return pickle.loads(raw_bytes)

def parse_config_yaml_vulnerable(yaml_text: str) -> dict:
    # FLAW 2: yaml.unsafe_load / yaml.Loader permits !!python/object instantiation!
    return yaml.load(yaml_text, Loader=yaml.Loader)
```

```python
# ============================================================================
# REMEDIATED SECURE PYTHON DATA PARSING (JSON + Pydantic & yaml.safe_load)
# ============================================================================
import hmac
import hashlib
import json
import yaml
from pydantic import BaseModel, ConfigDict, Field


class SessionPayloadSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(..., min_length=1, max_length=64)
    tenant_id: str = Field(..., min_length=1, max_length=64)
    roles: list[str]


def load_session_cache_secure(raw_bytes: bytes, hmac_key: bytes, expected_sig: str) -> SessionPayloadSchema:
    # 1. Verify cryptographic HMAC-SHA256 integrity BEFORE parsing any bytes
    computed_sig = hmac.new(hmac_key, raw_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(computed_sig, expected_sig):
        raise PermissionError("Session cache integrity verification failed")

    # 2. Parse strictly as JSON data and validate against Pydantic schema
    data = json.loads(raw_bytes.decode("utf-8"))
    return SessionPayloadSchema.model_validate(data)


def parse_config_yaml_secure(yaml_text: str) -> dict:
    # SECURE: yaml.safe_load resolves only standard YAML scalar/list/dict primitives
    parsed = yaml.safe_load(yaml_text)
    if not isinstance(parsed, dict):
        raise ValueError("Configuration root must be a YAML mapping")
    return parsed
```

### 30.3.2 Java: Enforcing JEP 290 `ObjectInputFilter` & Safe Jackson Configuration

In modern Java (JDK 9+ JEP 290 and JDK 17+ JEP 415), if legacy `ObjectInputStream` cannot be completely replaced with JSON or Protobuf, engineers must enforce a strict **Allowlist `ObjectInputFilter`** that rejects all classes except explicitly approved data transfer objects:

```java
// ============================================================================
// REMEDIATED SECURE JAVA DESERIALIZATION WITH JEP 290 ALLOWLIST FILTER
// ============================================================================
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

public final class SafeJavaDeserializer {
    // Allow ONLY com.example.dto.SafeSessionDto; reject all other classes (!*)
    // and enforce strict array/depth/reference limits against DoS
    private static final ObjectInputFilter STRICT_ALLOWLIST_FILTER =
        ObjectInputFilter.Config.createFilter(
            "maxdepth=3;maxarray=100;maxrefs=50;com.example.dto.SafeSessionDto;!*"
        );

    public static Object deserializeSafely(byte[] serializedBytes)
            throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(serializedBytes);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            // Attach JEP 290 allowlist filter BEFORE calling readObject()
            ois.setObjectInputFilter(STRICT_ALLOWLIST_FILTER);
            return ois.readObject();
        }
    }
}
```

---

# Appendix VI-A: Comprehensive OWASP Top 10 & WSTG v4.2 Server-Side Engineering Reference

## A.1 Mapping Server-Side Vulnerabilities to CWE, OWASP Top 10, and ASVS v4.0.3

| Vulnerability Class | CWE ID | OWASP Top 10 (2021) | OWASP WSTG v4.2 Test ID | Primary Architectural Remediation |
| :--- | :--- | :--- | :--- | :--- |
| **SQL Injection (SQLi)** | CWE-89 | A03:2021 Injection | `WSTG-INPV-05` | Parameterized queries / Prepared Statements (`?`, `$1`, `%s`); dictionary allowlists for `ORDER BY` identifiers. |
| **NoSQL Injection** | CWE-943 | A03:2021 Injection | `WSTG-INPV-05` | Strict runtime schema validation (`Zod`/`Pydantic`) enforcing primitive scalar types; disable `$where` JS execution. |
| **OS Command Injection** | CWE-78 | A03:2021 Injection | `WSTG-INPV-12` | Replace shell calls with native libraries; use `execve` array APIs (`shell=False`, `execFile`) + `--` option delimiter + strict regex. |
| **Server-Side Template Injection (SSTI)** | CWE-1336 | A03:2021 Injection | `WSTG-INPV-18` | Never concatenate user input into template source strings; bind variables via context dictionary with `autoescape=True`. |
| **Broken Object Level Auth (BOLA / IDOR)** | CWE-639 | A01:2021 Broken Access Control | `WSTG-ATHZ-04` | Scope every database query by authenticated `tenant_id` and `owner_id`; enable PostgreSQL Row-Level Security (RLS). |
| **Mass Assignment (BOPLA)** | CWE-915 | A01:2021 Broken Access Control | `WSTG-ATHZ-02` | Never bind raw request JSON directly to ORM entities; enforce explicit input/output DTO schemas (`extra="forbid"`). |
| **JWT Verification Flaws** | CWE-347 | A07:2021 Identification & Auth Failures | `WSTG-SESS-10` | Enforce RFC 8725: hardcode `algorithms=["RS256"]`, block `jku`/`x5u`/`jwk`, validate `kid` against static dictionary, require `aud`/`iss`/`exp`. |
| **Server-Side Request Forgery (SSRF)** | CWE-918 | A10:2021 SSRF | `WSTG-INPV-19` | Enforce AWS IMDSv2 (`http_tokens="required"`); resolve DNS once and verify `ip.is_global`; route webhooks via isolated egress proxy. |
| **XML External Entity (XXE)** | CWE-611 | A05:2021 Security Misconfiguration | `WSTG-INPV-07` | Set `disallow-doctype-decl=true`, `resolve_entities=False`, `no_network=True`, or use `defusedxml`. |
| **Path Traversal & Zip Slip** | CWE-22 | A01:2021 Broken Access Control | `WSTG-ATHZ-01` | Resolve canonical paths (`Path.resolve()`) and verify containment (`is_relative_to(base_dir)`) before file read/write. |
| **Insecure Deserialization** | CWE-502 | A08:2021 Software & Data Integrity | `WSTG-INPV-16` | Replace `pickle`/`unserialize`/`BinaryFormatter` with `JSON` + schema validation or Protobuf; verify HMAC before parsing. |

---

## Part VI: Academic Review Exercises & Secure Code Auditing Lab Problems

### Exercise 25.1: Multi-Tier Reverse Proxy Trust Boundary Analysis
An enterprise deploys a Node.js Express API behind an Nginx reverse proxy. The Express application implements login rate-limiting by reading `const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;`.
1. Explain how an external client can bypass this rate-limiting control when sending requests through the Nginx proxy if Nginx uses `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`.
2. Provide both the hardened Nginx configuration and the hardened Express `trust proxy` configuration so the client IP cannot be spoofed.

### Exercise 26.1: SQL AST Analysis & Dynamic Sorting Remediation
Review the following Python database function:
```python
def fetch_transactions(conn, account_id: str, sort_by: str):
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT id, amount, created_at FROM transactions WHERE account_id = %s ORDER BY {sort_by} DESC",
            (account_id,)
        )
        return cur.fetchall()
```
1. Even though `account_id` uses a parameterized placeholder (`%s`), explain why this function is still vulnerable to SQL Injection via `sort_by`.
2. Explain why `ORDER BY %s DESC` cannot be used in SQL prepared statements to specify a column identifier, and rewrite `fetch_transactions` so that both `account_id` and `sort_by` are 100% secure.

### Exercise 27.1: Cryptographic Audit of JWT Verification Logic
Explain the exact cryptographic mechanism of an **Asymmetric-to-Symmetric (`RS256` to `HS256`) Algorithm Confusion** vulnerability when a server verifies JWTs using `jwt.decode(token, key=rsa_public_key_pem, algorithms=jwt.get_unverified_header(token)['alg'])`. List the five mandatory verification checks required by **RFC 8725** to harden this implementation.

### Exercise 28.1: Designing Multi-Tenant BOLA & BOPLA Defenses
A healthcare SaaS API exposes `PUT /api/v2/patients/{patient_uuid}`. The engineering team argues that because `patient_uuid` is a 128-bit random `UUIDv4`, an authorization check comparing the logged-in doctor's `clinic_id` to the patient's `clinic_id` is unnecessary overhead.
1. Refute this argument using **CWE-639** and **OWASP API1:2023 (BOLA)** principles, identifying at least three ways UUIDv4 identifiers are routinely disclosed in normal application workflows.
2. Write a PostgreSQL Row-Level Security (RLS) policy on the `patients` table that guarantees clinic-level data isolation at the database engine layer.

### Exercise 29.1: Eliminating TOCTOU DNS Rebinding in Webhook Validators
A developer writes an SSRF protection function that resolves the hostname in a user-supplied `webhook_url`, checks that the IP does not start with `127.` or `10.`, and then calls `requests.post(webhook_url, json=payload)`.
1. Identify at least four flaws in this implementation (including omitted RFC 1918 / IPv6 / Link-Local ranges, HTTP redirects, and DNS rebinding TOCTOU).
2. Explain how AWS IMDSv2 (`PUT /latest/api/token` + `http_put_response_hop_limit = 1`) mitigates cloud metadata credential theft even if an application contains a `GET`-based SSRF flaw.

### Exercise 30.1: Remediating SSTI and Unsafe Deserialization
An application stores user dashboard layout preferences in a base64-encoded cookie that is parsed on the server using Python's `pickle.loads(base64.b64decode(cookie_val))`, and renders custom dashboard titles using `jinja2.Template(f"<h2>{layout.title}</h2>").render()`.
1. Explain the root cause of both the **CWE-502 (Insecure Deserialization)** flaw and the **CWE-1336 (Server-Side Template Injection)** flaw in this design.
2. Rewrite both components using HMAC-signed JSON validated with `Pydantic` and a pre-compiled `Jinja2` `Environment` with `autoescape=True`.


---

# Appendix VI-B: Codifying Server-Side AppSec Controls with Semgrep SAST Rules

Modern Application Security Engineering integrates **Static Application Security Testing (SAST)** into Continuous Integration (CI) pipelines so vulnerable code patterns (such as unparameterized SQL queries, `shell=True`, `pickle.loads()`, or `yaml.load()`) are automatically blocked during Pull Request review before reaching production.

Below is a production-ready **Semgrep** ruleset (`server_side_appsec_policy.yaml`) that detects the root-cause vulnerability patterns analyzed in Chapters 26 through 30:

```yaml
# server_side_appsec_policy.yaml
# Custom Semgrep SAST Policy for Continuous CI/CD Pull Request Verification
rules:
  - id: python-psycopg-sql-string-concatenation
    languages: [python]
    severity: ERROR
    message: >-
      Detected dynamic string formatting inside cursor.execute(). This introduces
      SQL Injection (CWE-89). Pass SQL placeholders (%s) in the query string and
      bind parameters as a tuple in the second argument of cursor.execute(sql, params).
    patterns:
      - pattern-either:
          - pattern: $CURSOR.execute(f"...", ...)
          - pattern: $CURSOR.execute("..." + $VAR, ...)
          - pattern: $CURSOR.execute("..." % ..., ...)
          - pattern: $CURSOR.execute("...".format(...), ...)
    metadata:
      cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"
      owasp: "A03:2021 - Injection"

  - id: python-jwt-unverified-header-alg-confusion
    languages: [python]
    severity: ERROR
    message: >-
      Do not derive the allowed JWT verification algorithms dynamically from
      jwt.get_unverified_header() (RFC 8725 violation / CWE-347). Hardcode an
      explicit asymmetric algorithm allowlist such as algorithms=["RS256"].
    patterns:
      - pattern: |
          $HEADER = jwt.get_unverified_header($TOKEN)
          ...
          jwt.decode($TOKEN, ..., algorithms=[..., $HEADER[...], ...], ...)
    metadata:
      cwe: "CWE-347: Improper Verification of Cryptographic Signature"
      owasp: "A07:2021 - Identification and Authentication Failures"

  - id: python-subprocess-shell-true-prohibited
    languages: [python]
    severity: ERROR
    message: >-
      Invoking subprocess with shell=True spawns a system shell (/bin/sh) and risks
      OS Command Injection (CWE-78). Pass arguments as a list with shell=False.
    pattern-either:
      - pattern: subprocess.run(..., shell=True, ...)
      - pattern: subprocess.Popen(..., shell=True, ...)
      - pattern: subprocess.call(..., shell=True, ...)
      - pattern: subprocess.check_output(..., shell=True, ...)
    metadata:
      cwe: "CWE-78: Improper Neutralization of Special Elements used in an OS Command"
      owasp: "A03:2021 - Injection"

  - id: python-unsafe-deserialization-pickle-and-yaml
    languages: [python]
    severity: ERROR
    message: >-
      Unsafe deserialization detected (CWE-502). Replace pickle.loads() with JSON +
      Pydantic schema validation, and replace yaml.load() with yaml.safe_load().
    pattern-either:
      - pattern: pickle.loads(...)
      - pattern: pickle.load(...)
      - pattern: yaml.unsafe_load(...)
      - pattern: yaml.load($DATA, Loader=yaml.Loader)
      - pattern: yaml.load($DATA, Loader=yaml.UnsafeLoader)
    metadata:
      cwe: "CWE-502: Deserialization of Untrusted Data"
      owasp: "A08:2021 - Software and Data Integrity Failures"

  - id: python-jinja2-ssti-template-from-fstring
    languages: [python]
    severity: ERROR
    message: >-
      Concatenating variables directly into jinja2.Template() or from_string()
      introduces Server-Side Template Injection (CWE-1336). Compile static templates
      and pass dynamic data strictly via .render(key=value) with autoescape=True.
    pattern-either:
      - pattern: jinja2.Template(f"...")
      - pattern: $ENV.from_string(f"...")
    metadata:
      cwe: "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine"
      owasp: "A03:2021 - Injection"
```
