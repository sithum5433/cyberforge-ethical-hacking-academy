# APPENDIX I: ARCHITECTURAL THREAT MODELING, SECURE CODE REVIEW PLAYBOOKS & STATIC ANALYSIS ENGINEERING

---

# Section I.1: Enterprise Threat Modeling Methodologies

**Threat Modeling** is the structured security engineering practice of analyzing a software or infrastructure architecture during the design phase ("Shift-Left Security") to identify trust boundaries, enumerate potential architectural weaknesses, prioritize risk, and specify verifiable security controls before code is written or deployed.

Every comprehensive threat model answers Adam Shostack's **Four Question Framework**:
1. **What are we working on?** (Decomposing the system via Data Flow Diagrams, asset inventories, and trust boundaries)
2. **What can go wrong?** (Systematic threat elicitation using STRIDE, PASTA, LINDDUN, or Attack Trees)
3. **What are we going to do about it?** (Engineering architectural mitigations, compensating controls, or risk acceptance)
4. **Did we do a good job?** (Validating the threat model via automated tests, code review, and retrospective verification)

---

## I.1.1 Data Flow Diagrams (DFDs) & Trust Boundary Decomposition

Before applying a threat elicitation framework, security architects decompose the system into five canonical **Data Flow Diagram (DFD)** primitives:

| DFD Element | Symbol / Notation | Definition | Primary Security Audit Questions |
| :--- | :--- | :--- | :--- |
| **External Entity (Interactor)** | Rectangle `[Entity]` | Any human user, external partner API, third-party SaaS webhook, or browser outside the system's direct control | How is this entity authenticated? Can its identity or origin IP be spoofed? |
| **Process** | Circle / Rounded Box `(Process)` | Any active runtime code unit that transforms, validates, or routes data (e.g., API Gateway, Worker Pod, Lambda) | Under what OS/IAM privilege does it run? Does it validate all inputs across trust boundaries? |
| **Data Store** | Parallel Lines `==Store==` | Any persistent or transient state repository (PostgreSQL, Redis, S3 bucket, Kafka topic, filesystem log) | Is data encrypted at rest (KMS) and in transit? Are access controls least-privilege? Are audit logs immutable? |
| **Data Flow** | Directed Arrow `--->` | Network protocol call, IPC socket, RPC stream, or message bus payload moving between elements | What protocol is used (TLS 1.3 / mTLS)? Is payload integrity and replay protection enforced? |
| **Trust Boundary** | Dashed Box `- - -` | Any boundary where privilege levels, network zones, or administrative ownership change | Is there a Policy Enforcement Point (PEP) validating authentication, authorization, and schema at this boundary? |

```
+-----------------------------------------------------------------------------------+
|               DATA FLOW DIAGRAM (DFD) & TRUST BOUNDARY DECOMPOSITION              |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [External User Browser]                     [3rd-Party Payment Webhook]          |
|            |                                              |                       |
|  ==========|=============== TRUST BOUNDARY 1 =============|=====================  |
|            | (Public Internet -> DMZ Edge TLS 1.3)        | (HMAC-SHA256 Signed)  |
|            v                                              v                       |
|    (1.0 Edge API Gateway / Envoy) <------------ (1.1 Webhook Receiver Service)    |
|            |                                              |                       |
|  ----------|-- TRUST BOUNDARY 2 (Zero-Trust Service Mesh / SPIFFE mTLS) --------  |
|            v                                              v                       |
|    (2.0 Core Order & Ledger Service) ---------> ==[D1: Kafka Event Bus]==         |
|            |                                                                      |
|  ----------|-- TRUST BOUNDARY 3 (Isolated Persistence VPC Tier) ----------------  |
|            v                                                                      |
|    ==[D2: PostgreSQL Primary Cluster (RDS + KMS + RLS)]==                         |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

## I.1.2 The STRIDE Threat Elicitation Methodology

Developed at Microsoft by Loren Kohnfelder and Praerit Garg, **STRIDE** maps six fundamental threat categories directly against the six core security properties they violate, and associates each category with the specific DFD primitives susceptible to it:

| STRIDE Category | Violated Security Property | Core Definition | Applicable DFD Elements | Canonical Architectural Mitigations |
| :--- | :--- | :--- | :--- | :--- |
| **S — Spoofing** | **Authentication** | Impersonating another user, microservice, host, or external webhook sender | External Entities, Processes, Data Flows | WebAuthn/FIDO2 MFA, mTLS (SPIFFE/SPIRE), RFC 8725 JWT validation, HMAC webhook signatures |
| **T — Tampering** | **Integrity** | Unauthorized modification of data in transit over a network or at rest in a data store/cookie | Processes, Data Stores, Data Flows | TLS 1.3 in transit, HMAC/JWS digital signatures, PostgreSQL Row-Level Security, immutable WORM storage |
| **R — Repudiation** | **Non-Repudiation & Auditability** | Performing a state-changing or privileged action without leaving an attributable, tamper-evident audit trail | External Entities, Processes | Append-only cryptographic audit logs, centralized SIEM forwarding, asymmetric transaction signing |
| **I — Information Disclosure** | **Confidentiality** | Unauthorized read access to sensitive data in transit, in storage, or via side-channels / verbose errors | Processes, Data Stores, Data Flows | Field-level envelope encryption (AES-256-GCM), RFC 9457 sanitized errors, constant-time comparisons, BOLA checks |
| **D — Denial of Service** | **Availability** | Exhausting compute, memory, connection pools, disk I/O, or rate quotas to degrade legitimate access | Processes, Data Stores, Data Flows | Token-bucket rate limiting, connection timeouts, bounded pagination, circuit breakers, Zip/XML bomb limits |
| **E — Elevation of Privilege** | **Authorization** | Executing commands or accessing functions/resources beyond assigned role or tenant permissions | Processes | RBAC/ABAC Policy Enforcement Points, parameterized queries (preventing SQLi/Command Injection), distroless non-root containers |

### STRIDE-per-Interaction Matrix

During a design review workshop, security architects iterate over **every Data Flow arrow that crosses a Trust Boundary** and evaluate all six STRIDE dimensions systematically:

1. **Spoofing the Source:** How does the receiving process (`2.0 Core Order Service`) cryptographically prove that the caller is genuinely `1.0 Edge API Gateway` and not a compromised pod in an adjacent namespace?
2. **Tampering with the Payload:** Could parameters inside the request body be modified between validation at the gateway and execution at the backend service (e.g., parameter pollution or JSON duplicate keys)?
3. **Repudiation of the Transaction:** If a dispute occurs over a financial transfer, do we log the immutable `trace_id`, authenticated `sub` claim, client IP, timestamp, and cryptographic hash of the request payload to an append-only log store?
4. **Information Disclosure on the Return Path:** Does the response DTO accidentally serialize internal database fields, or do error conditions leak stack traces or timing side-channels?
5. **Denial of Service on the Target Process:** What happens if a single authenticated tenant sends an unbounded GraphQL query (`depth=20`) or requests `limit=10000000` rows?
6. **Elevation of Privilege inside the Target Process:** Can untrusted fields in the payload alter an interpreter's AST (SQLi, SSTI, Deserialization) or modify privileged attributes (Mass Assignment)?

---

## I.1.3 Comparative Frameworks: PASTA, DREAD / CVSS v4.0, LINDDUN & Attack Trees

While STRIDE excels at component-level technical threat discovery, enterprise security programs combine STRIDE with risk-centric, privacy-centric, and attacker-centric methodologies:

### 1. PASTA (Process for Attack Simulation and Threat Analysis)
PASTA is a seven-stage, risk-centric methodology that aligns technical threat modeling directly with business impact and threat intelligence:
- **Stage I — Define Objectives (DO):** Document business requirements, regulatory compliance mandates (PCI-DSS v4.0, HIPAA, GDPR, Sri Lanka PDPA), and recovery time objectives (RTO/RPO).
- **Stage II — Define Technical Scope (DTS):** Inventory software dependencies (SBOM), cloud infrastructure, APIs, and data classifications.
- **Stage III — Application Decomposition (AD):** Construct DFDs, map trust boundaries, and catalog authentication/authorization roles.
- **Stage IV — Threat Analysis (TA):** Correlate internal telemetry and industry threat intelligence (MITRE ATT&CK matrices) relevant to the organization's sector.
- **Stage V — Vulnerability & Weakness Analysis (VWA):** Map design flaws to CWEs, SAST/DAST findings, and architectural single points of failure.
- **Stage VI — Attack Modeling (AM):** Construct hierarchical **Attack Trees** showing multi-step paths from initial access to business impact.
- **Stage VII — Risk & Impact Analysis (RIA):** Calculate residual risk and prioritize engineering countermeasures.

### 2. Quantitative Risk Scoring: DREAD vs. CVSS v4.0 & OWASP Risk Rating
Historically, teams scored threats using **DREAD** (*Damage, Reproducibility, Exploitability, Affected Users, Discoverability* on a 1–10 scale). Because subjective DREAD averages often suffer from reviewer variance, modern AppSec teams use the **OWASP Risk Rating Methodology** (`Likelihood x Technical/Business Impact`) or **CVSS v4.0 Base + Threat + Environmental metrics**:

| Risk Dimension | Low Severity (Score 1–3) | Medium Severity (Score 4–6) | High / Critical Severity (Score 7–10) |
| :--- | :--- | :--- | :--- |
| **Privilege Required** | Requires administrative + physical/bastion access | Requires authenticated standard user account | Unauthenticated network access (`PR:N`) |
| **Attack Complexity** | Requires rare race window + non-default config | Requires specific user interaction or multi-step precondition | Deterministic, repeatable single request (`AC:L`) |
| **Confidentiality & Integrity Impact** | Minimal non-sensitive metadata disclosure | Scoped to a single non-privileged user's session | Cross-tenant data access, full DB read/write, or key compromise |
| **Remediation SLA** | Next quarterly release / backlog | Within 14–30 days | Immediate hotfix / within 24–72 hours |

### 3. Hierarchical Attack Trees (Bruce Schneier Notation)
An **Attack Tree** models an adverse outcome as the **Root Node** (Goal) and decomposes the preconditions required to achieve that goal into **AND** (all child conditions must be met) and **OR** (any single child condition suffices) branches. Defenders use Attack Trees to identify **high-leverage chokepoints** where placing a single control breaks an entire `AND` branch:

```
ROOT GOAL: Unauthorized Modification of Customer Payout Bank Account
 ├── [OR] Branch 1: Compromise Customer Session Credentials
 │    ├── [AND] 1.1 Credential Stuffing + Missing/Bypassed MFA
 │    │    ├── Obtain leaked password from external breach corpus
 │    │    └── Account has MFA disabled OR MFA rate-limit is missing [CONTROL: Mandatory WebAuthn/TOTP + Strict Lockout]
 │    └── [OR] 1.2 Session Token Theft
 │         ├── Read session cookie via DOM XSS [CONTROL: HttpOnly + Strict CSP]
 │         └── Intercept token over unencrypted Wi-Fi [CONTROL: __Host- Prefix + Secure + HSTS]
 │
 ├── [OR] Branch 2: Exploit Broken Access Control (BOLA) on Bank Account API
 │    └── Authenticated User B sends PUT /api/v1/payout-accounts/{user_a_id}
 │         [CONTROL: Scope SQL UPDATE strictly by authenticated session user_id + Step-Up MFA]
 │
 └── [OR] Branch 3: Compromise Internal Customer Support Portal
      └── [AND] Support agent modifies payout details without dual-control approval
           [CONTROL: Four-Eyes Approval Workflow + Immutable Customer Notification + 24h Cooling Period]
```

---

## I.1.4 Domain-Specific Threat Modeling Reference Architectures

### Architecture Case Study 1: Cloud-Native Microservices & Kubernetes Service Mesh
When threat modeling a microservice architecture (e.g., 40 Go and Python services communicating over gRPC and Kafka inside Kubernetes), traditional perimeter-only security ("hard shell, soft interior") fails if any single container is compromised.

| Architectural Threat | Root Cause in Microservices | Zero-Trust Architectural Countermeasure |
| :--- | :--- | :--- |
| **Lateral Movement Between Pods** | Flat Kubernetes cluster network (`CNI`) where every pod can connect to every other pod's IP on any port | Enforce default-deny **Kubernetes `NetworkPolicy`** (or Cilium eBPF L7 policies) restricting pod-to-pod communication strictly to declared service dependencies. |
| **Confused Deputy / Missing User Context** | Edge gateway verifies the user's JWT and forwards only a plaintext `X-User-ID: 123` header to downstream internal services | Combine **Mutual TLS (mTLS via SPIFFE/Istio)** (authenticating the calling *service* identity) with **End-User JWT Propagation** (so downstream services cryptographically verify *both* the calling service and the end-user's claims). |
| **Container Breakout to Host Node** | Running container processes as `UID 0 (root)` with default Linux capabilities (`CAP_SYS_ADMIN`, `CAP_NET_RAW`) or mounted `/var/run/docker.sock` | Enforce Kubernetes **Pod Security Admission (`restricted` profile)**: `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities: {drop: ["ALL"]}`, and `seccompProfile: RuntimeDefault`. |

---

### Architecture Case Study 2: FinTech Payment Gateways & Ledger Systems
Financial technology systems, core banking gateways, and digital wallets face specialized business-logic and concurrency threats beyond standard OWASP Top 10 injection flaws:

1. **Double-Spending via Race Conditions (Time-of-Check to Time-of-Use / TOCTOU - CWE-367):**
   * **Vulnerability Mechanics:** Suppose a wallet transfer endpoint executes:
     1. `SELECT balance FROM wallets WHERE user_id = $1;` (Reads `balance = 100.00`)
     2. `if balance >= transfer_amount:`
     3. `UPDATE wallets SET balance = balance - $2 WHERE user_id = $1;`
   * If a client transmits 20 parallel HTTP/2 requests in a single TCP packet (a "single-packet attack") for a `100.00` withdrawal, all 20 concurrent database transactions execute Step 1 simultaneously before any transaction commits Step 3. All 20 see `balance = 100.00`, resulting in `2,000.00` withdrawn from a `100.00` balance!
   * **Architectural Remediation:**
     - **Pessimistic Row-Level Locking (`SELECT ... FOR UPDATE`):** Lock the source and destination wallet rows in deterministic primary-key order (to prevent deadlocks) inside a single ACID transaction, OR
     - **Atomic Conditional Update + `CHECK (balance >= 0)` Constraint:**
       ```sql
       -- Atomic single-statement deduction that cannot race
       UPDATE wallets
       SET balance = balance - $1, updated_at = NOW()
       WHERE user_id = $2 AND balance >= $1
       RETURNING balance;
       ```
     - **Mandatory Idempotency Keys (`Idempotency-Key` Header):** Require a unique client-generated UUID (`Idempotency-Key`) stored with a `UNIQUE` database constraint so network retries or parallel duplicate submissions never execute a transfer twice.

2. **Floating-Point Precision & Rounding Manipulation (CWE-681 / CWE-1339):**
   * **Vulnerability Mechanics:** Representing currency using IEEE 754 floating-point types (`float` / `double` in Python, JS `number`, or SQL `FLOAT`) causes binary representation inaccuracies (`0.1 + 0.2 == 0.30000000000000004`), negative zero `-0.0`, `NaN`, or `Infinity` bugs.
   * **Architectural Remediation:** Always store and compute monetary amounts as **64-bit signed integers of the smallest currency subunit** (e.g., cents/paisa, where LKR `250.50` is stored as integer `25050` with a strict `CHECK (amount > 0)` constraint) or fixed-point `NUMERIC(19, 4)` / Python `decimal.Decimal` with explicit `ROUND_HALF_EVEN` bankers' rounding.

3. **Webhook Spoofing & Replay Attacks on Payment Callbacks:**
   * **Vulnerability Mechanics:** Payment processors notify merchant backends of completed payments via asynchronous HTTP webhooks (`POST /webhooks/payment-status`). If the endpoint does not verify the cryptographic signature and timestamp, an external caller can forge a `PAYMENT_SUCCEEDED` webhook.
   * **Architectural Remediation:** Verify the raw request body using `hmac.compare_digest()` against the provider's HMAC-SHA256 signature header, enforce a strict 5-minute timestamp window against replay, and record processed `event_id` values in an idempotency table.

---

### Architecture Case Study 3: AI & Large Language Model (LLM) Applications (OWASP Top 10 for LLM Apps)
Enterprise applications integrating Large Language Models (RAG pipelines, AI customer support agents, automated tool-calling assistants) introduce a new trust boundary where **natural language text acts as instructions to the model**:

| OWASP LLM Risk Category | Architectural Root Cause | Engineering Defense-in-Depth Control |
| :--- | :--- | :--- |
| **LLM01: Prompt Injection (Direct & Indirect)** | Untrusted external data (emails, web pages, RAG documents) is concatenated into the LLM context window alongside system instructions, causing the LLM to follow instructions embedded inside the untrusted document. | Treat all LLM outputs as **untrusted by default**; separate system prompts from retrieved data using structured delimiters; never grant an LLM agent ambient permissions across trust boundaries. |
| **LLM02: Insecure Output Handling** | Rendering raw LLM-generated Markdown/HTML directly in the browser (`dangerouslySetInnerHTML`) or passing LLM-generated SQL/shell strings directly to a database/OS interpreter. | Sanitize all LLM HTML output with `DOMPurify`; forbid LLMs from executing raw SQL or shell commands (expose only parameterized, pre-defined read-only API tools). |
| **LLM06: Sensitive Information Disclosure (RAG Leakage)** | Vector database similarity search (`top_k`) retrieves chunks from documents across all tenants without filtering by the querying user's authorization scope. | Enforce **Pre-Retrieval Metadata Filtering (ACL-aware RAG)**: attach `tenant_id` and `allowed_roles` metadata to every vector embedding and filter the vector query strictly by the authenticated user's session claims. |
| **LLM07 / LLM08: Excessive Agency & Tool-Calling Abuse** | Granting an LLM agent autonomous access to high-impact state-mutating tools (`delete_user`, `transfer_funds`, `send_external_email`) without human-in-the-loop confirmation. | Enforce deterministic **Policy Enforcement Points (PEPs)** outside the LLM on every tool call, scope OAuth tokens to the current user's least privilege, and require explicit **Human-in-the-Loop (HITL)** cryptographic approval for any state-changing action. |

---

# Section I.2: Language-by-Language Secure Code Review Playbooks

When conducting a manual or tool-assisted **Secure Code Review**, security engineers combine two complementary traversal strategies:
1. **Top-Down (Entry-Point / Route-Driven Review):** Start at the HTTP routing layer (`@app.route`, `router.post`, `@RestController`), verify authentication and authorization middleware on each route, and trace how untrusted request parameters flow downward into business logic and persistence layers (**Source-to-Sink Taint Analysis**).
2. **Bottom-Up (Dangerous Sink-Driven Review):** Grep the codebase for high-risk APIs ("Sinks"—such as raw SQL execution, process spawning, file I/O, XML/YAML deserialization, cryptographic primitives, and template compilers) and trace backward to verify whether any untrusted input ("Source") can reach that sink unvalidated.

---

## I.2.1 Python (FastAPI, Django, Flask) Secure Code Review Playbook

### High-Risk Python Sinks & Anti-Patterns Table

| Vulnerability Category | Dangerous Python Sinks / Anti-Patterns to Grep | Secure Python Replacement Pattern |
| :--- | :--- | :--- |
| **Code & Deserialization Execution** | `eval()`, `exec()`, `pickle.loads()`, `cPickle`, `dill`, `shelve`, `marshal.loads()`, `yaml.load()` (without `SafeLoader`), `jsonpickle.decode()` | `ast.literal_eval()` (for simple literals), `json.loads()` + `Pydantic`, `yaml.safe_load()` |
| **OS Command Execution** | `os.system()`, `os.popen()`, `subprocess.run(..., shell=True)`, `subprocess.Popen(..., shell=True)`, `asyncio.create_subprocess_shell()` | `subprocess.run([bin, "--", arg], shell=False, timeout=5)` or `asyncio.create_subprocess_exec()` |
| **SQL Injection (Django / SQLAlchemy / Raw)** | `cursor.execute(f"...")`, `Model.objects.raw(f"...")`, `.extra(where=[...])`, `RawSQL(f"...")`, `sqlalchemy.text(f"...")` | `cursor.execute("... %s", (val,))`, Django ORM `filter()`, `sqlalchemy.text("... :v").bindparams(v=val)` |
| **Server-Side Template Injection (SSTI)** | `flask.render_template_string(f"...")`, `jinja2.Template(user_str)`, `mako.template.Template(user_str)` | `flask.render_template("static.html", var=user_str)` with `autoescape=True` |
| **Weak Randomness (CWE-338)** | `random.random()`, `random.randint()`, `random.choice()`, `uuid.uuid1()` for tokens/OTP/keys | `secrets.token_urlsafe(32)`, `secrets.token_hex(32)`, `secrets.randbelow()`, `uuid.uuid4()` |
| **Timing Side-Channel Comparison** | `if signature == expected_sig:` or `if api_key == stored_key:` | `hmac.compare_digest(signature, expected_sig)` |
| **XML External Entities (XXE)** | `xml.etree.ElementTree`, `xml.dom.minidom`, `xml.sax`, `lxml.etree` (with `resolve_entities=True`) | `defusedxml.ElementTree.fromstring()` |
| **Python Assert Statements for Auth** | `assert user.is_admin, "Unauthorized"` | Explicit `if not user.is_admin: raise PermissionError(...)` (`python -O` strips all `assert` statements in optimized bytecode!) |

### Subtle Python Security Pitfalls to Check in Code Audits

1. **FastAPI Dependency Injection (`Depends`) Omission on Routers:**
   * Check whether a developer defined `get_current_user` but accidentally wrote `user = get_current_user` (missing `Depends(get_current_user)`) or forgot to attach `dependencies=[Depends(require_admin)]` to an `APIRouter`.
2. **Django `mark_safe()` and `|safe` Template Filter:**
   * Django templates autoescape HTML by default, but any call to `django.utils.safestring.mark_safe(f"<div>{user_input}</div>")` bypasses autoescaping. Replace `mark_safe()` with `django.utils.html.format_html("<div>{}</div>", user_input)`, which escapes all interpolated arguments automatically.
3. **Python `tarfile` and `zipfile` Extraction:**
   * Audit every call to `tar.extractall()` (ensure `filter='data'` is passed in Python 3.12+) and `zip.extractall()` (verify canonical path containment).

---

## I.2.2 JavaScript & TypeScript (Node.js, Express, Next.js, React) Secure Code Review Playbook

### High-Risk JavaScript/TypeScript Sinks & Anti-Patterns Table

| Vulnerability Category | Dangerous JS/TS Sinks / Anti-Patterns to Grep | Secure JS/TS Replacement Pattern |
| :--- | :--- | :--- |
| **Prototype Pollution (CWE-1321)** | Recursive object merge `target[key] = source[key]`, `Object.assign` on nested untrusted paths, unvalidated `lodash.merge` / `lodash.set` | Filter out `__proto__`, `constructor`, and `prototype` keys; use `Object.create(null)` or `Map<string, V>`; validate with `Zod` `.strict()` |
| **Command & Code Execution** | `eval()`, `new Function()`, `setTimeout(string)`, `vm.runInNewContext()` (Node `vm` is *not* a security sandbox!), `child_process.exec()`, `child_process.execSync()` | `child_process.execFile(bin, ['--', arg], { shell: false, timeout: 5000 })` |
| **Regular Expression DoS (ReDoS - CWE-1333)** | Nested catastrophic backtracking regexes (`/^([a-zA-Z0-9]+)*$/`, `/(a+)+$/`) evaluated on Node's single-threaded Event Loop | Use linear-time `re2` (`google/re2` bindings), enforce strict input length caps (`max(256)`) prior to regex matching |
| **DOM XSS in React / Next.js** | `dangerouslySetInnerHTML={{ __html: data }}`, `<a href={userProvidedUrl}>` (allows `javascript:...` URI scheme!), `ref.current.innerHTML = ...` | Standard JSX `{data}` binding; sanitize rich HTML with `DOMPurify.sanitize()`; validate URLs start with `https://` or `/` |
| **Next.js Server Actions & SSR Data Leaks** | Passing full database ORM user objects (containing `passwordHash` or internal tokens) from Server Components into Client Components (`"use client"`), or missing auth checks inside `"use server"` Server Actions | Every `"use server"` function is a public HTTP `POST` endpoint—verify session + RBAC inside every Server Action and pass minimal DTOs to Client Components |
| **Weak CSPRNG** | `Math.random()` for tokens, OTPs, or session IDs | `crypto.randomBytes(32).toString('base64url')` or `crypto.randomUUID()` |

###Side-by-Side Comparison: Preventing Prototype Pollution & ReDoS in TypeScript

```typescript
// ============================================================================
// VULNERABLE TYPESCRIPT MERGE FUNCTION (Susceptible to Prototype Pollution CWE-1321)
// ============================================================================
export function mergeSettingsVulnerable(target: any, untrustedInput: any): any {
  for (const key in untrustedInput) {
    // FLAW: If untrustedInput contains JSON {"__proto__": {"isAdmin": true}},
    // target["__proto__"]["isAdmin"] pollutes Object.prototype across the process!
    if (typeof untrustedInput[key] === 'object' && untrustedInput[key] !== null) {
      if (!target[key]) target[key] = {};
      mergeSettingsVulnerable(target[key], untrustedInput[key]);
    } else {
      target[key] = untrustedInput[key];
    }
  }
  return target;
}
```

```typescript
// ============================================================================
// REMEDIATED SECURE TYPESCRIPT MERGE & VALIDATION (Proto-Guard + Zod Schema)
// ============================================================================
import { z } from 'zod';

const FORBIDDEN_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function safeDeepMerge(
  target: Record<string, unknown>,
  source: Record<string, unknown>
): Record<string, unknown> {
  for (const key of Object.keys(source)) {
    // 1. Explicitly block prototype chain keys
    if (FORBIDDEN_PROTO_KEYS.has(key)) {
      throw new Error(`Disallowed object property key: ${key}`);
    }
    const sourceVal = source[key];
    const targetVal = Object.prototype.hasOwnProperty.call(target, key) ? target[key] : undefined;

    if (
      typeof sourceVal === 'object' &&
      sourceVal !== null &&
      !Array.isArray(sourceVal) &&
      typeof targetVal === 'object' &&
      targetVal !== null &&
      !Array.isArray(targetVal)
    ) {
      safeDeepMerge(
        targetVal as Record<string, unknown>,
        sourceVal as Record<string, unknown>
      );
    } else {
      target[key] = sourceVal;
    }
  }
  return target;
}
```


---

## I.2.3 Java (Spring Boot, Spring Security, Jakarta EE / Hibernate) Secure Code Review Playbook

### High-Risk Java Sinks & Anti-Patterns Table

| Vulnerability Category | Dangerous Java Sinks / Anti-Patterns to Grep | Secure Java / Spring Boot Replacement Pattern |
| :--- | :--- | :--- |
| **Spring Expression Language (SpEL) Injection (CWE-917)** | `SpelExpressionParser().parseExpression(userStr).getValue()` (uses `StandardEvaluationContext` by default, allowing arbitrary class instantiation `T(java.lang.Runtime)`) | Never parse user input as SpEL expressions; if restricted evaluation is required, use `SimpleEvaluationContext.forReadOnlyDataBinding().build()` |
| **Java Native & Polymorphic Deserialization (CWE-502)** | `ObjectInputStream.readObject()`, `XMLDecoder`, `XStream` (without allowlist), Jackson `ObjectMapper.enableDefaultTyping()`, `@JsonTypeInfo(use = Id.CLASS)` | Disable Jackson Default Typing; use `@JsonTypeInfo(use = Id.NAME)` with explicit `@JsonSubTypes`; enforce JEP 290 `ObjectInputFilter` |
| **Hibernate HQL / JPQL & JDBC Injection (CWE-89)** | `entityManager.createQuery("FROM User WHERE name = '" + name + "'")`, `jdbcTemplate.queryForList("... " + input)`, `Statement.executeQuery()` | `createQuery("FROM User u WHERE u.name = :name").setParameter("name", name)` or Spring Data JPA `@Query` with `:param` bindings |
| **Java Naming and Directory Interface (JNDI) Lookup Injection** | `new InitialContext().lookup(userSuppliedUri)` (allows remote `ldap://`, `rmi://`, `dns://` reference loading) | Never pass untrusted strings to `Context.lookup()`; restrict JVM with `-Dcom.sun.jndi.ldap.object.trustURLCodebase=false` |
| **OS Command Execution** | `Runtime.getRuntime().exec(singleStringCommand)` | `new ProcessBuilder(List.of("/usr/bin/tool", "--", validatedArg)).start()` |
| **Spring Boot Actuator Exposure** | `management.endpoints.web.exposure.include=*` (`/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`, `/actuator/jolokia`) | Expose only `health,info`; bind management server to loopback `127.0.0.1:9001`; require Spring Security authentication |
| **Weak Cryptography & PRNG** | `new java.util.Random()`, `Cipher.getInstance("AES")` (defaults to insecure `AES/ECB/PKCS5Padding`!), `MessageDigest.getInstance("MD5" / "SHA-1")` | `new java.security.SecureRandom()`, `Cipher.getInstance("AES/GCM/NoPadding")` with 96-bit IV and 128-bit auth tag |

### Side-by-Side Comparison: Spring Security 6 Filter Chain & HQL Parameterization

```java
// ============================================================================
// VULNERABLE SPRING / HIBERNATE CODE (HQL Injection + SpEL Evaluation)
// ============================================================================
@Repository
public class VulnerableUserRepository {
    @PersistenceContext
    private EntityManager em;

    public List<UserEntity> searchUsersVulnerable(String roleFilter, String spelSortExpr) {
        // FLAW 1: String concatenation inside HQL createQuery() -> HQL/SQL Injection!
        String hql = "SELECT u FROM UserEntity u WHERE u.role = '" + roleFilter + "'";
        List<UserEntity> users = em.createQuery(hql, UserEntity.class).getResultList();

        // FLAW 2: Evaluating untrusted string with StandardEvaluationContext -> RCE!
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression(spelSortExpr);
        exp.getValue();
        return users;
    }
}
```

```java
// ============================================================================
// REMEDIATED SECURE SPRING / HIBERNATE CODE (Parameterized JPQL + Spring Security 6)
// ============================================================================
@Repository
public class SecureUserRepository {
    @PersistenceContext
    private EntityManager em;

    private static final Map<String, String> ALLOWED_SORT_FIELDS = Map.of(
        "created", "u.createdAt",
        "email", "u.email"
    );

    public List<UserEntity> searchUsersSecure(String roleFilter, String sortKey) {
        String safeSortColumn = ALLOWED_SORT_FIELDS.getOrDefault(sortKey, "u.createdAt");

        // SECURE: Named parameter (:role) bound safely via setParameter()
        String jpql = "SELECT u FROM UserEntity u WHERE u.role = :role ORDER BY " + safeSortColumn + " ASC";
        return em.createQuery(jpql, UserEntity.class)
                 .setParameter("role", roleFilter)
                 .setMaxResults(100)
                 .getResultList();
    }
}
```

---

## I.2.4 Go (Golang) & Rust Systems Secure Code Review Playbook

Go and Rust provide strong memory-safety guarantees compared to C/C++, but systems code reviewers must audit concurrency models, HTTP server timeouts, TLS verification settings, and `unsafe` blocks.

### High-Risk Go (Golang) Sinks & Anti-Patterns Table

| Vulnerability Category | Dangerous Go Anti-Patterns to Grep | Secure Go Engineering Pattern |
| :--- | :--- | :--- |
| **Unbounded `http.DefaultServer` / `http.ListenAndServe`** | `http.ListenAndServe(":8080", handler)` (sets **zero** `ReadTimeout`, `ReadHeaderTimeout`, `WriteTimeout`, or `IdleTimeout`—vulnerable to Slowloris DoS!) | Always instantiate `&http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}` and wrap bodies with `http.MaxBytesReader` |
| **Template XSS (`text/template` vs `html/template`)** | Importing `"text/template"` to render HTML responses, or casting user strings to `template.HTML(userInput)` / `template.JS(userInput)` | Always import `"html/template"`, which performs context-aware autoescaping across HTML body, attribute, URL, and CSS contexts |
| **TLS Verification Disabled (CWE-295)** | `&tls.Config{InsecureSkipVerify: true}` | Remove `InsecureSkipVerify: true`; load internal CA roots via `x509.SystemCertPool()` and set `MinVersion: tls.VersionTLS13` |
| **Goroutine Data Races & Slice Aliasing** | Mutating shared maps or struct fields across concurrent HTTP handler goroutines without `sync.Mutex` / `sync.RWMutex` | Run `go test -race ./...` in CI; protect shared state with mutexes or channels |
| **Path Traversal in `filepath.Join`** | Assuming `filepath.Join(baseDir, r.URL.Path)` prevents escaping when `baseDir` is relative or symlinks exist | Resolve with `filepath.EvalSymlinks` + `filepath.Abs` and verify prefix with `filepath.Rel(baseDir, targetPath)` |
| **SQL Injection in `database/sql` / `GORM`** | `db.Query("SELECT * FROM users WHERE name = '" + name + "'")`, `gormDB.Where(fmt.Sprintf("name = '%s'", name))`, `gormDB.Order(userSort)` | `db.QueryContext(ctx, "SELECT ... WHERE name = $1", name)`, `gormDB.Where("name = ?", name)` |

#### Hardened Go HTTP Server Template

```go
package main

import (
	"crypto/tls"
	"net/http"
	"time"
)

func NewHardenedHTTPServer(addr string, handler http.Handler) *http.Server {
	// Wrap handler with a strict 1 MiB request body limit to prevent memory exhaustion
	boundedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB
		handler.ServeHTTP(w, r)
	})

	return &http.Server{
		Addr:              addr,
		Handler:           boundedHandler,
		ReadHeaderTimeout: 5 * time.Second,  // Defends against Slowloris header attacks
		ReadTimeout:       10 * time.Second, // Total request read deadline
		WriteTimeout:      15 * time.Second, // Response write deadline
		IdleTimeout:       60 * time.Second, // Keep-Alive idle timeout
		MaxHeaderBytes:    1 << 14,          // 16 KiB max HTTP headers
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}
}
```

### High-Risk Rust Systems Code Review Checklist

When auditing Rust backend services (`axum`, `actix-web`, `tokio`, `sqlx`) and systems crates:
1. **`unsafe { ... }` Blocks & FFI Boundaries:**
   * Grep for every `unsafe` keyword, `std::mem::transmute`, raw pointer dereference (`*const T`, `*mut T`), and `extern "C"` Foreign Function Interface (FFI) boundary. Verify that every `unsafe` block has a `// SAFETY:` comment proving that pointer alignment, lifetime validity, bounds checks, and aliasing invariants (`&mut T` exclusivity) cannot be violated by caller inputs.
2. **Integer Overflow in Release Builds:**
   * In Rust `--debug` builds, integer arithmetic (`a + b`, `a * b`) panics on overflow. However, in **`--release` builds (`opt-level = 3`)**, standard operators wrap silently using two's complement arithmetic unless `overflow-checks = true` is set in `Cargo.toml`!
   * **Audit Fix:** Always use explicit checked or saturating methods (`checked_add()`, `checked_mul()`, `saturating_sub()`) on security-critical lengths, buffer sizes, and financial quantities, AND enable `overflow-checks = true` under `[profile.release]` in `Cargo.toml`.
3. **Panic-Induced Denial of Service (`.unwrap()` / `.expect()` / Indexing `slice[i]`):**
   * On untrusted network inputs, calling `.unwrap()`, `.expect()`, or direct slice indexing `buf[idx]` panics the worker task or thread on malformed input. Enforce Clippy lints `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]` in production crates and propagate errors cleanly via `Result<T, E>` and `.get(idx)`.

---

## I.2.5 PHP (Laravel) & C# (ASP.NET Core) Secure Code Review Playbook

### High-Risk PHP (Laravel) Sinks & Anti-Patterns

| Vulnerability Category | Dangerous PHP / Laravel Anti-Patterns to Grep | Secure Laravel / PHP 8.3+ Pattern |
| :--- | :--- | :--- |
| **Eloquent Raw SQL Injection** | `DB::raw("... $input")`, `->whereRaw("name = '$name'")`, `->orderByRaw($sort)`, `->selectRaw("... $col")` | `->where('name', $name)`, `->whereRaw('name = ?', [$name])`, strict allowlist array for `orderBy` |
| **Eloquent Mass Assignment (BOPLA)** | `protected $guarded = [];` on Eloquent Models combined with `User::create($request->all())` or `$user->update($request->all())` | Define explicit `protected $fillable = ['name', 'email'];` AND pass only `$request->validated()` from a strict `FormRequest` class |
| **Blade Template XSS** | `{!! $userContent !!}` (Unescaped raw Blade output syntax) | `{{ $userContent }}` (Automatically runs `htmlspecialchars($val, ENT_QUOTES, 'UTF-8')`) |
| **PHP Loose Type Juggling (`==` vs `===`)** | `if ($token == $expected)` or `in_array($role, $allowed)` (without `strict: true`) | Enforce `declare(strict_types=1);` at top of every PHP file; use `===`, `hash_equals($expected, $token)`, and `in_array($val, $arr, true)` |
| **Object Deserialization** | `unserialize($input)` or passing user-controlled `phar://` stream paths into `file_exists()` / `fopen()` | `json_decode($input, associative: true, flags: JSON_THROW_ON_ERROR)` |

### High-Risk C# (ASP.NET Core / Entity Framework Core) Sinks & Anti-Patterns

| Vulnerability Category | Dangerous C# / .NET Anti-Patterns to Grep | Secure ASP.NET Core / EF Core Pattern |
| :--- | :--- | :--- |
| **EF Core Raw SQL Injection** | `context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{name}'")` or `ExecuteSqlRaw($"...")` | Use `FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}")` (or `FromSql($"...")` in EF Core 7+), which automatically converts interpolated C# variables into `DbParameter` objects! |
| **.NET Deserialization (CWE-502)** | `BinaryFormatter.Deserialize()`, `NetDataContractSerializer`, `LosFormatter`, `JsonConvert.DeserializeObject` with `TypeNameHandling.All` / `TypeNameHandling.Auto` | Use `System.Text.Json.JsonSerializer.Deserialize<SafeDto>(json)` (which forbids polymorphic arbitrary type instantiation by default) |
| **ASP.NET Core Controller Auth Omission** | `[AllowAnonymous]` accidentally left on administrative actions, or missing `[Authorize(Policy = "...")]` on newly added Controllers | Configure a global `FallbackPolicy` requiring authentication by default across all endpoints (`RequireAuthenticatedUser()`), requiring explicit opt-out for public routes |
| **Razor / Blazor Unescaped HTML** | `@Html.Raw(Model.UserBio)` or `MarkupString(userInput)` in Blazor | Standard `@Model.UserBio` Razor syntax (HTML-encodes automatically) |

---

# Section I.3: Custom Semgrep SAST Rules Reference (20 Production Rules)

Static Application Security Testing (SAST) becomes exponentially more effective when security engineers write **custom, framework-aware AST pattern rules** tailored to their organization's technology stack and business logic invariants.

Below is a complete, multi-language reference library of **20 Custom Semgrep Rules** (`enterprise_code_audit_rules.yaml`) covering Python, TypeScript/JavaScript, Java, Go, PHP, and C# to detect subtle authentication, authorization, cryptographic, concurrency, and injection flaws during automated code reviews.

```yaml
# ======================================================================================
# enterprise_code_audit_rules.yaml
# 20 Production-Grade Custom Semgrep SAST Rules for Enterprise Secure Code Review
# Run with: semgrep scan --config enterprise_code_audit_rules.yaml .
# ======================================================================================

rules:
  # ------------------------------------------------------------------------------------
  # RULE 1: Python - Non-Constant-Time Secret / HMAC Signature Comparison (CWE-208)
  # ------------------------------------------------------------------------------------
  - id: audit-py-timing-unsafe-hmac-comparison
    languages: [python]
    severity: ERROR
    message: >-
      Comparing cryptographic digests or webhook signatures with '==' or '!=' is
      vulnerable to byte-by-byte timing side-channel attacks (CWE-208). Use
      hmac.compare_digest(a, b) for constant-time verification.
    patterns:
      - pattern-either:
          - pattern: |
              $DIGEST = hmac.new(...).hexdigest()
              ...
              if $DIGEST == $INPUT: ...
          - pattern: |
              $DIGEST = hmac.new(...).digest()
              ...
              if $DIGEST == $INPUT: ...
    metadata:
      cwe: "CWE-208: Observable Timing Discrepancy"
      category: cryptography

  # ------------------------------------------------------------------------------------
  # RULE 2: Python - Weak PRNG Used for Security Tokens or OTPs (CWE-338)
  # ------------------------------------------------------------------------------------
  - id: audit-py-weak-random-for-security-token
    languages: [python]
    severity: ERROR
    message: >-
      Python's 'random' module uses the Mersenne Twister PRNG, which is completely
      predictable after observing 624 outputs (CWE-338). Use the 'secrets' module
      (secrets.token_urlsafe, secrets.token_hex, secrets.randbelow) for tokens and OTPs.
    patterns:
      - pattern-either:
          - pattern: random.choice(...)
          - pattern: random.randint(...)
          - pattern: random.choices(...)
          - pattern: random.getrandbits(...)
      - pattern-inside: |
          def $FUNC(...):
              ...
      - metavariable-regex:
          metavariable: $FUNC
          regex: (?i).*(token|otp|reset|password|secret|key|nonce|verify|code|session).*
    metadata:
      cwe: "CWE-338: Use of Cryptographically Weak PRNG"
      category: cryptography

  # ------------------------------------------------------------------------------------
  # RULE 3: Python - FastAPI / Pydantic Model Allowing Mass Assignment (CWE-915)
  # ------------------------------------------------------------------------------------
  - id: audit-py-sqlalchemy-setattr-mass-assignment
    languages: [python]
    severity: ERROR
    message: >-
      Iterating over dynamic dictionary items and calling setattr(orm_obj, k, v)
      allows Mass Assignment / Broken Object Property Level Authorization (CWE-915).
      Assign only explicitly allowlisted DTO fields.
    pattern: |
      for $KEY, $VAL in $PAYLOAD.items():
          ...
          setattr($MODEL, $KEY, $VAL)
    metadata:
      cwe: "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes"
      owasp: "API3:2023 - Broken Object Property Level Authorization"

  # ------------------------------------------------------------------------------------
  # RULE 4: Python - Django RawSQL / extra() SQL Injection (CWE-89)
  # ------------------------------------------------------------------------------------
  - id: audit-py-django-raw-sql-formatting
    languages: [python]
    severity: ERROR
    message: >-
      Detected string interpolation inside Django .raw() or RawSQL(). Use parameterized
      placeholders (%s) and pass the params list as the second argument (CWE-89).
    pattern-either:
      - pattern: $MODEL.objects.raw(f"...", ...)
      - pattern: $MODEL.objects.raw("..." % ..., ...)
      - pattern: $MODEL.objects.raw("...".format(...), ...)
      - pattern: RawSQL(f"...", ...)
      - pattern: RawSQL("...".format(...), ...)
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 - Injection"

  # ------------------------------------------------------------------------------------
  # RULE 5: Python - Python 'assert' Statement Used for Authorization Checks (CWE-617)
  # ------------------------------------------------------------------------------------
  - id: audit-py-assert-used-for-security-check
    languages: [python]
    severity: WARNING
    message: >-
      Do not use 'assert' statements to enforce authentication or authorization checks.
      Running Python with optimization flags (python -O or PYTHONOPTIMIZE=1) removes
      all assert statements from compiled bytecode! Raise an explicit HTTPException
      or PermissionError instead.
    pattern-either:
      - pattern: assert $USER.is_admin, ...
      - pattern: assert $USER.is_authenticated, ...
      - pattern: assert $USER.role == ..., ...
      - pattern: assert has_permission(...), ...
    metadata:
      cwe: "CWE-617: Reachable Assertion"
      category: authorization

  # ------------------------------------------------------------------------------------
  # RULE 6: Python - Tarfile / Zipfile Unvalidated extractall() (Zip Slip CWE-22)
  # ------------------------------------------------------------------------------------
  - id: audit-py-archive-unsafe-extractall
    languages: [python]
    severity: ERROR
    message: >-
      Calling .extractall() on an archive without path traversal validation or
      tarfile filter='data' allows arbitrary file overwrite outside the destination
      directory (Zip Slip / CWE-22). Validate member canonical paths before extracting.
    patterns:
      - pattern: $ARCHIVE.extractall(...)
      - pattern-not: $ARCHIVE.extractall(..., filter="data")
    metadata:
      cwe: "CWE-22: Path Traversal"
      category: filesystem

  # ------------------------------------------------------------------------------------
  # RULE 7: Python - Outbound HTTP Request With TLS Certificate Verification Disabled
  # ------------------------------------------------------------------------------------
  - id: audit-py-requests-httpx-verify-false
    languages: [python]
    severity: ERROR
    message: >-
      Disabling TLS certificate verification (verify=False) allows Man-in-the-Middle
      (MitM) interception of outbound API traffic (CWE-295). Configure a valid CA
      bundle path instead.
    pattern-either:
      - pattern: requests.$METHOD(..., verify=False, ...)
      - pattern: httpx.$METHOD(..., verify=False, ...)
      - pattern: httpx.Client(..., verify=False, ...)
      - pattern: httpx.AsyncClient(..., verify=False, ...)
    metadata:
      cwe: "CWE-295: Improper Certificate Validation"
      category: cryptography

  # ------------------------------------------------------------------------------------
  # RULE 8: TypeScript/JavaScript - Node.js child_process.exec Command Injection
  # ------------------------------------------------------------------------------------
  - id: audit-ts-child-process-exec-interpolation
    languages: [typescript, javascript]
    severity: ERROR
    message: >-
      Passing template literals or concatenated strings to child_process.exec() or
      execSync() spawns /bin/sh and introduces OS Command Injection (CWE-78). Use
      child_process.execFile() with an argument array and { shell: false }.
    pattern-either:
      - pattern: child_process.exec(`...${$VAR}...`, ...)
      - pattern: child_process.execSync(`...${$VAR}...`, ...)
      - pattern: exec(`...${$VAR}...`, ...)
      - pattern: execSync(`...${$VAR}...`, ...)
    metadata:
      cwe: "CWE-78: OS Command Injection"
      owasp: "A03:2021 - Injection"

  # ------------------------------------------------------------------------------------
  # RULE 9: TypeScript/JavaScript - Express JWT Verification Without Algorithm List
  # ------------------------------------------------------------------------------------
  - id: audit-ts-jsonwebtoken-missing-algorithms-option
    languages: [typescript, javascript]
    severity: ERROR
    message: >-
      Calling jwt.verify() without an explicit 'algorithms' allowlist option in the
      options object risks asymmetric-to-symmetric algorithm confusion (RFC 8725 / CWE-347).
      Specify { algorithms: ['RS256'], issuer: '...', audience: '...' }.
    patterns:
      - pattern: jwt.verify($TOKEN, $KEY)
    metadata:
      cwe: "CWE-347: Improper Verification of Cryptographic Signature"
      owasp: "A07:2021 - Identification and Authentication Failures"

  # ------------------------------------------------------------------------------------
  # RULE 10: TypeScript/JavaScript - React dangerouslySetInnerHTML Without DOMPurify
  # ------------------------------------------------------------------------------------
  - id: audit-ts-react-dangerouslysetinnerhtml-unsanitized
    languages: [typescript, javascript]
    severity: WARNING
    message: >-
      Rendering raw HTML via dangerouslySetInnerHTML without sanitizing through
      DOMPurify.sanitize() introduces DOM Cross-Site Scripting (CWE-79).
    patterns:
      - pattern: dangerouslySetInnerHTML={{ __html: $HTML }}
      - pattern-not: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(...) }}
    metadata:
      cwe: "CWE-79: Cross-site Scripting (XSS)"
      owasp: "A03:2021 - Injection"

  # ------------------------------------------------------------------------------------
  # RULE 11: TypeScript/JavaScript - PostMessage Wildcard TargetOrigin ('*') (CWE-345)
  # ------------------------------------------------------------------------------------
  - id: audit-ts-postmessage-wildcard-origin
    languages: [typescript, javascript]
    severity: ERROR
    message: >-
      Sending cross-window messages with targetOrigin '*' leaks the message payload to
      any malicious iframe or window reference (CWE-345). Specify an exact origin URL.
    pattern: $WINDOW.postMessage($MSG, "*")
    metadata:
      cwe: "CWE-345: Insufficient Verification of Data Authenticity"
      category: client-side

  # ------------------------------------------------------------------------------------
  # RULE 12: Java - Spring Expression Language (SpEL) Injection on Untrusted Input
  # ------------------------------------------------------------------------------------
  - id: audit-java-spel-standard-evaluation-context
    languages: [java]
    severity: ERROR
    message: >-
      Evaluating dynamic expressions with SpelExpressionParser without restricting to
      SimpleEvaluationContext allows arbitrary Java class instantiation and method
      invocation (CWE-917).
    patterns:
      - pattern: |
          ExpressionParser $P = new SpelExpressionParser(...);
          ...
          Expression $E = $P.parseExpression($INPUT);
          ...
          $E.getValue(...);
      - pattern-not-inside: |
          SimpleEvaluationContext $CTX = ...;
          ...
          $E.getValue($CTX, ...);
    metadata:
      cwe: "CWE-917: Expression Language Injection"
      owasp: "A03:2021 - Injection"

  # ------------------------------------------------------------------------------------
  # RULE 13: Java - Insecure AES ECB Mode or Static IV Usage (CWE-327)
  # ------------------------------------------------------------------------------------
  - id: audit-java-cipher-aes-ecb-mode
    languages: [java]
    severity: ERROR
    message: >-
      Cipher.getInstance("AES") defaults to ECB mode (AES/ECB/PKCS5Padding), which is
      deterministic and leaks plaintext block patterns (CWE-327). Use authenticated
      encryption: Cipher.getInstance("AES/GCM/NoPadding") with a 12-byte random IV.
    pattern-either:
      - pattern: Cipher.getInstance("AES")
      - pattern: Cipher.getInstance("AES/ECB/PKCS5Padding")
      - pattern: Cipher.getInstance("AES/ECB/NoPadding")
      - pattern: Cipher.getInstance("DES/...")
    metadata:
      cwe: "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"
      category: cryptography

  # ------------------------------------------------------------------------------------
  # RULE 14: Java - XML DocumentBuilderFactory Without Disallowing DOCTYPE (XXE CWE-611)
  # ------------------------------------------------------------------------------------
  - id: audit-java-xxe-missing-disallow-doctype
    languages: [java]
    severity: ERROR
    message: >-
      DocumentBuilderFactory.newInstance() is vulnerable to XML External Entity (XXE)
      injection unless 'http://apache.org/xml/features/disallow-doctype-decl' is
      explicitly set to true (CWE-611).
    patterns:
      - pattern: |
          DocumentBuilderFactory $DBF = DocumentBuilderFactory.newInstance();
          ...
          $DBF.newDocumentBuilder();
      - pattern-not: |
          DocumentBuilderFactory $DBF = DocumentBuilderFactory.newInstance();
          ...
          $DBF.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
          ...
          $DBF.newDocumentBuilder();
    metadata:
      cwe: "CWE-611: Improper Restriction of XML External Entity Reference"
      owasp: "A05:2021 - Security Misconfiguration"

  # ------------------------------------------------------------------------------------
  # RULE 15: Java - Jackson Polymorphic Deserialization Default Typing Enabled (CWE-502)
  # ------------------------------------------------------------------------------------
  - id: audit-java-jackson-enable-default-typing
    languages: [java]
    severity: ERROR
    message: >-
      Enabling DefaultTyping on Jackson ObjectMapper permits arbitrary polymorphic
      gadget instantiation from untrusted JSON payloads (CWE-502). Use explicit
      @JsonTypeInfo(use = Id.NAME) and @JsonSubTypes allowlists instead.
    pattern-either:
      - pattern: $MAPPER.enableDefaultTyping(...)
      - pattern: $MAPPER.activateDefaultTyping(...)
    metadata:
      cwe: "CWE-502: Deserialization of Untrusted Data"
      owasp: "A08:2021 - Software and Data Integrity Failures"

  # ------------------------------------------------------------------------------------
  # RULE 16: Go - Unbounded http.ListenAndServe Without Timeouts (Slowloris DoS CWE-400)
  # ------------------------------------------------------------------------------------
  - id: audit-go-http-listenandserve-no-timeouts
    languages: [go]
    severity: WARNING
    message: >-
      http.ListenAndServe() uses a default http.Server with zero ReadHeaderTimeout,
      ReadTimeout, or WriteTimeout, making the service vulnerable to Slowloris
      connection exhaustion (CWE-400). Instantiate an explicit &http.Server{} with
      strict timeouts.
    pattern-either:
      - pattern: http.ListenAndServe($ADDR, $HANDLER)
      - pattern: http.ListenAndServeTLS($ADDR, $CERT, $KEY, $HANDLER)
    metadata:
      cwe: "CWE-400: Uncontrolled Resource Consumption"
      category: availability

  # ------------------------------------------------------------------------------------
  # RULE 17: Go - TLS InsecureSkipVerify Enabled (CWE-295)
  # ------------------------------------------------------------------------------------
  - id: audit-go-tls-insecureskipverify-true
    languages: [go]
    severity: ERROR
    message: >-
      Setting InsecureSkipVerify: true in tls.Config disables all X.509 certificate
      chain and hostname validation, exposing connections to active interception (CWE-295).
    pattern: |
      &tls.Config{
          ...,
          InsecureSkipVerify: true,
          ...,
      }
    metadata:
      cwe: "CWE-295: Improper Certificate Validation"
      category: cryptography

  # ------------------------------------------------------------------------------------
  # RULE 18: Go - SQL String Formatting via fmt.Sprintf Inside db.Query / Exec (CWE-89)
  # ------------------------------------------------------------------------------------
  - id: audit-go-database-sql-sprintf-injection
    languages: [go]
    severity: ERROR
    message: >-
      Constructing SQL queries with fmt.Sprintf() introduces SQL Injection (CWE-89).
      Pass positional placeholders ($1, $2 or ?) to db.QueryContext / db.ExecContext.
    pattern-either:
      - pattern: $DB.Query(fmt.Sprintf(...), ...)
      - pattern: $DB.QueryContext($CTX, fmt.Sprintf(...), ...)
      - pattern: $DB.Exec(fmt.Sprintf(...), ...)
      - pattern: $DB.ExecContext($CTX, fmt.Sprintf(...), ...)
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 - Injection"

  # ------------------------------------------------------------------------------------
  # RULE 19: PHP (Laravel) - Eloquent Model Disabling Mass Assignment Guard (CWE-915)
  # ------------------------------------------------------------------------------------
  - id: audit-php-laravel-eloquent-empty-guarded
    languages: [php]
    severity: ERROR
    message: >-
      Setting protected $guarded = [] on an Eloquent Model disables Mass Assignment
      protection across all database columns (CWE-915). Declare an explicit
      protected $fillable = [...] allowlist instead.
    pattern: |
      class $MODEL extends Model {
          ...
          protected $guarded = [];
          ...
      }
    metadata:
      cwe: "CWE-915: Mass Assignment"
      owasp: "API3:2023 - Broken Object Property Level Authorization"

  # ------------------------------------------------------------------------------------
  # RULE 20: C# (.NET Core) - Entity Framework Core FromSqlRaw String Interpolation
  # ------------------------------------------------------------------------------------
  - id: audit-csharp-efcore-fromsqlraw-interpolated-string
    languages: [csharp]
    severity: ERROR
    message: >-
      Passing a C# interpolated string ($"...") into FromSqlRaw() or ExecuteSqlRaw()
      concatenates variables directly into SQL before parameterization (CWE-89). Use
      FromSqlInterpolated($"...") or FromSql($"...") so EF Core binds DbParameters.
    pattern-either:
      - pattern: $SET.FromSqlRaw($"...", ...)
      - pattern: $DB.ExecuteSqlRaw($"...", ...)
      - pattern: $DB.ExecuteSqlRawAsync($"...", ...)
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 - Injection"
```

---

# Section I.4: Inter-Procedural Taint Tracking with CodeQL

While syntactic AST tools like Semgrep excel at fast single-file pattern matching (`< 10 seconds` in CI), **CodeQL** compiles an entire repository into a relational semantic database, enabling **inter-procedural dataflow and taint tracking** across dozens of function calls, classes, and files.

## I.4.1 Anatomy of a CodeQL Taint-Tracking Query (`DataFlow::PathGraph`)

Every CodeQL security query defines three predicates inside a `TaintTracking::Configuration` (or modern `DataFlow::ConfigSig` module):
1. **`isSource(DataFlow::Node source)`**: Identifies where untrusted user input enters the program (e.g., an HTTP request parameter, header, or body).
2. **`isSink(DataFlow::Node sink)`**: Identifies the sensitive operation (e.g., the SQL string argument of `cursor.execute(sql)` or path argument of `open(path)`).
3. **`isBarrier(DataFlow::Node node)` (Sanitizer)**: Identifies validation steps that safely neutralize taint (e.g., casting the variable to an `int()`, looking it up in a static allowlist dictionary, or checking `path.is_relative_to(base_dir)`).

```ql
/**
 * @name Inter-procedural SQL Injection from FastAPI Request Parameter to Database Sink
 * @description Tracks untrusted HTTP request inputs across function calls into raw SQL execution
 *              when no integer conversion or allowlist barrier intervenes.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @id py/enterprise-interprocedural-sql-injection
 * @tags security
 *       external/cwe/cwe-89
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
import DataFlow::PathGraph

module EnterpriseSqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Sources: FastAPI / Flask HTTP request inputs
    exists(DataFlow::Node reqAttr |
      reqAttr = API::moduleImport("fastapi").getMember("Request").getInstance().getAMember().getACall()
      and source = reqAttr
    )
  }

  predicate isBarrier(DataFlow::Node sanitizer) {
    // Barrier 1: Explicit integer type conversion int(x)
    sanitizer = API::builtin("int").getACall()
  }

  predicate isSink(DataFlow::Node sink) {
    // Sink: First positional argument (the SQL query string) of cursor.execute(sql, ...)
    exists(DataFlow::CallCfgNode call |
      call.getFunction().asCfgNode().(AttrNode).getName() = "execute" and
      sink.asCfgNode() = call.getArg(0).asCfgNode()
    )
  }
}

module SqlInjectionFlow = TaintTracking::Global<EnterpriseSqlInjectionConfig>;

from SqlInjectionFlow::PathNode source, SqlInjectionFlow::PathNode sink
where SqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted HTTP input from $@ flows into raw SQL execution without parameterization.",
  source.getNode(), "this request source"
```

---

## Appendix I: Master Enterprise Pull Request Secure Code Review Checklist

Before approving any Pull Request that introduces or modifies an API endpoint, database query, authentication workflow, or external integration, verify the following **12 Mandatory Architectural Gates**:

| Gate # | Control Domain | Mandatory Verification Question | Pass Criteria |
| :--- | :--- | :--- | :--- |
| **1** | **Authentication** | Does the endpoint enforce authentication via centralized middleware, and are step-up MFA states verified server-side? | Unauthenticated requests deterministically return `401 Unauthorized`. |
| **2** | **Function-Level Auth (BFLA)** | Is the caller's role/permission scope (`permissions.includes("...")`) checked before executing the controller action? | Standard users calling admin actions deterministically return `403 Forbidden`. |
| **3** | **Object-Level Auth (BOLA/IDOR)** | Does every database query (`SELECT`/`UPDATE`/`DELETE`) scope the `WHERE` clause by the authenticated session's `tenant_id` and `owner_id`? | Cross-tenant object ID access returns `404 Not Found` and modifies zero rows. |
| **4** | **Property-Level Auth (BOPLA)** | Are both the request body and response body bound to explicit, strict DTO schemas (`extra="forbid"`) rather than raw ORM models? | Unapproved input properties are rejected (`400`/`422`); internal columns are never serialized. |
| **5** | **Parameterized Persistence** | Are all SQL/NoSQL queries parameterized (`?`, `$1`, `%s`), and are dynamic `ORDER BY` identifiers resolved from a hardcoded dictionary? | Zero string interpolation (`f"..."`, `${...}`, `+`) inside any query builder. |
| **6** | **Concurrency & Financial Integrity** | Are balance deductions or quota checks protected against race conditions via atomic SQL updates (`WHERE balance >= $1`) or `SELECT ... FOR UPDATE` + idempotency keys? | Parallel duplicate requests (`N=20`) never overdraw balances or duplicate payouts. |
| **7** | **Outbound Network (SSRF)** | If the code makes outbound HTTP calls to user-influenced URLs, does it validate `ip.is_global`, block redirects, and use an isolated egress proxy? | Requests resolving to `127.0.0.0/8`, `10.0.0.0/8`, `169.254.169.254`, or `::1` are blocked before socket connect. |
| **8** | **File & Archive Handling** | Are file paths verified with `.resolve().is_relative_to(base_dir)`, and are uploads stored outside the web root with generated UUID keys? | Path traversal sequences (`../`, symlinks, Zip Slip) are rejected prior to file I/O. |
| **9** | **Serialization & XML/YAML** | Are all parsers safe-by-default (`json.loads`, `yaml.safe_load`, `defusedxml`, `disallow-doctype-decl`)? | Zero usage of `pickle`, `unserialize`, `BinaryFormatter`, or DTD-enabled XML parsers. |
| **10** | **Cryptographic Hygiene** | Are secrets generated with CSPRNG (`secrets`/`crypto.randomBytes`), passwords hashed with `Argon2id`, and signatures compared with `hmac.compare_digest`? | Zero usage of `random`, `Math.random`, `MD5`/`SHA1`, `AES-ECB`, or hardcoded secrets. |
| **11** | **Error Handling & Logging** | Are unhandled exceptions caught by a global RFC 9457 handler that logs stack traces internally while returning sanitized JSON externally? | Zero stack traces, SQL errors, or PII/tokens written to client responses or plaintext logs. |
| **12** | **Resource Bounds & DoS** | Are request body sizes, pagination `limit` parameters, regex inputs, and upstream network timeouts strictly bounded? | Every I/O call has an explicit timeout; every list query enforces `LIMIT <= 100`. |


---

# Section I.5: End-to-End Architectural Threat Model & Code Audit Case Studies

To demonstrate how Threat Modeling (Section I.1), Manual Secure Code Review (Section I.2), and Automated SAST Rules (Sections I.3–I.4) work together in practice, this section presents three complete end-to-end engineering case studies:
1. **Case Study A:** FinTech Instant Wallet Transfer Microservice (Python / FastAPI / PostgreSQL)
2. **Case Study B:** Multi-Tenant B2B Document Processing Worker (TypeScript / Node.js / Express)
3. **Case Study C:** Enterprise Healthcare SSO & Patient Record Service (Java / Spring Boot / Hibernate)

---

## I.5.1 Case Study A: FinTech Instant Wallet Transfer Microservice (Python / FastAPI)

### 1. Architectural Context & Threat Model (STRIDE Analysis)
A FinTech startup builds an instant peer-to-peer wallet transfer endpoint (`POST /api/v1/wallets/transfer`) allowing authenticated users to send funds (in LKR) to another user's wallet.

| STRIDE Dimension | Identified Threat in Initial Design | Architectural Mitigation Required |
| :--- | :--- | :--- |
| **Spoofing** | Replaying a captured request or retrying a network timeout executes duplicate debits | Require a mandatory `Idempotency-Key` UUIDv4 header stored with a unique constraint per `(sender_id, idempotency_key)` |
| **Tampering** | Supplying a negative `amount` (`-5000.00`) reverses the transfer direction and steals funds from the recipient! | Enforce strict integer cents (`amount_cents > 0`) at both the Pydantic DTO layer and PostgreSQL `CHECK (balance_cents >= 0)` constraint |
| **Repudiation** | Mutable wallet balance column updated in-place without an immutable double-entry ledger journal | Record every debit/credit pair in an append-only `ledger_entries` table inside the same ACID transaction |
| **Information Disclosure** | Error handler returns full SQLAlchemy exception when recipient wallet does not exist | Return generic RFC 9457 Problem Details JSON response |
| **Denial of Service** | Two concurrent transfers between User A -> User B and User B -> User A lock rows in opposite order, causing database deadlocks | Lock wallet rows in deterministic ascending primary-key order (`ORDER BY wallet_id ASC FOR UPDATE`) |
| **Elevation of Privilege** | Race condition (TOCTOU) allows 10 parallel requests to overdraw the sender's wallet balance | Acquire pessimistic row locks (`SELECT ... FOR UPDATE`) before checking balance, inside a `SERIALIZABLE` or `READ COMMITTED` transaction |

### 2. Side-by-Side Code Audit: Vulnerable vs. Hardened FinTech Ledger Service

```python
# ============================================================================
# VULNERABLE FINTECH WALLET TRANSFER CODE (Multiple Critical Flaws)
# ============================================================================
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

router = APIRouter()

@router.post("/api/v1/wallets/transfer")
def transfer_funds_vulnerable(
    sender_wallet_id: str,      # FLAW 1 (BOLA): Trusts sender_wallet_id from client!
    recipient_wallet_id: str,
    amount: float,              # FLAW 2 (Precision & Negative Amount): Uses float & no > 0 check!
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # FLAW 3 (TOCTOU Race Condition): Reads balance without row-level locking (FOR UPDATE)!
    sender = db.query(Wallet).filter(Wallet.id == sender_wallet_id).first()
    recipient = db.query(Wallet).filter(Wallet.id == recipient_wallet_id).first()

    if sender.balance < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    # If amount is -1000.0, sender.balance -= (-1000.0) INCREASES sender's balance!
    sender.balance -= amount
    recipient.balance += amount
    db.commit()
    return {"status": "ok", "new_balance": sender.balance}
```

```python
# ============================================================================
# REMEDIATED SECURE FINTECH WALLET TRANSFER CODE (ACID + Row Locking + Idempotency)
# ============================================================================
import uuid
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

router = APIRouter()


class TransferRequestDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recipient_wallet_id: uuid.UUID
    # Store and validate strictly as positive integer cents (min 100 cents = 1.00 LKR, max 10M)
    amount_cents: int = Field(..., gt=0, le=100_000_000)
    reference_note: str = Field(default="", max_length=140)


class TransferResponseDTO(BaseModel):
    transaction_id: uuid.UUID
    status: str
    debited_cents: int
    remaining_balance_cents: int


@router.post(
    "/api/v1/wallets/transfer",
    response_model=TransferResponseDTO,
    status_code=status.HTTP_201_CREATED,
)
def transfer_funds_secure(
    dto: TransferRequestDTO,
    idempotency_key: uuid.UUID = Header(..., alias="Idempotency-Key"),
    current_user=Depends(get_authenticated_mfa_user),
    db: Session = Depends(get_db),
):
    # 1. Resolve sender's wallet strictly from authenticated user identity (Prevents BOLA)
    sender_wallet_id: uuid.UUID = current_user.primary_wallet_id
    if sender_wallet_id == dto.recipient_wallet_id:
        raise HTTPException(status_code=400, detail="Cannot transfer to the same wallet")

    # 2. Sort wallet UUIDs deterministically before acquiring FOR UPDATE locks
    #    to guarantee deadlock-free concurrent execution when A->B and B->A run simultaneously.
    ordered_ids = sorted([sender_wallet_id, dto.recipient_wallet_id])

    try:
        with db.begin_nested():
            # 3. Record Idempotency Key first (unique constraint on sender_id + idempotency_key)
            idem_record = IdempotencyRecord(
                sender_user_id=current_user.id,
                idempotency_key=idempotency_key,
            )
            db.add(idem_record)
            db.flush()

            # 4. Acquire pessimistic row-level locks in deterministic primary-key order
            stmt = (
                select(Wallet)
                .where(Wallet.id.in_(ordered_ids))
                .order_by(Wallet.id.asc())
                .with_for_update()
            )
            locked_wallets = {w.id: w for w in db.execute(stmt).scalars().all()}

            sender_wallet = locked_wallets.get(sender_wallet_id)
            recipient_wallet = locked_wallets.get(dto.recipient_wallet_id)

            if sender_wallet is None or recipient_wallet is None:
                raise HTTPException(status_code=404, detail="Recipient wallet not found")

            if not sender_wallet.is_active or not recipient_wallet.is_active:
                raise HTTPException(status_code=403, detail="Wallet is frozen or inactive")

            # 5. Verify sufficient balance under exclusive row lock (Eliminates TOCTOU)
            if sender_wallet.balance_cents < dto.amount_cents:
                raise HTTPException(status_code=422, detail="Insufficient wallet balance")

            # 6. Execute atomic balance update and append immutable double-entry ledger rows
            sender_wallet.balance_cents -= dto.amount_cents
            recipient_wallet.balance_cents += dto.amount_cents

            txn_id = uuid.uuid4()
            db.add(
                LedgerEntry(
                    transaction_id=txn_id,
                    wallet_id=sender_wallet.id,
                    direction="DEBIT",
                    amount_cents=dto.amount_cents,
                    balance_after_cents=sender_wallet.balance_cents,
                )
            )
            db.add(
                LedgerEntry(
                    transaction_id=txn_id,
                    wallet_id=recipient_wallet.id,
                    direction="CREDIT",
                    amount_cents=dto.amount_cents,
                    balance_after_cents=recipient_wallet.balance_cents,
                )
            )

        db.commit()
        return TransferResponseDTO(
            transaction_id=txn_id,
            status="COMPLETED",
            debited_cents=dto.amount_cents,
            remaining_balance_cents=sender_wallet.balance_cents,
        )
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Duplicate Idempotency-Key: transfer request already processed",
        )
```

---

## I.5.2 Case Study B: Multi-Tenant B2B Document Processing Worker (TypeScript / Node.js)

### 1. Architectural Context & Threat Model
An enterprise SaaS platform allows tenant users to import data via a remote HTTPS JSON feed URL (`POST /api/v1/imports/url`) and merge the imported metadata into their workspace configuration.

### 2. Side-by-Side Code Audit: Vulnerable vs. Hardened Node.js Controller

```typescript
// ============================================================================
// VULNERABLE NODE.JS DOCUMENT IMPORT CONTROLLER (SSRF + Prototype Pollution + Path Traversal)
// ============================================================================
import express from 'express';
import axios from 'axios';
import fs from 'fs';
import path from 'path';

const app = express();
app.use(express.json());

app.post('/api/v1/imports/url', async (req, res) => {
  const { feedUrl, localCacheFile, customConfig } = req.body;

  // FLAW 1 (SSRF): Fetches arbitrary user-supplied URL without IP/scheme validation!
  const response = await axios.get(feedUrl);

  // FLAW 2 (Prototype Pollution): Unsafe recursive merge of untrusted JSON keys!
  const mergedConfig: any = {};
  for (const k of Object.keys(customConfig)) {
    mergedConfig[k] = customConfig[k];
  }

  // FLAW 3 (Path Traversal): Writes file using unvalidated localCacheFile path!
  const targetPath = path.join('/var/app/cache', localCacheFile);
  fs.writeFileSync(targetPath, JSON.stringify(response.data));

  res.json({ status: 'imported', config: mergedConfig });
});
```

```typescript
// ============================================================================
// REMEDIATED SECURE NODE.JS DOCUMENT IMPORT CONTROLLER
// ============================================================================
import express, { Request, Response } from 'express';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { z } from 'zod';

const CACHE_BASE_DIR = path.resolve('/var/app/cache');

// 1. Strict Zod validation schema rejecting unknown keys and bounding string lengths
const ImportRequestSchema = z
  .object({
    feedUrl: z
      .string()
      .url()
      .refine((u) => u.startsWith('https://'), {
        message: 'Only HTTPS URLs are permitted',
      }),
    customConfig: z.record(
      z.string().regex(/^[a-zA-Z0-9_]{1,32}$/),
      z.union([z.string().max(256), z.number(), z.boolean()])
    ),
  })
  .strict();

export async function handleDocumentImportSecure(req: Request, res: Response) {
  const parsed = ImportRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input schema' });
  }

  const { feedUrl, customConfig } = parsed.data;

  // 2. Construct null-prototype object and forbid prototype chain properties
  const safeConfig: Record<string, string | number | boolean> = Object.create(null);
  for (const [key, val] of Object.entries(customConfig)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return res.status(400).json({ error: 'Forbidden property key' });
    }
    safeConfig[key] = val;
  }

  // 3. Never accept filenames from client; generate an immutable server-side UUIDv4 filename
  const generatedFileName = `${crypto.randomUUID()}.json`;
  const resolvedTarget = path.resolve(CACHE_BASE_DIR, generatedFileName);

  // Verify canonical path containment inside CACHE_BASE_DIR
  if (!resolvedTarget.startsWith(CACHE_BASE_DIR + path.sep)) {
    return res.status(403).json({ error: 'Invalid storage path' });
  }

  // (Note: feedUrl must be fetched via the dedicated SSRF-safe egress proxy / socket guard)
  await fs.writeFile(resolvedTarget, JSON.stringify({ feedUrl, safeConfig }), {
    encoding: 'utf-8',
    mode: 0o600,
  });

  return res.status(201).json({ cacheId: generatedFileName });
}
```

---

# Section I.6: CI/CD DevSecOps Pipeline Architecture & Automated SARIF Gateways

To operationalize threat modeling and secure code review across an engineering organization, security checks must run automatically on every commit and pull request using the **Static Analysis Results Interchange Format (SARIF v2.1.0, OASIS Standard)**.

```
+-----------------------------------------------------------------------------------+
|               ENTERPRISE DEVSECOPS PULL REQUEST SECURITY GATEWAY                  |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [Developer git push / Pull Request]                                              |
|         |                                                                         |
|         v                                                                         |
|  +-----------------------------------------------------------------------------+  |
|  | Stage 1: Secret & Dependency Hygiene (< 15 Seconds)                         |  |
|  |  - Gitleaks / TruffleHog (Blocks hardcoded API keys, JWT secrets, PEM keys) |  |
|  |  - OSV-Scanner / Trivy SCA (Blocks known vulnerable transitive CVEs + SBOM) |  |
|  +-----------------------------------------------------------------------------+  |
|         |                                                                         |
|         v                                                                         |
|  +-----------------------------------------------------------------------------+  |
|  | Stage 2: Custom SAST & Taint Analysis (< 90 Seconds)                        |  |
|  |  - Semgrep Custom Ruleset (Enforces 20 architectural & framework rules)     |  |
|  |  - CodeQL Inter-Procedural Taint Analysis (Emits SARIF v2.1.0 report)       |  |
|  +-----------------------------------------------------------------------------+  |
|         |                                                                         |
|         v                                                                         |
|  +-----------------------------------------------------------------------------+  |
|  | Stage 3: Infrastructure-as-Code & Container Verification (< 60 Seconds)     |  |
|  |  - Checkov / Trivy Config (Verifies S3 Public Block, IMDSv2, K8s Non-Root)  |  |
|  |  - Authorization Matrix Pytest Suite (Verifies BOLA / BFLA / 401 Gates)     |  |
|  +-----------------------------------------------------------------------------+  |
|         |                                                                         |
|         v                                                                         |
|  [Automated Merge Gate: Blocks PR Merge on Any HIGH / CRITICAL SARIF Finding]     |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

## I.6.1 Complete GitHub Actions DevSecOps Workflow (`.github/workflows/appsec-gate.yml`)

Below is a production-ready CI/CD pipeline configuration that runs **Gitleaks** (secret scanning), **Semgrep** (custom SAST rules emitting SARIF), **Trivy** (Software Composition Analysis & IaC scanning), and the **Automated Authorization Matrix Test Suite** on every Pull Request:

```yaml
# .github/workflows/appsec-gate.yml
name: Enterprise AppSec & Secure Code Review Gate

on:
  pull_request:
    branches: [ "main", "release/*" ]
  push:
    branches: [ "main" ]

permissions:
  contents: read
  security-events: write
  actions: read

jobs:
  secret-and-sca-audit:
    name: "1. Secret Scanning & Dependency SCA"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository (Full History for Secret Audit)
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Gitleaks Secret Scanner
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Run Trivy Vulnerability & IaC Misconfiguration Scanner
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: "fs"
          scanners: "vuln,misconfig"
          severity: "CRITICAL,HIGH"
          exit-code: "1"
          ignore-unfixed: true

  custom-sast-semgrep:
    name: "2. Custom Semgrep SAST & SARIF Upload"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Execute Enterprise Custom Semgrep Rules
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/default
            p/owasp-top-ten
            enterprise_code_audit_rules.yaml
          generateSarif: "1"

      - name: Upload SARIF Findings to GitHub Code Scanning Tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif

  authorization-matrix-verification:
    name: "3. Automated BOLA / BFLA Authorization Matrix Suite"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Set up Python 3.12
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install Test Dependencies
        run: |
          python -m pip install --upgrade pip
          pip install pytest httpx pydantic

      - name: Run Authorization Matrix Integration Suite
        run: |
          pytest --maxfail=1 --disable-warnings -v
```

---

## Appendix I: Review Exercises & Threat Modeling Workshop Problems

### Exercise I.1: Constructing a STRIDE Threat Model & Attack Tree for an AI-Powered HR Portal
An enterprise builds an internal AI Assistant that answers employee questions by querying a Vector Database (RAG) populated with HR policy PDFs, executive compensation spreadsheets, and engineering design docs, and can invoke an internal API tool `update_employee_address(employee_id, new_address)`.
1. Draw the Data Flow Diagram (DFD) identifying all External Entities, Processes, Data Stores, Data Flows, and Trust Boundaries.
2. Apply **STRIDE** and the **OWASP Top 10 for LLM Applications** to identify how **Indirect Prompt Injection (`LLM01`)** and **ACL-Unaware Vector Retrieval (`LLM06`)** could lead to unauthorized disclosure of executive compensation data or unauthorized modification of another employee's address.
3. Specify the exact architectural controls required at the Vector DB retrieval layer and the Tool-Calling Policy Enforcement Point (PEP).

### Exercise I.2: Auditing a Multi-Threaded Payment Withdrawal Service for Concurrency Bugs
Explain why wrapping a database `SELECT` and `UPDATE` inside a default `READ COMMITTED` transaction without `SELECT ... FOR UPDATE` or an atomic `WHERE balance >= $1` predicate fails to prevent double-spending when 20 parallel HTTP/2 requests arrive simultaneously. Write the exact SQL query and dead-lock prevention ordering rule required to make a peer-to-peer wallet transfer atomic.

### Exercise I.3: Authoring a Custom Semgrep Rule for Framework-Specific Access Control
Write a custom Semgrep YAML rule (`id: audit-fastapi-missing-auth-dependency`) that flags any FastAPI `@router.post(...)`, `@router.put(...)`, or `@router.delete(...)` endpoint function that does not include `Depends(get_authenticated_user)` or `Depends(require_admin)` in its parameter list or decorator `dependencies=[...]`.
