# VAPT — Vulnerability Assessment & Penetration Testing Report
### Security Assessment Report — Companies Act 2013 Compliance Tool

---

| | |
|---|---|
| **Prepared by** | Yusuf |
| **Role** | Security Reviewer |
| **Institution** | St. Joseph Engineering College (SJEC) |
| **Date** | May 2025 |
| **Classification** | CONFIDENTIAL |

---

## 01 — Executive Summary

This report documents the findings of a Vulnerability Assessment and Penetration Testing (VAPT) exercise conducted on the **Companies Act 2013 Compliance Tool** — a web-based platform designed to help organizations track and maintain compliance with India's Companies Act 2013.

The assessment followed the **OWASP Testing Guide (OTG v4.2)** and **PTES methodology**. Testing was performed in a controlled staging environment. A total of **12 vulnerabilities** were identified across the application stack.

| Severity | Count |
|---|---|
| 🔴 Critical | 1 |
| 🟠 High | 4 |
| 🟡 Medium | 3 |
| 🟢 Low / Info | 4 |

> Immediate remediation is advised for all Critical and High severity findings. The tool handles sensitive compliance records and director-level company data — any breach could result in regulatory penalties and reputational damage for the organizations relying on it.

---

## 02 — Scope of Assessment

| Field | Details |
|---|---|
| Application | Companies Act 2013 Compliance Tool |
| Application Type | Web-based compliance management platform |
| Assessment Type | Black Box + Grey Box |
| Environment | Staging / Test instance |
| Assessment Date | May 2025 |
| Tools Used | Burp Suite, OWASP ZAP, Nmap, Nikto, SQLMap, Dirb |
| Standards | OWASP Top 10 (2021), NIST SP 800-115, PTES |

### In-Scope Components
- User authentication and session management module
- Company profile creation and management flows
- Compliance deadline tracking dashboard
- Document upload and filing submission endpoints
- Admin panel and role management interface
- All exposed API endpoints and form inputs

### Out-of-Scope
- Third-party integrations (MCA portal, payment gateway)
- Mobile application (not yet deployed)
- Physical server infrastructure and network layer
- Social engineering, phishing, or DoS testing

---

## 03 — Methodology

Testing followed a structured five-phase approach:

| Phase | Name | Description |
|---|---|---|
| 01 | Reconnaissance | Passive and active information gathering — identifying technology stack, exposed endpoints, and entry points of the Compliance Tool. |
| 02 | Scanning | Automated scanning with Nmap, Nikto, and OWASP ZAP to enumerate open services, outdated components, and known CVEs. |
| 03 | Exploitation | Controlled manual exploitation of identified vulnerabilities — validating existence, assessing exploitability, and measuring business impact. |
| 04 | Post-Exploitation | Evaluating lateral movement potential after initial access — privilege escalation paths and data accessible to an attacker. |
| 05 | Reporting | Documenting all findings with severity ratings, reproduction steps, and tailored remediation recommendations. |

---

## 04 — Findings Summary

| # | Vulnerability | Severity | CVSS | Component | Status |
|---|---|---|---|---|---|
| 1 | SQL Injection — Login & Search Endpoints | 🔴 Critical | 9.8 | Auth Module | Open |
| 2 | Cross-Site Scripting (Stored XSS) | 🟠 High | 7.6 | Filing Dashboard | Open |
| 3 | Broken Authentication / Weak Session Tokens | 🟠 High | 7.1 | Session Manager | Open |
| 4 | Insecure Direct Object Reference (IDOR) | 🟠 High | 6.8 | Company Records | Open |
| 5 | Missing Role-Based Access Control | 🟠 High | 6.5 | Admin Panel | Open |
| 6 | Sensitive Data Exposure (Plaintext Passwords) | 🟡 Medium | 5.9 | Database Layer | Open |
| 7 | Security Misconfiguration (Default Credentials) | 🟡 Medium | 5.3 | Server Config | Open |
| 8 | Missing HTTP Security Headers | 🟡 Medium | 4.3 | Web Server | Open |
| 9 | Directory Traversal in File Upload | 🟡 Medium | 4.8 | Document Upload | Open |
| 10 | Outdated Libraries with Known CVEs | 🟢 Low | 3.1 | Dependencies | Open |
| 11 | Verbose Error Messages (Stack Trace Disclosure) | 🟢 Low | 2.6 | Error Handler | Open |
| 12 | Server Version Disclosure via Response Headers | 🔵 Info | 0.0 | HTTP Headers | Informational |

---

## 05 — Detailed Findings

---

### F-01 · SQL Injection — `CRITICAL` · CVSS 9.8

| Field | Detail |
|---|---|
| CWE | CWE-89 — Improper Neutralization of SQL Commands |
| Component | Login form, company search endpoint |
| Impact | Authentication bypass, full database extraction |

The login form and company search fields were directly concatenating user input into SQL queries without sanitization. An attacker can manipulate the query logic to bypass authentication, enumerate database tables, and extract the full compliance records database — including director details and filing histories.

**Proof of Concept**
```
Username: ' OR '1'='1' --
Result:   Authentication bypassed. Logged in as admin without credentials.
```

**Remediation**
- Replace all raw SQL queries with parameterized queries or prepared statements
- Implement an ORM layer to abstract direct database access
- Deploy a Web Application Firewall (WAF) with SQL injection detection rules
- Audit every input field that interacts with the database

---

### F-02 · Cross-Site Scripting (Stored XSS) — `HIGH` · CVSS 7.6

| Field | Detail |
|---|---|
| CWE | CWE-79 — Improper Neutralization of Input During Web Page Generation |
| Component | Filing dashboard, company remarks field |
| Impact | Session hijacking, credential theft, page defacement |

Stored XSS was identified in the company filing remarks and notes fields. Injected scripts persist in the database and execute in the browser of every user who views the affected record — including compliance officers and administrators.

**Remediation**
- Apply context-aware output encoding on all user-supplied data rendered in the UI
- Implement a strict Content Security Policy (CSP) header
- Use a frontend framework with auto-escaping (React, Angular)
- Sanitize inputs server-side using an allowlist-based validation library

---

### F-03 · Broken Authentication & Weak Session Management — `HIGH` · CVSS 7.1

| Field | Detail |
|---|---|
| CWE | CWE-287 — Improper Authentication |
| Component | Session management, login endpoint |
| Impact | Session hijacking, unauthorized access to compliance records |

Session tokens were short, predictable, and not invalidated upon logout. The login endpoint had no rate limiting or account lockout policy, making it susceptible to brute force and credential stuffing attacks.

**Remediation**
- Generate session IDs using a CSPRNG with at least 128 bits of entropy
- Enforce session invalidation on logout, password change, and after 15 minutes of inactivity
- Implement rate limiting (5 attempts) and account lockout on the login endpoint
- Enforce MFA for admin and CA-level accounts

---

### F-04 · Insecure Direct Object Reference (IDOR) — `HIGH` · CVSS 6.8

| Field | Detail |
|---|---|
| CWE | CWE-639 — Authorization Bypass Through User-Controlled Key |
| Component | Company records, document download endpoint |
| Impact | Unauthorized access to confidential company compliance data |

The application uses sequential numeric IDs in URLs to reference company records (e.g. `/company/record?id=104`). No server-side authorization check verifies whether the logged-in user is permitted to access the requested record. By incrementing the ID, any authenticated user can access data belonging to other companies.

**Remediation**
- Enforce server-side authorization checks for every resource access request
- Replace sequential IDs with UUIDs or indirect reference maps that are user-scoped
- Implement RBAC to restrict data access to the owning user or organization

---

### F-05 · Missing Role-Based Access Control — `HIGH` · CVSS 6.5

| Field | Detail |
|---|---|
| Component | Admin panel, privileged routes |
| Impact | Privilege escalation, unauthorized admin actions |

Standard user accounts were able to access admin-only functions — including user management, audit log viewing, and bulk data export — by directly navigating to admin routes. No server-side role enforcement was present.

**Remediation**
- Enforce role checks server-side on every protected route and API endpoint
- Adopt a deny-by-default policy — explicitly grant access rather than blocking it
- Conduct a full authorization audit across all application routes

---

### F-06 · Sensitive Data Exposure — `MEDIUM` · CVSS 5.9

Passwords were stored in plaintext in the database. Sensitive PII including PAN numbers and director details were unencrypted at rest.

**Remediation**
- Hash all passwords using bcrypt or Argon2id (minimum cost factor 12)
- Encrypt sensitive PII fields using AES-256 at the application layer
- Enforce HTTPS with TLS 1.2+ on all endpoints; implement HSTS

---

### F-07 · Security Misconfiguration — `MEDIUM` · CVSS 5.3

Default credentials (`admin / admin123`) were active on the admin panel. Directory listing was enabled on the web server, exposing the application's internal file structure.

**Remediation**
- Change all default credentials immediately post-deployment
- Disable directory listing in the server configuration
- Harden server settings per CIS Benchmarks; remove unused modules and services

---

### F-08 · Missing HTTP Security Headers — `MEDIUM` · CVSS 4.3

The application lacked `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, and `Content-Security-Policy` headers, leaving it open to clickjacking and MIME-sniffing attacks.

**Remediation**
- Configure the web server to include all OWASP-recommended security headers on every response

---

### F-09 · Directory Traversal in Document Upload — `MEDIUM` · CVSS 4.8

The document upload module did not validate file paths, allowing traversal to arbitrary server directories using `../` sequences.

**Remediation**
- Validate and normalize all uploaded file paths server-side
- Restrict file writes to a designated sandboxed upload directory with no execute permissions

---

### F-10 · Outdated Libraries with Known CVEs — `LOW` · CVSS 3.1

Several third-party dependencies were found to be running outdated versions with publicly known CVEs.

**Remediation** — Update all packages to latest stable versions; monitor continuously via Dependabot or Snyk.

---

### F-11 · Verbose Error Messages — `LOW` · CVSS 2.6

Full stack traces were returned in HTTP responses on error, disclosing internal application structure and file paths.

**Remediation** — Disable debug mode in production; implement generic custom error pages.

---

### F-12 · Server Version Disclosure — `INFO` · CVSS 0.0

`Server` and `X-Powered-By` response headers were disclosing the exact server version and technology stack, aiding attacker reconnaissance.

**Remediation** — Suppress version-disclosing headers in production server configuration.

---

## 06 — Risk Matrix

| Finding | Likelihood | Impact | Risk Level | Priority |
|---|---|---|---|---|
| SQL Injection | High | Critical | **Critical** | Now |
| Stored XSS | High | High | **High** | Urgent |
| Broken Auth | Medium | High | **High** | Urgent |
| IDOR | Medium | High | **High** | Urgent |
| Missing RBAC | Medium | High | **High** | Urgent |
| Data Exposure | Low | High | **Medium** | 1 Week |
| Misconfiguration | Medium | Medium | **Medium** | 1 Week |
| Missing Headers | High | Low | **Medium** | 1 Week |

---

## 07 — Recommendations

### Immediate — Critical & High
- Rewrite all database queries using parameterized statements or an ORM
- Apply output encoding and CSP to eliminate XSS attack surface
- Rebuild session management with CSPRNG tokens, proper invalidation, and MFA for admin accounts
- Implement server-side RBAC and replace sequential IDs with UUIDs across all resource endpoints

### Short-Term — Within 2 Weeks
- Hash all stored passwords with bcrypt / Argon2id; encrypt sensitive PII at rest
- Change default credentials; disable directory listing; harden server config per CIS Benchmarks
- Add all missing HTTP security headers; enforce HTTPS with HSTS
- Fix directory traversal in the document upload module

### Long-Term — Preventive Posture
- Integrate SAST/DAST scanning into the CI/CD pipeline (OWASP ZAP, SonarQube)
- Establish a quarterly VAPT cycle for the Compliance Tool
- Run OWASP Top 10 security training for the development team
- Maintain a vulnerability register and track remediation status to closure

---

## 08 — Conclusion

The Companies Act 2013 Compliance Tool in its current state carries significant security risk. The critical SQL Injection vulnerability alone could allow a complete database compromise, exposing the confidential compliance records of every company registered on the platform.

Given the sensitivity of the data handled — director details, filing statuses, and regulatory documents — remediation of all Critical and High findings should be treated as a blocker before any production deployment. Following remediation, a re-test is strongly recommended to verify that all identified issues have been fully resolved.

Building security into the development lifecycle from the start — rather than as a post-hoc assessment — will significantly reduce both the cost of remediation and the risk exposure of the platform going forward.

---

## 09 — Disclaimer

This report was prepared solely for the internal use of the project stakeholders. All testing was conducted in a controlled staging environment with explicit authorization. Findings reflect the security posture of the application at the time of assessment and may not account for changes made after that date.

The contents of this report are confidential and should be shared only with personnel directly responsible for remediation.

---

*Prepared by Yusuf · Security Reviewer · SJEC · May 2025*
