# Phase 2: Functional Gaps and Data Model Cleanup Report

This report documents the security hardening, naming alignment, database cascading rules, active threat logging integrations, and test verification details completed during Phase 2 of CyberGuard AI.

---

## 1. Cryptographic Password Reset Design

### 1.1 Old Reset Workflow (Legacy)
- **Token Mechanism**: Mock token string derived from UUID (`rst_{user.uuid[:8]}_token`).
- **Security Flaws**:
  - **No Expiration**: Reset tokens were infinite and did not expire.
  - **Infinite Reuse**: A single token could be reused multiple times to change passwords.
  - **Insecure Parsing**: Derived from user UUID, making tokens guessable/derivable.

### 1.2 New Cryptographic Reset Workflow
- **Token Mechanism**: Cryptographically signed JSON Web Token-style timed serializer using `itsdangerous.URLSafeTimedSerializer`.
- **Payload Bound**: Bundles `(user.email, user.password_hash)`.
- **Expiration Enforcement**: Checked against a strict 15-minute window (`max_age=900`).
- **Reuse Prevention**: Once the password is changed, the user's password hash in the database changes. This makes the hash inside pre-existing tokens mismatch, rendering them immediately invalid.

---

## 2. Security Score Semantics Alignment

### 2.1 Mismatch Resolution
- **Issue**: The database column `risk_score` actually represented a "Security Compliance Score" (where 100 is best/fully compliant, and 0 is insecure). This conflicted with "risk" definitions where higher numbers denote greater risk.
- **Solution**: Implemented an ORM-level `@hybrid_property` alias called `security_score` on the `Scan` model.
- **Benefit**: Retains full SQLite compatibility without requiring complex, risky schema changes, while aligning application-level code, views, reports, and API responses with semantic security definitions.

---

## 3. Database Cascade Mappings

### 3.1 Orphan Records Prevention
- **Old Setup**: SQLite foreign keys cascade rules were only database-level, leaving orphans if SQLite `PRAGMA foreign_keys = ON;` was disabled.
- **New Setup**: Defined explicit SQLAlchemy relationship cascading rules on the `User` model:
  - `network_scans`: `cascade='all, delete-orphan'`
  - `saved_passwords`: `cascade='all, delete-orphan'`
- **Effect**: Deleting a user account now automatically and cleanly deletes all of their simulated network scans and saved password vault records.

---

## 4. Threat Logging Integration

### 4.1 Threat Log Activation
- **Old Setup**: The `ThreatLog` model and its table mapping `threat_logs` existed but were completely unused.
- **New Setup**: Log entries are automatically generated when:
  1. A user attempts SSRF scans (private or loopback IPs).
  2. A user attempts unauthorized cross-user BOLA/IDOR scans or report access.
- **Admin Visibility**: Added a dedicated "Recorded Threat Event Logs" panel inside the Admin Logs Center (`/admin/logs`) which allows administrators to examine active security events and mark them as resolved.

---

## 5. Security Improvements Verification

| Hardening Requirement | Status | Evidence |
| :--- | :---: | :--- |
| **Token Timing & Expiration** | **MET** | Timed reset tokens expire after timeout limit (`test_forgot_password_token_expiration`). |
| **Token Reuse Protection** | **MET** | Password changes immediately invalidate all existing tokens (`test_forgot_password_token_invalidation_on_change`). |
| **SSRF Threat Recording** | **MET** | Private IP scanning attempts write high-severity SSRF events (`test_ssrf_blocks_record_threat_log`). |
| **BOLA Threat Recording** | **MET** | Unauthorized scan retrieval writes critical BOLA attempts (`test_bola_blocks_record_threat_log`). |
| **Orphan Cascades** | **MET** | Deleting users removes all associated model children (`test_user_deletion_cascades`). |

---

## 6. Verification Results

### 6.1 Automated Pytest Runs
- **Total Tests**: **69** (added 6 new comprehensive tests covering timed tokens, expiration, token reuse, SSRF/BOLA threat logging, and cascades).
- **Result**: **100% Passing** (69 passed, 7 warnings).
- **Runtime**: Completed successfully in 41.77s.
