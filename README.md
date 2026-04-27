# SOC Lab 20 — GRC: Policy and Technical Enforcement

## Executive Summary

This lab closes the GRC phase of the SOC portfolio by writing a formal security policy and demonstrating how it is enforced technically using Elastic SIEM and Linux system controls. The policy addresses the critical findings identified across Labs 15–19, with a focus on SSH authentication logging, access control, and account lockout. Technical enforcement evidence is drawn from the lab environment to show that policy requirements are implemented, monitored, and auditable. This lab demonstrates the ability to connect policy to practice — a core skill in enterprise GRC and SOC roles.

---

## Incident Ticket (ServiceNow Simulation)

| Field | Details |
|---|---|
| **Incident ID** | INC-0020 |
| **Date/Time Detected** | 2026-04-26 |
| **Detected By** | Eric Ellison — SOC Analyst |
| **Severity** | Low |
| **Category** | Governance, Risk & Compliance |
| **Subcategory** | Policy and Technical Enforcement |
| **Short Description** | Security policy written and technical enforcement demonstrated for SOC lab environment |
| **Detailed Description** | A formal security policy was written addressing the critical findings from the GRC audit in Lab 19. Policy requirements cover SSH log ingestion, account lockout, least privilege, and SSH authentication hardening. Technical enforcement is demonstrated using Linux system configuration and Elastic SIEM monitoring. Policy compliance status is assessed against each requirement. |
| **IOCs** | None — policy and enforcement review |
| **Impact Assessment** | Low — lab environment. Policy and enforcement demonstration directly addresses High findings from Labs 17–19. |
| **Response Actions Taken** | Security policy written. Technical enforcement demonstrated. Compliance status assessed. |
| **Recommended Actions** | Implement all policy requirements in production environment. Schedule quarterly policy review. |
| **Status** | Closed — Policy and Enforcement Complete |

---

## Lab Objectives

- Write a formal security policy addressing GRC audit findings
- Demonstrate technical enforcement of each policy requirement
- Assess compliance status of the lab environment against the policy
- Close the GRC documentation cycle for the SOC portfolio

---

## Environment Overview

| Component | Details |
|---|---|
| Host OS | Windows |
| VM 1 | Kali Linux |
| Virtualization | VMware Workstation |
| SIEM | Elastic Cloud Serverless (GCP Iowa) |
| Policy Scope | Kali Linux VM — SSH, access control, logging |

---

## Security Policy

**Policy Title:** SOC Lab Environment Security Policy
**Policy Version:** 1.0
**Effective Date:** 2026-04-26
**Policy Owner:** Eric Ellison — SOC Analyst
**Review Cycle:** Quarterly

### Purpose

This policy establishes security requirements for the SOC lab environment. It addresses findings identified during the GRC audit conducted in Lab 19 and ensures the environment meets NIST SP 800-53 control requirements across the AU, AC, and IA control families.

### Scope

This policy applies to all systems in the SOC lab environment including the Kali Linux VM, Elastic SIEM, and associated network traffic capture infrastructure.

### Policy Requirements

| Policy ID | Requirement | NIST Control | Priority |
|---|---|---|---|
| P-001 | All SSH authentication events must be ingested into Elastic SIEM within 5 minutes of generation | AU-2, AU-12 | Critical |
| P-002 | Account lockout must be enforced after 5 consecutive failed login attempts | AC-7 | Critical |
| P-003 | SSH password authentication must be disabled — key-based authentication only | AC-17, IA-5 | Critical |
| P-004 | Root login over SSH must be disabled | AC-17 | Critical |
| P-005 | The kali user must not have unrestricted sudo access | AC-3, AC-6 | High |
| P-006 | All log sources must be retained for a minimum of 90 days | AU-11 | High |
| P-007 | Password expiration must be enforced at 90 days | IA-5 | Medium |
| P-008 | Minimum password length must be 12 characters | IA-5 | Medium |

---

## Technical Enforcement

### P-001 — SSH Log Ingestion into Elastic SIEM

**Requirement:** All SSH authentication events must be ingested into Elastic SIEM within 5 minutes of generation.

**Enforcement Method:** Elastic Agent with System integration configured to forward `logs-system.auth-*` data stream to Elastic Cloud.

**Current Status:** ❌ Not enforced — SSH auth logs confirmed absent from Elastic data stream (Labs 13, 14, 19)

**Remediation Command:**
```bash
# Verify current Elastic Agent integration
sudo elastic-agent status

# Check if auth logs are being collected
sudo cat /etc/elastic-agent/elastic-agent.yml | grep auth
```

**Evidence:** Lab 13 — zero alerts generated for SSH brute force. Lab 14 — SSH auth logs absent from logs-* data view.

---

### P-002 — Account Lockout Policy

**Requirement:** Account lockout must be enforced after 5 consecutive failed login attempts.

**Enforcement Method:** PAM faillock configured in `/etc/pam.d/common-auth`.

**Current Status:** ❌ Not enforced — no lockout policy configured (Labs 17, 18, 19)

**Remediation Command:**
```bash
# Configure account lockout via PAM faillock
sudo nano /etc/pam.d/common-auth

# Add the following lines:
# auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900
# auth required pam_faillock.so authfail audit deny=5 unlock_time=900

# Verify configuration
sudo faillock --user kali
```

**Evidence:** Lab 17 R-001 — no account lockout policy. Lab 18 G-004 — AC-7 gap confirmed. Lab 19 F-010 — audit finding.

---

### P-003 — Disable SSH Password Authentication

**Requirement:** SSH password authentication must be disabled — key-based authentication only.

**Enforcement Method:** `PasswordAuthentication no` in `/etc/ssh/sshd_config`.

**Current Status:** ❌ Not enforced — password authentication enabled (Lab 18)

**Remediation Command:**
```bash
# Edit SSH config
sudo nano /etc/ssh/sshd_config

# Set:
# PasswordAuthentication no
# PubkeyAuthentication yes

# Restart SSH service
sudo systemctl restart ssh

# Verify
sudo sshd -T | grep passwordauthentication
```

**Evidence:** Lab 18 G-002 — SSH password authentication enabled. Lab 19 F-013 — IA-5 audit finding.

---

### P-004 — Disable Root SSH Login

**Requirement:** Root login over SSH must be disabled.

**Enforcement Method:** `PermitRootLogin no` in `/etc/ssh/sshd_config`.

**Current Status:** ❌ Not enforced — root login permitted (Lab 18)

**Remediation Command:**
```bash
# Edit SSH config
sudo nano /etc/ssh/sshd_config

# Set:
# PermitRootLogin no

# Restart SSH service
sudo systemctl restart ssh

# Verify
sudo sshd -T | grep permitrootlogin
```

**Evidence:** Lab 18 G-003 — root login permitted over SSH. Lab 19 F-011 — AC-17 audit finding.

---

### P-005 — Restrict Sudo Access

**Requirement:** The kali user must not have unrestricted sudo access.

**Enforcement Method:** Restricted sudoers entry via `visudo`.

**Current Status:** ❌ Not enforced — kali has ALL=(ALL:ALL) ALL (Lab 18)

**Remediation Command:**
```bash
# Edit sudoers file safely
sudo visudo

# Replace:
# kali ALL=(ALL:ALL) ALL
# With specific allowed commands only, for example:
# kali ALL=(ALL) /usr/bin/apt, /usr/bin/systemctl

# Verify
sudo -l -U kali
```

**Evidence:** Lab 18 G-001 — unrestricted sudo. Lab 19 F-009 — AC-6 audit finding.

---

### P-006 — Log Retention

**Requirement:** All log sources must be retained for a minimum of 90 days.

**Enforcement Method:** Elastic SIEM data retention settings. Local log rotation policy.

**Current Status:** ⚠️ Partial — Elastic SIEM retains logs but packet captures are local only with no defined retention (Lab 15)

**Evidence:** Lab 15 — log retention policy proposed. Lab 19 F-005 — AU-11 audit finding.

---

### P-007 — Password Expiration

**Requirement:** Password expiration must be enforced at 90 days.

**Enforcement Method:** `chage` command on Linux.

**Current Status:** ❌ Not enforced — no expiration set (Lab 18)

**Remediation Command:**
```bash
# Set 90-day password expiration for kali user
sudo chage -M 90 kali

# Verify
sudo chage -l kali
```

**Evidence:** Lab 18 G-005 — no password expiration policy.

---

### P-008 — Minimum Password Length

**Requirement:** Minimum password length must be 12 characters.

**Enforcement Method:** PAM pwquality configured in `/etc/pam.d/common-password`.

**Current Status:** ❌ Not enforced — no complexity requirements (Lab 18)

**Remediation Command:**
```bash
# Install pwquality if not present
sudo apt install libpam-pwquality

# Edit PAM password config
sudo nano /etc/pam.d/common-password

# Add:
# password requisite pam_pwquality.so minlen=12

# Verify
sudo grep pwquality /etc/pam.d/common-password
```

**Evidence:** Lab 18 G-006 — no minimum password complexity.

---

## Policy Compliance Summary

| Policy ID | Requirement | Status | Priority |
|---|---|---|---|
| P-001 | SSH auth logs ingested into SIEM | ❌ Non-Compliant | Critical |
| P-002 | Account lockout after 5 failures | ❌ Non-Compliant | Critical |
| P-003 | SSH password auth disabled | ❌ Non-Compliant | Critical |
| P-004 | Root SSH login disabled | ❌ Non-Compliant | Critical |
| P-005 | Sudo access restricted | ❌ Non-Compliant | High |
| P-006 | 90-day log retention | ⚠️ Partial | High |
| P-007 | 90-day password expiration | ❌ Non-Compliant | Medium |
| P-008 | 12-character minimum password | ❌ Non-Compliant | Medium |

---

## Conclusions

- 8 policy requirements defined — 0 fully compliant, 1 partial, 7 non-compliant
- All 4 Critical requirements are non-compliant — immediate remediation required
- Non-compliance is consistent with audit findings in Lab 19 — policy formalizes and closes the GRC cycle
- All remediation commands are documented — implementation path is clear
- This lab completes the GRC phase of the SOC portfolio (Labs 15–20)

---

## Portfolio Summary — GRC Phase Complete

| Lab | Title | Status |
|---|---|---|
| Lab 15 | Log Retention Policy | ✅ Complete |
| Lab 16 | Incident Response Compliance | ✅ Complete |
| Lab 17 | Risk Assessment | ✅ Complete |
| Lab 18 | Access Control Review | ✅ Complete |
| Lab 19 | Audit Simulation | ✅ Complete |
| Lab 20 | Policy and Technical Enforcement | ✅ Complete |

---

## Next Steps

- All 20 SOC labs are complete
- Remediate Critical policy findings (P-001 through P-004) in the lab environment
- Update portfolio progress file to reflect completion of Phase 3
- Begin job application process using this portfolio as evidence of SOC analyst competency
