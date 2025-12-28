# Security Log Analysis Guide

This document describes how to analyze security logs from the GCP Serverless Security Lab for SIEM integration and threat detection.

## Log Structure

All security events follow this schema:

```json
{
  "event_type": "string",
  "user_id": "string",
  "email": "string", 
  "source_ip": "string",
  "endpoint": "string",
  "method": "string",
  "result": "string",
  "reason": "string",
  "severity": "string",
  "timestamp": "ISO8601",
  "environment": "string",
  "request_id": "string",
  "resource_identifiers": {}
}
```

## Event Types

### 1. `access` - General API Access
Logged for all endpoint access attempts.

**Key Fields:**
- `result`: allowed, denied
- `reason`: authorized, unauthorized, not_found

**Example:**
```json
{
  "event_type": "access",
  "user_id": "abc123",
  "endpoint": "/profile",
  "method": "GET",
  "result": "allowed",
  "reason": "authorized",
  "severity": "INFO"
}
```

### 2. `upload` - Image Upload Events
Logged when users upload images.

**Key Fields:**
- `result`: success, failure
- `reason`: file_uploaded, no_file_provided, invalid_file_type
- `resource_identifiers.image_id`
- `resource_identifiers.bucket`
- `resource_identifiers.object_path`

**Security Considerations:**
- Monitor for unusual upload volumes
- Track file types and sizes
- Alert on upload failures (could indicate attack attempts)

### 3. `download` - Image Download/Access
Logged when users request image access.

**Key Fields:**
- `result`: allowed, denied
- `reason`: authorized_owner, unauthorized_not_owner, not_found, lab_mode_skip_ownership
- `resource_identifiers.actual_owner` (when denied)

**Security Considerations:**
- **CRITICAL:** Monitor for `reason: "unauthorized_not_owner"` - indicates IDOR attempt
- Alert on high frequency of denied downloads from same user/IP
- Track `lab_mode_skip_ownership` events (should only occur in controlled lab)

### 4. `delete` - Image Deletion
Logged when users attempt to delete images.

**Key Fields:**
- `result`: allowed, denied
- `reason`: authorized_owner, unauthorized_not_owner, not_found, lab_mode_skip_ownership

**Security Considerations:**
- Monitor unauthorized deletion attempts
- Track mass deletion patterns
- Alert on deletion of recently uploaded files (potential compromise)

### 5. `admin_access` - Administrative Actions
Logged for admin-only endpoint access.

**Key Fields:**
- `result`: allowed, denied
- `reason`: admin_authorized, not_admin

**Security Considerations:**
- **HIGH PRIORITY:** All admin access should be reviewed
- Alert on denied admin access attempts (privilege escalation attempts)
- Monitor admin access outside business hours
- Track frequency of admin actions per user

### 6. `auth_audit` - Authentication Events
Logged for login/logout events and token validation issues.

**Key Fields:**
- `result`: success, failure, allowed, denied
- `reason`: login_success, login_failure, lab_mode_weak_validation
- `action`: login, logout

**Security Considerations:**
- Monitor failed login attempts (brute force)
- Alert on unusual login locations (source_ip)
- Track concurrent logins from different IPs
- **CRITICAL:** Alert on any `lab_mode_weak_validation` events

## Detection Rules for Wazuh

### Rule 1: IDOR Attempt Detection
```xml
<rule id="100001" level="10">
  <decoded_as>json</decoded_as>
  <field name="event_type">download|delete</field>
  <field name="result">denied</field>
  <field name="reason">unauthorized_not_owner</field>
  <description>Insecure Direct Object Reference (IDOR) attempt detected</description>
  <group>attack,authorization_failure,pci_dss_10.2.4</group>
</rule>
```

### Rule 2: Admin Privilege Escalation Attempt
```xml
<rule id="100002" level="12">
  <decoded_as>json</decoded_as>
  <field name="event_type">admin_access</field>
  <field name="result">denied</field>
  <field name="reason">not_admin</field>
  <description>Unauthorized admin access attempt</description>
  <group>attack,privilege_escalation,pci_dss_10.2.2</group>
</rule>
```

### Rule 3: Multiple Authentication Failures
```xml
<rule id="100003" level="8" frequency="5" timeframe="300">
  <decoded_as>json</decoded_as>
  <field name="event_type">auth_audit</field>
  <field name="result">failure</field>
  <same_source_ip/>
  <description>Multiple authentication failures from same IP</description>
  <group>attack,authentication_failure,pci_dss_10.2.4</group>
</rule>
```

### Rule 4: Lab Mode Active (Should Never Occur in Production)
```xml
<rule id="100004" level="15">
  <decoded_as>json</decoded_as>
  <field name="reason">lab_mode</field>
  <description>CRITICAL: Lab mode vulnerability active</description>
  <group>configuration_error,security_misconfiguration</group>
</rule>
```

### Rule 5: Mass Data Export
```xml
<rule id="100005" level="7">
  <decoded_as>json</decoded_as>
  <field name="event_type">access</field>
  <field name="endpoint">/export</field>
  <field name="result">success</field>
  <description>User data export occurred</description>
  <group>data_loss_prevention,gdpr,compliance</group>
</rule>
```

### Rule 6: Unusual Upload Activity
```xml
<rule id="100006" level="6" frequency="20" timeframe="60">
  <decoded_as>json</decoded_as>
  <field name="event_type">upload</field>
  <field name="result">success</field>
  <same_user/>
  <description>High volume of file uploads from single user</description>
  <group>anomaly,abuse</group>
</rule>
```

## Query Examples

### Find All IDOR Attempts
```
resource.type="cloud_function"
jsonPayload.event_type=("download" OR "delete")
jsonPayload.result="denied"
jsonPayload.reason="unauthorized_not_owner"
```

### Find Failed Admin Access
```
resource.type="cloud_function"
jsonPayload.event_type="admin_access"
jsonPayload.result="denied"
```

### Authentication Failures by IP
```
resource.type="cloud_function"
jsonPayload.event_type="auth_audit"
jsonPayload.result="failure"
jsonPayload.source_ip="1.2.3.4"
```

### All Actions by Specific User
```
resource.type="cloud_function"
jsonPayload.user_id="USER_UID_HERE"
```

### High Severity Events Only
```
resource.type="cloud_function"
jsonPayload.severity="ERROR" OR jsonPayload.severity="WARNING"
```

### Lab Mode Violations
```
resource.type="cloud_function"
jsonPayload.reason=~"lab_mode.*"
```

### Successful Uploads in Time Range
```
resource.type="cloud_function"
jsonPayload.event_type="upload"
jsonPayload.result="success"
timestamp>="2024-01-01T00:00:00Z"
timestamp<="2024-01-31T23:59:59Z"
```

### Access from Suspicious IP
```
resource.type="cloud_function"
jsonPayload.source_ip=~"(suspicious-ip-pattern)"
```

## Compliance Mapping

### PCI DSS 3.2.1
- **Requirement 10.2.2** (Invalid access attempts): `admin_access` with `result="denied"`
- **Requirement 10.2.4** (Unauthorized access): All `result="denied"` events
- **Requirement 10.2.5** (Access to audit trails): Track `/export` access
- **Requirement 10.3** (Log entries): All events include user, timestamp, event type, success/failure

### GDPR
- **Article 30** (Records of processing): All `upload`, `download`, `delete` events
- **Article 15** (Right of access): `/export` endpoint logs
- **Article 17** (Right to erasure): `delete` event tracking

### NIST 800-53
- **AU-2** (Audit Events): All event types covered
- **AU-3** (Content of Audit Records): Full structured logging
- **AC-2** (Account Management): `auth_audit` events
- **AC-6** (Least Privilege): `admin_access` monitoring

## Alert Thresholds

### Critical (Immediate Response)
1. Any `lab_mode` events in production
2. Multiple IDOR attempts (>3 in 5 minutes)
3. Successful admin access outside approved hours
4. Mass deletion events (>10 files in 1 minute)

### High (Response within 1 hour)
1. Failed admin access attempts
2. Multiple authentication failures (>5 in 5 minutes)
3. Access from blacklisted IPs
4. Unusual upload volumes (>50 in 5 minutes)

### Medium (Response within 4 hours)
1. Single IDOR attempt
2. Data export during unusual hours
3. Access patterns deviating from baseline

### Low (Review during business hours)
1. Normal denied access (not_found, validation errors)
2. Routine uploads and downloads
3. Standard user operations

## Integration with SIEM

### Log Forwarding Options

1. **Pub/Sub to Wazuh** (Recommended)
   - Real-time streaming
   - Minimal latency
   - See README.md for setup

2. **Cloud Logging API Pull**
   - Periodic queries
   - Good for batch processing
   - Higher latency

3. **Log Router Sink to BigQuery**
   - For long-term analytics
   - Complex queries
   - Not real-time

### Field Mapping for Wazuh

```json
{
  "timestamp": "timestamp",
  "hostname": "Cloud Function",
  "program": "sec-lab-api",
  "user": "jsonPayload.user_id",
  "srcip": "jsonPayload.source_ip",
  "action": "jsonPayload.event_type",
  "status": "jsonPayload.result",
  "data": {
    "email": "jsonPayload.email",
    "endpoint": "jsonPayload.endpoint",
    "method": "jsonPayload.method",
    "reason": "jsonPayload.reason",
    "resource": "jsonPayload.resource_identifiers"
  }
}
```

## Baseline Behavior

Establish baselines for:
- Normal upload frequency per user (e.g., 5-10 per day)
- Typical access patterns (business hours)
- Standard IP ranges (office/VPN)
- Admin access frequency (rare)
- Failed auth rate (<1% of total)

Monitor for deviations from baseline as potential indicators of compromise.

## Retention Policy

Recommended log retention:
- **Hot tier (immediate access):** 30 days
- **Warm tier (slower access):** 90 days
- **Cold tier (archive):** 1-7 years (compliance dependent)

Configure in Cloud Logging retention settings.

