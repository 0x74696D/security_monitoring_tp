# 🔍 Wazuh Monitor Queries - Field-Based (No Custom Rules Required)

These queries work directly with the log fields from your security application, without requiring custom Wazuh rules.

---

## 📋 Monitor 1: Failed Login Attempts

**Name:** `Failed Login Attempts`

**Description:** Detect individual failed login attempts

**Query:**
```json
{
    "size": 0,
    "query": {
        "bool": {
            "must": [
                {
                    "term": {
                        "data.gcp.jsonPayload.event_type.keyword": "auth_audit"
                    }
                },
                {
                    "term": {
                        "data.gcp.jsonPayload.result.keyword": "failure"
                    }
                },
                {
                    "term": {
                        "data.gcp.jsonPayload.action.keyword": "login"
                    }
                }
            ],
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": "now-5m"
                    }
                }
            }
        }
    }
}
```

**Alert Threshold:** > 0 results  
**Severity:** Low  
**Schedule:** Every 5 minutes

---

## 🚨 Monitor 2: Brute Force Attack (5+ Failures in 5 Minutes)

**Name:** `Brute Force Attack - Same Account`

**Description:** Detect 5 or more failed login attempts for the same email within 5 minutes

**Query:**
```json
{
    "size": 0,
    "query": {
        "bool": {
            "must": [
                {
                    "term": {
                        "data.gcp.jsonPayload.event_type.keyword": "auth_audit"
                    }
                },
                {
                    "term": {
                        "data.gcp.jsonPayload.result.keyword": "failure"
                    }
                },
                {
                    "term": {
                        "data.gcp.jsonPayload.action.keyword": "login"
                    }
                }
            ],
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": "now-5m"
                    }
                }
            }
        }
    },
    "aggs": {
        "by_email": {
            "terms": {
                "field": "data.gcp.jsonPayload.email.keyword",
                "min_doc_count": 5
            }
        }
    }
}
```

**Alert Threshold:** `ctx.results[0].aggregations.by_email.buckets.length > 0`  
**Severity:** High  
**Schedule:** Every 5 minutes  
**Action:** Send immediate alert with email address

---

## 🌐 Monitor 3: Distributed Brute Force (Multiple IPs, Same Target)

**Name:** `Distributed Brute Force Attack`

**Description:** Detect failed logins from 3+ different IPs targeting the same account

**Query:**
```json
{
    "size": 0,
    "query": {
        "bool": {
            "must": [
                {
                    "term": {
                        "data.gcp.jsonPayload.event_type.keyword": "auth_audit"
                    }
                },
                {
                    "term": {
                        "data.gcp.jsonPayload.result.keyword": "failure"
                    }
                }
            ],
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": "now-5m"
                    }
                }
            }
        }
    },
    "aggs": {
        "by_email": {
            "terms": {
                "field": "data.gcp.jsonPayload.email.keyword"
            },
            "aggs": {
                "unique_ips": {
                    "cardinality": {
                        "field": "data.gcp.jsonPayload.source_ip"
                    }
                },
                "ip_filter": {
                    "bucket_selector": {
                        "buckets_path": {
                            "ip_count": "unique_ips"
                        },
                        "script": "params.ip_count >= 3"
                    }
                }
            }
        }
    }
}
```

**Alert Threshold:** `ctx.results[0].aggregations.by_email.buckets.length > 0`  
**Severity:** High  
**Schedule:** Every 5 minutes

---

## 💀 Monitor 4: Successful Login After Failed Attempts

**Name:** `Potential Account Compromise`

**Description:** Detect successful login after multiple recent failures (potential breach)

**Step 1 - Query for accounts with recent failures:**
```json
{
    "size": 0,
    "query": {
        "bool": {
            "must": [
                {
                    "term": {
                        "data.gcp.jsonPayload.result.keyword": "failure"
                    }
                }
            ],
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": "now-10m"
                    }
                }
            }
        }
    },
    "aggs": {
        "by_email": {
            "terms": {
                "field": "data.gcp.jsonPayload.email.keyword",
                "min_doc_count": 3
            }
        }
    }
}
```

**Step 2 - Query for recent successes:**
```json
{
    "size": 10,
    "query": {
        "bool": {
            "must": [
                {
                    "term": {
                        "data.gcp.jsonPayload.event_type.keyword": "auth_audit"
                    }
                },
                {
                    "term": {
                        "data.gcp.jsonPayload.result.keyword": "success"
                    }
                }
            ],
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": "now-5m"
                    }
                }
            }
        }
    }
}
```

**Alert Logic:** Correlate the two - if an email from Step 1 appears in Step 2  
**Severity:** Critical  
**Schedule:** Every 5 minutes  
**Action:** Immediate escalation

---

## 🔓 Monitor 5: IDOR Exploitation

**Name:** `IDOR Vulnerability Exploitation`

**Description:** Detect users accessing resources owned by others

**Query:**
```json
{
    "size": 10,
    "query": {
        "bool": {
            "must": [
                {
                    "term": {
                        "data.gcp.jsonPayload.vulnerability.keyword": "IDOR"
                    }
                }
            ],
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": "now-5m"
                    }
                }
            }
        }
    }
}
```

**Alternative Query (Lab Mode):**
```json
{
    "size": 10,
    "query": {
        "bool": {
            "must": [
                {
                    "term": {
                        "data.gcp.jsonPayload.lab_mode.keyword": "skip_ownership_check"
                    }
                },
                {
                    "term": {
                        "data.gcp.jsonPayload.result.keyword": "allowed"
                    }
                },
                {
                    "exists": {
                        "field": "data.gcp.jsonPayload.resource_identifiers.actual_owner"
                    }
                }
            ],
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": "now-5m"
                    }
                }
            }
        }
    }
}
```

**Alert Threshold:** > 0 results  
**Severity:** High  
**Schedule:** Every 5 minutes

---

## 🔐 Monitor 6: Privilege Escalation Attempts

**Name:** `Admin Access Attempts by Non-Admins`

**Description:** Detect users trying to access admin endpoints

**Query:**
```json
{
    "size": 10,
    "query": {
        "bool": {
            "must": [
                {
                    "term": {
                        "data.gcp.jsonPayload.event_type.keyword": "admin_access"
                    }
                },
                {
                    "term": {
                        "data.gcp.jsonPayload.result.keyword": "denied"
                    }
                },
                {
                    "term": {
                        "data.gcp.jsonPayload.reason.keyword": "not_admin"
                    }
                }
            ],
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": "now-5m"
                    }
                }
            }
        }
    }
}
```

**Alert Threshold:** > 0 results  
**Severity:** High  
**Schedule:** Every 5 minutes

---

## 🔄 Monitor 7: Multiple Privilege Escalation (Same User)

**Name:** `Repeated Privilege Escalation Attempts`

**Description:** Detect 3+ privilege escalation attempts by same user

**Query:**
```json
{
    "size": 0,
    "query": {
        "bool": {
            "must": [
                {
                    "term": {
                        "data.gcp.jsonPayload.event_type.keyword": "admin_access"
                    }
                },
                {
                    "term": {
                        "data.gcp.jsonPayload.result.keyword": "denied"
                    }
                }
            ],
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": "now-5m"
                    }
                }
            }
        }
    },
    "aggs": {
        "by_user": {
            "terms": {
                "field": "data.gcp.jsonPayload.email.keyword",
                "min_doc_count": 3
            }
        }
    }
}
```

**Alert Threshold:** `ctx.results[0].aggregations.by_user.buckets.length > 0`  
**Severity:** Critical  
**Schedule:** Every 5 minutes

---

## 📤 Monitor 8: Large Data Exports

**Name:** `Potential Data Exfiltration`

**Description:** Detect exports of 50+ records

**Query:**
```json
{
    "size": 10,
    "query": {
        "bool": {
            "must": [
                {
                    "term": {
                        "data.gcp.jsonPayload.event_type.keyword": "access"
                    }
                },
                {
                    "term": {
                        "data.gcp.jsonPayload.reason.keyword": "data_export"
                    }
                },
                {
                    "range": {
                        "data.gcp.jsonPayload.exported_count": {
                            "gte": 50
                        }
                    }
                }
            ],
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": "now-5m"
                    }
                }
            }
        }
    }
}
```

**Alert Threshold:** > 0 results  
**Severity:** High  
**Schedule:** Every 5 minutes

---

## 🚫 Monitor 9: Unauthorized Access Attempts

**Name:** `Unauthorized Resource Access`

**Description:** Users trying to access resources they don't own

**Query:**
```json
{
    "size": 10,
    "query": {
        "bool": {
            "must": [
                {
                    "term": {
                        "data.gcp.jsonPayload.result.keyword": "denied"
                    }
                },
                {
                    "term": {
                        "data.gcp.jsonPayload.reason.keyword": "unauthorized_not_owner"
                    }
                }
            ],
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": "now-5m"
                    }
                }
            }
        }
    }
}
```

**Alert Threshold:** > 0 results  
**Severity:** Medium  
**Schedule:** Every 5 minutes

---

## 🔬 Monitor 10: Lab Mode Vulnerabilities

**Name:** `Lab Mode Security Issues`

**Description:** Detect when lab mode vulnerabilities are being exploited

**Query:**
```json
{
    "size": 10,
    "query": {
        "bool": {
            "should": [
                {
                    "term": {
                        "data.gcp.jsonPayload.lab_mode.keyword": "weak_token_validation"
                    }
                },
                {
                    "term": {
                        "data.gcp.jsonPayload.lab_mode.keyword": "skip_ownership_check"
                    }
                }
            ],
            "minimum_should_match": 1,
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": "now-5m"
                    }
                }
            }
        }
    }
}
```

**Alert Threshold:** > 0 results  
**Severity:** Medium  
**Schedule:** Every 5 minutes

---

## 📊 Monitor 11: Top Attacking IPs

**Name:** `Most Active Attackers`

**Description:** Identify IPs with most failed login attempts

**Query:**
```json
{
    "size": 0,
    "query": {
        "bool": {
            "must": [
                {
                    "term": {
                        "data.gcp.jsonPayload.result.keyword": "failure"
                    }
                }
            ],
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": "now-1h"
                    }
                }
            }
        }
    },
    "aggs": {
        "top_ips": {
            "terms": {
                "field": "data.gcp.jsonPayload.source_ip",
                "size": 10,
                "order": {
                    "_count": "desc"
                },
                "min_doc_count": 10
            }
        }
    }
}
```

**Alert Threshold:** `ctx.results[0].aggregations.top_ips.buckets.length > 0`  
**Severity:** Medium  
**Schedule:** Every 15 minutes

---

## 📊 Monitor 12: Top Targeted Accounts

**Name:** `Most Targeted Accounts`

**Description:** Identify which accounts are under attack

**Query:**
```json
{
    "size": 0,
    "query": {
        "bool": {
            "must": [
                {
                    "term": {
                        "data.gcp.jsonPayload.result.keyword": "failure"
                    }
                }
            ],
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": "now-1h"
                    }
                }
            }
        }
    },
    "aggs": {
        "top_targets": {
            "terms": {
                "field": "data.gcp.jsonPayload.email.keyword",
                "size": 10,
                "order": {
                    "_count": "desc"
                },
                "min_doc_count": 5
            }
        }
    }
}
```

**Alert Threshold:** `ctx.results[0].aggregations.top_targets.buckets.length > 0`  
**Severity:** Medium  
**Schedule:** Every 15 minutes

---

## 🎯 Quick Setup Guide

### How to Create a Monitor in Wazuh:

1. **Open Wazuh Dashboard** → http://localhost:5601
2. Go to **"Alerting"** → **"Monitors"**
3. Click **"Create monitor"**
4. Fill in:
   - **Monitor name:** (from above)
   - **Index:** `wazuh-alerts-*`
   - **Query:** (Copy-paste JSON from above)
   - **Schedule:** (as specified)
   - **Trigger condition:** (as specified)
5. **Create trigger**:
   - Trigger name: Alert trigger
   - Severity level: (as specified)
   - Condition: (as specified)
6. **Add action**: Email, Slack, Webhook, etc.
7. **Create**

---

## ✅ Recommended Priority Order

Deploy monitors in this order:

1. ✅ **Monitor 2** - Brute Force (most critical)
2. ✅ **Monitor 4** - Successful after failures (breach detection)
3. ✅ **Monitor 7** - Multiple privilege escalation
4. ✅ **Monitor 5** - IDOR exploitation
5. ✅ **Monitor 8** - Data exfiltration
6. ✅ **Monitor 6** - Privilege escalation
7. ⚠️ **Monitor 1** - Failed logins (informational)
8. ⚠️ **Monitor 9** - Unauthorized access
9. ℹ️ **Monitor 10** - Lab mode
10. ℹ️ **Monitor 11** - Top attackers
11. ℹ️ **Monitor 12** - Top targets

---

## 🧪 Testing

Generate test events to verify monitors:

```bash
# Test brute force
cd lab_terraform/3applications/3.1applications_vuln_app/
bash bruteforce-test.sh API_KEY GATEWAY_URL test@example.com 'password'

# Check Wazuh for alerts (wait 2-3 minutes)
```

---

**All queries work directly with log fields - no custom rules required!** ✅

