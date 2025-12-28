# GCP Pub/Sub Integration - Working Configuration

## Summary

The GCP Pub/Sub integration with Wazuh is now **working correctly** using the **command wodle** approach.

## Key Discovery

**The `gcp-pubsub` is NOT a native wodle module name in Wazuh Docker.**

Instead, GCP integration is invoked via:
- **`<wodle name="command">`** calling `/var/ossec/wodles/gcloud/gcloud` script

## Working Configuration

### 1. Python Dependencies
Install dependencies in **Wazuh's framework Python** (not system Python):
```bash
/var/ossec/framework/python/bin/pip3 install google-cloud-pubsub==2.18.4
```

### 2. Wodle Configuration in ossec.conf
```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>gcp</tag>
  <command>/var/ossec/wodles/gcloud/gcloud -T pubsub -p PROJECT_ID -s SUBSCRIPTION_ID -c /var/ossec/wodles/gcp-pubsub/credentials.json -m 100 -l 1</command>
  <interval>1m</interval>
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```

### 3. Command Parameters
- `-T pubsub` - Integration type (Pub/Sub)
- `-p` - GCP Project ID
- `-s` - Pub/Sub Subscription ID
- `-c` - Path to credentials file
- `-m 100` - Max messages per pull
- `-l 1` - Log level (1=DEBUG, 2=INFO, etc.)

### 4. Credentials Location
```
/var/ossec/wodles/gcp-pubsub/credentials.json
```

## Verification Commands

### Check if wodle is running:
```bash
docker exec single-node-wazuh.manager-1 grep 'command:gcp' /var/ossec/logs/ossec.log
```

### Test manual execution:
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/wodles/gcloud/gcloud \
  -T pubsub \
  -p telecom-3app \
  -s wazuh-gcp-logs-sub \
  -c /var/ossec/wodles/gcp-pubsub/credentials.json \
  -m 2 \
  -l 1
```

### Check GCP alerts in Elasticsearch:
```bash
curl -k -u admin:PASSWORD 'https://localhost:9200/wazuh-alerts-*/_search?q=integration:gcp&size=5'
```

### View GCP alerts in logs:
```bash
docker exec single-node-wazuh.manager-1 grep '"integration":"gcp"' /var/ossec/logs/alerts/alerts.json
```

## Dashboard Access

1. **Create SSH Tunnel:**
   ```bash
   gcloud compute ssh wazuh-aio --zone=us-central1-a --project=telecom-3app -- -L 5601:localhost:5601
   ```

2. **Open Dashboard:**
   - URL: http://localhost:5601
   - Username: admin
   - Password: (from terraform.tfvars)

3. **Search for GCP logs:**
   - Filter: `rule.groups:gcp` OR `integration:gcp`
   - Index: `wazuh-alerts-*`

## Captured Log Types

The log sink captures:
- ✅ **Cloud Run** - HTTP requests, container logs
- ✅ **Cloud Functions** - Execution logs
- ✅ **API Gateway** - Authentication, authorization, errors
- ✅ **GCS Bucket** - Storage operations
- ✅ **Cloud Audit Logs** - IAM, Compute, Network, Firewall changes
- ✅ **Compute Engine** - Instance operations
- ✅ **Networking** - Firewall rules, VPC changes

## Tested and Confirmed Working

- **Date:** 2025-12-28
- **Wazuh Version:** 4.14.1
- **Docker Deployment:** single-node
- **GCP Project:** telecom-3app
- **Subscription:** wazuh-gcp-logs-sub
- **Alerts Generated:** 17+ (confirmed in Elasticsearch)

## Common Issues

### Issue: "Unknown module 'gcp-pubsub'"
**Solution:** Use `<wodle name="command">` instead of `<wodle name="gcp-pubsub">`

### Issue: No alerts in Elasticsearch
**Solution:** Restart Filebeat: `docker exec single-node-wazuh.manager-1 pkill filebeat`

### Issue: Python dependencies not found
**Solution:** Install in framework Python: `/var/ossec/framework/python/bin/pip3 install google-cloud-pubsub`

## Updated Files

- **install.sh** - Updated to use command wodle approach
- **main.tf** - Passes GCP credentials and Pub/Sub details to VM
- **variables.tf** - Defines gcp_service_account_key_path, pubsub_project_id, pubsub_subscription_id
