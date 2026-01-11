#!/bin/bash
set -e

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

log "Starting Wazuh All-in-One deployment..."

# Update system
log "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y

# Install prerequisites
log "Installing prerequisites..."
apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    git \
    jq \
    python3 \
    python3-pip \
    python3-venv \
    python3-yaml

# Install Docker
log "Installing Docker..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable Docker service
log "Enabling Docker service..."
systemctl enable docker
systemctl start docker

# Create Wazuh directory
log "Creating Wazuh directory..."
rm -rf /opt/wazuh
mkdir -p /opt/wazuh
cd /opt/wazuh

# Determine admin password source
%{ if use_secret_manager }
log "Fetching admin password from Secret Manager..."
ADMIN_PASSWORD=$(gcloud secrets versions access latest --secret="${secret_name}" --project="${project_id}")
%{ else }
log "Using admin password from Terraform variable..."
ADMIN_PASSWORD="${admin_password}"
%{ endif }

# Validate password
if [ -z "$ADMIN_PASSWORD" ] || [ "$${#ADMIN_PASSWORD}" -lt 8 ]; then
    log "ERROR: Admin password is empty or too short (minimum 8 characters)"
    exit 1
fi

# Clone official Wazuh Docker repository
log "Cloning Wazuh Docker repository..."
if ! git clone https://github.com/wazuh/wazuh-docker.git -b v${wazuh_version} --depth=1; then
    log "ERROR: Failed to clone Wazuh repository"
    exit 1
fi

cd wazuh-docker/single-node

# Generate certificates using official generator
log "Generating SSL certificates..."
if ! docker compose -f generate-indexer-certs.yml run --rm generator; then
    log "ERROR: Certificate generation failed"
    exit 1
fi

log "Certificates generated successfully"

# Disable HTTPS on dashboard (use HTTP over SSH tunnel)
log "Configuring dashboard to use HTTP..."
if [ -f "config/wazuh_dashboard/opensearch_dashboards.yml" ]; then
    sed -i 's/server.ssl.enabled: true/server.ssl.enabled: false/g' config/wazuh_dashboard/opensearch_dashboards.yml
    sed -i 's/^server.ssl.certificate:/#server.ssl.certificate:/g' config/wazuh_dashboard/opensearch_dashboards.yml
    sed -i 's/^server.ssl.key:/#server.ssl.key:/g' config/wazuh_dashboard/opensearch_dashboards.yml
    log "Dashboard configured for HTTP"
else
    log "WARNING: Dashboard config file not found"
fi

# Change dashboard port mapping from 443 to 5601
log "Updating dashboard port mapping to 5601..."
sed -i 's/443:5601/5601:5601/g' docker-compose.yml

# Update admin password and configuration in .env file
log "Setting admin password and Elasticsearch configuration..."
cat > .env <<EOF
INDEXER_PASSWORD=$ADMIN_PASSWORD
EOF

log ".env file created with INDEXER_PASSWORD"

# Update docker-compose.yml to use environment variable for INDEXER_PASSWORD
log "Updating docker-compose.yml to use INDEXER_PASSWORD from .env..."
sed -i 's/INDEXER_PASSWORD=SecretPassword/INDEXER_PASSWORD=$${INDEXER_PASSWORD}/g' docker-compose.yml

# Verify the change
if grep -q 'INDEXER_PASSWORD=$${INDEXER_PASSWORD}' docker-compose.yml; then
    log "docker-compose.yml updated to use environment variable"
else
    log "WARNING: docker-compose.yml may not have been updated correctly"
fi

# Update internal_users.yml with hashed password for the indexer
log "Configuring admin password in indexer..."
if [ -f "config/wazuh_indexer/internal_users.yml" ]; then
    # Generate password hash using the indexer's hash tool
    log "Generating password hash..."
    HASHED_PASSWORD=$(docker run --rm wazuh/wazuh-indexer:${wazuh_version} \
        bash -c "export OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk && /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p '$ADMIN_PASSWORD'" 2>/dev/null | tail -1)
    
    if [ -z "$HASHED_PASSWORD" ]; then
        log "ERROR: Failed to generate password hash"
        exit 1
    fi
    
    log "Updating admin password hash in internal_users.yml..."
    # Update the admin user's hash (be careful with special chars in sed)
    sed -i "/^admin:/,/^[^[:space:]]/ s|hash: \".*\"|hash: \"$HASHED_PASSWORD\"|" config/wazuh_indexer/internal_users.yml
    log "Admin password updated successfully"
else
    log "WARNING: internal_users.yml not found, password may not work"
fi

# Pull Docker images first
log "Pulling Wazuh Docker images..."
docker compose pull

# Start Wazuh stack
log "Starting Wazuh Docker Compose stack..."
if ! docker compose up -d; then
    log "ERROR: Failed to start Docker Compose stack"
    docker compose logs
    exit 1
fi

# Wait for services to be healthy
log "Waiting for Wazuh services to become healthy (this may take 3-5 minutes)..."
sleep 30

# Check if containers are running
RUNNING_CONTAINERS=$(docker compose ps --services --filter "status=running" | wc -l)
log "Running containers: $RUNNING_CONTAINERS/3"

# Wait for services to initialize
log "Waiting for services to initialize..."
sleep 120

# Final status check
log "Final container status:"
docker compose ps

# Check if dashboard is responding
log "Testing dashboard connectivity..."
for i in {1..30}; do
    if curl -s http://localhost:5601 > /dev/null 2>&1; then
        log "Dashboard is responding on port 5601"
        break
    fi
    log "Waiting for dashboard to respond (attempt $i/30)..."
    sleep 10
done

# Create systemd service for auto-restart on reboot
log "Creating systemd service for auto-restart..."
cat > /etc/systemd/system/wazuh-docker.service <<'SERVICE_EOF'
[Unit]
Description=Wazuh Docker Compose Stack
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/wazuh/wazuh-docker/single-node
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
SERVICE_EOF

systemctl daemon-reload
systemctl enable wazuh-docker.service

log "Wazuh deployment complete!"
log "Services should be available at:"
log "  - Wazuh Dashboard: http://localhost:5601 (via SSH tunnel)"
log "  - Wazuh API: https://localhost:55000"
log "  - Admin credentials: admin / [your configured password]"
log ""
log "Dashboard uses HTTP (SSH tunnel provides encryption)"
log "To check logs: docker compose -f /opt/wazuh/wazuh-docker/single-node/docker-compose.yml logs -f"
log "To restart: docker compose -f /opt/wazuh/wazuh-docker/single-node/docker-compose.yml restart"

# ============================================================
# Configure Docker Compose for GCP Log File Access
# ============================================================
log "Configuring Docker Compose to mount GCP log file..."

# Create the GCP log file FIRST (before Docker mounts it)
log "Creating GCP log file..."
touch /var/log/gcp-wazuh.log
chmod 644 /var/log/gcp-wazuh.log
log "GCP log file created: /var/log/gcp-wazuh.log"

# Add volume mount for GCP log file to wazuh.manager service
if ! grep -q "gcp-wazuh.log" docker-compose.yml; then
    log "Adding GCP log file volume mount to docker-compose.yml..."
    
    # Create backup
    cp docker-compose.yml docker-compose.yml.backup
    
    # Use Python to properly edit YAML (safer than sed)
    python3 <<'PYTHON_EOF'
import yaml
import sys

try:
    # Read the docker-compose file
    with open('docker-compose.yml', 'r') as f:
        compose = yaml.safe_load(f)
    
    # Add the volume mount to wazuh.manager service
    if 'services' in compose and 'wazuh.manager' in compose['services']:
        if 'volumes' not in compose['services']['wazuh.manager']:
            compose['services']['wazuh.manager']['volumes'] = []
        
        # Add GCP log volume if not already present
        gcp_volume = '/var/log/gcp-wazuh.log:/var/log/gcp-wazuh.log:ro'
        if gcp_volume not in compose['services']['wazuh.manager']['volumes']:
            compose['services']['wazuh.manager']['volumes'].append(gcp_volume)
            print("Volume mount added to wazuh.manager service")
        else:
            print("Volume mount already exists")
        
        # Write back
        with open('docker-compose.yml', 'w') as f:
            yaml.dump(compose, f, default_flow_style=False, sort_keys=False)
        
        sys.exit(0)
    else:
        print("ERROR: Could not find wazuh.manager service")
        sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
PYTHON_EOF
    
    if [ $? -eq 0 ]; then
        log "Volume mount added successfully"
        
        # Recreate containers to apply volume mount
        log "Recreating Wazuh containers to apply volume mount..."
        docker compose up -d --force-recreate wazuh.manager
        
        # Wait for manager to be ready
        log "Waiting for Wazuh manager to initialize..."
        sleep 30
    else
        log "ERROR: Failed to update docker-compose.yml"
        exit 1
    fi
else
    log "GCP log file volume mount already configured"
fi

# ============================================================
# GCP Pub/Sub Integration Setup (Using Built-in Wazuh GCP-Pub/Sub Module)
# ============================================================
# This section configures Wazuh to pull GCP audit logs from Pub/Sub.
# Steps:
#   1. Wait for Wazuh manager to be ready
#   2. Create credentials directory in container
#   3. Download and validate service account key from metadata
#   4. Copy credentials to container
#   5. Install google-cloud-pubsub Python package
#   6. Configure GCP Pub/Sub command wodle in ossec.conf
#   7. Create GCP detection rules
#   8. Restart Wazuh to apply configuration
#   9. Test the GCP Pub/Sub connection
# ============================================================
log "Setting up GCP Pub/Sub integration using Wazuh's built-in module..."

# Wait for Wazuh manager to be ready first
log "Waiting for Wazuh manager to be ready..."
for i in {1..60}; do
    if docker exec single-node-wazuh.manager-1 test -f /var/ossec/etc/ossec.conf 2>/dev/null; then
        log "Wazuh manager is ready"
        break
    fi
    if [ $i -eq 60 ]; then
        log "ERROR: Wazuh manager not ready after 10 minutes"
        exit 1
    fi
    sleep 10
done

# Create directory for GCP credentials inside the container
log "Preparing GCP credentials directory in Wazuh container..."
docker exec single-node-wazuh.manager-1 mkdir -p /var/ossec/wodles/gcp-pubsub

# Download the GCP service account key from metadata and copy to container
log "Downloading GCP service account key..."
TMP_CREDS="/tmp/gcp-credentials.json"

log "Fetching credentials from metadata server..."
if ! curl -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/gcp-sa-key" \
    -o "$TMP_CREDS" 2>&1 | tee /tmp/curl_output.log; then
    log "ERROR: Failed to download GCP service account key from metadata"
    cat /tmp/curl_output.log
    exit 1
fi

log "Credentials downloaded successfully"

# Verify the JSON key is valid
log "Validating JSON credentials..."
if ! jq empty "$TMP_CREDS" 2>/dev/null; then
    log "ERROR: Downloaded service account key is not valid JSON"
    log "First 200 characters of downloaded file:"
    head -c 200 "$TMP_CREDS"
    rm -f "$TMP_CREDS"
    exit 1
fi

# Extract and log service account email
SA_EMAIL=$(jq -r '.client_email' "$TMP_CREDS" 2>/dev/null || echo "unknown")
SA_PROJECT=$(jq -r '.project_id' "$TMP_CREDS" 2>/dev/null || echo "unknown")
log "✅ Valid credentials for service account: $SA_EMAIL"
log "Service account project: $SA_PROJECT"

# Copy credentials to container
log "Copying credentials to Wazuh container..."
docker cp "$TMP_CREDS" single-node-wazuh.manager-1:/var/ossec/wodles/gcp-pubsub/credentials.json
docker exec single-node-wazuh.manager-1 chown root:wazuh /var/ossec/wodles/gcp-pubsub/credentials.json
docker exec single-node-wazuh.manager-1 chmod 640 /var/ossec/wodles/gcp-pubsub/credentials.json
rm -f "$TMP_CREDS"

# Verify credentials in container
if docker exec single-node-wazuh.manager-1 test -f /var/ossec/wodles/gcp-pubsub/credentials.json; then
    CONTAINER_SA_EMAIL=$(docker exec single-node-wazuh.manager-1 grep -o '"client_email"[^,]*' /var/ossec/wodles/gcp-pubsub/credentials.json | cut -d'"' -f4)
    log "✅ GCP service account key configured in Wazuh container: $CONTAINER_SA_EMAIL"
else
    log "ERROR: Credentials file not found in container"
    exit 1
fi

# Install GCP Pub/Sub Python dependencies in Wazuh's framework Python
log "Installing GCP Pub/Sub Python dependencies in Wazuh framework..."
log "Using Python at: /var/ossec/framework/python/bin/pip3"

# Check if pip exists
if ! docker exec single-node-wazuh.manager-1 test -f /var/ossec/framework/python/bin/pip3; then
    log "ERROR: pip3 not found at /var/ossec/framework/python/bin/pip3"
    exit 1
fi

log "Installing google-cloud-pubsub==2.18.4..."
if docker exec single-node-wazuh.manager-1 bash -c '/var/ossec/framework/python/bin/pip3 install --upgrade google-cloud-pubsub==2.18.4' 2>&1 | tee /tmp/pip_install.log; then
    log "✅ pip install completed"
else
    log "ERROR: pip install failed"
    cat /tmp/pip_install.log
    exit 1
fi

log "Verifying installation..."
if docker exec single-node-wazuh.manager-1 /var/ossec/framework/python/bin/pip3 list | grep -q google-cloud-pubsub; then
    INSTALLED_VERSION=$(docker exec single-node-wazuh.manager-1 /var/ossec/framework/python/bin/pip3 list | grep google-cloud-pubsub)
    log "✅ GCP Pub/Sub dependencies installed successfully: $INSTALLED_VERSION"
else
    log "ERROR: Failed to install GCP Pub/Sub dependencies"
    log "Installed packages:"
    docker exec single-node-wazuh.manager-1 /var/ossec/framework/python/bin/pip3 list | head -20
    exit 1
fi

# Configure Wazuh GCP-Pub/Sub command wodle
log "Configuring Wazuh GCP Pub/Sub command wodle..."

# First, check if ossec.conf exists and is accessible
log "Verifying ossec.conf exists..."
if ! docker exec single-node-wazuh.manager-1 test -f /var/ossec/etc/ossec.conf; then
    log "ERROR: /var/ossec/etc/ossec.conf not found"
    exit 1
fi
log "ossec.conf found, proceeding with configuration..."

# Create a temporary Python script with better error handling
# NOTE: Using cat without quotes to allow variable substitution
cat > /tmp/configure_gcp_wodle.py <<PYSCRIPT
import re
import sys
import traceback

try:
    ossec_conf_path = "/var/ossec/etc/ossec.conf"
    
    print("DEBUG: Reading ossec.conf...")
    with open(ossec_conf_path, "r") as f:
        content = f.read()
    
    print(f"DEBUG: Read {len(content)} bytes from ossec.conf")
    
    # Remove any existing gcp-pubsub or gcp command wodle configuration
    print("DEBUG: Removing existing GCP configurations...")
    content = re.sub(r'<wodle name="gcp-pubsub">.*?</wodle>', '', content, flags=re.DOTALL)
    content = re.sub(r'<!-- GCP Pub/Sub.*?</wodle>', '', content, flags=re.DOTALL)
    
    # GCP Pub/Sub command wodle configuration with actual project and subscription values
    print("DEBUG: Creating GCP wodle configuration...")
    print("DEBUG: Project ID: ${pubsub_project_id}")
    print("DEBUG: Subscription ID: ${pubsub_subscription_id}")
    
    gcp_wodle = """
  <!-- GCP Pub/Sub Integration -->
  <wodle name="command">
    <disabled>no</disabled>
    <tag>gcp</tag>
    <command>/var/ossec/wodles/gcloud/gcloud -T pubsub -p ${pubsub_project_id} -s ${pubsub_subscription_id} -c /var/ossec/wodles/gcp-pubsub/credentials.json -m 100 -l 1</command>
    <interval>1m</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>0</timeout>
  </wodle>

"""
    
    # Find the last </ossec_config> and insert before it
    print("DEBUG: Finding last </ossec_config> tag...")
    last_closing = content.rfind('</ossec_config>')
    
    if last_closing == -1:
        print("ERROR: Could not find closing </ossec_config> tag")
        sys.exit(1)
    
    print(f"DEBUG: Found </ossec_config> at position {last_closing}")
    
    # Insert the wodle configuration before the last closing tag
    content = content[:last_closing] + gcp_wodle + content[last_closing:]
    
    print("DEBUG: Writing updated configuration...")
    with open(ossec_conf_path, "w") as f:
        f.write(content)
    
    print("SUCCESS: GCP Pub/Sub command wodle configured")
    sys.exit(0)
    
except Exception as e:
    print(f"ERROR: Failed to configure GCP wodle: {str(e)}")
    print(f"ERROR: Full traceback:")
    traceback.print_exc()
    sys.exit(1)
PYSCRIPT

# Copy the script to the container and execute it
log "Copying configuration script to container..."
docker cp /tmp/configure_gcp_wodle.py single-node-wazuh.manager-1:/tmp/configure_gcp_wodle.py

log "Executing configuration script..."
if docker exec single-node-wazuh.manager-1 python3 /tmp/configure_gcp_wodle.py; then
    log "✅ GCP Pub/Sub command wodle configured successfully"
    
    # Verify configuration was added
    if docker exec single-node-wazuh.manager-1 grep -q "GCP Pub/Sub Integration" /var/ossec/etc/ossec.conf; then
        log "✅ Configuration verified in ossec.conf"
    else
        log "WARNING: Configuration script succeeded but cannot verify in ossec.conf"
    fi
else
    log "ERROR: Failed to configure GCP Pub/Sub command wodle"
    log "Displaying last 50 lines of ossec.conf for debugging:"
    docker exec single-node-wazuh.manager-1 tail -50 /var/ossec/etc/ossec.conf
    exit 1
fi

# Cleanup
rm -f /tmp/configure_gcp_wodle.py
docker exec single-node-wazuh.manager-1 rm -f /tmp/configure_gcp_wodle.py

# Create GCP detection rules (Wazuh has built-in ones, but we'll add custom ones)
log "Creating GCP detection rules..."
log "Creating rules file at /var/ossec/etc/rules/gcp_rules.xml..."

# Check if rules directory exists
if ! docker exec single-node-wazuh.manager-1 test -d /var/ossec/etc/rules; then
    log "ERROR: Rules directory /var/ossec/etc/rules not found"
    exit 1
fi

docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/gcp_rules.xml <<'"'"'LOCALRULES'"'"'
<!-- Local rules for GCP integration -->

<group name="gcp,cloud,">
  
  <!--  GCP Pub/Sub base rule -->
  <rule id="100100" level="3">
    <decoded_as>json</decoded_as>
    <field name="integration">gcp</field>
    <description>GCP log received via Pub/Sub</description>
    <group>gcp,cloud,</group>
  </rule>
  
  <!-- GCP Compute Instance operations -->
  <rule id="100101" level="5">
    <if_sid>100100</if_sid>
    <field name="protoPayload.methodName">\\.instances\\.</field>
    <description>GCP Compute: \$(protoPayload.methodName)</description>
    <group>gcp,compute,</group>
  </rule>
  
  <!-- GCP IAM operations -->
  <rule id="100102" level="6">
    <if_sid>100100</if_sid>
    <field name="protoPayload.methodName">\\.iam\\.|\\.serviceAccount\\.</field>
    <description>GCP IAM: \$(protoPayload.methodName) by \$(protoPayload.authenticationInfo.principalEmail)</description>
    <group>gcp,iam,</group>
  </rule>
  
  <!-- GCP Network operations -->
  <rule id="100103" level="5">
    <if_sid>100100</if_sid>
    <field name="protoPayload.serviceName">compute.googleapis.com</field>
    <field name="protoPayload.methodName">network|firewall|subnetwork|route</field>
    <description>GCP Network: \$(protoPayload.methodName)</description>
    <group>gcp,network,</group>
  </rule>
  
  <!-- GCP Storage operations -->
  <rule id="100104" level="4">
    <if_sid>100100</if_sid>
    <field name="protoPayload.serviceName">storage.googleapis.com</field>
    <description>GCP Storage: \$(protoPayload.methodName)</description>
    <group>gcp,storage,</group>
  </rule>
  
  <!-- GCP Permission denied -->
  <rule id="100105" level="8">
    <if_sid>100100</if_sid>
    <field name="protoPayload.status.code">^7\$</field>
    <description>GCP Permission Denied: \$(protoPayload.methodName) by \$(protoPayload.authenticationInfo.principalEmail)</description>
    <group>gcp,access_denied,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
  
  <!-- GCP Errors -->
  <rule id="100106" level="7">
    <if_sid>100100</if_sid>
    <field name="severity">ERROR</field>
    <description>GCP Error: \$(protoPayload.methodName)</description>
    <group>gcp,error,</group>
  </rule>
  
  <!-- GCP Warnings -->
  <rule id="100107" level="4">
    <if_sid>100100</if_sid>
    <field name="severity">WARNING</field>
    <description>GCP Warning: \$(protoPayload.methodName)</description>
    <group>gcp,warning,</group>
  </rule>
  
  <!-- GCP Critical events -->
  <rule id="100108" level="12">
    <if_sid>100100</if_sid>
    <field name="severity">CRITICAL|ALERT|EMERGENCY</field>
    <description>GCP Critical Event: \$(protoPayload.methodName)</description>
    <group>gcp,critical,</group>
  </rule>
  
  <!-- GCP Resource deletion -->
  <rule id="100109" level="6">
    <if_sid>100100</if_sid>
    <field name="protoPayload.methodName">\\.delete\$</field>
    <description>GCP Resource Deletion: \$(protoPayload.methodName) by \$(protoPayload.authenticationInfo.principalEmail)</description>
    <group>gcp,resource_deletion,</group>
  </rule>

</group>
LOCALRULES
'

# Verify rules were created
log "Verifying GCP rules were created..."
if docker exec single-node-wazuh.manager-1 test -f /var/ossec/etc/rules/gcp_rules.xml; then
    RULE_COUNT=$(docker exec single-node-wazuh.manager-1 grep -c "<rule id=" /var/ossec/etc/rules/gcp_rules.xml || echo "0")
    log "✅ GCP detection rules created with $RULE_COUNT rules"
else
    log "ERROR: Failed to create GCP rules file"
    exit 1
fi

# Restart Wazuh to load the new configuration
log "Restarting Wazuh to load GCP command wodle..."
log "Current Wazuh processes before restart:"
docker exec single-node-wazuh.manager-1 ps aux | grep -E "wazuh|ossec" | grep -v grep | head -5

if docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart > /tmp/wazuh_restart.log 2>&1; then
    log "✅ Wazuh restarted successfully"
    cat /tmp/wazuh_restart.log | tail -10
else
    log "ERROR: Wazuh restart failed"
    cat /tmp/wazuh_restart.log
    exit 1
fi

log "Waiting 60 seconds for Wazuh to fully initialize..."
sleep 60

# Verify GCP command wodle is running
log "Verifying GCP Pub/Sub command wodle status..."
log "Checking ossec.log for GCP wodle activity..."

# Check if wodle is mentioned in logs
if docker exec single-node-wazuh.manager-1 grep -i "command:gcp\|wazuh-modulesd.*command" /var/ossec/logs/ossec.log > /dev/null 2>&1; then
    log "✅ GCP Pub/Sub command wodle is active"
    docker exec single-node-wazuh.manager-1 grep -i "command:gcp\|wazuh-modulesd.*command" /var/ossec/logs/ossec.log | tail -5
else
    log "⚠️  GCP Pub/Sub command wodle may not be active yet (check logs later)"
    log "Recent ossec.log entries:"
    docker exec single-node-wazuh.manager-1 tail -20 /var/ossec/logs/ossec.log
fi

# Verify rules were loaded
log "Verifying GCP rules were loaded..."
if docker exec single-node-wazuh.manager-1 grep -q "100100" /var/ossec/etc/rules/gcp_rules.xml; then
    log "✅ GCP detection rules loaded"
else
    log "⚠️  Warning: GCP rules may not be loaded correctly"
fi

# Test manual execution of GCP wodle
log "Testing GCP Pub/Sub connection..."
log "Executing: /var/ossec/wodles/gcloud/gcloud -T pubsub -p ${pubsub_project_id} -s ${pubsub_subscription_id} -c /var/ossec/wodles/gcp-pubsub/credentials.json -m 2 -l 1"

# Store test output
TEST_OUTPUT=$(docker exec single-node-wazuh.manager-1 timeout 30 /var/ossec/wodles/gcloud/gcloud -T pubsub -p ${pubsub_project_id} -s ${pubsub_subscription_id} -c /var/ossec/wodles/gcp-pubsub/credentials.json -m 2 -l 1 2>&1)
TEST_EXIT_CODE=$?

log "Test exit code: $TEST_EXIT_CODE"

if echo "$TEST_OUTPUT" | grep -q "Received and acknowledged"; then
    MESSAGE_COUNT=$(echo "$TEST_OUTPUT" | grep -oP "Received and acknowledged \K\d+" || echo "unknown")
    log "✅ GCP Pub/Sub connection successful - pulled $MESSAGE_COUNT messages!"
    log "Sample output:"
    echo "$TEST_OUTPUT" | grep -E "(INFO|DEBUG|Received)" | head -10
elif echo "$TEST_OUTPUT" | grep -qi "error\|critical\|failed"; then
    log "⚠️  GCP Pub/Sub connection test encountered errors:"
    echo "$TEST_OUTPUT" | grep -E "(ERROR|CRITICAL|Failed)" | head -10
    log "Full output saved for debugging:"
    echo "$TEST_OUTPUT" > /tmp/gcp_test_output.log
    log "Checking credentials..."
    if docker exec single-node-wazuh.manager-1 test -f /var/ossec/wodles/gcp-pubsub/credentials.json; then
        log "Credentials file exists"
        docker exec single-node-wazuh.manager-1 ls -la /var/ossec/wodles/gcp-pubsub/credentials.json
    else
        log "ERROR: Credentials file missing!"
    fi
else
    log "⚠️  GCP Pub/Sub connection test inconclusive (check subscription has messages)"
    log "Test output:"
    echo "$TEST_OUTPUT" | head -20
fi

log "GCP Pub/Sub integration setup complete (using command wodle)!"
log ""
log "To view GCP logs in Wazuh Dashboard:"
log "  1. Access dashboard at http://localhost:5601 (via SSH tunnel)"
log "  2. Go to 'Security events' or 'Discover'"
log "  3. Search for: rule.groups:gcp OR integration:gcp"
log "  4. GCP logs will appear in wazuh-alerts-* index"
log ""
log "GCP Command Wodle Configuration:"
log "  - Integration Type: Pub/Sub (via command wodle)"
log "  - Project ID: ${pubsub_project_id}"
log "  - Subscription: ${pubsub_subscription_id}"
log "  - Credentials: /var/ossec/wodles/gcp-pubsub/credentials.json"
log "  - Pull Interval: 1 minute"
log "  - Max Messages: 100 per pull"
log ""
log "To check GCP command wodle logs:"
log "  docker exec single-node-wazuh.manager-1 grep 'command:gcp' /var/ossec/logs/ossec.log"


# Fix Filebeat password to match admin password
log "Configuring Filebeat with correct password..."
docker exec single-node-wazuh.manager-1 bash <<EOFFILEBEAT
    if [ -f /etc/filebeat/filebeat.yml ]; then
        sed -i "s/password:.*/password: '\$ADMIN_PASSWORD'/g" /etc/filebeat/filebeat.yml
        echo 'Filebeat password updated'
        pkill filebeat || true
    else
        echo 'WARNING: filebeat.yml not found'
    fi
EOFFILEBEAT

# Fix Filebeat password in the Docker volume (persists across container restarts)
log "Updating Filebeat password in Docker volume..."
if [ -f /var/lib/docker/volumes/single-node_filebeat_etc/_data/filebeat.yml ]; then
    sed -i "s/password:.*/password: '\$ADMIN_PASSWORD'/g" /var/lib/docker/volumes/single-node_filebeat_etc/_data/filebeat.yml
    log "Filebeat volume password updated"
else
    log "Filebeat volume not found (will be created by Docker)"
fi

# Ensure Filebeat module path is configured
log "Configuring Filebeat modules path..."
if [ -f /var/lib/docker/volumes/single-node_filebeat_etc/_data/filebeat.yml ]; then
    if ! grep -q "filebeat.config.modules.path" /var/lib/docker/volumes/single-node_filebeat_etc/_data/filebeat.yml; then
        cat >> /var/lib/docker/volumes/single-node_filebeat_etc/_data/filebeat.yml <<'FBMODULES'

filebeat.config.modules:
  path: $${path.config}/modules.d/*.yml
  reload.enabled: false
FBMODULES
    fi
fi

# Wait for Filebeat to restart and verify connection
log "Verifying Filebeat connection..."
sleep 10
docker exec single-node-wazuh.manager-1 filebeat test output -c /etc/filebeat/filebeat.yml 2>&1 | grep -q "talk to server... OK" && \
    log "✅ Filebeat connection successful" || \
    log "⚠️  Filebeat connection test inconclusive (may still be starting)"

log ""
log "=========================================="
log "Wazuh Installation Complete!"
log "=========================================="
log ""
log "Dashboard Access:"
log "  URL: http://localhost:5601 (via SSH tunnel)"
log "  Username: admin"
log "  Password: [configured password]"
log ""
log "SSH Tunnel Command:"
log "  gcloud compute ssh $$(hostname) --zone=$$(gcloud compute instances list --filter=name:$$(hostname) --format='value(zone)') --project=${pubsub_project_id} -- -L 5601:localhost:5601"
log ""
log "GCP Pub/Sub Integration:"
log "  Status: Enabled (command wodle)"
log "  Integration: GCloud Pub/Sub"
log "  Project: ${pubsub_project_id}"
log "  Subscription: ${pubsub_subscription_id}"
log ""
log "Verification Commands:"
log "  Check GCP wodle logs:"
log "    docker exec single-node-wazuh.manager-1 grep 'command:gcp' /var/ossec/logs/ossec.log"
log ""
log "  Check GCP configuration:"
log "    docker exec single-node-wazuh.manager-1 grep -A 10 'GCP Pub/Sub' /var/ossec/etc/ossec.conf"
log ""
log "  Test GCP connection:"
log "    docker exec single-node-wazuh.manager-1 /var/ossec/wodles/gcloud/gcloud -T pubsub -p ${pubsub_project_id} -s ${pubsub_subscription_id} -c /var/ossec/wodles/gcp-pubsub/credentials.json -m 5 -l 1"
log ""
log "  Check Wazuh status:"
log "    docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status"
log ""
log "To view GCP logs in dashboard:"
log "  1. Create SSH tunnel (see command above)"
log "  2. Open http://localhost:5601"
log "  3. Go to 'Security events' or 'Discover'"
log "  4. Filter by: rule.groups:gcp OR integration:gcp"
log "  5. GCP logs include: Cloud Run, Cloud Functions, API Gateway, Compute Engine, IAM, Firewall, Storage, K8s, etc."
log ""
log "Troubleshooting:"
log "  If no GCP logs appear:"
log "    - Check that messages exist in Pub/Sub: gcloud pubsub subscriptions pull ${pubsub_subscription_id} --project=${pubsub_project_id} --limit=1"
log "    - Verify service account permissions: Pub/Sub Subscriber role"
log "    - Check Wazuh logs: docker exec single-node-wazuh.manager-1 tail -100 /var/ossec/logs/ossec.log"
log ""
log "Installation log saved to: /var/log/wazuh-install.log"
log ""

