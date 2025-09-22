# Splunk Cluster Deployment Guide

This guide covers the deployment and configuration of the Splunk Enterprise cluster for the SOC environment.

## Overview

The Splunk deployment includes:
- **Indexer Cluster**: 3 indexers for data storage and search processing
- **Search Head Cluster**: 2 search heads for user interface and search coordination
- **Heavy Forwarders**: Data collection and parsing
- **Cluster Master**: Manages indexer cluster (combined with search head)
- **Deployment Server**: App and configuration management

## Prerequisites

- Infrastructure deployed (from [Step 1](01-infrastructure-setup.md))
- Ansible installed and configured
- SSH access to deployed instances
- Splunk license file (optional for evaluation)

## Step 1: Prepare for Deployment

### 1.1 Verify Infrastructure
```bash
# Check that all instances are running
./scripts/validation/validate-infrastructure.sh

# Generate Ansible inventory from Terraform outputs
cd infrastructure/ansible
python3 inventories/prod/terraform_inventory.py --list
```

### 1.2 Test Ansible Connectivity
```bash
# Test connection to all hosts
ansible all -i inventories/prod/terraform_inventory.py -m ping

# Check sudo access
ansible all -i inventories/prod/terraform_inventory.py -m shell -a "sudo whoami" --become
```

## Step 2: Deploy Base Configuration

### 2.1 Deploy Common Configuration
```bash
# Deploy common configuration to all hosts
ansible-playbook -i inventories/prod/terraform_inventory.py playbooks/site.yml --tags common

# Verify common deployment
ansible all -i inventories/prod/terraform_inventory.py -m shell -a "systemctl status chronyd"
```

### 2.2 Configure Networking
```bash
# Verify internal DNS resolution
ansible all -i inventories/prod/terraform_inventory.py -m shell -a "nslookup cluster-master.enterprise-soc.local"
```

## Step 3: Deploy Splunk Indexers

### 3.1 Install Splunk on Indexers
```bash
# Deploy Splunk indexers
ansible-playbook -i inventories/prod/terraform_inventory.py playbooks/site.yml --tags splunk,indexers

# Check indexer status
ansible splunk_indexers -i inventories/prod/terraform_inventory.py -m shell -a "sudo /opt/splunk/bin/splunk status"
```

### 3.2 Configure Indexer Clustering
The indexers will automatically configure clustering based on the Ansible variables. Verify clustering:

```bash
# Check cluster status on each indexer
ansible splunk_indexers -i inventories/prod/terraform_inventory.py -m shell -a "sudo /opt/splunk/bin/splunk show cluster-status"
```

### 3.3 Verify Storage Configuration
```bash
# Check mounted storage
ansible splunk_indexers -i inventories/prod/terraform_inventory.py -m shell -a "df -h /opt/splunk/var/lib/splunk/"

# Check index configuration
ansible splunk_indexers -i inventories/prod/terraform_inventory.py -m shell -a "sudo /opt/splunk/bin/splunk list index"
```

## Step 4: Deploy Splunk Search Heads

### 4.1 Install Search Heads
```bash
# Deploy search heads
ansible-playbook -i inventories/prod/terraform_inventory.py playbooks/site.yml --tags splunk,search_heads

# Check search head status
ansible splunk_search_heads -i inventories/prod/terraform_inventory.py -m shell -a "sudo /opt/splunk/bin/splunk status"
```

### 4.2 Configure Search Head Clustering
```bash
# Initialize search head cluster (run on first search head only)
FIRST_SH=$(ansible splunk_search_heads -i inventories/prod/terraform_inventory.py --list-hosts | head -n 1)

ansible $FIRST_SH -i inventories/prod/terraform_inventory.py -m shell -a "
sudo /opt/splunk/bin/splunk init shcluster-config \
  -auth admin:YourSecurePassword123! \
  -mgmt_uri https://$FIRST_SH:8089 \
  -replication_port 9887 \
  -replication_factor 2 \
  -conf_deploy_fetch_url https://deployer.enterprise-soc.local:8089 \
  -secret YourSharedSecret \
  -shcluster_label enterprise-soc-shc
"
```

### 4.3 Verify Search Head Access
```bash
# Get load balancer URL
SPLUNK_URL=$(cd infrastructure/terraform && terraform output -json | jq -r '.splunk_web_url.value')
echo "Splunk Web URL: $SPLUNK_URL"

# Test web interface
curl -k -I "$SPLUNK_URL/en-US/account/login"
```

## Step 5: Deploy Heavy Forwarders

### 5.1 Install Heavy Forwarders
```bash
# Deploy heavy forwarders
ansible-playbook -i inventories/prod/terraform_inventory.py playbooks/site.yml --tags splunk,forwarders

# Check forwarder status
ansible splunk_heavy_forwarders -i inventories/prod/terraform_inventory.py -m shell -a "sudo /opt/splunkforwarder/bin/splunk status"
```

### 5.2 Configure Data Inputs
Heavy forwarders are configured to receive data from:
- Syslog (port 514)
- HTTP Event Collector (port 8088)
- Splunk forwarders (port 9997)

Test data input:
```bash
# Test syslog input
HF_IP=$(ansible splunk_heavy_forwarders -i inventories/prod/terraform_inventory.py --list-hosts | head -n 1)
logger -n $HF_IP -P 514 "Test message from SOC deployment"
```

## Step 6: Deploy Splunk Apps

### 6.1 Package Custom Apps
```bash
# Package SOC apps
cd splunk/apps

# Technology Add-on
tar -czf TA_enterprise_soc.tar.gz TA_enterprise_soc/

# Detection Rules
tar -czf DA_enterprise_soc_detections.tar.gz DA_enterprise_soc_detections/

# Dashboards
tar -czf DA_enterprise_soc_dashboards.tar.gz DA_enterprise_soc_dashboards/

# Lookup Tables
tar -czf LA_enterprise_soc_lookups.tar.gz LA_enterprise_soc_lookups/
```

### 6.2 Deploy Apps to Search Heads
```bash
# Copy apps to search heads
ansible splunk_search_heads -i inventories/prod/terraform_inventory.py -m copy -a "
  src=splunk/apps/TA_enterprise_soc.tar.gz 
  dest=/tmp/TA_enterprise_soc.tar.gz
"

# Extract and install apps
ansible splunk_search_heads -i inventories/prod/terraform_inventory.py -m shell -a "
  cd /opt/splunk/etc/apps && 
  sudo tar -xzf /tmp/TA_enterprise_soc.tar.gz && 
  sudo chown -R splunk:splunk TA_enterprise_soc
"

# Restart Splunk to load apps
ansible splunk_search_heads -i inventories/prod/terraform_inventory.py -m shell -a "
  sudo /opt/splunk/bin/splunk restart
"
```

### 6.3 Deploy Apps to Indexers
```bash
# Deploy essential apps to indexers
ansible splunk_indexers -i inventories/prod/terraform_inventory.py -m copy -a "
  src=splunk/apps/TA_enterprise_soc.tar.gz 
  dest=/tmp/TA_enterprise_soc.tar.gz
"

ansible splunk_indexers -i inventories/prod/terraform_inventory.py -m shell -a "
  cd /opt/splunk/etc/apps && 
  sudo tar -xzf /tmp/TA_enterprise_soc.tar.gz && 
  sudo chown -R splunk:splunk TA_enterprise_soc &&
  sudo /opt/splunk/bin/splunk restart
"
```

## Step 7: Configure Detection Rules

### 7.1 Enable Saved Searches
```bash
# Access Splunk Web and navigate to Settings > Searches, reports, and alerts
# Or use REST API to enable searches

SPLUNK_URL="https://$(ansible splunk_search_heads -i inventories/prod/terraform_inventory.py --list-hosts | head -n 1):8089"

# Enable a detection rule via REST API
curl -k -u admin:YourSecurePassword123! \
  -X POST \
  "$SPLUNK_URL/services/saved/searches/SOC%20-%20Suspicious%20PowerShell%20Execution" \
  -d "disabled=0"
```

### 7.2 Configure Alerting
```bash
# Configure email alerting
ansible splunk_search_heads -i inventories/prod/terraform_inventory.py -m shell -a "
sudo /opt/splunk/bin/splunk set default-hostname $(hostname -f)
sudo /opt/splunk/bin/splunk set servername $(hostname -f)
"
```

## Step 8: Data Onboarding

### 8.1 Configure Universal Forwarders
Create a deployment package for Universal Forwarders:

```bash
# Create UF deployment package
mkdir -p deployment/universalforwarder
cd deployment/universalforwarder

# Create deploymentclient.conf
cat > deploymentclient.conf << EOF
[deployment-client]
targetUri = deployment-server.enterprise-soc.local:8089

[target-broker:deploymentServer]
targetUri = deployment-server.enterprise-soc.local:8089
EOF

# Create outputs.conf
cat > outputs.conf << EOF
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = heavy-forwarder.enterprise-soc.local:9997
useACK = true
EOF
```

### 8.2 Windows Event Collection
Configure Windows event collection:

```bash
# Create inputs.conf for Windows
cat > inputs_windows.conf << EOF
[WinEventLog://Security]
disabled = 0
index = winevent
renderXml = 0
checkpointInterval = 5

[WinEventLog://System]
disabled = 0
index = winevent
renderXml = 0

[WinEventLog://Application]
disabled = 0
index = winevent
renderXml = 0

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = winevent
renderXml = 0
EOF
```

### 8.3 Linux Log Collection
```bash
# Create inputs.conf for Linux
cat > inputs_linux.conf << EOF
[monitor:///var/log/secure]
disabled = 0
index = os
sourcetype = linux_secure

[monitor:///var/log/messages]
disabled = 0
index = os
sourcetype = linux_messages_syslog

[monitor:///var/log/auth.log]
disabled = 0
index = auth
sourcetype = linux_secure

[monitor:///var/log/audit/audit.log]
disabled = 0
index = os
sourcetype = linux_audit
EOF
```

## Step 9: Verification and Testing

### 9.1 Cluster Health Check
```bash
# Run comprehensive cluster health check
ansible-playbook -i inventories/prod/terraform_inventory.py playbooks/site.yml --tags verification

# Check cluster status
SPLUNK_URL="https://$(ansible splunk_search_heads -i inventories/prod/terraform_inventory.py --list-hosts | head -n 1):8089"

curl -k -u admin:YourSecurePassword123! \
  "$SPLUNK_URL/services/cluster/master/status" \
  -d "output_mode=json" | jq .
```

### 9.2 Search Testing
```bash
# Test basic search functionality
curl -k -u admin:YourSecurePassword123! \
  "$SPLUNK_URL/services/search/jobs" \
  -d "search=search index=_internal | head 10" \
  -d "output_mode=json"
```

### 9.3 Data Ingestion Test
```bash
# Send test data
HF_IP=$(ansible splunk_heavy_forwarders -i inventories/prod/terraform_inventory.py --list-hosts | head -n 1)

# Send via syslog
logger -n $HF_IP -P 514 "SOC_TEST: Deployment verification test message"

# Send via HEC
curl -k -H "Authorization: Splunk your-hec-token" \
  -d '{"event": "SOC deployment test", "sourcetype": "deployment_test"}' \
  "https://$HF_IP:8088/services/collector"
```

### 9.4 Run Detection Tests
```bash
# Run detection rule tests
./scripts/validation/test-detections.sh \
  --splunk-host $(ansible splunk_search_heads -i inventories/prod/terraform_inventory.py --list-hosts | head -n 1) \
  --splunk-user admin
```

## Step 10: Performance Tuning

### 10.1 Indexer Performance
```bash
# Check indexer performance
ansible splunk_indexers -i inventories/prod/terraform_inventory.py -m shell -a "
sudo /opt/splunk/bin/splunk show config inputs --debug
"

# Monitor indexing performance
ansible splunk_indexers -i inventories/prod/terraform_inventory.py -m shell -a "
sudo /opt/splunk/bin/splunk list inputstatus
"
```

### 10.2 Search Performance
```bash
# Configure search head pooling
ansible splunk_search_heads -i inventories/prod/terraform_inventory.py -m shell -a "
sudo /opt/splunk/bin/splunk edit cluster-config -mode searchhead -master_uri https://cluster-master.enterprise-soc.local:8089
"
```

### 10.3 Storage Optimization
```bash
# Check storage usage
ansible splunk_indexers -i inventories/prod/terraform_inventory.py -m shell -a "
du -sh /opt/splunk/var/lib/splunk/*/db
"

# Configure bucket rolling policies
# This is done through indexes.conf in the TA_enterprise_soc app
```

## Step 11: Security Configuration

### 11.1 SSL/TLS Configuration
```bash
# Generate SSL certificates (or use existing ones)
ansible splunk_search_heads -i inventories/prod/terraform_inventory.py -m shell -a "
sudo openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
  -keyout /opt/splunk/etc/auth/splunk.key \
  -out /opt/splunk/etc/auth/splunk.crt \
  -subj '/CN=splunk.enterprise-soc.local'
sudo chown splunk:splunk /opt/splunk/etc/auth/splunk.*
"
```

### 11.2 User Authentication
```bash
# Configure LDAP authentication (example)
# This would typically be done through Splunk Web UI or REST API
# Settings > Authentication > LDAP
```

### 11.3 Role-Based Access Control
```bash
# Create SOC-specific roles
curl -k -u admin:YourSecurePassword123! \
  "$SPLUNK_URL/services/authorization/roles" \
  -d "name=soc_analyst" \
  -d "capabilities=edit_search_schedule_priority,list_search_jobs,search" \
  -d "srchIndexesAllowed=*" \
  -d "srchIndexesDefault=os,winevent,auth,network"
```

## Troubleshooting

### Common Issues

#### 11.1 Cluster Formation Issues
```bash
# Check cluster master connectivity
ansible splunk_indexers -i inventories/prod/terraform_inventory.py -m shell -a "
telnet cluster-master.enterprise-soc.local 8089
"

# Reset cluster configuration if needed
ansible splunk_indexers -i inventories/prod/terraform_inventory.py -m shell -a "
sudo /opt/splunk/bin/splunk stop
sudo rm -rf /opt/splunk/var/lib/splunk/cluster/
sudo /opt/splunk/bin/splunk start
"
```

#### 11.2 Search Head Issues
```bash
# Check search head cluster status
curl -k -u admin:YourSecurePassword123! \
  "$SPLUNK_URL/services/shcluster/status" \
  -d "output_mode=json"

# View search head logs
ansible splunk_search_heads -i inventories/prod/terraform_inventory.py -m shell -a "
sudo tail -f /opt/splunk/var/log/splunk/splunkd.log
"
```

#### 11.3 Data Input Issues
```bash
# Check input status
curl -k -u admin:YourSecurePassword123! \
  "$SPLUNK_URL/services/data/inputs/tcp/cooked" \
  -d "output_mode=json"

# Test network connectivity
ansible splunk_heavy_forwarders -i inventories/prod/terraform_inventory.py -m shell -a "
netstat -tlnp | grep :514
"
```

### Performance Issues

#### 11.4 Slow Searches
```bash
# Check search concurrency
curl -k -u admin:YourSecurePassword123! \
  "$SPLUNK_URL/services/search/jobs" \
  -d "output_mode=json" | jq '.entry | length'

# Review search performance
curl -k -u admin:YourSecurePassword123! \
  "$SPLUNK_URL/services/search/jobs" \
  -d "output_mode=json" | jq '.entry[] | {sid: .name, runtime: .content.runDuration}'
```

#### 11.5 Indexing Performance
```bash
# Check indexer queue status
ansible splunk_indexers -i inventories/prod/terraform_inventory.py -m shell -a "
sudo /opt/splunk/bin/splunk show inputstatus | grep -E 'queue|blocked'
"
```

## Next Steps

After successful Splunk deployment:

1. **[Configure SOAR Platform](03-soar-setup.md)** - Set up automation and orchestration
2. **[Deploy Detection Rules](04-detection-rules.md)** - Implement security detections
3. **[Data Source Integration](../integration-guides/)** - Connect additional data sources
4. **[User Training](../user-guides/)** - Train SOC analysts on the platform

## Support Resources

- **Splunk Documentation**: https://docs.splunk.com/
- **Community Forums**: https://community.splunk.com/
- **SOC App Documentation**: [../apps/README.md](../apps/README.md)
- **Troubleshooting Guide**: [../troubleshooting.md](../troubleshooting.md)

---

**Next**: [SOAR Platform Setup](03-soar-setup.md)
