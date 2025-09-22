"""
High Risk Login Response Playbook
Automated response for high-risk authentication events

MITRE ATT&CK Coverage:
- T1078: Valid Accounts
- T1110: Brute Force
- T1021: Remote Services
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container, summary):
    """
    Called when the playbook starts
    """
    phantom.debug('Starting High Risk Login Response Playbook')
    
    # Get container artifacts
    artifacts = container.get('artifacts', [])
    
    if not artifacts:
        phantom.error('No artifacts found in container')
        return
    
    # Extract key information from artifacts
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    # Key fields
    user = cef_data.get('user', 'unknown')
    src_ip = cef_data.get('src_ip', 'unknown')
    risk_score = int(cef_data.get('risk_score', 0))
    
    phantom.debug(f'Processing high risk login: user={user}, src_ip={src_ip}, risk_score={risk_score}')
    
    # Decision tree based on risk score
    if risk_score >= 80:
        # Critical risk - immediate containment
        phantom.debug('Critical risk detected - initiating immediate containment')
        enrich_and_contain(container, summary)
    elif risk_score >= 60:
        # High risk - enrich and analyze
        phantom.debug('High risk detected - enriching for analysis')
        enrich_and_analyze(container, summary)
    else:
        # Medium risk - monitor and alert
        phantom.debug('Medium risk detected - monitoring and alerting')
        monitor_and_alert(container, summary)

def enrich_and_contain(container, summary):
    """
    Immediate containment actions for critical risk events
    """
    phantom.debug('Executing containment actions')
    
    artifacts = container.get('artifacts', [])
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    user = cef_data.get('user')
    src_ip = cef_data.get('src_ip')
    
    # Step 1: Enrich with threat intelligence
    enrich_ip_reputation(container, src_ip, callback=containment_decision)
    
    # Step 2: Get user context
    get_user_context(container, user, callback=containment_decision)

def containment_decision(action, success, container, results, handle=None, filtered_artifacts=None, filtered_results=None):
    """
    Make containment decisions based on enrichment results
    """
    phantom.debug('Making containment decisions')
    
    # Analyze enrichment results
    reputation_bad = False
    user_privileged = False
    
    # Check IP reputation results
    for result in results:
        if result.get('action') == 'ip reputation':
            reputation_score = result.get('data', [{}])[0].get('reputation_score', 0)
            if reputation_score < -50:  # Negative score indicates bad reputation
                reputation_bad = True
    
    # Check user context
    for result in results:
        if result.get('action') == 'get user info':
            user_groups = result.get('data', [{}])[0].get('groups', [])
            if any('admin' in group.lower() for group in user_groups):
                user_privileged = True
    
    phantom.debug(f'Containment analysis: reputation_bad={reputation_bad}, user_privileged={user_privileged}')
    
    # Execute containment actions based on analysis
    if reputation_bad or user_privileged:
        # High priority containment
        execute_immediate_containment(container)
    else:
        # Standard containment
        execute_standard_containment(container)

def execute_immediate_containment(container):
    """
    Execute immediate containment actions
    """
    phantom.debug('Executing immediate containment')
    
    artifacts = container.get('artifacts', [])
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    user = cef_data.get('user')
    src_ip = cef_data.get('src_ip')
    host = cef_data.get('host', cef_data.get('dest', 'unknown'))
    
    # 1. Disable user account
    disable_user_account(container, user)
    
    # 2. Block IP at firewall
    block_ip_address(container, src_ip)
    
    # 3. Isolate host if available
    if host != 'unknown':
        isolate_host(container, host)
    
    # 4. Create high priority ticket
    create_incident_ticket(container, priority='P1', title=f'CRITICAL: High Risk Login - {user}')
    
    # 5. Send immediate notification
    send_slack_notification(
        container, 
        channel='#security-critical',
        message=f'🚨 CRITICAL ALERT: High risk login detected for {user} from {src_ip}. Immediate containment actions executed.',
        color='danger'
    )
    
    # 6. Page on-call team
    page_oncall_team(container, f'Critical security incident: High risk login {user}@{src_ip}')

def execute_standard_containment(container):
    """
    Execute standard containment actions
    """
    phantom.debug('Executing standard containment')
    
    artifacts = container.get('artifacts', [])
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    user = cef_data.get('user')
    src_ip = cef_data.get('src_ip')
    
    # 1. Reset user password and require MFA
    reset_user_password(container, user)
    
    # 2. Block IP temporarily (1 hour)
    block_ip_address(container, src_ip, duration=3600)
    
    # 3. Create standard priority ticket
    create_incident_ticket(container, priority='P2', title=f'High Risk Login - {user}')
    
    # 4. Send team notification
    send_slack_notification(
        container,
        channel='#security-alerts',
        message=f'⚠️ High risk login detected for {user} from {src_ip}. Standard containment applied.',
        color='warning'
    )

def enrich_and_analyze(container, summary):
    """
    Enrichment and analysis for high risk events
    """
    phantom.debug('Enriching and analyzing high risk event')
    
    artifacts = container.get('artifacts', [])
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    src_ip = cef_data.get('src_ip')
    user = cef_data.get('user')
    
    # Enrich with multiple sources
    enrich_ip_reputation(container, src_ip)
    get_geolocation(container, src_ip)
    get_user_context(container, user)
    check_user_recent_activity(container, user)
    
    # Create investigation ticket
    create_incident_ticket(container, priority='P3', title=f'Investigation: High Risk Login - {user}')
    
    # Notify team for manual review
    send_slack_notification(
        container,
        channel='#security-investigations',
        message=f'🔍 High risk login requires investigation: {user} from {src_ip}',
        color='good'
    )

def monitor_and_alert(container, summary):
    """
    Monitoring and alerting for medium risk events
    """
    phantom.debug('Monitoring and alerting for medium risk event')
    
    artifacts = container.get('artifacts', [])
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    user = cef_data.get('user')
    src_ip = cef_data.get('src_ip')
    
    # Basic enrichment
    enrich_ip_reputation(container, src_ip)
    
    # Create monitoring ticket
    create_incident_ticket(container, priority='P4', title=f'Monitor: Suspicious Login - {user}')
    
    # Send low priority notification
    send_slack_notification(
        container,
        channel='#security-monitoring',
        message=f'📊 Suspicious login activity: {user} from {src_ip}',
        color='#36a64f'
    )

# Helper Functions

def enrich_ip_reputation(container, ip_address, callback=None):
    """
    Enrich IP address with reputation data
    """
    phantom.debug(f'Enriching IP reputation for {ip_address}')
    
    # VirusTotal IP reputation
    phantom.act('ip reputation', parameters={'ip': ip_address}, assets=['virustotal'], callback=callback)
    
    # Additional reputation sources
    phantom.act('ip reputation', parameters={'ip': ip_address}, assets=['abuseipdb'], callback=callback)

def get_geolocation(container, ip_address):
    """
    Get geolocation information for IP address
    """
    phantom.debug(f'Getting geolocation for {ip_address}')
    phantom.act('geolocate ip', parameters={'ip': ip_address}, assets=['maxmind'])

def get_user_context(container, username, callback=None):
    """
    Get user context from identity provider
    """
    phantom.debug(f'Getting user context for {username}')
    phantom.act('get user info', parameters={'username': username}, assets=['active_directory'], callback=callback)

def check_user_recent_activity(container, username):
    """
    Check user's recent authentication activity
    """
    phantom.debug(f'Checking recent activity for {username}')
    
    # Query Splunk for recent user activity
    query = f'index=auth user="{username}" earliest=-7d | stats count by src_ip, action | sort -count'
    phantom.act('run query', parameters={'query': query}, assets=['splunk'])

def disable_user_account(container, username):
    """
    Disable user account in identity provider
    """
    phantom.debug(f'Disabling user account: {username}')
    phantom.act('disable user', parameters={'username': username}, assets=['active_directory'])

def reset_user_password(container, username):
    """
    Reset user password and require MFA
    """
    phantom.debug(f'Resetting password for user: {username}')
    phantom.act('reset password', parameters={'username': username, 'require_change': True}, assets=['active_directory'])

def block_ip_address(container, ip_address, duration=86400):
    """
    Block IP address at firewall
    """
    phantom.debug(f'Blocking IP address: {ip_address} for {duration} seconds')
    phantom.act('block ip', parameters={'ip': ip_address, 'duration': duration}, assets=['palo_alto_firewall'])

def isolate_host(container, hostname):
    """
    Isolate host using EDR platform
    """
    phantom.debug(f'Isolating host: {hostname}')
    phantom.act('isolate endpoint', parameters={'hostname': hostname}, assets=['crowdstrike'])

def create_incident_ticket(container, priority='P3', title='Security Incident'):
    """
    Create incident ticket in ITSM system
    """
    phantom.debug(f'Creating incident ticket: {title}')
    
    artifacts = container.get('artifacts', [])
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    description = f"""
    Security Incident Details:
    - Event: {title}
    - User: {cef_data.get('user', 'N/A')}
    - Source IP: {cef_data.get('src_ip', 'N/A')}
    - Risk Score: {cef_data.get('risk_score', 'N/A')}
    - Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    - Container ID: {container.get('id')}
    """
    
    phantom.act('create ticket', 
                parameters={
                    'title': title,
                    'description': description,
                    'priority': priority,
                    'category': 'Security Incident'
                }, 
                assets=['servicenow'])

def send_slack_notification(container, channel='#security-alerts', message='Security Alert', color='warning'):
    """
    Send notification to Slack channel
    """
    phantom.debug(f'Sending Slack notification to {channel}')
    
    artifacts = container.get('artifacts', [])
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    attachment = {
        'color': color,
        'fields': [
            {'title': 'User', 'value': cef_data.get('user', 'N/A'), 'short': True},
            {'title': 'Source IP', 'value': cef_data.get('src_ip', 'N/A'), 'short': True},
            {'title': 'Risk Score', 'value': cef_data.get('risk_score', 'N/A'), 'short': True},
            {'title': 'Container ID', 'value': container.get('id'), 'short': True}
        ],
        'footer': 'Enterprise SOC SOAR',
        'ts': int(datetime.now().timestamp())
    }
    
    phantom.act('send message', 
                parameters={
                    'channel': channel,
                    'message': message,
                    'attachments': json.dumps([attachment])
                }, 
                assets=['slack'])

def page_oncall_team(container, message):
    """
    Page on-call team for critical incidents
    """
    phantom.debug('Paging on-call team')
    phantom.act('send notification', 
                parameters={
                    'message': message,
                    'severity': 'critical'
                }, 
                assets=['pagerduty'])

def on_finish(container, summary):
    """
    Called when the playbook finishes
    """
    phantom.debug('High Risk Login Response Playbook completed')
    
    # Update container status
    phantom.set_status(container, 'closed')
    
    # Add summary note
    phantom.add_note(container, f"High Risk Login Response completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
