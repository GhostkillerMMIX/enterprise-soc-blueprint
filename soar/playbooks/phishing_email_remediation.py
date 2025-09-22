"""
Phishing Email Remediation Playbook
Automated response for phishing email incidents

MITRE ATT&CK Coverage:
- T1566.001: Spearphishing Attachment
- T1566.002: Spearphishing Link
- T1566.003: Spearphishing via Service
"""

import phantom.rules as phantom
import json
import hashlib
import re
from datetime import datetime, timedelta

def on_start(container, summary):
    """
    Called when the playbook starts
    """
    phantom.debug('Starting Phishing Email Remediation Playbook')
    
    # Get container artifacts
    artifacts = container.get('artifacts', [])
    
    if not artifacts:
        phantom.error('No artifacts found in container')
        return
    
    # Extract email information
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    # Key email fields
    sender = cef_data.get('sender', cef_data.get('from', 'unknown'))
    recipient = cef_data.get('recipient', cef_data.get('to', 'unknown'))
    subject = cef_data.get('subject', 'No Subject')
    message_id = cef_data.get('message_id', cef_data.get('messageId', ''))
    
    phantom.debug(f'Processing phishing email: sender={sender}, recipient={recipient}, subject={subject}')
    
    # Start remediation workflow
    analyze_email_content(container, summary)

def analyze_email_content(container, summary):
    """
    Analyze email content for malicious indicators
    """
    phantom.debug('Analyzing email content')
    
    artifacts = container.get('artifacts', [])
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    # Extract URLs and attachments from email
    email_body = cef_data.get('body', cef_data.get('message', ''))
    attachments = cef_data.get('attachments', [])
    
    # Extract URLs from email body
    urls = extract_urls_from_text(email_body)
    
    phantom.debug(f'Found {len(urls)} URLs and {len(attachments)} attachments')
    
    # Analyze URLs
    if urls:
        for url in urls[:5]:  # Limit to first 5 URLs
            analyze_url(container, url)
    
    # Analyze attachments
    if attachments:
        for attachment in attachments[:5]:  # Limit to first 5 attachments
            analyze_attachment(container, attachment)
    
    # Get sender reputation
    sender = cef_data.get('sender', cef_data.get('from', ''))
    if sender:
        check_sender_reputation(container, sender)
    
    # Wait for analysis to complete, then make containment decision
    phantom.callback(containment_decision, container, summary)

def extract_urls_from_text(text):
    """
    Extract URLs from email text
    """
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    return list(set(urls))  # Remove duplicates

def analyze_url(container, url):
    """
    Analyze URL for malicious content
    """
    phantom.debug(f'Analyzing URL: {url}')
    
    # VirusTotal URL analysis
    phantom.act('url reputation', parameters={'url': url}, assets=['virustotal'])
    
    # URLVoid analysis
    phantom.act('url reputation', parameters={'url': url}, assets=['urlvoid'])
    
    # Screenshot URL for analysis
    phantom.act('get screenshot', parameters={'url': url}, assets=['urlscan'])

def analyze_attachment(container, attachment):
    """
    Analyze email attachment for malware
    """
    phantom.debug(f'Analyzing attachment: {attachment}')
    
    # Get attachment hash if available
    attachment_hash = attachment.get('hash', '')
    attachment_name = attachment.get('name', 'unknown')
    
    if attachment_hash:
        # VirusTotal file hash analysis
        phantom.act('file reputation', parameters={'hash': attachment_hash}, assets=['virustotal'])
    
    # Detonate file in sandbox if available
    if 'vault_id' in attachment:
        phantom.act('detonate file', parameters={'vault_id': attachment['vault_id']}, assets=['cuckoo_sandbox'])

def check_sender_reputation(container, sender):
    """
    Check sender reputation and history
    """
    phantom.debug(f'Checking sender reputation: {sender}')
    
    # Check sender against threat intelligence
    phantom.act('domain reputation', parameters={'domain': sender.split('@')[1]}, assets=['virustotal'])
    
    # Query Splunk for sender history
    query = f'index=email sender="{sender}" earliest=-30d | stats count by recipient, subject | sort -count'
    phantom.act('run query', parameters={'query': query}, assets=['splunk'])

def containment_decision(container, summary):
    """
    Make containment decisions based on analysis results
    """
    phantom.debug('Making containment decisions')
    
    # Analyze all action results
    malicious_indicators = 0
    suspicious_indicators = 0
    
    # Get all action results
    for action_result in phantom.get_action_results():
        if action_result.get('action') in ['url reputation', 'file reputation', 'domain reputation']:
            data = action_result.get('data', [{}])[0]
            
            # Check VirusTotal results
            if 'positives' in data and 'total' in data:
                positives = int(data.get('positives', 0))
                total = int(data.get('total', 1))
                detection_ratio = positives / total if total > 0 else 0
                
                if detection_ratio >= 0.3:  # 30% or more engines detected as malicious
                    malicious_indicators += 1
                elif detection_ratio >= 0.1:  # 10-29% engines detected as suspicious
                    suspicious_indicators += 1
    
    phantom.debug(f'Analysis results: malicious={malicious_indicators}, suspicious={suspicious_indicators}')
    
    # Decision logic
    if malicious_indicators >= 1:
        # Confirmed malicious - immediate remediation
        execute_immediate_remediation(container)
    elif suspicious_indicators >= 2:
        # Likely malicious - standard remediation
        execute_standard_remediation(container)
    else:
        # Potentially suspicious - monitoring
        execute_monitoring_actions(container)

def execute_immediate_remediation(container):
    """
    Execute immediate remediation for confirmed malicious emails
    """
    phantom.debug('Executing immediate remediation')
    
    artifacts = container.get('artifacts', [])
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    sender = cef_data.get('sender', cef_data.get('from', ''))
    subject = cef_data.get('subject', '')
    message_id = cef_data.get('message_id', '')
    
    # 1. Search and delete similar emails across organization
    search_and_delete_emails(container, sender, subject)
    
    # 2. Block sender domain at email gateway
    if sender:
        sender_domain = sender.split('@')[1] if '@' in sender else sender
        block_sender_domain(container, sender_domain)
    
    # 3. Add URLs to web proxy block list
    urls = extract_urls_from_email(container)
    for url in urls:
        block_url_at_proxy(container, url)
    
    # 4. Create high priority incident
    create_incident_ticket(
        container, 
        priority='P1', 
        title=f'CRITICAL: Malicious Phishing Email - {subject[:50]}...'
    )
    
    # 5. Send immediate alert
    send_slack_notification(
        container,
        channel='#security-critical',
        message=f'🚨 CRITICAL: Malicious phishing email detected and remediated\nSender: {sender}\nSubject: {subject}',
        color='danger'
    )
    
    # 6. Notify affected users
    notify_affected_users(container)

def execute_standard_remediation(container):
    """
    Execute standard remediation for likely malicious emails
    """
    phantom.debug('Executing standard remediation')
    
    artifacts = container.get('artifacts', [])
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    sender = cef_data.get('sender', cef_data.get('from', ''))
    subject = cef_data.get('subject', '')
    
    # 1. Quarantine similar emails
    quarantine_similar_emails(container, sender, subject)
    
    # 2. Add sender to monitoring list
    add_sender_to_monitoring(container, sender)
    
    # 3. Create standard priority incident
    create_incident_ticket(
        container,
        priority='P2',
        title=f'Suspicious Phishing Email - {subject[:50]}...'
    )
    
    # 4. Send team notification
    send_slack_notification(
        container,
        channel='#security-alerts',
        message=f'⚠️ Suspicious phishing email detected\nSender: {sender}\nSubject: {subject}',
        color='warning'
    )

def execute_monitoring_actions(container):
    """
    Execute monitoring actions for potentially suspicious emails
    """
    phantom.debug('Executing monitoring actions')
    
    artifacts = container.get('artifacts', [])
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    sender = cef_data.get('sender', cef_data.get('from', ''))
    subject = cef_data.get('subject', '')
    
    # 1. Add to monitoring watchlist
    add_sender_to_monitoring(container, sender)
    
    # 2. Create low priority ticket for review
    create_incident_ticket(
        container,
        priority='P4',
        title=f'Monitor: Potential Phishing Email - {subject[:50]}...'
    )
    
    # 3. Send monitoring notification
    send_slack_notification(
        container,
        channel='#security-monitoring',
        message=f'📊 Potential phishing email flagged for monitoring\nSender: {sender}\nSubject: {subject}',
        color='good'
    )

# Helper Functions

def extract_urls_from_email(container):
    """
    Extract all URLs from email content
    """
    artifacts = container.get('artifacts', [])
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    email_body = cef_data.get('body', cef_data.get('message', ''))
    return extract_urls_from_text(email_body)

def search_and_delete_emails(container, sender, subject):
    """
    Search for and delete similar emails across the organization
    """
    phantom.debug(f'Searching and deleting emails from {sender} with subject containing "{subject}"')
    
    # Search for similar emails
    search_params = {
        'sender': sender,
        'subject': subject[:30],  # Use first 30 characters of subject
        'max_results': 100
    }
    
    phantom.act('search emails', parameters=search_params, assets=['office365'], callback=delete_found_emails)

def delete_found_emails(action, success, container, results, handle=None, filtered_artifacts=None, filtered_results=None):
    """
    Delete emails found by search
    """
    if not success:
        phantom.error('Email search failed')
        return
    
    # Extract email IDs from search results
    for result in results:
        emails = result.get('data', [])
        for email in emails:
            email_id = email.get('id', email.get('message_id', ''))
            if email_id:
                phantom.debug(f'Deleting email: {email_id}')
                phantom.act('delete email', parameters={'message_id': email_id}, assets=['office365'])

def quarantine_similar_emails(container, sender, subject):
    """
    Quarantine similar emails instead of deleting
    """
    phantom.debug(f'Quarantining emails from {sender}')
    
    search_params = {
        'sender': sender,
        'subject': subject[:30],
        'max_results': 50
    }
    
    phantom.act('search emails', parameters=search_params, assets=['office365'], callback=quarantine_found_emails)

def quarantine_found_emails(action, success, container, results, handle=None, filtered_artifacts=None, filtered_results=None):
    """
    Quarantine emails found by search
    """
    if not success:
        phantom.error('Email search failed')
        return
    
    for result in results:
        emails = result.get('data', [])
        for email in emails:
            email_id = email.get('id', email.get('message_id', ''))
            if email_id:
                phantom.debug(f'Quarantining email: {email_id}')
                phantom.act('quarantine email', parameters={'message_id': email_id}, assets=['office365'])

def block_sender_domain(container, domain):
    """
    Block sender domain at email gateway
    """
    phantom.debug(f'Blocking sender domain: {domain}')
    phantom.act('block domain', parameters={'domain': domain}, assets=['proofpoint'])

def block_url_at_proxy(container, url):
    """
    Block URL at web proxy
    """
    phantom.debug(f'Blocking URL at proxy: {url}')
    phantom.act('block url', parameters={'url': url}, assets=['bluecoat_proxy'])

def add_sender_to_monitoring(container, sender):
    """
    Add sender to monitoring watchlist
    """
    phantom.debug(f'Adding sender to monitoring: {sender}')
    
    # Add to custom lookup table for monitoring
    phantom.act('add to list', 
                parameters={
                    'list_name': 'email_monitoring_watchlist',
                    'value': sender,
                    'category': 'suspicious_sender'
                }, 
                assets=['splunk'])

def notify_affected_users(container):
    """
    Notify users who received the malicious email
    """
    phantom.debug('Notifying affected users')
    
    artifacts = container.get('artifacts', [])
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    recipients = cef_data.get('recipients', [cef_data.get('recipient', cef_data.get('to', ''))])
    
    notification_message = """
    SECURITY ALERT: Malicious Email Detected
    
    A malicious email has been detected and removed from your mailbox. 
    
    If you clicked any links or opened attachments from this email, please:
    1. Run a full antivirus scan on your computer
    2. Change your passwords immediately
    3. Contact the Security Team at security@company.com
    
    Thank you for your vigilance.
    Security Operations Center
    """
    
    for recipient in recipients:
        if recipient and '@' in recipient:
            phantom.act('send email', 
                        parameters={
                            'to': recipient,
                            'subject': 'SECURITY ALERT: Malicious Email Removed',
                            'body': notification_message
                        }, 
                        assets=['smtp'])

def create_incident_ticket(container, priority='P3', title='Phishing Email Incident'):
    """
    Create incident ticket in ITSM system
    """
    phantom.debug(f'Creating incident ticket: {title}')
    
    artifacts = container.get('artifacts', [])
    artifact = artifacts[0]
    cef_data = artifact.get('cef', {})
    
    description = f"""
    Phishing Email Incident Details:
    - Subject: {cef_data.get('subject', 'N/A')}
    - Sender: {cef_data.get('sender', cef_data.get('from', 'N/A'))}
    - Recipient: {cef_data.get('recipient', cef_data.get('to', 'N/A'))}
    - Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    - Container ID: {container.get('id')}
    - Message ID: {cef_data.get('message_id', 'N/A')}
    """
    
    phantom.act('create ticket',
                parameters={
                    'title': title,
                    'description': description,
                    'priority': priority,
                    'category': 'Phishing Incident'
                },
                assets=['servicenow'])

def send_slack_notification(container, channel='#security-alerts', message='Phishing Alert', color='warning'):
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
            {'title': 'Sender', 'value': cef_data.get('sender', cef_data.get('from', 'N/A')), 'short': True},
            {'title': 'Subject', 'value': cef_data.get('subject', 'N/A')[:50] + '...', 'short': True},
            {'title': 'Recipient', 'value': cef_data.get('recipient', cef_data.get('to', 'N/A')), 'short': True},
            {'title': 'Container ID', 'value': container.get('id'), 'short': True}
        ],
        'footer': 'Enterprise SOC SOAR - Phishing Response',
        'ts': int(datetime.now().timestamp())
    }
    
    phantom.act('send message',
                parameters={
                    'channel': channel,
                    'message': message,
                    'attachments': json.dumps([attachment])
                },
                assets=['slack'])

def on_finish(container, summary):
    """
    Called when the playbook finishes
    """
    phantom.debug('Phishing Email Remediation Playbook completed')
    
    # Update container status
    phantom.set_status(container, 'closed')
    
    # Add summary note
    phantom.add_note(container, f"Phishing email remediation completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
