"""
Threat Intelligence Enrichment Custom App
Automated threat intelligence enrichment for IOCs

This app provides centralized threat intelligence enrichment
across multiple sources and maintains a local cache for performance.
"""

import phantom.app as phantom
import requests
import json
import hashlib
import time
from datetime import datetime, timedelta

class ThreatIntelEnrichmentApp(phantom.BaseConnector):
    
    def __init__(self):
        super(ThreatIntelEnrichmentApp, self).__init__()
        self._state = None
        
        # Threat intelligence sources configuration
        self._ti_sources = {
            'virustotal': {
                'enabled': True,
                'api_key': None,
                'base_url': 'https://www.virustotal.com/vtapi/v2/',
                'rate_limit': 4,  # requests per minute
                'last_request': 0
            },
            'abuseipdb': {
                'enabled': True,
                'api_key': None,
                'base_url': 'https://api.abuseipdb.com/api/v2/',
                'rate_limit': 1000,  # requests per day
                'last_request': 0
            },
            'otx': {
                'enabled': True,
                'api_key': None,
                'base_url': 'https://otx.alienvault.com/api/v1/',
                'rate_limit': 10000,  # requests per hour
                'last_request': 0
            },
            'misp': {
                'enabled': True,
                'api_key': None,
                'base_url': None,  # Configured per instance
                'rate_limit': 100,  # requests per minute
                'last_request': 0
            }
        }

    def initialize(self):
        """
        Initialize the app
        """
        self._state = self.load_state()
        
        # Get configuration
        config = self.get_config()
        
        # Configure threat intelligence sources
        for source in self._ti_sources:
            api_key = config.get(f'{source}_api_key')
            if api_key:
                self._ti_sources[source]['api_key'] = api_key
                
        # Configure MISP base URL
        misp_url = config.get('misp_url')
        if misp_url:
            self._ti_sources['misp']['base_url'] = misp_url
            
        return phantom.APP_SUCCESS

    def finalize(self):
        """
        Finalize the app
        """
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        """
        Test connectivity to threat intelligence sources
        """
        self.save_progress("Testing connectivity to threat intelligence sources...")
        
        test_results = {}
        
        for source_name, source_config in self._ti_sources.items():
            if not source_config['enabled'] or not source_config['api_key']:
                test_results[source_name] = "Disabled or not configured"
                continue
                
            try:
                if source_name == 'virustotal':
                    result = self._test_virustotal()
                elif source_name == 'abuseipdb':
                    result = self._test_abuseipdb()
                elif source_name == 'otx':
                    result = self._test_otx()
                elif source_name == 'misp':
                    result = self._test_misp()
                else:
                    result = "Unknown source"
                    
                test_results[source_name] = "Connected" if result else "Failed"
                
            except Exception as e:
                test_results[source_name] = f"Error: {str(e)}"
        
        # Display results
        for source, status in test_results.items():
            self.save_progress(f"{source}: {status}")
            
        if all("Connected" in status for status in test_results.values() if "Disabled" not in status):
            return self.set_status(phantom.APP_SUCCESS, "Test connectivity passed")
        else:
            return self.set_status(phantom.APP_ERROR, "Some connections failed")

    def _handle_enrich_ip(self, param):
        """
        Enrich IP address with threat intelligence
        """
        self.save_progress("Starting IP enrichment...")
        
        ip_address = param['ip']
        
        if not self._validate_ip(ip_address):
            return self.set_status(phantom.APP_ERROR, "Invalid IP address format")
        
        # Check cache first
        cache_key = f"ip_{hashlib.md5(ip_address.encode()).hexdigest()}"
        cached_result = self._get_from_cache(cache_key)
        
        if cached_result and not self._is_cache_expired(cached_result):
            self.save_progress("Using cached result")
            action_result = self.add_action_result(phantom.ActionResult(dict(param)))
            action_result.add_data(cached_result['data'])
            return action_result.set_status(phantom.APP_SUCCESS)
        
        # Enrich from multiple sources
        enrichment_data = {
            'ip': ip_address,
            'enrichment_time': datetime.now().isoformat(),
            'sources': {}
        }
        
        # VirusTotal IP report
        if self._ti_sources['virustotal']['enabled']:
            vt_data = self._enrich_ip_virustotal(ip_address)
            if vt_data:
                enrichment_data['sources']['virustotal'] = vt_data
        
        # AbuseIPDB check
        if self._ti_sources['abuseipdb']['enabled']:
            abuse_data = self._enrich_ip_abuseipdb(ip_address)
            if abuse_data:
                enrichment_data['sources']['abuseipdb'] = abuse_data
        
        # AlienVault OTX
        if self._ti_sources['otx']['enabled']:
            otx_data = self._enrich_ip_otx(ip_address)
            if otx_data:
                enrichment_data['sources']['otx'] = otx_data
        
        # MISP
        if self._ti_sources['misp']['enabled']:
            misp_data = self._enrich_ip_misp(ip_address)
            if misp_data:
                enrichment_data['sources']['misp'] = misp_data
        
        # Calculate overall reputation score
        reputation_score = self._calculate_ip_reputation(enrichment_data)
        enrichment_data['reputation_score'] = reputation_score
        enrichment_data['reputation_level'] = self._get_reputation_level(reputation_score)
        
        # Cache the result
        self._save_to_cache(cache_key, enrichment_data)
        
        # Return results
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))
        action_result.add_data(enrichment_data)
        
        summary = {
            'ip': ip_address,
            'reputation_score': reputation_score,
            'reputation_level': enrichment_data['reputation_level'],
            'sources_checked': len(enrichment_data['sources'])
        }
        action_result.update_summary(summary)
        
        return action_result.set_status(phantom.APP_SUCCESS, f"Successfully enriched IP {ip_address}")

    def _handle_enrich_hash(self, param):
        """
        Enrich file hash with threat intelligence
        """
        self.save_progress("Starting hash enrichment...")
        
        file_hash = param['hash'].strip().lower()
        
        if not self._validate_hash(file_hash):
            return self.set_status(phantom.APP_ERROR, "Invalid hash format")
        
        # Check cache first
        cache_key = f"hash_{file_hash}"
        cached_result = self._get_from_cache(cache_key)
        
        if cached_result and not self._is_cache_expired(cached_result):
            self.save_progress("Using cached result")
            action_result = self.add_action_result(phantom.ActionResult(dict(param)))
            action_result.add_data(cached_result['data'])
            return action_result.set_status(phantom.APP_SUCCESS)
        
        # Enrich from multiple sources
        enrichment_data = {
            'hash': file_hash,
            'hash_type': self._get_hash_type(file_hash),
            'enrichment_time': datetime.now().isoformat(),
            'sources': {}
        }
        
        # VirusTotal file report
        if self._ti_sources['virustotal']['enabled']:
            vt_data = self._enrich_hash_virustotal(file_hash)
            if vt_data:
                enrichment_data['sources']['virustotal'] = vt_data
        
        # MISP lookup
        if self._ti_sources['misp']['enabled']:
            misp_data = self._enrich_hash_misp(file_hash)
            if misp_data:
                enrichment_data['sources']['misp'] = misp_data
        
        # Calculate malware confidence
        malware_confidence = self._calculate_malware_confidence(enrichment_data)
        enrichment_data['malware_confidence'] = malware_confidence
        enrichment_data['malware_verdict'] = self._get_malware_verdict(malware_confidence)
        
        # Cache the result
        self._save_to_cache(cache_key, enrichment_data)
        
        # Return results
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))
        action_result.add_data(enrichment_data)
        
        summary = {
            'hash': file_hash,
            'hash_type': enrichment_data['hash_type'],
            'malware_confidence': malware_confidence,
            'malware_verdict': enrichment_data['malware_verdict'],
            'sources_checked': len(enrichment_data['sources'])
        }
        action_result.update_summary(summary)
        
        return action_result.set_status(phantom.APP_SUCCESS, f"Successfully enriched hash {file_hash}")

    def _handle_enrich_domain(self, param):
        """
        Enrich domain with threat intelligence
        """
        self.save_progress("Starting domain enrichment...")
        
        domain = param['domain'].strip().lower()
        
        if not self._validate_domain(domain):
            return self.set_status(phantom.APP_ERROR, "Invalid domain format")
        
        # Check cache first
        cache_key = f"domain_{hashlib.md5(domain.encode()).hexdigest()}"
        cached_result = self._get_from_cache(cache_key)
        
        if cached_result and not self._is_cache_expired(cached_result):
            self.save_progress("Using cached result")
            action_result = self.add_action_result(phantom.ActionResult(dict(param)))
            action_result.add_data(cached_result['data'])
            return action_result.set_status(phantom.APP_SUCCESS)
        
        # Enrich from multiple sources
        enrichment_data = {
            'domain': domain,
            'enrichment_time': datetime.now().isoformat(),
            'sources': {}
        }
        
        # VirusTotal domain report
        if self._ti_sources['virustotal']['enabled']:
            vt_data = self._enrich_domain_virustotal(domain)
            if vt_data:
                enrichment_data['sources']['virustotal'] = vt_data
        
        # AlienVault OTX
        if self._ti_sources['otx']['enabled']:
            otx_data = self._enrich_domain_otx(domain)
            if otx_data:
                enrichment_data['sources']['otx'] = otx_data
        
        # Calculate domain reputation
        reputation_score = self._calculate_domain_reputation(enrichment_data)
        enrichment_data['reputation_score'] = reputation_score
        enrichment_data['reputation_level'] = self._get_reputation_level(reputation_score)
        
        # Cache the result
        self._save_to_cache(cache_key, enrichment_data)
        
        # Return results
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))
        action_result.add_data(enrichment_data)
        
        summary = {
            'domain': domain,
            'reputation_score': reputation_score,
            'reputation_level': enrichment_data['reputation_level'],
            'sources_checked': len(enrichment_data['sources'])
        }
        action_result.update_summary(summary)
        
        return action_result.set_status(phantom.APP_SUCCESS, f"Successfully enriched domain {domain}")

    # Threat Intelligence Source Methods

    def _enrich_ip_virustotal(self, ip_address):
        """
        Enrich IP using VirusTotal
        """
        try:
            if not self._check_rate_limit('virustotal'):
                return None
                
            url = f"{self._ti_sources['virustotal']['base_url']}ip-address/report"
            params = {
                'apikey': self._ti_sources['virustotal']['api_key'],
                'ip': ip_address
            }
            
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'detected_urls': data.get('detected_urls', []),
                    'detected_samples': data.get('detected_samples', []),
                    'resolutions': data.get('resolutions', []),
                    'country': data.get('country', ''),
                    'as_owner': data.get('as_owner', ''),
                    'asn': data.get('asn', '')
                }
                
        except Exception as e:
            self.debug_print(f"VirusTotal IP enrichment error: {str(e)}")
            
        return None

    def _enrich_ip_abuseipdb(self, ip_address):
        """
        Enrich IP using AbuseIPDB
        """
        try:
            if not self._check_rate_limit('abuseipdb'):
                return None
                
            url = f"{self._ti_sources['abuseipdb']['base_url']}check"
            headers = {
                'Key': self._ti_sources['abuseipdb']['api_key'],
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', {})
                
        except Exception as e:
            self.debug_print(f"AbuseIPDB enrichment error: {str(e)}")
            
        return None

    def _calculate_ip_reputation(self, enrichment_data):
        """
        Calculate overall IP reputation score
        """
        score = 0
        
        # VirusTotal scoring
        if 'virustotal' in enrichment_data['sources']:
            vt_data = enrichment_data['sources']['virustotal']
            detected_urls = len(vt_data.get('detected_urls', []))
            detected_samples = len(vt_data.get('detected_samples', []))
            
            if detected_urls > 0 or detected_samples > 0:
                score -= 50  # Negative score for malicious activity
        
        # AbuseIPDB scoring
        if 'abuseipdb' in enrichment_data['sources']:
            abuse_data = enrichment_data['sources']['abuseipdb']
            abuse_confidence = abuse_data.get('abuseConfidencePercentage', 0)
            
            if abuse_confidence > 75:
                score -= 40
            elif abuse_confidence > 50:
                score -= 25
            elif abuse_confidence > 25:
                score -= 10
        
        return max(-100, min(100, score))  # Clamp between -100 and 100

    def _get_reputation_level(self, score):
        """
        Get reputation level from score
        """
        if score <= -75:
            return "Malicious"
        elif score <= -50:
            return "Suspicious"
        elif score <= -25:
            return "Questionable"
        elif score <= 25:
            return "Neutral"
        else:
            return "Good"

    # Utility Methods

    def _validate_ip(self, ip_address):
        """
        Validate IP address format
        """
        import ipaddress
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    def _validate_hash(self, hash_value):
        """
        Validate hash format
        """
        if len(hash_value) == 32:  # MD5
            return all(c in '0123456789abcdef' for c in hash_value.lower())
        elif len(hash_value) == 40:  # SHA1
            return all(c in '0123456789abcdef' for c in hash_value.lower())
        elif len(hash_value) == 64:  # SHA256
            return all(c in '0123456789abcdef' for c in hash_value.lower())
        return False

    def _get_hash_type(self, hash_value):
        """
        Get hash type from length
        """
        length = len(hash_value)
        if length == 32:
            return "MD5"
        elif length == 40:
            return "SHA1"
        elif length == 64:
            return "SHA256"
        return "Unknown"

    def _validate_domain(self, domain):
        """
        Validate domain format
        """
        import re
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return re.match(pattern, domain) is not None

    def _check_rate_limit(self, source):
        """
        Check if we can make a request to the source
        """
        current_time = time.time()
        source_config = self._ti_sources[source]
        
        time_diff = current_time - source_config['last_request']
        
        # Simple rate limiting - can be enhanced
        if time_diff < 60 / source_config['rate_limit']:  # Convert to seconds
            return False
            
        source_config['last_request'] = current_time
        return True

    def _get_from_cache(self, cache_key):
        """
        Get data from cache
        """
        if not self._state:
            self._state = {}
            
        cache = self._state.get('cache', {})
        return cache.get(cache_key)

    def _save_to_cache(self, cache_key, data):
        """
        Save data to cache
        """
        if not self._state:
            self._state = {}
            
        if 'cache' not in self._state:
            self._state['cache'] = {}
            
        self._state['cache'][cache_key] = {
            'data': data,
            'timestamp': datetime.now().isoformat()
        }
        
        # Cleanup old cache entries (keep only last 1000)
        cache = self._state['cache']
        if len(cache) > 1000:
            # Remove oldest entries
            sorted_keys = sorted(cache.keys(), key=lambda k: cache[k]['timestamp'])
            for key in sorted_keys[:len(cache) - 1000]:
                del cache[key]

    def _is_cache_expired(self, cached_result, max_age_hours=24):
        """
        Check if cached result is expired
        """
        cache_time = datetime.fromisoformat(cached_result['timestamp'])
        age = datetime.now() - cache_time
        return age > timedelta(hours=max_age_hours)

    def handle_action(self, param):
        """
        Handle actions
        """
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'enrich_ip': self._handle_enrich_ip,
            'enrich_hash': self._handle_enrich_hash,
            'enrich_domain': self._handle_enrich_domain
        }
        
        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS
        
        if action in action_mapping:
            action_function = action_mapping[action]
            action_execution_status = action_function(param)
        else:
            action_execution_status = phantom.APP_ERROR
            
        return action_execution_status

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)
        
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        
        connector = ThreatIntelEnrichmentApp()
        connector.print_progress_message = True
        return_value = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(return_value), indent=4))
