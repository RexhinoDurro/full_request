# security_monitoring/threat_detection.py - Advanced threat detection
import re
import ipaddress
from datetime import datetime, timedelta
from django.core.cache import cache
from django.db.models import Count, Q
from .models import SecurityEvent

class ThreatIntelligence:
    """Threat intelligence and detection system"""
    
    def __init__(self):
        self.malicious_ips = set()
        self.suspicious_patterns = self.load_threat_patterns()
        self.load_threat_feeds()
    
    def load_threat_patterns(self):
        """Load known attack patterns"""
        return {
            'sql_injection': [
                r"(\bunion\b.*\bselect\b)",
                r"(\bor\b.*=.*)",
                r"(--|#|\/\*)",
                r"(\bxp_cmdshell\b)",
                r"(\bdrop\b.*\btable\b)",
            ],
            'xss': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"<iframe[^>]*>",
                r"eval\s*\(",
            ],
            'command_injection': [
                r";\s*(cat|ls|pwd|whoami|id|uname)",
                r"\|\s*(cat|ls|pwd|whoami|id|uname)",
                r"&&\s*(cat|ls|pwd|whoami|id|uname)",
                r"`.*`",
                r"\$\(.*\)",
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"%2e%2e%2f",
                r"%2e%2e\\",
                r"\.\.%2f",
            ]
        }
    
    def load_threat_feeds(self):
        """Load threat intelligence feeds"""
        # In production, load from external threat feeds
        # For now, load known malicious IP ranges
        known_malicious = [
            '10.0.0.0/8',  # Example - replace with real threat feeds
            '192.168.0.0/16',  # Example
        ]
        
        for cidr in known_malicious:
            try:
                network = ipaddress.ip_network(cidr)
                for ip in network:
                    self.malicious_ips.add(str(ip))
            except ValueError:
                pass
    
    def is_malicious_ip(self, ip_address):
        """Check if IP is in threat intelligence feeds"""
        try:
            ip = ipaddress.ip_address(ip_address)
            return str(ip) in self.malicious_ips
        except ValueError:
            return False
    
    def detect_attack_patterns(self, text):
        """Detect attack patterns in text"""
        detected_attacks = []
        
        for attack_type, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    detected_attacks.append(attack_type)
                    break
        
        return detected_attacks
    
    def analyze_behavior_anomalies(self, ip_address, time_window=3600):
        """Analyze behavioral anomalies"""
        cutoff_time = datetime.now() - timedelta(seconds=time_window)
        
        # Get recent events from this IP
        events = SecurityEvent.objects.filter(
            ip_address=ip_address,
            timestamp__gte=cutoff_time
        )
        
        anomalies = []
        
        # Check event frequency
        event_count = events.count()
        if event_count > 50:  # More than 50 events per hour
            anomalies.append(f"High event frequency: {event_count} events/hour")
        
        # Check event diversity
        event_types = events.values('event_type').distinct().count()
        if event_types > 10:  # More than 10 different event types
            anomalies.append(f"High event diversity: {event_types} different types")
        
        # Check severity distribution
        high_severity_count = events.filter(severity__in=['HIGH', 'CRITICAL']).count()
        if high_severity_count > 5:
            anomalies.append(f"Multiple high-severity events: {high_severity_count}")
        
        # Check time patterns (rapid succession)
        timestamps = list(events.values_list('timestamp', flat=True))
        if len(timestamps) > 1:
            intervals = []
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                intervals.append(interval)
            
            avg_interval = sum(intervals) / len(intervals)
            if avg_interval < 5:  # Less than 5 seconds between events
                anomalies.append(f"Rapid event succession: {avg_interval:.2f}s average")
        
        return anomalies
    
    def calculate_threat_score(self, ip_address, events=None):
        """Calculate threat score for an IP address"""
        if events is None:
            events = SecurityEvent.objects.filter(ip_address=ip_address)
        
        score = 0
        
        # Base score for malicious IP
        if self.is_malicious_ip(ip_address):
            score += 50
        
        # Score based on event severity
        severity_weights = {'LOW': 1, 'MEDIUM': 3, 'HIGH': 7, 'CRITICAL': 15}
        for event in events:
            score += severity_weights.get(event.severity, 0)
        
        # Score based on event types
        dangerous_events = [
            'SQL_INJECTION', 'XSS_ATTEMPT', 'BRUTE_FORCE', 
            'API_ABUSE', 'REPLAY_ATTACK'
        ]
        for event in events:
            if event.event_type in dangerous_events:
                score += 10
        
        # Score based on frequency
        recent_events = events.filter(
            timestamp__gte=datetime.now() - timedelta(hours=24)
        )
        if recent_events.count() > 20:
            score += 20
        
        return min(score, 100)  # Cap at 100

class AutomatedResponse:
    """Automated response to security threats"""
    
    def __init__(self):
        self.threat_intelligence = ThreatIntelligence()
    
    def assess_and_respond(self, security_event):
        """Assess threat and take automated response"""
        ip_address = security_event.ip_address
        
        # Calculate threat score
        recent_events = SecurityEvent.objects.filter(
            ip_address=ip_address,
            timestamp__gte=datetime.now() - timedelta(hours=24)
        )
        threat_score = self.threat_intelligence.calculate_threat_score(
            ip_address, recent_events
        )
        
        # Determine response based on threat score
        if threat_score >= 80:
            self.block_ip_temporarily(ip_address, hours=24)
            self.send_critical_alert(security_event, threat_score)
        elif threat_score >= 60:
            self.block_ip_temporarily(ip_address, hours=1)
            self.send_high_priority_alert(security_event, threat_score)
        elif threat_score >= 40:
            self.increase_monitoring(ip_address)
            self.send_medium_priority_alert(security_event, threat_score)
        
        return threat_score
    
    def block_ip_temporarily(self, ip_address, hours=1):
        """Temporarily block an IP address"""
        from .models import IPBlacklist
        from django.utils import timezone
        
        block_until = timezone.now() + timedelta(hours=hours)
        
        IPBlacklist.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                'reason': f'Automated block - high threat score',
                'blocked_until': block_until,
                'permanent': False
            }
        )
    
    def increase_monitoring(self, ip_address):
        """Increase monitoring for suspicious IP"""
        cache_key = f"monitor_ip:{ip_address}"
        cache.set(cache_key, True, 3600)  # Monitor for 1 hour
    
    def send_critical_alert(self, event, threat_score):
        """Send critical security alert"""
        from security_monitoring.utils import send_security_alert
        
        send_security_alert(
            'CRITICAL_THREAT_DETECTED',
            'CRITICAL',
            event.ip_address,
            f'Automated threat detection: Score {threat_score}/100'
        )
    
    def send_high_priority_alert(self, event, threat_score):
        """Send high priority alert"""
        # Log to security channel/system
        pass
    
    def send_medium_priority_alert(self, event, threat_score):
        """Send medium priority alert"""
        # Log for review
        pass