"""CloudTrail Analyzer for security events"""

import boto3
from botocore.exceptions import ClientError
import logging
from datetime import datetime, timedelta, timezone
import json

logger = logging.getLogger(__name__)

class CloudTrailAnalyzer:
    def __init__(self, session):
        self.cloudtrail = session.client('cloudtrail')
        self.session = session
    
    def check_trails(self):
        """List all CloudTrail trails"""
        try:
            response = self.cloudtrail.describe_trails()
            trails = response['trailList']
            logger.info(f"Found {len(trails)} CloudTrail trails")
            return trails
        except ClientError as e:
            logger.error(f"Failed to describe trails: {str(e)}")
            return []
    
    def check_trail_status(self, trail_name):
        """Check if a trail is logging"""
        try:
            status = self.cloudtrail.get_trail_status(Name=trail_name)
            return {
                'is_logging': status['IsLogging'],
                'latest_delivery_time': str(status.get('LatestDeliveryTime', 'N/A')),
                'latest_notification_time': str(status.get('LatestNotificationTime', 'N/A'))
            }
        except ClientError as e:
            logger.error(f"Failed to get status for {trail_name}: {str(e)}")
            return {'is_logging': False, 'error': str(e)}
    
    def check_multi_region_trails(self, trails):
        """Check if multi-region trails are enabled"""
        multi_region = [t for t in trails if t.get('IsMultiRegionTrail', False)]
        return {
            'has_multi_region': len(multi_region) > 0,
            'count': len(multi_region),
            'trails': multi_region
        }
    
    def check_log_file_validation(self, trails):
        """Check if log file validation is enabled"""
        validated = [t for t in trails if t.get('LogFileValidationEnabled', False)]
        return {
            'has_validation': len(validated) > 0,
            'count': len(validated)
        }
    
    def analyze_recent_events(self, hours=24):
        """Analyze recent CloudTrail events for suspicious activity"""
        try:
            # Look back specified hours
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=hours)
            
            # Look for suspicious events
            suspicious_events = []
            event_counts = {}
            
            # Common suspicious event names
            suspicious_patterns = [
                'CreateAccessKey', 'DeleteAccessKey', 'UpdateAccessKey',
                'CreateUser', 'DeleteUser', 'AttachUserPolicy', 'DetachUserPolicy',
                'CreatePolicy', 'DeletePolicy', 'AttachRolePolicy',
                'ModifyInstanceAttribute', 'StopInstances', 'TerminateInstances',
                'AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupIngress',
                'DeleteTrail', 'StopLogging', 'UpdateTrail',
                'PutBucketPolicy', 'DeleteBucketPolicy', 'PutBucketAcl'
            ]
            
            # Use LookupEvents (limited to 50 events per call, but good for recent analysis)
            paginator = self.cloudtrail.get_paginator('lookup_events')
            
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=end_time
            ):
                for event in page['Events']:
                    event_name = event.get('EventName', '')
                    event_counts[event_name] = event_counts.get(event_name, 0) + 1
                    
                    if event_name in suspicious_patterns:
                        suspicious_events.append({
                            'event_name': event_name,
                            'event_time': event.get('EventTime', ''),
                            'username': event.get('Username', 'N/A'),
                            'event_source': event.get('EventSource', ''),
                            'resources': event.get('Resources', [])
                        })
            
            return {
                'lookup_period_hours': hours,
                'total_events': sum(event_counts.values()),
                'unique_event_types': len(event_counts),
                'suspicious_events_count': len(suspicious_events),
                'suspicious_events': suspicious_events,
                'event_counts': dict(list(event_counts.items())[:20])  # Top 20 events
            }
        except ClientError as e:
            logger.error(f"Failed to lookup events: {str(e)}")
            return {'error': str(e)}
    
    def check_cloudtrail_best_practices(self):
        """Check CloudTrail against AWS best practices"""
        trails = self.check_trails()
        
        if not trails:
            return {
                'has_trails': False,
                'issues': ['No CloudTrail trails found'],
                'score': 0
            }
        
        issues = []
        score = 100
        
        # Check trail status
        for trail in trails:
            trail_name = trail['Name']
            status = self.check_trail_status(trail_name)
            
            if not status.get('is_logging'):
                issues.append(f"Trail {trail_name} is not logging")
                score -= 20
        
        # Check multi-region
        multi_region_check = self.check_multi_region_trails(trails)
        if not multi_region_check['has_multi_region']:
            issues.append("No multi-region CloudTrail configured")
            score -= 30
        
        # Check log validation
        validation_check = self.check_log_file_validation(trails)
        if not validation_check['has_validation']:
            issues.append("Log file validation not enabled")
            score -= 15
        
        # Check if trails are encrypted
        encrypted_trails = [t for t in trails if t.get('KmsKeyId')]
        if not encrypted_trails:
            issues.append("CloudTrail logs not encrypted with KMS")
            score -= 15
        
        return {
            'has_trails': True,
            'total_trails': len(trails),
            'trails': trails,
            'multi_region': multi_region_check,
            'log_validation': validation_check,
            'encrypted_trails_count': len(encrypted_trails),
            'issues': issues,
            'score': max(0, score)
        }
    
    def analyze(self):
        """Main analysis function"""
        logger.info("Starting CloudTrail analysis")
        
        best_practices = self.check_cloudtrail_best_practices()
        recent_events = self.analyze_recent_events(168)  # Last 7 days
        
        findings = {
            'best_practices_check': best_practices,
            'recent_events_analysis': recent_events,
            'issues': best_practices.get('issues', []),
            'recommendations': []
        }
        
        # Add recommendations
        if not best_practices.get('has_trails'):
            findings['recommendations'].append("Enable CloudTrail in all regions")
        
        if best_practices.get('multi_region', {}).get('count', 0) == 0:
            findings['recommendations'].append("Configure multi-region CloudTrail")
        
        if not best_practices.get('log_validation', {}).get('has_validation'):
            findings['recommendations'].append("Enable log file validation for CloudTrail")
        
        if recent_events.get('suspicious_events_count', 0) > 0:
            findings['recommendations'].append(f"Review {recent_events['suspicious_events_count']} suspicious events in the last 7 days")
        
        findings['total_issues'] = len(findings['issues'])
        
        return findings