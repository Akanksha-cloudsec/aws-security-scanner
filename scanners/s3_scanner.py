"""S3 Bucket Security Scanner"""

import boto3
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)

class S3Scanner:
    def __init__(self, session):
        self.s3 = session.client('s3')
        self.session = session
    
    def list_all_buckets(self):
        """List all S3 buckets in the account"""
        try:
            response = self.s3.list_buckets()
            buckets = [bucket['Name'] for bucket in response['Buckets']]
            logger.info(f"Found {len(buckets)} buckets")
            return buckets
        except ClientError as e:
            logger.error(f"Failed to list buckets: {str(e)}")
            return []
    
    def check_bucket_acl(self, bucket_name):
        """Check bucket ACL permissions"""
        try:
            acl = self.s3.get_bucket_acl(Bucket=bucket_name)
            public_grants = []
            
            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})
                if 'URI' in grantee:
                    uri = grantee['URI']
                    if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                        public_grants.append({
                            'type': 'public' if 'AllUsers' in uri else 'authenticated',
                            'permission': grant['Permission']
                        })
            
            return {
                'public_read': any(g['permission'] in ['READ', 'FULL_CONTROL'] and g['type'] == 'public' for g in public_grants),
                'public_write': any(g['permission'] in ['WRITE', 'FULL_CONTROL'] and g['type'] == 'public' for g in public_grants),
                'public_grants': public_grants
            }
        except ClientError as e:
            logger.error(f"Failed to get ACL for {bucket_name}: {str(e)}")
            return {'error': str(e)}
    
    def check_bucket_policy(self, bucket_name):
        """Check bucket policy for public access"""
        try:
            policy = self.s3.get_bucket_policy(Bucket=bucket_name)
            # Basic check - in production, parse policy JSON properly
            policy_str = policy['Policy']
            is_public = '*' in policy_str and ('Principal' in policy_str or 'principal' in policy_str)
            return {'has_policy': True, 'is_public': is_public, 'policy': policy_str}
        except ClientError as e:
            if 'NoSuchBucketPolicy' in str(e):
                return {'has_policy': False, 'is_public': False}
            logger.error(f"Failed to get policy for {bucket_name}: {str(e)}")
            return {'error': str(e)}
    
    def check_bucket_encryption(self, bucket_name):
        """Check if bucket has default encryption enabled"""
        try:
            encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            return {'enabled': True, 'rules': rules}
        except ClientError as e:
            if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                return {'enabled': False}
            return {'error': str(e)}
    
    def check_bucket_versioning(self, bucket_name):
        """Check if versioning is enabled"""
        try:
            versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get('Status', 'Disabled')
            return {'enabled': status == 'Enabled'}
        except ClientError as e:
            logger.error(f"Failed to get versioning for {bucket_name}: {str(e)}")
            return {'error': str(e)}
    
    def check_bucket_logging(self, bucket_name):
        """Check if access logging is enabled"""
        try:
            logging_config = self.s3.get_bucket_logging(Bucket=bucket_name)
            return {'enabled': 'LoggingEnabled' in logging_config}
        except ClientError as e:
            logger.error(f"Failed to get logging for {bucket_name}: {str(e)}")
            return {'error': str(e)}
    
    def scan_all_buckets(self):
        """Scan all buckets and return comprehensive findings"""
        buckets = self.list_all_buckets()
        findings = {
            'total_buckets': len(buckets),
            'buckets': [],
            'issues': []
        }
        
        for bucket_name in buckets:
            logger.info(f"Scanning bucket: {bucket_name}")
            
            bucket_info = {
                'name': bucket_name,
                'acl': self.check_bucket_acl(bucket_name),
                'policy': self.check_bucket_policy(bucket_name),
                'encryption': self.check_bucket_encryption(bucket_name),
                'versioning': self.check_bucket_versioning(bucket_name),
                'logging': self.check_bucket_logging(bucket_name)
            }
            
            # Identify issues
            issues = []
            if bucket_info['acl'].get('public_read'):
                issues.append('Public read access')
            if bucket_info['acl'].get('public_write'):
                issues.append('Public write access')
            if bucket_info['policy'].get('is_public'):
                issues.append('Public bucket policy')
            if not bucket_info['encryption'].get('enabled'):
                issues.append('Encryption not enabled')
            if not bucket_info['versioning'].get('enabled'):
                issues.append('Versioning not enabled')
            if not bucket_info['logging'].get('enabled'):
                issues.append('Access logging not enabled')
            
            bucket_info['issues'] = issues
            findings['buckets'].append(bucket_info)
            
            if issues:
                findings['issues'].extend([f"{bucket_name}: {issue}" for issue in issues])
        
        findings['total_issues'] = len(findings['issues'])
        return findings