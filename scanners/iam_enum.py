"""IAM Enumeration Scanner"""

import boto3
from botocore.exceptions import ClientError
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class IAMEnumerator:
    def __init__(self, session):
        self.iam = session.client('iam')
        self.session = session
    
    def list_users(self):
        """List all IAM users"""
        try:
            users = []
            paginator = self.iam.get_paginator('list_users')
            for page in paginator.paginate():
                users.extend(page['Users'])
            logger.info(f"Found {len(users)} IAM users")
            return users
        except ClientError as e:
            logger.error(f"Failed to list users: {str(e)}")
            return []
    
    def list_roles(self):
        """List all IAM roles"""
        try:
            roles = []
            paginator = self.iam.get_paginator('list_roles')
            for page in paginator.paginate():
                roles.extend(page['Roles'])
            logger.info(f"Found {len(roles)} IAM roles")
            return roles
        except ClientError as e:
            logger.error(f"Failed to list roles: {str(e)}")
            return []
    
    def list_policies(self):
        """List all customer managed policies"""
        try:
            policies = []
            paginator = self.iam.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):
                policies.extend(page['Policies'])
            logger.info(f"Found {len(policies)} customer managed policies")
            return policies
        except ClientError as e:
            logger.error(f"Failed to list policies: {str(e)}")
            return []
    
    def get_user_access_keys(self, username):
        """Get access keys for a user"""
        try:
            response = self.iam.list_access_keys(UserName=username)
            keys = []
            for key in response['AccessKeyMetadata']:
                # Check if key is older than 90 days
                create_date = key['CreateDate'].replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                age_days = (now - create_date).days
                
                keys.append({
                    'key_id': key['AccessKeyId'],
                    'status': key['Status'],
                    'created_date': str(key['CreateDate']),
                    'age_days': age_days,
                    'is_old': age_days > 90
                })
            return keys
        except ClientError as e:
            logger.error(f"Failed to get keys for {username}: {str(e)}")
            return []
    
    def get_user_groups(self, username):
        """Get groups for a user"""
        try:
            response = self.iam.list_groups_for_user(UserName=username)
            return [group['GroupName'] for group in response['Groups']]
        except ClientError as e:
            logger.error(f"Failed to get groups for {username}: {str(e)}")
            return []
    
    def get_user_mfa(self, username):
        """Check if user has MFA enabled"""
        try:
            response = self.iam.list_mfa_devices(UserName=username)
            return len(response['MFADevices']) > 0
        except ClientError as e:
            logger.error(f"Failed to check MFA for {username}: {str(e)}")
            return False
    
    def get_attached_policies(self, user_or_role_name, type='user'):
        """Get policies attached to a user or role"""
        try:
            if type == 'user':
                response = self.iam.list_attached_user_policies(UserName=user_or_role_name)
            else:
                response = self.iam.list_attached_role_policies(RoleName=user_or_role_name)
            return response['AttachedPolicies']
        except ClientError as e:
            logger.error(f"Failed to get policies for {user_or_role_name}: {str(e)}")
            return []
    
    def check_privileged_access(self, policies):
        """Check if policies grant privileged access"""
        privileged_actions = [
            'admin', '*', 'AdministratorAccess',
            'iam:*', 'iam:CreateUser', 'iam:CreateAccessKey',
            'ec2:*', 's3:*', 'lambda:*'
        ]
        
        for policy in policies:
            policy_name = policy['PolicyName'].lower()
            for priv_action in privileged_actions:
                if priv_action in policy_name or priv_action == '*':
                    return True
        return False
    
    def enumerate_all(self):
        """Enumerate all IAM resources and return findings"""
        users = self.list_users()
        roles = self.list_roles()
        policies = self.list_policies()
        
        findings = {
            'users': [],
            'roles': [],
            'policies': [],
            'statistics': {},
            'issues': []
        }
        
        # Process users
        for user in users:
            username = user['UserName']
            access_keys = self.get_user_access_keys(username)
            has_mfa = self.get_user_mfa(username)
            groups = self.get_user_groups(username)
            attached_policies = self.get_attached_policies(username, 'user')
            has_privileged = self.check_privileged_access(attached_policies)
            
            user_info = {
                'username': username,
                'created_date': str(user['CreateDate']),
                'has_mfa': has_mfa,
                'groups': groups,
                'access_keys': access_keys,
                'attached_policies': [p['PolicyName'] for p in attached_policies],
                'has_privileged_access': has_privileged,
                'issues': []
            }
            
            # Check for issues
            if not has_mfa:
                user_info['issues'].append('MFA not enabled')
            if has_privileged:
                user_info['issues'].append('Privileged access')
            
            for key in access_keys:
                if key['is_old'] and key['status'] == 'Active':
                    user_info['issues'].append(f"Old active key: {key['key_id']} ({key['age_days']} days)")
                if key['status'] == 'Inactive':
                    user_info['issues'].append(f"Inactive key exists: {key['key_id']}")
            
            if user_info['issues']:
                findings['issues'].extend([f"User {username}: {issue}" for issue in user_info['issues']])
            
            findings['users'].append(user_info)
        
        # Process roles
        for role in roles:
            role_name = role['RoleName']
            attached_policies = self.get_attached_policies(role_name, 'role')
            has_privileged = self.check_privileged_access(attached_policies)
            
            role_info = {
                'role_name': role_name,
                'created_date': str(role['CreateDate']),
                'attached_policies': [p['PolicyName'] for p in attached_policies],
                'has_privileged_access': has_privileged
            }
            
            if has_privileged:
                findings['issues'].append(f"Role {role_name}: Has privileged access")
            
            findings['roles'].append(role_info)
        
        # Statistics
        findings['statistics'] = {
            'total_users': len(users),
            'users_without_mfa': sum(1 for u in findings['users'] if not u['has_mfa']),
            'users_with_privileged_access': sum(1 for u in findings['users'] if u['has_privileged_access']),
            'total_roles': len(roles),
            'roles_with_privileged_access': sum(1 for r in findings['roles'] if r['has_privileged_access']),
            'total_customer_policies': len(policies)
        }
        
        findings['total_issues'] = len(findings['issues'])
        return findings