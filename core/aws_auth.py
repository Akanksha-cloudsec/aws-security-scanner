"""AWS Authentication and Session Management"""

import boto3
import logging
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

def create_aws_session(access_key, secret_key, region='us-east-1'):
    """
    Create boto3 session with provided credentials
    
    Args:
        access_key: AWS Access Key ID
        secret_key: AWS Secret Access Key
        region: AWS region name
    
    Returns:
        boto3.Session object
    """
    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        logger.info(f"AWS session created for region {region}")
        return session
    except Exception as e:
        logger.error(f"Failed to create AWS session: {str(e)}")
        raise

def validate_credentials(session):
    """
    Validate AWS credentials by making a simple API call
    
    Args:
        session: boto3.Session object
    
    Returns:
        bool: True if credentials are valid
    """
    try:
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        logger.info(f"Credentials validated. Account: {identity['Account']}, User: {identity['Arn']}")
        return True
    except ClientError as e:
        logger.error(f"Credential validation failed: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during validation: {str(e)}")
        return False

def get_account_id(session):
    """Get AWS Account ID"""
    try:
        sts = session.client('sts')
        return sts.get_caller_identity()['Account']
    except Exception as e:
        logger.error(f"Failed to get account ID: {str(e)}")
        return None