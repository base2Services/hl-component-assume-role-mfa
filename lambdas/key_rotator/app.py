import boto3
import logging

logger = logging.getLogger(__name__)

def lambda_handler(event, context):
    # get secret id from event
    if 'SecretId' not in event:
        return