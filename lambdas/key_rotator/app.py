import boto3
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Secrets Manager Rotation Template
    Rotates a IAM access key in a secret
    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)
        context (LambdaContext): The Lambda runtime information
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not properly configured for rotation
        KeyError: If the event parameters do not contain the expected keys
    """
    
    logger.info(f"event: {event}")
    
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Setup the client
    service_client = boto3.client('secretsmanager')

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error(f"Secret {arn} is not enabled for rotation")
        raise ValueError(f"Secret {arn} is not enabled for rotation")
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error(f"Secret version {token} has no stage for rotation of secret {arn}.")
        raise ValueError(f"Secret version {token} has no stage for rotation of secret {arn}.")
    if "AWSCURRENT" in versions[token]:
        logger.info(f"Secret version {token} already set as AWSCURRENT for secret {arn}.")
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error(f"Secret version {token} not set as AWSPENDING for rotation of secret {arn}.")
        raise ValueError(f"Secret version {token} not set as AWSPENDING for rotation of secret {arn}.")

    if step == "createSecret":
        create_secret(service_client, arn, token)

    elif step == "setSecret":
        set_secret(service_client, arn, token)

    elif step == "testSecret":
        test_secret(service_client, arn, token)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")


def create_secret(service_client, arn, token):
    """Create the secret
    Calls IAM to create a new access key and updates the secret wit the new secret key in a pending state.
    Adds the access key to the pending key tag on the secret.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    iam_client = boto3.client('iam')

    # describe current secret
    secret = service_client.describe_secret(SecretId=arn)
    username = next((tag['Value'] for tag in secret['Tags'] if tag['Key'] == 'ciinabox:iam:user'), None)
    
    # fail here is the secret doesn't contain the user tag with the iam user name value
    if username is None:
        raise ValueError(f"The secret {arn} is missing the 'ciinabox:iam:user' tag")
    
    # we need to check if there are 2 keys, if so we need to delete one before we can create the new key due to the resource limit.
    existing_access_keys = sorted(iam_client.list_access_keys(UserName=username)['AccessKeyMetadata'], key=lambda x: x['CreateDate'])
    if len(existing_access_keys) >= 2:
        logger.info("at least 2 access keys already exist. deleting the oldest version: %s" % existing_access_keys[0]['AccessKeyId'])
        iam_client.delete_access_key(UserName=username, AccessKeyId=existing_access_keys[0]['AccessKeyId'])
    
    # create the new key
    new_key = iam_client.create_access_key(UserName=username)
    access_key_id = new_key['AccessKey']['AccessKeyId']
    secret_key_id = new_key['AccessKey']['SecretAccessKey']
    
    # Update the secret key id in the secret and set it to a pending state
    service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=secret_key_id, VersionStages=['AWSPENDING'])
    # tag the secret with a pending key with the new access key id
    service_client.tag_resource(SecretId=arn, Tags=[{'Key': 'ciinabox:iam:pendingkey','Value': access_key_id}])

def set_secret(service_client, arn, token):
    """Set the secret
    The IAM service sets the secret in the user so there is nothing to do here
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    logging.info("Nothing to do here")


def test_secret(service_client, arn, token):
    """Test the secret
    Tests the new IAM access key
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    secret = service_client.describe_secret(SecretId=arn)
        
    # get the user name from the secret tags
    username = next((tag['Value'] for tag in secret['Tags'] if tag['Key'] == 'ciinabox:iam:user'), None)
    if username is None:
        raise ValueError(f"The secret {arn} is missing the 'ciinabox:iam:user' tag")
    
    # get the pending access key id from the secret tags
    access_key_id = next((tag['Value'] for tag in secret['Tags'] if tag['Key'] == 'ciinabox:iam:pendingkey'), None)
    if access_key_id is None:
        raise ValueError(f"The secret {arn} is missing the 'ciinabox:iam:pendingkey' tag. It failed to add the tag during the create secret stage.")
    
    secret_value = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
    secret_key_id = secret_value['SecretString']
    
    test_client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=secret_key_id)
    try:
        test_client.get_account_authorization_details()
    except test_client.exceptions.ClientError as e:
        # the test fails if and only if Authentication fails. Authorization failures are acceptable.
        if e.response['Error']['Code'] == 'AuthFailure':
            raise ValueError(f"Pending IAM secret {arn} in rotation {username} failed the test to authenticate. exception: {e}")

def finish_secret(service_client, arn, token):
    """Finish the secret
    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.
    Tags the secret with the new access key and removes the pending key tag.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info(f"finishSecret: Version {version} already marked as AWSCURRENT for {arn}")
                return
            current_version = version
            break

    access_key_id = next((tag['Value'] for tag in secret['Tags'] if tag['Key'] == 'ciinabox:iam:pendingkey'), None)
    if access_key_id is None:
        raise ValueError(f"The secret {arn} is missing the 'ciinabox:iam:pendingkey' tag. It failed to add the tag during the create secret stage.")

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    # update the username key with the new pending access key id
    service_client.tag_resource(SecretId=arn, Tags=[{'Key': 'jenkins:credentials:username','Value': access_key_id}])
    # remove the pending key tag
    service_client.untag_resource(SecretId=arn, TagKeys=['ciinabox:iam:pendingkey'])
    logger.info(f"finishSecret: Successfully set AWSCURRENT stage to version {token} for secret {arn}.")