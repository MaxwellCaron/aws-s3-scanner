import boto3
from botocore.exceptions import ProfileNotFound


def resolve_aws_account(
        profile,
        access_key=None,
        secret_key=None,
        session_token=None,
        region=None
):
    if access_key or secret_key or session_token:
        account = AWSAccount(access_key, secret_key, session_token, region)
    else:
        account = get_account_from_profile(profile)
        if region:
            account.region = region

    return account


def get_account_from_profile(profile):
    try:
        session = boto3.Session(profile_name=profile)
        creds = session.get_credentials()

        access_key = creds.access_key
        secret_key = creds.secret_key
        session_token = creds.token
        region = session.region_name
        return AWSAccount(access_key, secret_key, session_token, region)

    except ProfileNotFound:
        raise AccountError()


class AccountError(Exception):
    pass


class AWSAccount:

    def __init__(self, access_key, secret_key, session_token, region):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.region = region
        self.session = self.get_session()
        self.name = self.get_name()

    def get_session(self):
        session = boto3.Session(
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
        )
        return session

    def get_name(self):
        response = self.session.client("sts").get_caller_identity()
        return response["Arn"].split('/')[-1]
