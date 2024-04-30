import os
import re

from humanize import naturalsize
import botocore.exceptions
from boto3 import Session, client
from botocore import UNSIGNED
from botocore.client import Config, BaseClient

from format import *
import args as argsmod
import awsaccount


class File:

    def __init__(self, _client: BaseClient, bucket: str, file_info: dict) -> None:
        """
        Establishes key, bytes_size, size, last_modified, type, name, and is_readable on initialization.

        :param _client: S3 Client
        :param bucket: Name of target bucket
        :param file_info: Data of file
        """
        self.__client: BaseClient = _client
        self.__bucket: str = bucket
        self.__file_info: dict = file_info

        self.key: str = file_info['Key']
        self.bytes_size: int = file_info['Size']
        self.size: str = naturalsize(self.bytes_size) if self.bytes_size > 0 else ''
        self.last_modified: str = file_info['LastModified'].strftime("%b %d %H:%M")
        self.type: str = self.get_type()
        self.name: str = self.get_name()
        self.is_readable: str = ' x' if self.is_file_readable() else ''

    def get_type(self) -> str:
        """
        Gets the type/extension of the file.

        :return: File type
        """
        file_name_parts = self.key.split('.')
        return file_name_parts[-1].lower() if len(file_name_parts) > 1 else 'dir'

    def get_name(self) -> str:
        """
        Gets the formatted version of a file including colorization and subdirectories.
        Used to print to the user when ls() is called.

        :return: Formatted file name
        """
        split_file = self.key.split('/')
        if len(split_file) > 1:
            split_file[0] = '[cyan]{}'.format(split_file[0])
            split_file[-1] = '[bold green]{}[/bold green]'.format(split_file[-1])
            return '/'.join(split_file)
        return '[bold green]{}[/bold green]'.format(split_file[0])

    def is_file_readable(self) -> bool:
        """
        Determines if a file is readable with the current permissions.

        :return: True if file is readable, False otherwise
        """
        try:
            self.__client.head_object(Bucket=self.__bucket, Key=self.key)
            return True
        except botocore.exceptions.ClientError:
            return False

    @property
    def printable_name(self) -> str:
        """
        Gets the name of the file, ignoring all subdirectories or stylization.
        Used for evaluation.

        :return:
        """
        split_file = self.key.replace(' ', '_').split('/')
        return split_file[-1] if len(split_file) > 1 else split_file[0]


###########################################
# ------------) Exceptions (-------------#
###########################################

def error_handler(func):
    """
    Handles errors for all functions that have the decorator assigned.
    """

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as e:
            response_code = e.response['Error']['Code']
            if response_code == 'NoSuchWebsiteConfiguration':
                print_data('No Website Configured')
            elif response_code == 'AccessDenied' or response_code == 'MethodNotAllowed':
                print_error('Access Denied', border=True)
            else:
                print(e.response)
        except PermissionError:
            print_error('This program does not have the permissions to write a file here.')
        except KeyboardInterrupt:
            pass

    return wrapper


###########################################
# -----------) AWS Commands (-------------#
###########################################

def get_caller_identity(session: Session) -> str:
    """
    Execute get_caller_identity to retrieve user information.

    :param session: Session object
    :return: Username
    """
    response = session.client("sts").get_caller_identity()
    return response["Arn"].split('/')[-1]


def bucket_exists(_client: BaseClient, bucket_name: str) -> bool:
    """
    Uses head_bucket to determine if a bucket exists or not.

    :param _client: S3 client
    :param bucket_name: Name of target bucket
    :return True if bucket exists, False otherwise
    """
    try:
        _client.head_bucket(Bucket=bucket_name)
        return True
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == '403':
            return True
        else:
            return False


@error_handler
def list_object_versions(_client: BaseClient, bucket_name: str) -> None:
    """
    Execute list_object_versions on a specified bucket and prints the output.
    If a non-latest version of an object is found, it will attempt to call get_object()
    to get the contents.

    :param _client: S3 client
    :param bucket_name: Name of target bucket
    """
    response = _client.list_object_versions(Bucket=bucket_name)
    old_versions = [version for version in response['Versions'] if version['IsLatest'] is False]
    print_info('Found {} non-latest versions'.format(len(old_versions)))

    for file in old_versions:
        print_title2('{} ({})'.format(file['Key'], file['VersionId']))

        file_extension = file['Key'].split('.')[-1].lower()
        if file_extension not in BLACKLISTED_EXTENSIONS:
            print_title3('get-object')
            get_object(_client, bucket_name, file['Key'], file['VersionId'])


@error_handler
def get_object(_client: BaseClient, bucket_name: str, key: str, version_id: str) -> None:
    """
    Execute get_object on a specified object in a bucket with a specific VersionId.

    :param _client: S3 client
    :param bucket_name: Name of target bucket
    :param key: Key of target file
    :param version_id: VersionId of target file
    """
    response = _client.get_object(Bucket=bucket_name, Key=key, VersionId=version_id)
    try:
        file_contents = response['Body'].read().decode('utf-8')
        if file_contents:
            print_data(file_contents)
    except UnicodeDecodeError:
        pass


@error_handler
def get_bucket_acl(_client: BaseClient, bucket_name: str) -> None:
    """
    Execute get_bucket_acl on a specified bucket and prints the output.

    :param _client: S3 client
    :param bucket_name: Name of target bucket
    """
    response = _client.get_bucket_acl(Bucket=bucket_name)
    grants = response['Grants']

    for grant in grants:
        print_data(grant)


@error_handler
def get_bucket_policy(_client: BaseClient, bucket_name: str) -> None:
    """
    Execute get_bucket_policy on a specified bucket and prints the output.

    :param _client: S3 client
    :param bucket_name: Name of target bucket
    """
    response = _client.get_bucket_policy(Bucket=bucket_name)
    parsed_policy = json.loads(response['Policy'])
    statements = parsed_policy['Statement']

    for statement in statements:
        print_data(statement)


@error_handler
def get_bucket_tagging(_client: BaseClient, bucket_name: str) -> None:
    """
    Execute get_bucket_tagging on a specified bucket and prints the output.

    :param _client: S3 client
    :param bucket_name: Name of target bucket
    """
    response = _client.get_bucket_tagging(Bucket=bucket_name)
    tags = response['TagSet']

    for tag in tags:
        print_data(tag)


@error_handler
def get_bucket_website(_client: BaseClient, bucket_name: str) -> None:
    """
    Execute get_bucket_website on a specified bucket and prints the output.

    :param _client: S3 client
    :param bucket_name: Name of target bucket
    """
    response = _client.get_bucket_website(Bucket=bucket_name)
    print_data(response)


###########################################
# -------) ls + file download (----------#
###########################################


@error_handler
def ls(_client: BaseClient, bucket_name: str) -> None:
    """
    Execute list_objects_v2 on a specified bucket and prints objects in a readable format.

    :param _client: S3 client
    :param bucket_name: Name of target bucket
    """
    response = _client.list_objects_v2(Bucket=bucket_name)
    files = response['Contents']
    readable_files = []

    print_info('Found {} objects in {}\n[cyan]║[/cyan]'.format(len(files), bucket_name))
    print_file_headers()

    for file_data in files:
        file = File(_client, bucket_name, file_data)
        if file.is_readable:
            readable_files.append(file)
        print_file(file)

    readable_dict = get_completions(readable_files)
    download(_client, bucket_name, readable_dict)


def get_completions(files: list[File]) -> dict:
    """
    Generate a dictionary for prompt auto-completions.

    :param files: List of File objects
    :return: Dictionary to be used for prompt auto-completion
    """
    completions = {'*': ''}
    directories = []

    # Add all directories
    for file in files:
        directory = os.path.dirname(file.key)
        while directory:
            if directory not in directories:
                directories.append(directory)
            directory = os.path.dirname(directory)

    # Add wildcard to each directory
    for directory in directories:
        completions[directory + '/*'] = ''

    # Add all printable names
    for file in files:
        if file.printable_name:
            completions[file.printable_name] = file

    return completions


def download(_client: BaseClient, bucket_name: str, readable_dict: dict) -> None:
    """
    Parses user's input to determine what files should be downloaded if any.

    :param _client: S3 client
    :param bucket_name: Name of target bucket
    :param readable_dict: Dictionary to be used for prompt auto-completion
    """
    readable_file_objs = [file_obj for file_obj in readable_dict.values() if file_obj]
    user_input = download_prompt(list(readable_dict.keys()))

    while user_input:

        # SOLO WILDCARD: download all files | stops asking for user input since all files are already downloaded
        if '*' in user_input:
            for file in readable_file_objs:
                download_file(_client, bucket_name, file)
            break

        # WILDCARD ANYWHERE IN ARG: download all files that match supplied pattern
        elif has_wildcard(user_input):
            args = [arg for arg in user_input if '*' in arg]

            for arg in args:
                pattern = re.compile(arg.replace('*', '.*'), re.IGNORECASE)
                any_match = False

                for file in readable_file_objs:
                    if re.search(pattern, file.key):
                        any_match = True
                        download_file(_client, bucket_name, file)

                if not any_match:
                    print_error(f'No files match the pattern "{arg}"')

                user_input.remove(arg)

        # INDIVIDUAL FILE: download specific file
        for file_printable in user_input:
            try:
                file = readable_dict[file_printable]
                download_file(_client, bucket_name, file)
            except KeyError:
                print_error(f"{file_printable} not found.")
                pass

        user_input = download_prompt(list(readable_dict.keys()))


def download_file(_client: BaseClient, bucket_name: str, file: File) -> None:
    """
    Downloads a file from a specified S3 Bucket and supplies a progress bar.

    :param _client: S3 client
    :param bucket_name: Name of target bucket
    :param file: File object for the file that is to be downloaded
    """
    progress_bar = get_progress_bar()
    progress_bar.start()
    download_task = progress_bar.add_task(
        '{:<25}'.format(file.printable_name[:22] + "..." if len(file.printable_name) > 25 else file.printable_name),
        total=file.bytes_size)

    def progress_bar_callback(bytes_amount):
        progress_bar.update(download_task, advance=bytes_amount)

    _client.download_file(bucket_name, file.key, file.printable_name, Callback=progress_bar_callback)

    with progress_bar:
        while not progress_bar.finished:
            progress_bar.update(download_task)

    progress_bar.stop()


def has_wildcard(arguments: list[str]) -> bool:
    """
    Determine if a list of user's arguments have at least one wildcard argument.

    :param arguments: List of user's arguments
    :return: True if wildcard is present, False otherwise
    """
    for args in arguments:
        if '*' in args:
            return True
    return False


###########################################
# ----------------) Main (----------------#
###########################################


def authenticated_client(args) -> tuple[BaseClient, str] | None:
    try:
        account = awsaccount.resolve_aws_account(
            args.profile,
            access_key=args.access_key,
            secret_key=args.secret_key,
            session_token=args.session_token,
            region=args.region,
        )
    except awsaccount.AccountError as e:
        print_error(f"Error: {e}")
        return

    session = Session(
        aws_access_key_id=account.access_key,
        aws_secret_access_key=account.secret_key,
    )
    user_name = get_caller_identity(session)
    _authenticated_client = session.client('s3')

    return _authenticated_client, user_name


def enum(_client: BaseClient, bucket_name: str) -> None:
    """
    Runs all enumeration functions against a specified bucket.

    :param _client: S3 client
    :param bucket_name: Name of target bucket
    """
    functions = [
        (list_object_versions, 'list-object-versions'),
        (get_bucket_acl, 'get-bucket-acl'),
        (get_bucket_policy, 'get-bucket-policy'),
        (get_bucket_tagging, 'get-bucket-tagging'),
        (get_bucket_website, 'get-bucket-website'),
        (ls, 'ls')
    ]

    for func, title in functions:
        print_title1(title)
        func(_client, bucket_name)


@error_handler
def main() -> None:
    args = argsmod.parse_args()
    bucket_name = args.bucket
    unauthenticated_client = client('s3', config=Config(signature_version=UNSIGNED))

    if bucket_exists(unauthenticated_client, bucket_name):
        print_title('Unauthenticated')
        enum(unauthenticated_client, bucket_name)

        auth_client, user_name = authenticated_client(args)
        if auth_client:
            print_title(user_name)
            enum(auth_client, bucket_name)
    else:
        print_error('S3 bucket cannot be found')


if __name__ == '__main__':
    main()
