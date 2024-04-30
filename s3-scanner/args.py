import argparse


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--access-key",
        help="Access key for the API. "
             "If provided, secret key is also required."
    )

    parser.add_argument(
        "--secret-key",
        help="Secret key for the API."
    )

    parser.add_argument(
        "--session-token",
        help="Token for the API session."
    )

    parser.add_argument(
        "--profile",
        default="default",
        help="AWS profile to use in requests."
    )

    parser.add_argument(
        "--region",
        help="AWS region to inspect."
    )

    parser.add_argument(
        "--bucket",
        help="Name of bucket to enumerate."
    )

    parser.add_argument(
        "--no-anon",
        action="store_false",
        help="Only uses authenticated credentials for scan."
    )

    parser.add_argument(
        "--no-auth",
        action="store_false",
        help="Does not use any credentials for scan."
    )

    parser.add_argument(
        "--no-border",
        action="store_false",
        help="Removes pretty bordering for easy copy and paste."
    )

    parser.add_argument(
        "--only-ls",
        action="store_false",
        help="Only attempts to list files and prompt user for download."
    )

    args = parser.parse_args()
    return args