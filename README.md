# aws-s3-scanner

### Example Usage

```python
$ python3 main.py --access-key "ACCESS_KEY" --secret-key "SECRET_KEY" --bucket "meeks-test-bucket" --no-anon
```

```
                                                ╔═══════╗
════════════════════════════════════════════════╣ meeks ╠═════════════════════════════════════════════════
                                                ╚═══════╝

╔══════════╣ list-object-versions
║
║ [+] Found 3 non-latest versions
║
║
╠═════╣ 9-28-2019_12-56-55_PM-jolvb45w.png (FhX6Wun4mR4VrsTyRSXl7pIAAhVEXjsM)
║
╠═════╣ test.txt (nN1Oq4O4aniwpYLWLh7qIuRUMlM2W4cQ)
║
╠══╣ get-object
║ test test test NEW VERSION, SUPER COOL
║
╠═════╣ test.txt (gU_axfgnObpdqVE.WFnfsVRbR9buaLIj)
║
╠══╣ get-object
║ test test

╔══════════╣ get-bucket-acl
║ {
║     "Grantee": {
║         "DisplayName": "DisplayName",
║         "ID": "ID",
║         "Type": "CanonicalUser"
║     },
║     "Permission": "FULL_CONTROL"
║ }

╔══════════╣ get-bucket-policy
║ {
║     "Sid": "Statement1",
║     "Effect": "Allow",
║     "Principal": {
║         "AWS": "*"
║     },
║     "Action": "s3:ListBucketVersions",
║     "Resource": "arn:aws:s3:::meeks-test-bucket"
║ }
║ {
║     "Sid": "Statement2",
║     "Effect": "Allow",
║     "Principal": {
║         "AWS": "*"
║     },
║     "Action": "s3:GetBucketPolicy",
║     "Resource": "arn:aws:s3:::meeks-test-bucket"
║ }

╔══════════╣ get-bucket-tagging
║ {
║     "Key": "name",
║     "Value": "cool-bucket"
║ }

╔══════════╣ get-bucket-website
║ No Website Configured

╔══════════╣ ls
║
║ [+] Found 9 objects in meeks-test-bucket
║
║ Size        Last Modified   Type   Read  File Name
║ 1.9 MB      Apr 20 06:09    png     x    9-18-2018_3-26-43_PM.png
║ 803.6 kB    Apr 20 06:09    png     x    9-18-2018_3-31-04_PM.png
║ 820.6 kB    Apr 20 06:09    png     x    9-18-2018_3-34-10_PM.png
║ 1.6 MB      Apr 20 06:09    png     x    9-18-2019_1-14-29_PM-dsyvkgvo.png
║ 1.6 MB      Apr 20 06:09    png     x    9-18-2019_1-17-08_PM-odsav2lr.png
║ 2.2 MB      Apr 20 06:09    png     x    9-21-2018_1-23-12_PM.png
║ 896.1 kB    Apr 20 06:09    png     x    9-27-2018_3-00-24_PM.png
║ 2.3 MB      Apr 20 07:16    png     x    9-28-2019_12-56-55_PM-jolvb45w.png
║ 51 Bytes    Apr 20 18:28    txt     x    test.txt


Would you like to download any of the readable files? [y/n] (n): y
File(s): *.png
9-18-2018_3-26-43_PM.png  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% • 1.9/1.9 MB • 21.6 MB/s
9-18-2018_3-31-04_PM.png  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% • 803.6/803.6 kB • 33.8 MB/s
9-18-2018_3-34-10_PM.png  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% • 820.6/820.6 kB • 37.2 MB/s
9-18-2019_1-14-29_PM-d... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% • 1.6/1.6 MB • 43.0 MB/s
9-18-2019_1-17-08_PM-o... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% • 1.6/1.6 MB • 88.8 MB/s
9-21-2018_1-23-12_PM.png  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% • 2.2/2.2 MB • 61.2 MB/s
9-27-2018_3-00-24_PM.png  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% • 896.1/896.1 kB • 39.6 MB/s
9-28-2019_12-56-55_PM-... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% • 2.3/2.3 MB • 67.3 MB/s

```

### Help

```
usage: main.py [-h] [--access-key ACCESS_KEY] [--secret-key SECRET_KEY] [--session-token SESSION_TOKEN] [--profile PROFILE]
               [--region REGION] --bucket BUCKET [--no-anon] [--no-border] [--ls]

options:
  -h, --help            show this help message and exit
  --access-key ACCESS_KEY
                        Access key for the API. If provided, secret key is also required.
  --secret-key SECRET_KEY
                        Secret key for the API.
  --session-token SESSION_TOKEN
                        Token for the API session.
  --profile PROFILE     AWS profile to use in requests.
  --region REGION       AWS region to inspect.
  --bucket BUCKET       Name of bucket to enumerate.
  --no-anon             Only uses authenticated credentials for scan.
  --no-border           Removes pretty bordering.
  --ls                  Only attempts to list files and prompt user for download.
```

