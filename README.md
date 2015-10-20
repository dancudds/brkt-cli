**brkt-cli** is a command-line interface to the [Bracket Computing](http://www.brkt.com)
service.  It produces an encrypted version of an Amazon Machine Image, which can then be
launched in EC2.

## Requirements

In order to use the Bracket service, you must be a
registered Bracket customer.  Email support@brkt.com for
more information.

**brkt-cli** has the following dependencies:
* [boto](https://github.com/boto/boto) 2.38.0+ (Python interface to AWS)
* [requests](http://www.python-requests.org/en/latest/) 2.7.0+ (Python HTTP library)

## Installation

The latest release of **brkt-cli** is 0.9.2.  Use pip to install **brkt-cli** and its dependencies:

```
$ pip install git+https://github.com/brkt/brkt-cli.git@brkt-cli-0.9.2
```

To install the most recent **brkt-cli** code from the tip of the master branch, run

```
$ pip install git+https://github.com/brkt/brkt-cli.git
```

The master branch has the latest features and bug fixes, but is not as thoroughly tested as the official release.

## Usage
```
$ brkt encrypt-ami -h
usage: brkt encrypt-ami [-h] [--encryptor-ami ID] --key NAME [--validate-ami]
                        [--no-validate-ami] --region NAME
                        AMI_ID

positional arguments:
  AMI_ID              The AMI that will be encrypted

optional arguments:
  -h, --help          show this help message and exit
  --encryptor-ami ID  Bracket Encryptor AMI
  --key NAME          EC2 SSH Key Pair name
  --validate-ami      Validate AMI properties (default)
  --no-validate-ami   Don't validate AMI properties
  --region NAME       AWS region (e.g. us-west-2)
```

## Configuration

Before running the **brkt** command, make sure that you've set the AWS
environment variables:

```
$ export AWS_SECRET_ACCESS_KEY=<access key>
$ export AWS_ACCESS_KEY_ID=<key id>
```

You'll also need to make sure that your AWS account has the required
permissions, such as running an instance, describing an image, and
creating snapshots.  See [brkt-cli-iam-permissions.json](https://github.com/brkt/brkt-cli/blob/master/reference_templates/brkt-cli-iam-permissions.json)
for the complete list of required permissions.

## Encrypting an AMI

Run **brkt encrypt-ami** to create a new encrypted AMI based on an existing
image:

```
$ brkt encrypt-ami --key my-aws-key --region us-east-1 ami-76e27e1e
15:28:37 Starting encryptor session 0ba2065fbeec48e08002c6db1ca5ba46
15:28:38 Launching instance i-703f4c99 to snapshot root disk for ami-76e27e1e
...
15:57:11 Created encrypted AMI ami-07c2a262 based on ami-76e27e1e
15:57:11 Terminating encryptor instance i-753e4d9c
15:57:12 Deleting snapshot copy of original root volume snap-847da3e1
15:57:12 Done.
ami-07c2a262
```

When the process completes, the new AMI id is written to stdout.  All log
messages are written to stderr.
