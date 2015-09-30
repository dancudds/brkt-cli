## Reference Templates

This directory contains reference templates that may be used to help
setup your environment in preparation for running encrypted Bracket
AMIs. In general these templates follow principles of least privilege
and defense in depth to provide a secure cloud computing environment for
your sensitive workloads.

``brkt-cli-iam-permissions.json``: A sample IAM policy specifying the
minimal set of permissions required to run the brkt CLI command for
encrypted image import.

``vpc-dual-az-with-nat.json``: A cloudformation template that creates a
VPC with parallel public and private subnets in two availability zones
in a single region. A pair of NAT instances will be created to allow
instances in the private subnets Internet access. The default security
groups and network ACLs in this template permit instances to access only
tcp/80, tcp/443 and udp/123 (NTP) on the Internet. A security group
named ``InternetClientSG`` is created and is intended to be applied to
instances within the private subnet that need Internet access.

