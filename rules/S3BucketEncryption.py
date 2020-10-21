"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfnlint.rules import CloudFormationLintRule
from cfnlint.rules import RuleMatch


class S3BucketEncryption(CloudFormationLintRule):
    """Rule description """
    id = '' # New Rule ID
    shortdesc = '' # A short description about the rule
    description = '' # (Longer) description about the rule
    source_url = '' # A url to the source of the rule, e.g. documentation, AWS Blog posts etc
    tags = [] # A set of tags (strings) for searching

    def match(self, cfn):
        """Basic Rule Matching"""

        matches = []

        # Your Rule code goes here

        return matches
