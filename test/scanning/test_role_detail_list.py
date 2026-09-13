import copy
import json
import os
import unittest

from cloudsplaining.scan.managed_policy_detail import ManagedPolicyDetails
from cloudsplaining.scan.role_details import RoleDetail, RoleDetailList
from cloudsplaining.shared.exclusions import set_exclusion_output

example_authz_details_file = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        os.path.pardir,
        "files",
        "example-authz-details.json",
    )
)
with open(example_authz_details_file) as f:
    contents = f.read()
    auth_details_json = json.loads(contents)


class TestRoleDetail(unittest.TestCase):
    def test_role_detail_attached_managed_policies(self):
        role_detail_json_input = auth_details_json["RoleDetailList"][2]
        policy_details = ManagedPolicyDetails(auth_details_json.get("Policies"))

        role_detail = RoleDetail(role_detail_json_input, policy_details, flag_trust_policies=True)
        expected_detail_policy_results_file = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                os.path.pardir,
                "files",
                "scanning",
                "test_role_detail_results.json",
            )
        )
        with open(expected_detail_policy_results_file) as f:
            contents = f.read()
            expected_result = json.loads(contents)

        results = role_detail.json
        # print(json.dumps(results))
        self.maxDiff = None
        self.assertDictEqual(results, expected_result)


def _role(name, path, role_id, arn, attached_policies=None):
    return {
        "Path": path,
        "RoleName": name,
        "RoleId": role_id,
        "Arn": arn,
        "CreateDate": "2023-01-02 11:24:31+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "eks.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        "InstanceProfileList": [],
        "RolePolicyList": [],
        "AttachedManagedPolicies": attached_policies or [],
    }


SERVICE_LINKED_ROLE = _role(
    name="AWSServiceRoleForAmazonEKS",
    path="/aws-service-role/eks.amazonaws.com/",
    role_id="AROAEXAMPLESLR000001",
    arn="arn:aws:iam::111122223333:role/aws-service-role/eks.amazonaws.com/AWSServiceRoleForAmazonEKS",
    attached_policies=[
        {
            "PolicyName": "AmazonEKSServiceRolePolicy",
            "PolicyArn": "arn:aws:iam::aws:policy/aws-service-role/AmazonEKSServiceRolePolicy",
        }
    ],
)

CUSTOMER_ROLE = _role(
    name="eks-cluster-role",
    path="/",
    role_id="AROAEXAMPLECUST00001",
    arn="arn:aws:iam::111122223333:role/eks-cluster-role",
    attached_policies=[
        {
            "PolicyName": "eks-cluster-policy",
            "PolicyArn": "arn:aws:iam::111122223333:policy/eks-cluster-policy",
        }
    ],
)

CUSTOMER_POLICIES = [
    {
        "PolicyName": "eks-cluster-policy",
        "PolicyId": "ANPAEXAMPLE0000000001",
        "Arn": "arn:aws:iam::111122223333:policy/eks-cluster-policy",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": True,
        "CreateDate": "2023-01-02 11:24:31+00:00",
        "UpdateDate": "2023-01-02 11:24:31+00:00",
        "PolicyVersionList": [
            {
                "Document": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["*"]}],
                },
                "VersionId": "v1",
                "IsDefaultVersion": True,
                "CreateDate": "2023-01-02 11:24:31+00:00",
            }
        ],
    }
]


class TestRoleDetailListServiceLinkedRoles(unittest.TestCase):
    """AWS service-linked roles (path /aws-service-role/) stay in the results so the role total matches
    the account, but they are marked excluded and nothing about them is evaluated."""

    def setUp(self):
        self.addCleanup(set_exclusion_output, False)
        set_exclusion_output(False)

    def _role_detail_list(self, **kwargs):
        return RoleDetailList(
            copy.deepcopy([SERVICE_LINKED_ROLE, CUSTOMER_ROLE]),
            ManagedPolicyDetails(copy.deepcopy(CUSTOMER_POLICIES)),
            **kwargs,
        )

    def test_service_linked_role_is_listed_and_marked_excluded(self):
        results = self._role_detail_list().json
        self.assertIn(SERVICE_LINKED_ROLE["RoleId"], results)
        self.assertTrue(results[SERVICE_LINKED_ROLE["RoleId"]]["is_excluded"])
        self.assertFalse(results[CUSTOMER_ROLE["RoleId"]]["is_excluded"])

    def test_service_linked_role_policies_are_not_evaluated(self):
        results = self._role_detail_list().json
        service_linked = results[SERVICE_LINKED_ROLE["RoleId"]]
        self.assertEqual(service_linked["aws_managed_policies"], {})
        self.assertEqual(service_linked["customer_managed_policies"], {})
        self.assertEqual(service_linked["inline_policies"], {})
        # The customer-managed role next to it is still evaluated as before.
        self.assertEqual(
            results[CUSTOMER_ROLE["RoleId"]]["customer_managed_policies"],
            {"ANPAEXAMPLE0000000001": "eks-cluster-policy"},
        )

    def test_service_linked_role_trust_policy_is_not_flagged(self):
        results = self._role_detail_list(flag_trust_policies=True).json
        self.assertEqual(results[SERVICE_LINKED_ROLE["RoleId"]]["AssumableByComputeServices"]["findings"], [])
        self.assertEqual(results[CUSTOMER_ROLE["RoleId"]]["AssumableByComputeServices"]["findings"], ["eks"])

    def test_service_linked_role_names(self):
        self.assertEqual(self._role_detail_list().service_linked_role_names, ["AWSServiceRoleForAmazonEKS"])
