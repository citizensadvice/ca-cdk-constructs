from ca_cdk_constructs.ecr.ecr_repository import ECRRepository
from aws_cdk import Stack, App, assertions
from aws_cdk.aws_ecr import LifecycleRule, TagStatus
import pytest


@pytest.fixture(scope="function")
def stack():
    return Stack(App(), "TestStack")


def test_ecr_defaults(stack, snapshot):
    ECRRepository(stack, "TestECRRepository", name="test-repository")
    assert assertions.Template.from_stack(stack).to_json() == snapshot


def test_ecr_additional_rules(stack, snapshot):
    ECRRepository(
        stack,
        "TestECRRepository",
        name="test-repository",
        additional_lifecycle_rules=[
            LifecycleRule(
                description="Test rule",
                rule_priority=10,
                max_image_count=10,
                tag_status=TagStatus.UNTAGGED,
            )
        ],
    )
    assert assertions.Template.from_stack(stack).to_json() == snapshot


def test_ecr_additional_accounts_pull(stack, snapshot):
    ECRRepository(
        stack,
        "TestECRRepository",
        name="test-repository",
        additional_accounts_pull=["123456789012"],
    )
    assert assertions.Template.from_stack(stack).to_json() == snapshot


def test_ecr_additional_accounts_push(stack, snapshot):
    ECRRepository(
        stack,
        "TestECRRepository",
        name="test-repository",
        additional_accounts_push=["123456789012"],
    )
    assert assertions.Template.from_stack(stack).to_json() == snapshot


def test_ecr_scan_disabled(stack, snapshot):
    ECRRepository(stack, "TestECRRepository", name="test-repository", scan_on_push=False)
    assert assertions.Template.from_stack(stack).to_json() == snapshot


def test_ecr_output_disabled(stack, snapshot):
    ECRRepository(stack, "TestECRRepository", name="test-repository", outputs_enabled=False)
    assert assertions.Template.from_stack(stack).to_json() == snapshot
