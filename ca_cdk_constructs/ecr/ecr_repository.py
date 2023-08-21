from aws_cdk.aws_ecr import Repository, LifecycleRule, TagStatus
from aws_cdk import Duration, aws_iam as iam
from constructs import Construct


class ECRRepository(Construct):
    """
    An ECR repository with default lifecycle rules.

    The default rules are as follows:
    - Remove all untagged images after 1 day
    - Remove all development images after 90 days. Dev image tags start with `dev_`
    - Limit the max number of images to 1000

    Max development images and max images are configurable.

    :param scope: The scope of the construct, usually self.
    :param id: The id of the construct.
    :param name: The name of the repository. Must be unique within the account.
    :param additional_lifecycle_rules: Additional lifecycle rules to add in addition to the default rules. Priority must be unique and equal to or less than 10 as not to conflict with existing rules.
    :param additional_accounts_pull: Additional accounts that are allowed to pull from the repository in the form of their account number
    :param additional_accounts_push: Additional accounts that are allowed to push to the repository in the form of their account number.
    :param dev_image_max_age: The maximum age of a development image in days. Defaults to 90.
    :param max_images: The maximum number of images allowed in the repository. Defaults to 1000.
    :param scan_on_push: Whether to scan for vulnerabilities on the image on push. Defaults to True.
    """

    def __init__(
        self,
        scope: Construct,
        id: str,
        name: str,
        additional_lifecycle_rules: list[LifecycleRule] = [],
        additional_accounts_pull: list[str] = [],
        additional_accounts_push: list[str] = [],
        dev_image_max_age: int = 90,
        max_images: int = 1000,
        scan_on_push: bool = True,
    ):
        super().__init__(scope, id)
        lifecycle_rules = []

        lifecycle_rules.append(
            LifecycleRule(
                rule_priority=20,
                description="Limit max number of images",
                max_image_count=max_images,
                tag_status=TagStatus.ANY,
            )
        )
        lifecycle_rules.append(
            LifecycleRule(
                rule_priority=19,
                description="Delete untagged images",
                tag_status=TagStatus.UNTAGGED,
                max_image_age=Duration.days(1),
            )
        )
        lifecycle_rules.append(
            LifecycleRule(
                rule_priority=18,
                description="Delete development images after 90 days year",
                tag_status=TagStatus.TAGGED,
                tag_prefix_list=["dev_"],
                max_image_age=Duration.days(dev_image_max_age),
            )
        )

        lifecycle_rules += additional_lifecycle_rules

        self.repository = Repository(
            self,
            "Default",
            repository_name=name,
            lifecycle_rules=lifecycle_rules,
            image_scan_on_push=scan_on_push,
        )

        for account in additional_accounts_pull:
            self.repository.grant_pull(iam.AccountPrincipal(account))

        for account in additional_accounts_push:
            self.repository.grant_push(iam.AccountPrincipal(account))
