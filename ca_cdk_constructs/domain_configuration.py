from aws_cdk import Stack
from constructs import Construct

from aws_cdk.aws_route53 import HostedZone


class DomainConfiguration(Construct):
    """Conventional way to create DNS records."""

    def __init__(
        self,
        scope: Construct,
        id: str,
        record_name: str,
        hosted_zone_domain: str,
        is_domain_apdex: bool,
    ) -> None:
        """

        Args:
            scope (Construct): construct
            id (str): construct id
            record_name (str): R53 record name
            hosted_zone_domain (str): The hosted zone domain where the record will be created
            is_domain_apdex (bool): Is the HZ an APDEX domain. If yes, a new HZ will be created by the construct using a shared root (directly attached to cdkApp()) stack.
            The zone will be named <record_name>.<hosted_zone_domain>.
        """
        super().__init__(scope, id)

        self._is_domain_apdex = is_domain_apdex
        self.record_name = record_name
        self.hosted_zone_domain = hosted_zone_domain

        self.domain = f"{self.record_name}.{self.hosted_zone_domain}"
        self.ingress_domain = f"ingress.{self.record_name}.{self.hosted_zone_domain}"

        if self._is_domain_apdex:
            self.hosted_zone_domain = self.domain
            self.ingress_domain = f"ingress.{self.hosted_zone_domain}"
            stack = Stack(self.node.root, f"{record_name}HostedZoneStack")
            self.hosted_zone = HostedZone(stack, "HostedZone", zone_name=hosted_zone_domain)
        else:
            self.hosted_zone = HostedZone.from_lookup(
                self, "HostedZoneLookup", domain_name=hosted_zone_domain
            )

    @property
    def is_domain_apdex(self) -> bool:
        return self._is_domain_apdex
