from dataclasses import dataclass, field


@dataclass
class DomainProperties:
    """Conventional domain naming
    ``
    dp = DomainProperties(sub_domain="foo", zone_domain="bar.com")
    dp.domain # foo.bar.com
    dp.ingress_domain # foo-ingress.bar.com
    dp.zone_domain # bar.com

    DomainProperties(sub_domain="", zone_domain="foo.bar.com")
    # same as above
    DomainProperties(sub_domain="foo", zone_domain="foo.bar.com")
    # same as above

    DomainProperties(sub_domain="foo", zone_domain="qa.bar.com")
    dp.domain # foo.qa.bar.com
    dp.ingress_domain # foo-ingress.qa.bar.com
    dp.zone_domain # qa.bar.com
    ``

    """

    sub_domain: str
    zone_domain: str
    domain: str = field(init=False)
    ingress_domain: str = field(init=False)

    def __post_init__(self):
        self.domain = f"{self.sub_domain}.{self.zone_domain}"
        self.ingress_domain = f"{self.sub_domain}-ingress.{self.zone_domain}"

        zone_record, domain = self.zone_domain.split(".", 1)
        if not self.sub_domain:
            self.sub_domain = self.sub_domain or zone_record
            self.domain = self.zone_domain
            self.ingress_domain = f"{self.sub_domain}-ingress.{domain}"
