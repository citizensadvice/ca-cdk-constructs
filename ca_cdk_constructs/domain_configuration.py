class DomainConfiguration:
    def __init__(self, env_name: str, record_name: str, apex_domain: str) -> None:
        self.env_name = env_name
        self.record_name = record_name
        self.apex_domain = apex_domain

        self.is_prod = env_name == "prod"
        self.hosted_zone_domain = f"{env_name}.{apex_domain}"
        self.domain = f"{self.record_name}.{self.hosted_zone_domain}"

        self.ingress_domain = f"{self.record_name}-ingress.{self.hosted_zone_domain}"

        if self.is_prod:
            # the record is created in the hosted zone domain
            # i.e. a hosted zone myapp.rootdomain.com will have 'myapp' ALIAS or CNAME record in it.
            self.domain = self.hosted_zone_domain = f"{self.record_name}.{self.apex_domain}"
            self.ingress_domain = f"ingress.{self.domain}"
