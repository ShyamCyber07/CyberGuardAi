from abc import ABC, abstractmethod
from app.services.network_rules import calculate_network_risk

class RiskCalculatorInterface(ABC):
    """Abstract interface defining risk score and severity evaluations."""

    @abstractmethod
    def calculate_risk(self, findings: list, is_inconclusive: bool = False) -> str:
        """Evaluate network port findings to determine an overall severity rating."""
        pass


class SimpleRiskCalculator(RiskCalculatorInterface):
    """Concrete implementation of the risk assessment calculation interface."""

    def calculate_risk(self, findings: list, is_inconclusive: bool = False) -> str:
        return calculate_network_risk(findings, is_inconclusive=is_inconclusive)
