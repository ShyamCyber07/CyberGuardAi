from abc import ABC, abstractmethod

class RiskCalculatorInterface(ABC):
    """Abstract interface defining risk score and severity evaluations."""

    @abstractmethod
    def calculate_risk(self, findings: list, is_inconclusive: bool = False) -> str:
        """Evaluate network port findings to determine an overall severity rating."""
        pass


class SimpleRiskCalculator(RiskCalculatorInterface):
    """Concrete implementation of the risk assessment calculation interface."""

    def calculate_risk(self, findings: list, is_inconclusive: bool = False) -> str:
        if is_inconclusive:
            return 'Inconclusive'

        if not findings:
            return 'Low'

        # Only evaluate open ports for network exposure risk; closed/filtered ports do not represent active attack vectors
        open_findings = [f for f in findings if getattr(f, 'state', 'open').lower() == 'open']
        if not open_findings:
            return 'Low'

        # Analyze port vulnerability severity states
        severities = [finding.severity.lower() for finding in open_findings]

        if 'high' in severities or 'critical' in severities:
            return 'High'
        elif 'medium' in severities:
            return 'Medium'
        
        return 'Low'
