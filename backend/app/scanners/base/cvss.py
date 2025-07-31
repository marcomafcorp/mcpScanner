from dataclasses import dataclass
from enum import Enum
from typing import Optional


class AttackVector(str, Enum):
    """CVSS Attack Vector."""
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(str, Enum):
    """CVSS Attack Complexity."""
    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(str, Enum):
    """CVSS Privileges Required."""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(str, Enum):
    """CVSS User Interaction."""
    NONE = "N"
    REQUIRED = "R"


class Scope(str, Enum):
    """CVSS Scope."""
    UNCHANGED = "U"
    CHANGED = "C"


class Impact(str, Enum):
    """CVSS Impact (CIA)."""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


@dataclass
class CVSSv3:
    """CVSS v3.1 Calculator."""
    
    # Base Metrics
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality_impact: Impact = Impact.NONE
    integrity_impact: Impact = Impact.NONE
    availability_impact: Impact = Impact.NONE
    
    def calculate_base_score(self) -> float:
        """Calculate CVSS v3.1 base score."""
        # Calculate Impact Sub Score (ISS)
        iss = self._calculate_impact_subscore()
        
        # Calculate Exploitability
        exploitability = self._calculate_exploitability()
        
        # Calculate base score
        if iss <= 0:
            return 0.0
        
        if self.scope == Scope.UNCHANGED:
            base_score = min(iss + exploitability, 10)
        else:
            base_score = min(1.08 * (iss + exploitability), 10)
        
        # Round up to 1 decimal place
        return round(base_score * 10) / 10
    
    def _calculate_impact_subscore(self) -> float:
        """Calculate Impact Sub Score."""
        # Get impact values
        c_value = self._get_impact_value(self.confidentiality_impact)
        i_value = self._get_impact_value(self.integrity_impact)
        a_value = self._get_impact_value(self.availability_impact)
        
        # Calculate ISC Base
        isc_base = 1 - ((1 - c_value) * (1 - i_value) * (1 - a_value))
        
        if self.scope == Scope.UNCHANGED:
            return 6.42 * isc_base
        else:
            return 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)
    
    def _calculate_exploitability(self) -> float:
        """Calculate Exploitability score."""
        av_value = self._get_av_value()
        ac_value = self._get_ac_value()
        pr_value = self._get_pr_value()
        ui_value = self._get_ui_value()
        
        return 8.22 * av_value * ac_value * pr_value * ui_value
    
    def _get_impact_value(self, impact: Impact) -> float:
        """Get numeric value for impact."""
        return {
            Impact.NONE: 0.0,
            Impact.LOW: 0.22,
            Impact.HIGH: 0.56,
        }[impact]
    
    def _get_av_value(self) -> float:
        """Get Attack Vector value."""
        return {
            AttackVector.NETWORK: 0.85,
            AttackVector.ADJACENT: 0.62,
            AttackVector.LOCAL: 0.55,
            AttackVector.PHYSICAL: 0.2,
        }[self.attack_vector]
    
    def _get_ac_value(self) -> float:
        """Get Attack Complexity value."""
        return {
            AttackComplexity.LOW: 0.77,
            AttackComplexity.HIGH: 0.44,
        }[self.attack_complexity]
    
    def _get_pr_value(self) -> float:
        """Get Privileges Required value."""
        if self.scope == Scope.UNCHANGED:
            return {
                PrivilegesRequired.NONE: 0.85,
                PrivilegesRequired.LOW: 0.62,
                PrivilegesRequired.HIGH: 0.27,
            }[self.privileges_required]
        else:
            return {
                PrivilegesRequired.NONE: 0.85,
                PrivilegesRequired.LOW: 0.68,
                PrivilegesRequired.HIGH: 0.5,
            }[self.privileges_required]
    
    def _get_ui_value(self) -> float:
        """Get User Interaction value."""
        return {
            UserInteraction.NONE: 0.85,
            UserInteraction.REQUIRED: 0.62,
        }[self.user_interaction]
    
    def get_vector_string(self) -> str:
        """Get CVSS v3.1 vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector.value}/"
            f"AC:{self.attack_complexity.value}/"
            f"PR:{self.privileges_required.value}/"
            f"UI:{self.user_interaction.value}/"
            f"S:{self.scope.value}/"
            f"C:{self.confidentiality_impact.value}/"
            f"I:{self.integrity_impact.value}/"
            f"A:{self.availability_impact.value}"
        )
    
    def get_severity_rating(self) -> str:
        """Get severity rating based on score."""
        score = self.calculate_base_score()
        if score == 0.0:
            return "None"
        elif score <= 3.9:
            return "Low"
        elif score <= 6.9:
            return "Medium"
        elif score <= 8.9:
            return "High"
        else:
            return "Critical"
    
    @classmethod
    def from_vector_string(cls, vector: str) -> Optional["CVSSv3"]:
        """Create CVSSv3 instance from vector string."""
        try:
            parts = vector.split("/")
            if parts[0] != "CVSS:3.1":
                return None
            
            metrics = {}
            for part in parts[1:]:
                key, value = part.split(":")
                metrics[key] = value
            
            return cls(
                attack_vector=AttackVector(metrics.get("AV", "N")),
                attack_complexity=AttackComplexity(metrics.get("AC", "L")),
                privileges_required=PrivilegesRequired(metrics.get("PR", "N")),
                user_interaction=UserInteraction(metrics.get("UI", "N")),
                scope=Scope(metrics.get("S", "U")),
                confidentiality_impact=Impact(metrics.get("C", "N")),
                integrity_impact=Impact(metrics.get("I", "N")),
                availability_impact=Impact(metrics.get("A", "N")),
            )
        except Exception:
            return None


def estimate_cvss_from_finding(
    category: str,
    severity: str,
    requires_auth: bool = False,
    requires_user_interaction: bool = False,
) -> CVSSv3:
    """
    Estimate CVSS score from finding information.
    
    This is a simplified estimation and should be refined based on
    actual vulnerability characteristics.
    """
    cvss = CVSSv3()
    
    # Set common defaults
    cvss.attack_vector = AttackVector.NETWORK
    cvss.attack_complexity = AttackComplexity.LOW
    
    # Authentication/privileges
    if requires_auth:
        cvss.privileges_required = PrivilegesRequired.LOW
    else:
        cvss.privileges_required = PrivilegesRequired.NONE
    
    # User interaction
    if requires_user_interaction:
        cvss.user_interaction = UserInteraction.REQUIRED
    else:
        cvss.user_interaction = UserInteraction.NONE
    
    # Map severity to impact
    if severity == "critical":
        cvss.confidentiality_impact = Impact.HIGH
        cvss.integrity_impact = Impact.HIGH
        cvss.availability_impact = Impact.HIGH
        cvss.scope = Scope.CHANGED
    elif severity == "high":
        cvss.confidentiality_impact = Impact.HIGH
        cvss.integrity_impact = Impact.HIGH
        cvss.availability_impact = Impact.LOW
    elif severity == "medium":
        cvss.confidentiality_impact = Impact.LOW
        cvss.integrity_impact = Impact.LOW
        cvss.availability_impact = Impact.LOW
    elif severity == "low":
        cvss.confidentiality_impact = Impact.LOW
        cvss.integrity_impact = Impact.NONE
        cvss.availability_impact = Impact.NONE
    else:  # info
        cvss.confidentiality_impact = Impact.NONE
        cvss.integrity_impact = Impact.NONE
        cvss.availability_impact = Impact.NONE
    
    # Adjust based on category
    if "injection" in category.lower():
        cvss.integrity_impact = Impact.HIGH
        cvss.confidentiality_impact = Impact.HIGH
    elif "auth" in category.lower():
        cvss.confidentiality_impact = Impact.HIGH
    elif "config" in category.lower():
        cvss.attack_complexity = AttackComplexity.HIGH
    elif "network" in category.lower():
        cvss.availability_impact = Impact.HIGH
    
    return cvss