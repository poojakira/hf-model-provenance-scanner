from attack_core.index import ATTACKIndex
from attack_core.models import ATTACKMapping
from typing import List, Dict, Any


class ATTACKEnricher:
    def __init__(self, index: ATTACKIndex):
        self.index = index
        self._rule_table: Dict[str, List[str]] = {
            "unsigned_model_weights": ["T1195.001", "T1553.002"],
            "pickle_deserialization": ["T1059.006", "T1203"],
            "typosquatted_model_name": ["T1036.005", "T1195"],
            "modified_model_card": ["T1565.001", "T1027", "T1683/001"],
            "unauthorized_fine_tune": ["T1565", "T1190"],
            "huggingface_token_exposure": ["T1552.001", "T1078"],
            "trojanized_tokenizer": ["T1195.002", "T1027.002", "T1027/018"],
            "model_weight_exfiltration": ["T1041", "T1048"],
            "dependency_confusion": ["T1195.001"],
            "malicious_model_repo": ["T1583.001", "T1608.001"],
        }

    def enrich(self, finding_type: str, metadata: Dict[str, Any]) -> List[ATTACKMapping]:
        technique_ids = self._rule_table.get(finding_type, [])
        mappings = []
        for tid in technique_ids:
            tech = self.index.get(tid)
            if tech:
                tactic = self.index._tactics.get(tech.tactic_ids[0] if tech.tactic_ids else "", None)
                mappings.append(ATTACKMapping(
                    tactic_id=tech.tactic_ids[0] if tech.tactic_ids else "unknown",
                    tactic_name=tactic.name if tactic else "unknown",
                    technique_id=tech.attack_id,
                    technique_name=tech.name,
                    subtechnique_id=tech.attack_id if tech.is_subtechnique else None,
                    subtechnique_name=tech.name if tech.is_subtechnique else None,
                    domain=tech.domain,
                    confidence=metadata.get("confidence", 0.5),
                    data_sources=tech.data_sources,
                    platforms=tech.platforms,
                    url=tech.url,
                ))
        return mappings