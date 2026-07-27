from typing import Any, Dict, List

from attack_core.index import ATTACKIndex
from attack_core.mapping import ATTACKMappingBuilder
from attack_core.models import ATTACKMapping


class ATTACKEnricher:
    def __init__(self, index: ATTACKIndex):
        self.index = index
        self.mapping_builder = ATTACKMappingBuilder(index)
        self._rule_table: Dict[str, List[str]] = {
            "unsigned_model_weights": ["T1195.001", "T1553.002"],
            "pickle_deserialization": ["T1059.006", "T1203"],
            "typosquatted_model_name": ["T1036.005", "T1195"],
            "modified_model_card": ["T1565.001", "T1027", "T1683.001"],
            "unauthorized_fine_tune": ["T1565", "T1190"],
            "huggingface_token_exposure": ["T1552.001", "T1078"],
            "trojanized_tokenizer": ["T1195.002", "T1027.002", "T1027.018"],
            "model_weight_exfiltration": ["T1041", "T1048"],
            "dependency_confusion": ["T1195.001"],
            "malicious_model_repo": ["T1583.001", "T1608.001", "T1682"],
        }

    def enrich(self, finding_type: str, metadata: dict[str, Any]) -> list[ATTACKMapping]:
        confidence = metadata.get("confidence", 0.5)
        technique_ids = self._rule_table.get(finding_type, [])
        return self.mapping_builder.build_many(technique_ids, confidence)
