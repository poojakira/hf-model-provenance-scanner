from attack_core import ATTACKLoader, ATTACKIndex
from attack_mapping.enricher import ATTACKEnricher
from attack_mapping.reporter import NavigatorLayerReporter

loader = ATTACKLoader()
index = ATTACKIndex(loader)
enricher = ATTACKEnricher(index)
reporter = NavigatorLayerReporter()

all_mappings = []
for ft in ['unsigned_model_weights', 'pickle_deserialization', 'typosquatted_model_name', 'modified_model_card', 'unauthorized_fine_tune', 'huggingface_token_exposure', 'trojanized_tokenizer', 'model_weight_exfiltration', 'dependency_confusion', 'malicious_model_repo']:
    mappings = enricher.enrich(ft, {'confidence': 0.8})
    all_mappings.extend(mappings)

layer = reporter.generate('hf-model-provenance-scanner', all_mappings)
import json
data = json.loads(layer)
print(f'Techniques mapped: {len(data["techniques"])}')
for t in data['techniques']:
    print(f'  {t["techniqueID"]}: score={t["score"]}')