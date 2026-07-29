import pytest
from attack_v19_core import ATTACKIndex, ATTACKLoader

from scanner.attack_mapping.enricher import ATTACKEnricher


@pytest.fixture
def enricher():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    return ATTACKEnricher(index)


def mapped_ids(mappings):
    return {m.subtechnique_id or m.technique_id for m in mappings}


class TestHFProvenanceEnricher:
    def test_unsigned_weights(self, enricher):
        mappings = enricher.enrich("unsigned_model_weights", {"confidence": 0.9})
        assert "T1195.001" in mapped_ids(mappings)
        assert "T1553.002" in mapped_ids(mappings)

    def test_pickle_deserialization(self, enricher):
        mappings = enricher.enrich("pickle_deserialization", {"confidence": 0.95})
        assert "T1059.006" in mapped_ids(mappings)
        assert "T1203" in mapped_ids(mappings)

    def test_typosquatted_model(self, enricher):
        mappings = enricher.enrich("typosquatted_model_name", {"confidence": 0.8})
        assert "T1036.005" in mapped_ids(mappings)
        assert "T1195" in mapped_ids(mappings)

    def test_hf_token_exposure(self, enricher):
        mappings = enricher.enrich("huggingface_token_exposure", {"confidence": 0.85})
        assert "T1552.001" in mapped_ids(mappings)
        assert "T1078" in mapped_ids(mappings)
