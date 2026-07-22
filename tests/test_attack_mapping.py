import pytest
from attack_core import ATTACKLoader, ATTACKIndex
from attack_mapping.enricher import ATTACKEnricher


@pytest.fixture
def enricher():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    return ATTACKEnricher(index)


class TestHFProvenanceEnricher:
    def test_unsigned_weights(self, enricher):
        mappings = enricher.enrich("unsigned_model_weights", {"confidence": 0.9})
        technique_ids = [m.technique_id for m in mappings]
        assert "T1195.001" in technique_ids
        assert "T1553.002" in technique_ids

    def test_pickle_deserialization(self, enricher):
        mappings = enricher.enrich("pickle_deserialization", {"confidence": 0.95})
        technique_ids = [m.technique_id for m in mappings]
        assert "T1059.006" in technique_ids
        assert "T1203" in technique_ids

    def test_typosquatted_model(self, enricher):
        mappings = enricher.enrich("typosquatted_model_name", {"confidence": 0.8})
        technique_ids = [m.technique_id for m in mappings]
        assert "T1036.005" in technique_ids
        assert "T1195" in technique_ids

    def test_hf_token_exposure(self, enricher):
        mappings = enricher.enrich("huggingface_token_exposure", {"confidence": 0.85})
        technique_ids = [m.technique_id for m in mappings]
        assert "T1552.001" in technique_ids
        assert "T1078" in technique_ids