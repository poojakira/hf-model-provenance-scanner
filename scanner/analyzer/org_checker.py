import json
import os
from datetime import datetime, timezone
from typing import Optional

from scanner.models import Finding, OrgCheckResult
from scanner.rules.definitions import get_rule
from scanner.utils.hf_api import HFApiClient
from scanner.utils.levenshtein import levenshtein, token_cosine_similarity


def load_protected_orgs() -> list[str]:
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "protected_orgs.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [str(item).lower() for item in json.load(f)]
    except Exception:
        return []


def _emit(rule_id: str, evidence: str) -> Finding:
    rule = get_rule(rule_id)
    return Finding(rule_id, rule.severity, "", 0, 0, rule.description, evidence[:300], rule.remediation, rule.cwe)


def _parse_created_at(value: str):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def check_organization(repo_id: str, client: HFApiClient, distance_threshold: int = 2, card_sim_threshold: float = 0.90) -> tuple:
    findings: list[Finding] = []
    protected_orgs = load_protected_orgs()

    parts = repo_id.split("/")
    if len(parts) != 2:
        return None, findings

    org_name, model_name = parts[0], parts[1]
    org_lower = org_name.lower()

    try:
        info = client.get_model_info(repo_id)
    except Exception:
        return None, findings

    is_verified = bool(info.get("authorData", {}).get("isVerified") or info.get("authorData", {}).get("verified"))

    levenshtein_matches: list[tuple[str, int]] = []
    if org_lower not in protected_orgs:
        for protected in protected_orgs:
            dist = levenshtein(org_lower, protected)
            if dist <= distance_threshold:
                levenshtein_matches.append((protected, dist))
        if levenshtein_matches:
            findings.append(_emit("HFS-020", f"Org '{org_name}' is distance {min(d for _, d in levenshtein_matches)} from protected orgs: {[o for o, _ in levenshtein_matches]}"))

    created_at = _parse_created_at(info.get("createdAt", ""))
    age_hours = None
    velocity = None
    downloads = int(info.get("downloads") or 0)
    if created_at:
        age_td = datetime.now(timezone.utc) - created_at
        age_hours = age_td.total_seconds() / 3600.0
        if age_hours > 0:
            velocity = downloads / age_hours
        if age_hours < 72 and downloads > 10000:
            findings.append(_emit("HFS-022", f"Age: {age_hours:.1f} hours, Downloads: {downloads}"))

    target_card = client.get_model_card(repo_id)
    max_sim = 0.0
    if target_card:
        candidates = [org for org, _ in levenshtein_matches] or [org for org in protected_orgs if org != org_lower]
        comparison_available = False
        for candidate_org in candidates:
            protected_repo = f"{candidate_org}/{model_name}"
            protected_card = client.get_model_card(protected_repo)
            if not protected_card:
                continue
            comparison_available = True
            sim = token_cosine_similarity(target_card, protected_card)
            if sim > max_sim:
                max_sim = sim
            if sim >= card_sim_threshold:
                findings.append(_emit("HFS-021", f"README similarity {sim:.3f} vs {protected_repo}"))
                break
        if levenshtein_matches and not comparison_available:
            best_match_org = min(levenshtein_matches, key=lambda x: x[1])[0]
            findings.append(_emit("HFS-097", f"Failed to fetch model card for {best_match_org}/{model_name}"))

    return OrgCheckResult(repo_id, org_name, is_verified, levenshtein_matches, max_sim, age_hours, velocity), findings
