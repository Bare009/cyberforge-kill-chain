"""Per-incident risk score (B-1), so the worst incident is listed first.

Weighted sum adapted from AI-SOC's triage score: severity, furthest kill chain
stage reached, asset criticality, and how much the attacker can still reach.
"""
