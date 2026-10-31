"""ATT&CK reference data: technique names, technique-to-tactic lists, kill chain stage order.

data/attack_catalogue.json is copied from AI-SOC (ATT&CK Enterprise, 14 tactics,
691 techniques and sub-techniques). Its `attribution` field carries MITRE's
required notice. Stage order and 7-phase labels are in config/killchain.yml.
"""

from .catalogue import (  # noqa: F401
    AttackError, Technique, all_tactics, check_alternates, is_technique, kill_chain_stage, label,
    parent, stage_no, tactic, tactic_info, technique, unknown_label,
)
