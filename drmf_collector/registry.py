from __future__ import annotations

from typing import Callable, List

from .graph_client import GraphClient
from .models import ControlResult
from .evaluators.apps import (
    evaluate_admin_consent_workflow,
    evaluate_app_registration_restricted,
)
from .evaluators.auth_methods import evaluate_auth_methods_policy
from .evaluators.cross_tenant import evaluate_cross_tenant_access
from .evaluators.entra import (
    evaluate_break_glass,
    evaluate_compliant_device_required,
    evaluate_legacy_auth_blocked,
    evaluate_mfa_admin_roles,
    evaluate_mfa_all_users,
    evaluate_phishing_resistant_mfa_admins,
    evaluate_risk_policies,
    evaluate_security_defaults_replaced,
)
from .evaluators.governance import evaluate_access_reviews
from .evaluators.identity_protection import evaluate_identity_protection_triage
from .evaluators.intune import evaluate_bitlocker_escrow
from .evaluators.intune_expanded import (
    evaluate_asr_rules_block,
    evaluate_defender_av_cloud_protection,
    evaluate_device_compliance_policies,
    evaluate_device_control,
    evaluate_firewall_managed,
    evaluate_laps_policy,
    evaluate_local_admin_restrictions,
    evaluate_mam_byod,
    evaluate_mde_onboarding_coverage,
    evaluate_network_web_protection,
    evaluate_security_baselines,
    evaluate_update_rings,
)
from .evaluators.named_locations import evaluate_named_locations
from .evaluators.oauth_apps import evaluate_oauth_app_governance
from .evaluators.pim import evaluate_pim_privileged_roles


Evaluator = Callable[[GraphClient], ControlResult]


CONTROL_EVALUATORS: List[Evaluator] = [
    # Identity / Entra
    evaluate_mfa_all_users,
    evaluate_mfa_admin_roles,
    evaluate_legacy_auth_blocked,
    evaluate_pim_privileged_roles,
    evaluate_break_glass,
    evaluate_compliant_device_required,
    evaluate_phishing_resistant_mfa_admins,
    evaluate_risk_policies,
    evaluate_auth_methods_policy,
    evaluate_admin_consent_workflow,
    evaluate_app_registration_restricted,
    evaluate_oauth_app_governance,
    evaluate_cross_tenant_access,
    evaluate_named_locations,
    evaluate_security_defaults_replaced,
    evaluate_access_reviews,

    # Endpoint / Intune
    evaluate_mde_onboarding_coverage,
    evaluate_asr_rules_block,
    evaluate_bitlocker_escrow,
    evaluate_laps_policy,
    evaluate_local_admin_restrictions,
    evaluate_device_compliance_policies,
    evaluate_firewall_managed,
    evaluate_network_web_protection,
    evaluate_device_control,
    evaluate_update_rings,
    evaluate_defender_av_cloud_protection,
    evaluate_security_baselines,
    evaluate_mam_byod,

    # Monitoring / detection via Graph
    evaluate_identity_protection_triage,
]
