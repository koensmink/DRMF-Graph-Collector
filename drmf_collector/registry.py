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
from .evaluators.intune import evaluate_bitlocker_escrow
from .evaluators.named_locations import evaluate_named_locations


Evaluator = Callable[[GraphClient], ControlResult]


CONTROL_EVALUATORS: List[Evaluator] = [
    evaluate_mfa_all_users,
    evaluate_mfa_admin_roles,
    evaluate_legacy_auth_blocked,
    evaluate_break_glass,
    evaluate_compliant_device_required,
    evaluate_phishing_resistant_mfa_admins,
    evaluate_risk_policies,
    evaluate_auth_methods_policy,
    evaluate_admin_consent_workflow,
    evaluate_app_registration_restricted,
    evaluate_cross_tenant_access,
    evaluate_named_locations,
    evaluate_security_defaults_replaced,
    evaluate_access_reviews,
    evaluate_bitlocker_escrow,
]
