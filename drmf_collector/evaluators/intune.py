from __future__ import annotations

from ..graph_client import GraphClient
from ..models import ControlResult
from ..utils import result


def evaluate_bitlocker_escrow(client: GraphClient) -> ControlResult:
    keys = client.list_all("informationProtection/bitlocker/recoveryKeys")

    devices = []
    device_query_error = None

    try:
        devices = client.list_all(
            "deviceManagement/managedDevices",
            params={"$select": "id,deviceName,operatingSystem,complianceState,isEncrypted"},
        )
    except Exception as exc:
        device_query_error = str(exc)

    windows_devices = [
        d for d in devices
        if (d.get("operatingSystem") or "").lower() == "windows"
    ]

    encrypted_true = [
        d for d in windows_devices
        if d.get("isEncrypted") is True
    ]

    encrypted_false = [
        d for d in windows_devices
        if d.get("isEncrypted") is False
    ]

    if keys:
        status = "pass"
        reason = "At least one BitLocker recovery key is escrowed in Entra ID."
        observed = f"{len(keys)} BitLocker recovery key record(s) found."
    elif windows_devices:
        status = "fail"
        reason = "No BitLocker recovery keys were found while Windows managed devices exist."
        observed = (
            f"recovery_key_count=0; "
            f"windows_managed_device_count={len(windows_devices)}; "
            f"windows_devices_with_isEncrypted_false={len(encrypted_false)}"
        )
    else:
        status = "partial"
        reason = "No BitLocker recovery keys were found, and Windows device inventory could not be confirmed."
        observed = "recovery_key_count=0; windows_managed_device_count=0 or unavailable"

    return result(
        control_id="EP-05",
        title="BitLocker recovery keys escrowed",
        status=status,
        confidence="medium" if keys or windows_devices else "low",
        reason=reason,
        expected="BitLocker recovery keys are escrowed to Entra ID for all in-scope Windows devices, and encryption is enforced by Intune policy.",
        observed=observed,
        evidence={
            "recovery_key_count": len(keys),
            "recovery_key_sample": keys[:10],
            "managed_device_query_error": device_query_error,
            "managed_device_count_observed": len(devices),
            "windows_managed_device_count": len(windows_devices),
            "windows_devices_encrypted_true": len(encrypted_true),
            "windows_devices_encrypted_false": len(encrypted_false),
            "unencrypted_windows_device_sample": [
                {
                    "id": device.get("id"),
                    "deviceName": device.get("deviceName"),
                    "complianceState": device.get("complianceState"),
                    "isEncrypted": device.get("isEncrypted"),
                }
                for device in encrypted_false[:25]
            ],
        },
        remediation_hint="Verify Intune disk encryption policy assignment and confirm BitLocker recovery key escrow. For existing devices, rotate or back up recovery keys to Entra ID where needed.",
        notes="Recovery key presence proves escrow exists, not full coverage across all in-scope devices.",
    )
