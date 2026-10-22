"""Conservative decisions for repeated identity verification failures."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    action: str
    reason: str
    requires_explicit_opt_in: bool


class VerificationPolicy:
    def decide(
        self,
        state: str,
        consecutive_failures: int,
        failure_limit: int,
        automatic_lock_enabled: bool,
        action: str,
    ) -> PolicyDecision:
        if state == "camera_unavailable":
            return PolicyDecision(
                "notify",
                "Camera failure is not evidence of an attack.",
                False,
            )
        if state not in {"unknown_face", "no_face_detected"}:
            return PolicyDecision("none", "No response is required.", False)
        if consecutive_failures < failure_limit:
            return PolicyDecision(
                "record",
                "Failure limit has not been reached.",
                False,
            )
        if automatic_lock_enabled and action == "lock_after_grace":
            reason = (
                "Configured no-face failure threshold reached; "
                "grace-period warning required."
                if state == "no_face_detected"
                else "Configured unknown-face failure threshold reached; "
                "grace-period warning required."
            )
            return PolicyDecision(
                "warn_then_lock",
                reason,
                True,
            )
        reason = (
            "Repeated absence of the enrolled face recorded; workstation remains unlocked."
            if state == "no_face_detected"
            else "Repeated identity verification failure recorded; workstation remains unlocked."
        )
        return PolicyDecision(
            "notify",
            reason,
            False,
        )