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
        unknown_face_action: str,
    ) -> PolicyDecision:
        if state == "camera_unavailable":
            return PolicyDecision(
                "notify",
                "Camera failure is not evidence of an attack.",
                False,
            )
        if state == "no_face_detected":
            return PolicyDecision(
                "notify",
                "No face is currently present; this is not proof of an attack.",
                False,
            )
        if state != "unknown_face":
            return PolicyDecision("none", "No response is required.", False)
        if consecutive_failures < failure_limit:
            return PolicyDecision(
                "record",
                "Failure limit has not been reached.",
                False,
            )
        if automatic_lock_enabled and unknown_face_action == "lock_after_grace":
            return PolicyDecision(
                "warn_then_lock",
                "Configured failure threshold reached; grace-period warning required.",
                True,
            )
        return PolicyDecision(
            "notify",
            "Repeated identity verification failure recorded; workstation remains unlocked.",
            False,
        )