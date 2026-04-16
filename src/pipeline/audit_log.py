"""
Assignment 11 — Audit Log Plugin

WHAT: Records every interaction through the pipeline, including:
      - Timestamp, user ID
      - Input text and output text
      - Which safety layer blocked (if any)
      - Latency (time from input to output)
      Exports all logs to a JSON file for review.

WHY:  Audit logging is CRITICAL for production AI systems because:
      1. Compliance: Banks must maintain records of all customer interactions
      2. Debugging: When a false positive blocks a legitimate query, logs help
         identify which layer caused it and why
      3. Monitoring: Logs feed into the MonitoringAlert system for anomaly detection
      4. Forensics: After a security incident, logs show exactly what happened
      This layer doesn't catch attacks directly — it RECORDS everything so that
      other layers' decisions can be reviewed and improved.

DESIGN: Uses two callbacks:
        - on_user_message_callback: Records input + start time (never blocks)
        - after_model_callback: Records output + calculates latency (never modifies)
        Logs are stored in memory and can be exported to JSON at any time.
"""

import json
import time
from datetime import datetime, timezone

from google.genai import types
from google.adk.plugins import base_plugin
from google.adk.agents.invocation_context import InvocationContext


class AuditLogPlugin(base_plugin.BasePlugin):
    """Plugin that records every interaction for audit and compliance.

    WHY this is needed:
    - Other plugins (Rate Limiter, Input/Output Guardrails) make decisions
    - This plugin RECORDS those decisions for later review
    - Without audit logs, you cannot prove your safety system works

    The audit log never blocks or modifies any messages — it only observes.
    """

    def __init__(self):
        super().__init__(name="audit_log")
        self.logs = []
        # Temporary storage for tracking latency per request
        self._pending = {}

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: types.Content,
    ) -> types.Content | None:
        """Record the user's input and start time.

        WHY: We capture the input BEFORE any other plugin processes it.
        This means the audit log contains the RAW user input, even if
        it was later blocked by a guardrail. This is essential for
        reviewing false positives and understanding attack patterns.

        Returns:
            Always None — audit log never blocks messages.
        """
        # Extract text from Content object
        text = ""
        if user_message and user_message.parts:
            for part in user_message.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text

        # Extract user ID
        user_id = "anonymous"
        if invocation_context and hasattr(invocation_context, "user_id"):
            user_id = invocation_context.user_id or "anonymous"

        # Create log entry (output will be filled in after_model_callback)
        entry_id = len(self.logs)
        self._pending[user_id] = {
            "id": entry_id,
            "start_time": time.time(),
        }

        self.logs.append({
            "id": entry_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "input": text,
            "output": None,  # Filled later
            "blocked": False,
            "blocked_by": None,
            "latency_ms": None,
        })

        return None  # Never block

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ):
        """Record the model's output and calculate latency.

        WHY: We capture the output AFTER the model generates it but BEFORE
        other output plugins might modify it. This gives us the raw model
        output for comparison with the final (possibly redacted) output.

        Returns:
            Always returns the unmodified llm_response — audit log never changes output.
        """
        # Extract text from response
        response_text = ""
        if hasattr(llm_response, "content") and llm_response.content:
            for part in llm_response.content.parts:
                if hasattr(part, "text") and part.text:
                    response_text += part.text

        # Find the most recent pending entry and update it
        if self.logs:
            latest = self.logs[-1]
            if latest["output"] is None:
                latest["output"] = response_text

                # Check if this was a blocked response
                if "[BLOCKED]" in response_text or "[RATE LIMITED]" in response_text:
                    latest["blocked"] = True
                    if "[RATE LIMITED]" in response_text:
                        latest["blocked_by"] = "rate_limiter"
                    elif "[BLOCKED]" in response_text:
                        latest["blocked_by"] = "input_guardrail"
                elif "[JUDGE BLOCKED]" in response_text:
                    latest["blocked"] = True
                    latest["blocked_by"] = "llm_judge"

                # Calculate latency
                for user_id, pending in list(self._pending.items()):
                    if pending["id"] == latest["id"]:
                        latest["latency_ms"] = round(
                            (time.time() - pending["start_time"]) * 1000, 2
                        )
                        del self._pending[user_id]
                        break

        return llm_response  # Never modify

    def record_manual(self, user_id: str, input_text: str, output_text: str,
                      blocked: bool = False, blocked_by: str = None,
                      latency_ms: float = None):
        """Manually record an interaction (for pipeline-level logging).

        WHY: When the pipeline blocks a request at the rate limiter or
        input guardrail level, the ADK callbacks may not fire. This method
        allows the pipeline to manually record those interactions.

        Args:
            user_id: User identifier
            input_text: Raw user input
            output_text: Response sent to user
            blocked: Whether the request was blocked
            blocked_by: Which layer blocked it
            latency_ms: Processing time in milliseconds
        """
        self.logs.append({
            "id": len(self.logs),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "input": input_text,
            "output": output_text,
            "blocked": blocked,
            "blocked_by": blocked_by,
            "latency_ms": latency_ms,
        })

    def export_json(self, filepath: str = "audit_log.json") -> str:
        """Export all audit logs to a JSON file.

        Args:
            filepath: Output file path (default: audit_log.json)

        Returns:
            The filepath where logs were saved
        """
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, ensure_ascii=False, default=str)
        print(f"Audit log exported: {filepath} ({len(self.logs)} entries)")
        return filepath

    def get_summary(self) -> dict:
        """Get a summary of audit log statistics.

        Returns:
            dict with total, blocked, blocked_by_layer counts
        """
        total = len(self.logs)
        blocked = sum(1 for l in self.logs if l.get("blocked"))
        by_layer = {}
        for l in self.logs:
            layer = l.get("blocked_by")
            if layer:
                by_layer[layer] = by_layer.get(layer, 0) + 1

        avg_latency = 0
        latencies = [l["latency_ms"] for l in self.logs if l.get("latency_ms")]
        if latencies:
            avg_latency = sum(latencies) / len(latencies)

        return {
            "total_entries": total,
            "blocked_count": blocked,
            "blocked_by_layer": by_layer,
            "avg_latency_ms": round(avg_latency, 2),
        }
