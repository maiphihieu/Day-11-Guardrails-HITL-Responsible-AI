"""
Assignment 11 — Rate Limiter Plugin

WHAT: Implements a sliding-window rate limiter that tracks requests per user.
      When a user exceeds max_requests within window_seconds, their requests
      are blocked until the oldest request expires from the window.

WHY:  Rate limiting is the FIRST line of defense in a production AI pipeline.
      Without it, an attacker can brute-force prompt injection attempts at high
      speed, overwhelming the system and increasing API costs. It also prevents
      denial-of-service where a single user monopolizes LLM compute.
      This layer catches attacks that other layers miss: even if every individual
      request passes content filters, 100 requests/second is still an attack.

DESIGN: Uses collections.deque per user as a sliding window. Each request
        timestamp is appended; expired timestamps are pruned from the front.
        This gives O(1) amortized insert and O(k) prune where k = expired entries.
"""

from collections import defaultdict, deque
import time

from google.genai import types
from google.adk.plugins import base_plugin
from google.adk.agents.invocation_context import InvocationContext


class RateLimitPlugin(base_plugin.BasePlugin):
    """Sliding-window rate limiter plugin for Google ADK.

    Blocks users who send too many requests within a time window.
    This is essential for preventing brute-force attacks and API abuse.

    Args:
        max_requests: Maximum number of requests allowed per window (default: 10)
        window_seconds: Size of the sliding window in seconds (default: 60)
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Per-user sliding window: user_id -> deque of timestamps
        self.user_windows: dict[str, deque] = defaultdict(deque)
        # Metrics for monitoring
        self.total_requests = 0
        self.blocked_requests = 0

    def _clean_window(self, window: deque, now: float) -> None:
        """Remove expired timestamps from the front of the deque.

        Args:
            window: The user's request timestamp deque
            now: Current timestamp
        """
        cutoff = now - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: types.Content,
    ) -> types.Content | None:
        """Check if the user has exceeded their rate limit.

        WHY: This runs BEFORE any other processing. If a user is sending
        too many requests, we reject immediately without wasting LLM tokens
        or running expensive guardrail checks.

        Returns:
            None if within rate limit (allow request),
            types.Content with block message if rate limit exceeded.
        """
        self.total_requests += 1

        # Extract user ID from invocation context, fallback to "anonymous"
        user_id = "anonymous"
        if invocation_context and hasattr(invocation_context, "user_id"):
            user_id = invocation_context.user_id or "anonymous"

        now = time.time()
        window = self.user_windows[user_id]

        # Remove expired timestamps
        self._clean_window(window, now)

        # Check if user has exceeded the limit
        if len(window) >= self.max_requests:
            self.blocked_requests += 1
            # Calculate wait time until the oldest request expires
            wait_time = self.window_seconds - (now - window[0])
            return types.Content(
                role="model",
                parts=[types.Part.from_text(
                    text=f"[RATE LIMITED] Too many requests. "
                         f"Please wait {wait_time:.1f} seconds before trying again. "
                         f"(Limit: {self.max_requests} requests per {self.window_seconds}s)"
                )],
            )

        # Within limit — record this request and allow
        window.append(now)
        return None

    def get_metrics(self) -> dict:
        """Return current rate limiter metrics for monitoring.

        Returns:
            dict with total_requests, blocked_requests, block_rate
        """
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": (
                self.blocked_requests / self.total_requests
                if self.total_requests > 0
                else 0.0
            ),
        }
