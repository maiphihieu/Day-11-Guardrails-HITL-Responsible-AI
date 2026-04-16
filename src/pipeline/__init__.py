"""
Assignment 11 — Defense-in-Depth Pipeline Components

This package contains the production pipeline components:
- RateLimitPlugin: Sliding window per-user rate limiting
- LlmJudgePlugin: Multi-criteria response evaluation
- AuditLogPlugin: Interaction logging with JSON export
- MonitoringAlert: Metrics tracking and threshold alerts
- LanguageDetectionLayer: Block unsupported languages (bonus)
"""

from pipeline.rate_limiter import RateLimitPlugin
from pipeline.llm_judge import LlmJudgePlugin
from pipeline.audit_log import AuditLogPlugin
from pipeline.monitoring import MonitoringAlert
from pipeline.bonus_language_detection import LanguageDetectionPlugin
