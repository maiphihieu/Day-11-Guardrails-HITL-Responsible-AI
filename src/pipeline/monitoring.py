"""
Assignment 11 — Monitoring & Alerts

WHAT: Tracks real-time metrics from all pipeline components and fires
      alerts when security thresholds are exceeded. Monitored metrics:
      - Block rate (% of requests blocked by any layer)
      - Rate limit hit rate (% of requests hitting rate limiter)
      - Judge fail rate (% of responses failing LLM-as-Judge)
      - Average latency

WHY:  In production, guardrails can degrade silently. A regex pattern
      might stop matching after a model update; the LLM judge might
      start hallucinating PASS verdicts. Monitoring catches these
      SYSTEMIC failures that individual request-level checks miss.

      Alert scenarios:
      - Block rate > 50%: Possible false positive storm → check guardrails
      - Block rate < 5% under attack: Guardrails may be failing → investigate
      - Judge fail rate > 30%: LLM judge may be too strict or broken
      - Rate limit hits > 20%: Possible DDoS or bot attack

DESIGN: MonitoringAlert collects metrics from all plugins and checks
        against configurable thresholds. It does NOT block any requests —
        it only ALERTS operators when something is wrong.
"""


class MonitoringAlert:
    """Real-time monitoring and alerting for the defense pipeline.

    WHY this exists as a separate component (not inside a plugin):
    - Plugins only see their own data
    - MonitoringAlert has a GLOBAL view across ALL plugins
    - It can detect cross-layer anomalies (e.g., rate limiter not blocking
      but judge failing everything → suggests a new attack pattern)

    Args:
        plugins: List of pipeline plugins to monitor
        alert_thresholds: Custom thresholds for alerts
    """

    # Default alert thresholds
    DEFAULT_THRESHOLDS = {
        "block_rate_high": 0.50,      # > 50% blocked → false positive storm?
        "block_rate_low": 0.05,       # < 5% blocked under attack → guardrails failing?
        "rate_limit_rate": 0.20,      # > 20% rate limited → DDoS?
        "judge_fail_rate": 0.30,      # > 30% judge fails → judge too strict?
        "avg_latency_ms": 5000,       # > 5s average → performance issue?
    }

    def __init__(self, plugins: list = None, alert_thresholds: dict = None):
        self.plugins = plugins or []
        self.thresholds = {**self.DEFAULT_THRESHOLDS, **(alert_thresholds or {})}
        self.alerts = []

    def _get_plugin_by_name(self, name: str):
        """Find a plugin by its name.

        Args:
            name: Plugin name to search for

        Returns:
            Plugin instance or None
        """
        for plugin in self.plugins:
            if hasattr(plugin, "name") and plugin.name == name:
                return plugin
        return None

    def collect_metrics(self) -> dict:
        """Collect metrics from all plugins.

        WHY: Centralizes metric collection so monitoring logic doesn't
        need to know the internal structure of each plugin.

        Returns:
            dict with metrics from each plugin
        """
        metrics = {}

        # Rate limiter metrics
        rate_limiter = self._get_plugin_by_name("rate_limiter")
        if rate_limiter and hasattr(rate_limiter, "get_metrics"):
            metrics["rate_limiter"] = rate_limiter.get_metrics()

        # Input guardrail metrics
        input_guard = self._get_plugin_by_name("input_guardrail")
        if input_guard:
            metrics["input_guardrail"] = {
                "total": getattr(input_guard, "total_count", 0),
                "blocked": getattr(input_guard, "blocked_count", 0),
                "block_rate": (
                    input_guard.blocked_count / input_guard.total_count
                    if getattr(input_guard, "total_count", 0) > 0
                    else 0.0
                ),
            }

        # Output guardrail metrics
        output_guard = self._get_plugin_by_name("output_guardrail")
        if output_guard:
            metrics["output_guardrail"] = {
                "total": getattr(output_guard, "total_count", 0),
                "blocked": getattr(output_guard, "blocked_count", 0),
                "redacted": getattr(output_guard, "redacted_count", 0),
            }

        # LLM Judge metrics
        llm_judge = self._get_plugin_by_name("llm_judge")
        if llm_judge and hasattr(llm_judge, "get_metrics"):
            metrics["llm_judge"] = llm_judge.get_metrics()

        # Audit log metrics
        audit_log = self._get_plugin_by_name("audit_log")
        if audit_log and hasattr(audit_log, "get_summary"):
            metrics["audit_log"] = audit_log.get_summary()

        # Language detection metrics
        lang_detect = self._get_plugin_by_name("language_detection")
        if lang_detect and hasattr(lang_detect, "get_metrics"):
            metrics["language_detection"] = lang_detect.get_metrics()

        return metrics

    def check_metrics(self) -> list:
        """Check all metrics against thresholds and generate alerts.

        WHY: This is the core monitoring logic. It compares current metrics
        against thresholds and generates human-readable alerts.

        Returns:
            List of alert dicts with level (WARNING/CRITICAL), message, metric_value
        """
        metrics = self.collect_metrics()
        new_alerts = []

        # Check rate limiter
        rl = metrics.get("rate_limiter", {})
        if rl.get("block_rate", 0) > self.thresholds["rate_limit_rate"]:
            new_alerts.append({
                "level": "WARNING",
                "component": "rate_limiter",
                "message": f"High rate limit hit rate: {rl['block_rate']:.1%} "
                           f"(threshold: {self.thresholds['rate_limit_rate']:.1%})",
                "metric_value": rl["block_rate"],
            })

        # Check input guardrail block rate
        ig = metrics.get("input_guardrail", {})
        if ig.get("block_rate", 0) > self.thresholds["block_rate_high"]:
            new_alerts.append({
                "level": "WARNING",
                "component": "input_guardrail",
                "message": f"High block rate: {ig['block_rate']:.1%} — "
                           f"possible false positive storm",
                "metric_value": ig["block_rate"],
            })

        # Check LLM judge fail rate
        jd = metrics.get("llm_judge", {})
        if jd.get("fail_rate", 0) > self.thresholds["judge_fail_rate"]:
            new_alerts.append({
                "level": "CRITICAL",
                "component": "llm_judge",
                "message": f"High judge fail rate: {jd['fail_rate']:.1%} — "
                           f"judge may be too strict or model degraded",
                "metric_value": jd["fail_rate"],
            })

        # Check average latency
        al = metrics.get("audit_log", {})
        if al.get("avg_latency_ms", 0) > self.thresholds["avg_latency_ms"]:
            new_alerts.append({
                "level": "WARNING",
                "component": "pipeline",
                "message": f"High average latency: {al['avg_latency_ms']:.0f}ms "
                           f"(threshold: {self.thresholds['avg_latency_ms']}ms)",
                "metric_value": al["avg_latency_ms"],
            })

        self.alerts.extend(new_alerts)

        # Print alerts
        if new_alerts:
            print("\n" + "!" * 60)
            print("  MONITORING ALERTS")
            print("!" * 60)
            for alert in new_alerts:
                print(f"  [{alert['level']}] {alert['component']}: {alert['message']}")
            print("!" * 60)
        else:
            print("\n  [MONITORING] All metrics within normal thresholds. ✅")

        return new_alerts

    def print_dashboard(self):
        """Print a formatted monitoring dashboard.

        WHY: Provides a quick visual overview of the entire pipeline's health.
        In production, this would feed into Grafana/Datadog; here we use
        a formatted console output for the assignment.
        """
        metrics = self.collect_metrics()

        print("\n" + "=" * 70)
        print("  DEFENSE PIPELINE -- MONITORING DASHBOARD")
        print("=" * 70)

        # Rate Limiter
        rl = metrics.get("rate_limiter", {})
        print(f"\n  [RATE] Rate Limiter:")
        print(f"     Total requests:  {rl.get('total_requests', 0)}")
        print(f"     Blocked:         {rl.get('blocked_requests', 0)}")
        print(f"     Block rate:      {rl.get('block_rate', 0):.1%}")

        # Input Guardrail
        ig = metrics.get("input_guardrail", {})
        print(f"\n  [SHIELD] Input Guardrails:")
        print(f"     Total checked:   {ig.get('total', 0)}")
        print(f"     Blocked:         {ig.get('blocked', 0)}")
        print(f"     Block rate:      {ig.get('block_rate', 0):.1%}")

        # Output Guardrail
        og = metrics.get("output_guardrail", {})
        print(f"\n  [LOCK] Output Guardrails:")
        print(f"     Total checked:   {og.get('total', 0)}")
        print(f"     Blocked:         {og.get('blocked', 0)}")
        print(f"     Redacted:        {og.get('redacted', 0)}")

        # LLM Judge
        jd = metrics.get("llm_judge", {})
        print(f"\n  [JUDGE] LLM Judge:")
        print(f"     Total judged:    {jd.get('total_judged', 0)}")
        print(f"     Failed:          {jd.get('total_failed', 0)}")
        print(f"     Fail rate:       {jd.get('fail_rate', 0):.1%}")
        avg = jd.get("avg_scores", {})
        if avg:
            print(f"     Avg scores:      Safety={avg.get('safety', 0):.1f} "
                  f"Relevance={avg.get('relevance', 0):.1f} "
                  f"Accuracy={avg.get('accuracy', 0):.1f} "
                  f"Tone={avg.get('tone', 0):.1f}")

        # Language Detection
        ld = metrics.get("language_detection", {})
        if ld:
            print(f"\n  [LANG] Language Detection (Bonus):")
            print(f"     Total checked:   {ld.get('total_checked', 0)}")
            print(f"     Blocked:         {ld.get('blocked', 0)}")

        # Audit Log
        al = metrics.get("audit_log", {})
        print(f"\n  [LOG] Audit Log:")
        print(f"     Total entries:   {al.get('total_entries', 0)}")
        print(f"     Avg latency:     {al.get('avg_latency_ms', 0):.0f}ms")

        print("\n" + "=" * 70)
