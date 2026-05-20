#!/usr/bin/env python3
"""Generate grafana/dashboards/sniproxy-overview.json"""
import json
from pathlib import Path

DS = {"type": "prometheus", "uid": "${datasource}"}
F = 'job=~"$job", environment=~"$environment", instance=~"$instance"'
FV = F + ', domain=~"$domain"'


def prom(expr, legend=None, instant=False, ref="A"):
    t = {
        "datasource": DS,
        "editorMode": "code",
        "expr": expr,
        "range": not instant,
        "instant": instant,
        "refId": ref,
    }
    if legend:
        t["legendFormat"] = legend
    return t


def stat_panel(pid, title, expr, x, y, w, h, unit="short", thresholds=None):
    field = {"unit": unit}
    if thresholds:
        field["thresholds"] = thresholds
    return {
        "id": pid,
        "type": "stat",
        "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": DS,
        "targets": [prom(expr)],
        "options": {
            "colorMode": "value",
            "graphMode": "area",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
        },
        "fieldConfig": {"defaults": field, "overrides": []},
    }


def timeseries(pid, title, series, x, y, w, h, unit="short", stacking=None):
    defaults = {
        "unit": unit,
        "custom": {
            "drawStyle": "line",
            "lineWidth": 1,
            "fillOpacity": 15,
            "showPoints": "never",
            "stacking": {"mode": stacking or "none", "group": "A"},
        },
    }
    targets = []
    for i, (expr, leg) in enumerate(series):
        targets.append(prom(expr, leg, ref=chr(65 + i)))
    return {
        "id": pid,
        "type": "timeseries",
        "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": DS,
        "targets": targets,
        "options": {
            "legend": {"displayMode": "table", "placement": "bottom", "calcs": ["mean", "max", "last"]},
            "tooltip": {"mode": "multi"},
        },
        "fieldConfig": {"defaults": defaults, "overrides": []},
    }


def table_panel(pid, title, expr, x, y, w, h):
    return {
        "id": pid,
        "type": "table",
        "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": DS,
        "targets": [prom(expr, instant=True)],
        "options": {"showHeader": True},
        "fieldConfig": {"defaults": {"custom": {"align": "auto"}}, "overrides": []},
        "transformations": [
            {"id": "sortBy", "options": {"sort": [{"desc": True, "field": "Value"}]}}
        ],
    }


def row_panel(pid, title, y):
    return {
        "id": pid,
        "type": "row",
        "title": title,
        "gridPos": {"x": 0, "y": y, "w": 24, "h": 1},
        "collapsed": False,
    }


def stat_panel_range(pid, title, expr, x, y, w, h, unit="short"):
    """Single-value stats for the dashboard time picker (Grafana $__range)."""
    return {
        "id": pid,
        "type": "stat",
        "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": DS,
        "targets": [prom(expr, instant=True)],
        "options": {
            "colorMode": "value",
            "graphMode": "none",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
        },
        "fieldConfig": {"defaults": {"unit": unit}, "overrides": []},
        "description": "Totals for the dashboard time range and Domain variable. Uses increase() over $__range with domain=~\"$domain\" (All → .*).",
    }


def main():
    p = []
    y = 0

    p.append(row_panel(98, "Selected time range (totals)", y))
    y += 1
    p += [
        stat_panel_range(
            96,
            "Total data transferred",
            "sum(increase(sniproxy_bytes_proxied_by_target_total{%s}[$__range]))" % FV,
            0,
            y,
            6,
            4,
            unit="bytes",
        ),
        stat_panel_range(
            95,
            "Upload (client → upstream)",
            (
                'sum(increase(sniproxy_bytes_proxied_by_target_total{%s,direction="client_to_upstream"}[$__range]))'
                % FV
            ),
            6,
            y,
            6,
            4,
            unit="bytes",
        ),
        stat_panel_range(
            94,
            "Download (upstream → client)",
            (
                'sum(increase(sniproxy_bytes_proxied_by_target_total{%s,direction="upstream_to_client"}[$__range]))'
                % FV
            ),
            12,
            y,
            6,
            4,
            unit="bytes",
        ),
        stat_panel_range(
            93,
            "Sessions opened (requests)",
            "sum(increase(sniproxy_connections_by_target_total{%s}[$__range]))" % FV,
            18,
            y,
            6,
            4,
            unit="short",
        ),
    ]
    y += 4

    p.append(row_panel(100, "Overview", y))
    y += 1
    p += [
        stat_panel(
            1,
            "Target Up",
            "up{%s}" % F,
            0,
            y,
            4,
            4,
            unit="none",
            thresholds={
                "mode": "absolute",
                "steps": [
                    {"color": "red", "value": None},
                    {"color": "green", "value": 1},
                ],
            },
        ),
        stat_panel(2, "Active Connections", "sniproxy_active_connections{%s}" % F, 4, y, 4, 4),
        stat_panel(
            3,
            "Accepted / sec",
            "sum(rate(sniproxy_accepted_connections_total{%s}[5m]))" % F,
            8,
            y,
            4,
            4,
            unit="reqps",
        ),
        stat_panel(
            4,
            "Sessions Opened / sec",
            "rate(sniproxy_connections_total{%s}[5m])" % F,
            12,
            y,
            4,
            4,
            unit="reqps",
        ),
        stat_panel(
            5,
            "Errors / sec",
            "rate(sniproxy_connection_errors_total{%s}[5m])" % F,
            16,
            y,
            4,
            4,
            unit="reqps",
        ),
        stat_panel(
            6,
            "Error Rate %",
            (
                "100 * rate(sniproxy_connection_errors_total{%s}[5m]) "
                "/ clamp_min(sum(rate(sniproxy_accepted_connections_total{%s}[5m])), 1e-9)"
            )
            % (F, F),
            20,
            y,
            4,
            4,
            unit="percent",
        ),
    ]
    y += 4
    p += [
        stat_panel(
            7,
            "Throughput (Total)",
            "sum(rate(sniproxy_bytes_proxied_total{%s}[5m])) * 8" % F,
            0,
            y,
            6,
            4,
            unit="bps",
        ),
        stat_panel(
            8,
            "Upload (Client → Upstream)",
            (
                'sum(rate(sniproxy_bytes_proxied_by_target_total{%s,direction="client_to_upstream"}[5m])) * 8'
                % F
            ),
            6,
            y,
            6,
            4,
            unit="bps",
        ),
        stat_panel(
            9,
            "Download (Upstream → Client)",
            (
                'sum(rate(sniproxy_bytes_proxied_by_target_total{%s,direction="upstream_to_client"}[5m])) * 8'
                % F
            ),
            12,
            y,
            6,
            4,
            unit="bps",
        ),
        stat_panel(
            10,
            "Total Sessions (counter)",
            "sniproxy_connections_total{%s}" % F,
            18,
            y,
            6,
            4,
        ),
    ]
    y += 4

    p.append(row_panel(101, "Traffic & Bandwidth", y))
    y += 1
    p += [
        timeseries(
            11,
            "Throughput by Direction",
            [
                (
                    'sum(rate(sniproxy_bytes_proxied_by_target_total{%s,direction="client_to_upstream"}[5m])) * 8'
                    % F,
                    "Upload",
                ),
                (
                    'sum(rate(sniproxy_bytes_proxied_by_target_total{%s,direction="upstream_to_client"}[5m])) * 8'
                    % F,
                    "Download",
                ),
                ("sum(rate(sniproxy_bytes_proxied_total{%s}[5m])) * 8" % F, "Total"),
            ],
            0,
            y,
            12,
            8,
            unit="bps",
        ),
        timeseries(
            12,
            "Top Domains — Bandwidth (top 10)",
            [
                (
                    "topk(10, sum by (domain) (rate(sniproxy_bytes_proxied_by_target_total{%s}[5m])) * 8)"
                    % F,
                    "{{domain}}",
                ),
            ],
            12,
            y,
            12,
            8,
            unit="bps",
        ),
    ]
    y += 8
    p.append(
        timeseries(
            13,
            "Bandwidth by Domain (filtered)",
            [
                (
                    "sum by (domain) (rate(sniproxy_bytes_proxied_by_target_total{%s}[5m])) * 8" % FV,
                    "{{domain}}",
                ),
            ],
            0,
            y,
            24,
            8,
            unit="bps",
            stacking="normal",
        )
    )
    y += 8

    p.append(row_panel(102, "Connections", y))
    y += 1
    p += [
        timeseries(
            14,
            "Active Connections",
            [
                ("sniproxy_active_connections{%s}" % F, "Total"),
                (
                    "sum by (domain) (sniproxy_active_connections_by_target{%s})" % FV,
                    "{{domain}}",
                ),
            ],
            0,
            y,
            12,
            8,
        ),
        timeseries(
            15,
            "Connection Rates",
            [
                ("sum(rate(sniproxy_accepted_connections_total{%s}[5m]))" % F, "Accepted"),
                ("rate(sniproxy_connections_total{%s}[5m])" % F, "Opened (success)"),
                ("rate(sniproxy_connection_errors_total{%s}[5m])" % F, "Failed"),
            ],
            12,
            y,
            12,
            8,
            unit="reqps",
        ),
    ]
    y += 8
    p += [
        timeseries(
            16,
            "Sessions / sec by Domain (top 10)",
            [
                (
                    "topk(10, sum by (domain) (rate(sniproxy_connections_by_target_total{%s}[5m])))"
                    % F,
                    "{{domain}}",
                ),
            ],
            0,
            y,
            12,
            8,
            unit="reqps",
        ),
        timeseries(
            17,
            "Active by Upstream (top 10)",
            [
                (
                    "topk(10, sum by (upstream) (sniproxy_active_connections_by_target{%s}))"
                    % F,
                    "{{upstream}}",
                ),
            ],
            12,
            y,
            12,
            8,
        ),
    ]
    y += 8

    p.append(row_panel(103, "Errors & Reliability", y))
    y += 1
    p += [
        timeseries(
            18,
            "Error Rate %",
            [
                (
                    (
                        "100 * rate(sniproxy_connection_errors_total{%s}[5m]) "
                        "/ clamp_min(sum(rate(sniproxy_accepted_connections_total{%s}[5m])), 1e-9)"
                    )
                    % (F, F),
                    "Error %",
                ),
            ],
            0,
            y,
            12,
            8,
            unit="percent",
        ),
        timeseries(
            19,
            "Errors / sec by Domain (top 10)",
            [
                (
                    "topk(10, sum by (domain) (rate(sniproxy_connection_errors_by_target_total{%s}[5m])))"
                    % F,
                    "{{domain}}",
                ),
            ],
            12,
            y,
            12,
            8,
            unit="reqps",
        ),
    ]
    y += 8
    p += [
        table_panel(
            20,
            "Errors by Domain",
            "topk(20, sum by (domain) (rate(sniproxy_connection_errors_by_target_total{%s}[5m])))"
            % F,
            0,
            y,
            12,
            8,
        ),
        table_panel(
            21,
            "Errors by Client IP",
            "topk(20, sum by (client_ip) (rate(sniproxy_connection_errors_by_target_total{%s}[5m])))"
            % F,
            12,
            y,
            12,
            8,
        ),
    ]
    y += 8

    p.append(row_panel(104, "Top Talkers", y))
    y += 1
    p += [
        table_panel(
            22,
            "Top Domains — Sessions / sec",
            "topk(15, sum by (domain) (rate(sniproxy_connections_by_target_total{%s}[5m])))"
            % F,
            0,
            y,
            8,
            8,
        ),
        table_panel(
            23,
            "Top Client IPs — Accepted / sec",
            "topk(15, sum by (client_ip) (rate(sniproxy_accepted_connections_total{%s}[5m])))"
            % F,
            8,
            y,
            8,
            8,
        ),
        table_panel(
            24,
            "Top Domains — Bandwidth (bps)",
            "topk(15, sum by (domain) (rate(sniproxy_bytes_proxied_by_target_total{%s}[5m])) * 8)"
            % F,
            16,
            y,
            8,
            8,
        ),
    ]
    y += 8

    p.append(row_panel(105, "Domain Drill-down", y))
    y += 1
    p += [
        stat_panel(
            25,
            "Active (selected domains)",
            "sum(sniproxy_active_connections_by_target{%s})" % FV,
            0,
            y,
            4,
            4,
        ),
        stat_panel(
            26,
            "Sessions / sec",
            "sum(rate(sniproxy_connections_by_target_total{%s}[5m]))" % FV,
            4,
            y,
            4,
            4,
            unit="reqps",
        ),
        stat_panel(
            27,
            "Errors / sec",
            "sum(rate(sniproxy_connection_errors_by_target_total{%s}[5m]))" % FV,
            8,
            y,
            4,
            4,
            unit="reqps",
        ),
        stat_panel(
            28,
            "Bandwidth",
            "sum(rate(sniproxy_bytes_proxied_by_target_total{%s}[5m])) * 8" % FV,
            12,
            y,
            6,
            4,
            unit="bps",
        ),
    ]
    y += 4
    p += [
        timeseries(
            29,
            "Selected Domains: Upload vs Download",
            [
                (
                    'sum(rate(sniproxy_bytes_proxied_by_target_total{%s,direction="client_to_upstream"}[5m])) * 8'
                    % FV,
                    "Upload",
                ),
                (
                    'sum(rate(sniproxy_bytes_proxied_by_target_total{%s,direction="upstream_to_client"}[5m])) * 8'
                    % FV,
                    "Download",
                ),
            ],
            0,
            y,
            12,
            8,
            unit="bps",
        ),
        timeseries(
            30,
            "Selected Domains: Top Client IPs",
            [
                (
                    "topk(10, sum by (client_ip) (rate(sniproxy_connections_by_target_total{%s}[5m])))"
                    % FV,
                    "{{client_ip}}",
                ),
            ],
            12,
            y,
            12,
            8,
            unit="reqps",
        ),
    ]
    y += 8
    p.append(
        table_panel(
            31,
            "Selected Domains: Sessions / sec per Client IP",
            "sum by (client_ip) (rate(sniproxy_connections_by_target_total{%s}[5m]))" % FV,
            0,
            y,
            24,
            8,
        )
    )

    dashboard = {
        "annotations": {
            "list": [
                {
                    "builtIn": 1,
                    "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                    "enable": True,
                    "hide": True,
                    "name": "Annotations & Alerts",
                    "type": "dashboard",
                }
            ]
        },
        "editable": True,
        "graphTooltip": 1,
        "panels": p,
        "refresh": "30s",
        "schemaVersion": 39,
        "tags": ["sniproxy", "pingora-sniproxy", "proxy", "sni", "l4"],
        "templating": {
            "list": [
                {
                    "name": "datasource",
                    "type": "datasource",
                    "label": "Datasource",
                    "query": "prometheus",
                    "refresh": 1,
                },
                {
                    "name": "job",
                    "type": "query",
                    "label": "Job",
                    "datasource": DS,
                    "query": {
                        "query": "label_values(sniproxy_active_connections, job)",
                        "refId": "A",
                    },
                    "current": {"text": "sniproxy", "value": "sniproxy"},
                    "refresh": 2,
                    "sort": 1,
                },
                {
                    "name": "environment",
                    "type": "query",
                    "label": "Environment",
                    "datasource": DS,
                    "query": {
                        "query": 'label_values(sniproxy_active_connections{job=~"$job"}, environment)',
                        "refId": "A",
                    },
                    "includeAll": True,
                    "allValue": ".*",
                    "current": {"text": "production", "value": "production"},
                    "refresh": 2,
                    "sort": 1,
                },
                {
                    "name": "instance",
                    "type": "query",
                    "label": "Instance",
                    "datasource": DS,
                    "query": {
                        "query": 'label_values(sniproxy_active_connections{job=~"$job", environment=~"$environment"}, instance)',
                        "refId": "A",
                    },
                    "includeAll": True,
                    "allValue": ".*",
                    "multi": True,
                    "refresh": 2,
                    "sort": 1,
                },
                {
                    "name": "domain",
                    "type": "query",
                    "label": "Domain",
                    "datasource": DS,
                    "query": {
                        "query": 'label_values(sniproxy_connections_by_target_total{job=~"$job", environment=~"$environment", instance=~"$instance"}, domain)',
                        "refId": "A",
                    },
                    "includeAll": True,
                    "allValue": ".*",
                    "multi": True,
                    "refresh": 2,
                    "sort": 1,
                },
            ]
        },
        "time": {"from": "now-6h", "to": "now"},
        "timepicker": {"refresh_intervals": ["5s", "10s", "30s", "1m", "5m"]},
        "timezone": "browser",
        "title": "SNI Proxy — pingora-sniproxy",
        "uid": "sniproxy-overview",
        "version": 1,
        "description": "Production dashboard for pingora-sniproxy (Prometheus job: sniproxy).",
    }

    out = Path(__file__).parent / "dashboards" / "sniproxy-overview.json"
    out.write_text(json.dumps(dashboard, indent=2))
    print("Wrote", out, "panels:", len(p))


if __name__ == "__main__":
    main()
