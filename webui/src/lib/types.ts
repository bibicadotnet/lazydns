// Types for LazyDNS WebUI

export interface DashboardOverview {
    uptime_seconds: number;
    version: string;
    stats: QueryStats;
    upstream_summary: UpstreamSummary;
    recent_alerts: number;
}

export interface QueryStats {
    total_queries: number;
    qps_1min: number;
    qps_5min: number;
    cache_hit_rate: number;
    avg_response_time_ms: number;
}

export interface UpstreamSummary {
    total: number;
    healthy: number;
    degraded: number;
    down: number;
}

export interface CacheStats {
    size: number;
    hits: number;
    misses: number;
    evictions: number;
    expirations: number;
    hit_rate: number;
}

export interface ServerStats {
    version: string;
    uptime_seconds: number;
    uptime_human: string;
}

export interface QueryLogEntry {
    timestamp: string;
    query_id: number;
    client_ip: string | null;
    protocol: string;
    qname: string;
    qtype: string;
    qclass: string;
    rcode: string | null;
    answer_count: number | null;
    response_time_ms: number | null;
    cached: boolean | null;
    upstream: string | null;
    answers: string[] | null;
}

export interface SecurityEvent {
    timestamp: string;
    event_type: SecurityEventType;
    client_ip: string | null;
    domain: string | null;
    message: string;
    details: Record<string, unknown>;
}

export type SecurityEventType =
    | 'rate_limit_exceeded'
    | 'blocked_domain_query'
    | 'upstream_failure'
    | 'acl_denied'
    | 'malformed_query'
    | 'query_timeout';

export interface TopDomain {
    domain: string;
    count: number;
    percentage: number;
}

export interface TopClient {
    ip: string;
    queries: number;
    blocked: number;
    rate_limited: number;
    avg_response_ms: number;
}

export interface UpstreamHealth {
    name: string;
    address: string;
    status: 'healthy' | 'degraded' | 'down';
    success_rate: number;
    avg_latency_ms: number;
    total_requests: number;
    failed_requests: number;
    last_success_at: string | null;
    last_failure_at: string | null;
}

export interface Alert {
    id: string;
    severity: 'info' | 'warning' | 'critical';
    type: string;
    message: string;
    timestamp: string;
    details: Record<string, unknown>;
    acknowledged: boolean;
}

export interface TimeSeriesPoint {
    timestamp: string;
    value: number;
}

export interface LatencyDistribution {
    bucket: string;
    count: number;
    percentage: number;
}

export type TimeWindow = '1m' | '5m' | '1h' | '24h';
