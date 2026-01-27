// API client for LazyDNS WebUI

const API_BASE = '/api';

export interface DashboardOverviewResponse {
    status: string;
    uptime_secs: number;
    metrics: {
        total_queries: number;
        queries_per_second: number;
        cache_hit_rate: number;
        cache_hits: number;
        cache_misses: number;
        error_responses: number;
        blocked_queries: number;
        unique_domains: number;
        unique_clients: number;
    };
    recent_alerts: number;
    active_sse_connections: number;
}

export interface UpstreamHealthItem {
    address: string;
    tag: string | null;
    plugin?: string;
    status: string;
    success_rate: number;
    avg_response_time_ms: number;
    queries: number;
    successes: number;
    failures: number;
    last_success: string | null;
}

export interface UpstreamHealthResponse {
    upstreams: UpstreamHealthItem[];
}

export interface TopDomainsResponse {
    domains: Array<{
        rank: number;
        key: string;
        count: number;
    }>;
    total_unique: number;
}

export interface TopClientsResponse {
    clients: Array<{
        rank: number;
        key: string;
        count: number;
    }>;
    total_unique: number;
}

export interface QpsHistoryResponse {
    points: Array<{
        timestamp: string;
        value: number;
    }>;
    current_qps: number;
    stats: {
        min: number;
        max: number;
        avg: number;
        count: number;
    };
}

export interface LatencyResponse {
    distribution: {
        buckets: Array<{
            label: string;
            min_ms: number;
            max_ms: number | null;
            count: number;
        }>;
        total_samples: number;
        avg_latency_ms: number;
        p50_ms: number;
        p95_ms: number;
        p99_ms: number;
    };
}

class ApiClient {
    private baseUrl: string;

    constructor(baseUrl: string = API_BASE) {
        this.baseUrl = baseUrl;
    }

    private async fetch<T>(endpoint: string): Promise<T> {
        const response = await fetch(`${this.baseUrl}${endpoint}`);
        if (!response.ok) {
            throw new Error(`API error: ${response.status} ${response.statusText}`);
        }
        return response.json();
    }

    private async post<T>(endpoint: string, body?: unknown): Promise<T> {
        const response = await fetch(`${this.baseUrl}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: body ? JSON.stringify(body) : undefined,
        });
        if (!response.ok) {
            throw new Error(`API error: ${response.status} ${response.statusText}`);
        }
        return response.json();
    }

    // Dashboard
    async getDashboardOverview(): Promise<DashboardOverviewResponse> {
        return this.fetch<DashboardOverviewResponse>('/dashboard/overview');
    }

    async getRecentAlerts(): Promise<{ alerts: Alert[]; total: number }> {
        return this.fetch<{ alerts: Alert[]; total: number }>('/alerts/recent');
    }

    // Metrics
    async getUpstreamHealth(): Promise<UpstreamHealthResponse> {
        return this.fetch<UpstreamHealthResponse>('/metrics/upstream-health');
    }

    async getTopDomains(limit: number = 10): Promise<TopDomainsResponse> {
        return this.fetch<TopDomainsResponse>(`/metrics/top-domains?limit=${limit}`);
    }

    async getTopClients(limit: number = 10): Promise<TopClientsResponse> {
        return this.fetch<TopClientsResponse>(`/metrics/top-clients?limit=${limit}`);
    }

    async getQpsHistory(): Promise<QpsHistoryResponse> {
        return this.fetch<QpsHistoryResponse>('/metrics/qps');
    }

    async getLatencyDistribution(): Promise<LatencyResponse> {
        return this.fetch<LatencyResponse>('/metrics/latency');
    }

    // SSE endpoints for audit logs
    createQueryLogStream(): EventSource {
        return new EventSource(`${this.baseUrl}/audit/query-logs/stream`);
    }

    createSecurityEventsStream(): EventSource {
        return new EventSource(`${this.baseUrl}/audit/security-events/stream`);
    }

    // Deprecated - use specific stream methods
    createAlertsStream(): EventSource {
        return new EventSource(`${this.baseUrl}/stream/alerts`);
    }
}

// Types for alerts
export interface Alert {
    id: string;
    severity: 'info' | 'warning' | 'critical';
    type: string;
    message: string;
    timestamp: string;
    details: Record<string, unknown>;
    acknowledged: boolean;
}

// Types for query log entries (from SSE)
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

// Types for security events (from SSE)
export interface SecurityEvent {
    timestamp: string;
    event_type: string;
    client_ip: string | null;
    domain: string | null;
    message: string;
    details: Record<string, unknown>;
}

export const api = new ApiClient();
export default api;
