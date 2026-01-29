// Mock data for development and testing

import type {
    DashboardOverview,
    QueryLogEntry,
    SecurityEvent,
    TopDomain,
    TopClient,
    UpstreamHealth,
    Alert,
    CacheStats,
    TimeSeriesPoint,
    LatencyDistribution
} from './types';

// Dashboard Overview
export const mockDashboardOverview: DashboardOverview = {
    uptime_seconds: 86400 + 5 * 3600 + 32 * 60,
    version: '0.2.73',
    stats: {
        total_queries: 1234567,
        qps_1min: 245.3,
        qps_5min: 198.7,
        cache_hit_rate: 82.5,
        avg_response_time_ms: 12.3
    },
    upstream_summary: {
        total: 4,
        healthy: 3,
        degraded: 1,
        down: 0
    },
    recent_alerts: 5
};

// Cache Stats
export const mockCacheStats: CacheStats = {
    size: 12456,
    hits: 1024567,
    misses: 209876,
    evictions: 4532,
    expirations: 8976,
    hit_rate: 82.99
};

// QPS Time Series (last hour, 1-minute intervals)
export function generateQpsTimeSeries(points: number = 60): TimeSeriesPoint[] {
    const now = Date.now();
    const data: TimeSeriesPoint[] = [];
    let baseQps = 200;

    for (let i = points - 1; i >= 0; i--) {
        const timestamp = new Date(now - i * 60000).toISOString();
        // Add some realistic variation
        const variation = Math.sin(i / 10) * 50 + Math.random() * 30 - 15;
        const value = Math.max(0, baseQps + variation);
        data.push({ timestamp, value: Math.round(value * 10) / 10 });
        baseQps += (Math.random() - 0.5) * 10;
    }

    return data;
}

// Latency Distribution
export const mockLatencyDistribution: LatencyDistribution[] = [
    { bucket: '0-5ms', count: 45678, percentage: 37.0 },
    { bucket: '5-10ms', count: 34567, percentage: 28.0 },
    { bucket: '10-20ms', count: 24567, percentage: 19.9 },
    { bucket: '20-50ms', count: 12345, percentage: 10.0 },
    { bucket: '50-100ms', count: 4567, percentage: 3.7 },
    { bucket: '100-200ms', count: 1234, percentage: 1.0 },
    { bucket: '>200ms', count: 456, percentage: 0.4 }
];

// Query Logs
export function generateQueryLogs(count: number = 100): QueryLogEntry[] {
    const domains = [
        'www.google.com',
        'api.github.com',
        'cdn.jsdelivr.net',
        'fonts.googleapis.com',
        'www.youtube.com',
        'api.twitter.com',
        'graph.facebook.com',
        'aws.amazon.com',
        'storage.googleapis.com',
        'cdn.cloudflare.com',
        'ad.doubleclick.net',
        'tracking.example.com',
        'analytics.google.com',
        'api.openai.com',
        'registry.npmjs.org'
    ];

    const protocols = ['udp', 'tcp', 'tls', 'doh', 'doq'];
    const qtypes = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA', 'PTR'];
    const rcodes = ['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED'];
    const upstreams = ['cloudflare', 'google', 'quad9', 'opendns'];
    const clientIps = [
        '192.168.1.100',
        '192.168.1.105',
        '192.168.1.200',
        '10.0.0.50',
        '10.0.0.51',
        '172.16.0.100'
    ];

    const logs: QueryLogEntry[] = [];
    const now = Date.now();

    for (let i = 0; i < count; i++) {
        const isBlocked = Math.random() < 0.05;
        const isCached = !isBlocked && Math.random() < 0.7;
        const domain = domains[Math.floor(Math.random() * domains.length)];

        logs.push({
            timestamp: new Date(now - i * 1000 - Math.random() * 500).toISOString(),
            query_id: 10000 + Math.floor(Math.random() * 50000),
            client_ip: clientIps[Math.floor(Math.random() * clientIps.length)],
            protocol: protocols[Math.floor(Math.random() * protocols.length)],
            qname: domain,
            qtype: qtypes[Math.floor(Math.random() * qtypes.length)],
            qclass: 'IN',
            rcode: isBlocked ? 'REFUSED' : rcodes[Math.floor(Math.random() * rcodes.length)],
            answer_count: isBlocked ? 0 : Math.floor(Math.random() * 5) + 1,
            response_time_ms: Math.round(Math.random() * 50 + 5),
            cached: isCached,
            upstream: isCached ? null : upstreams[Math.floor(Math.random() * upstreams.length)],
            answers: isBlocked ? null : ['1.2.3.4', '5.6.7.8'].slice(0, Math.floor(Math.random() * 2) + 1)
        });
    }

    return logs;
}

// Security Events
export function generateSecurityEvents(count: number = 50): SecurityEvent[] {
    const eventTypes: Array<{ type: SecurityEvent['event_type']; message: string }> = [
        { type: 'rate_limit_exceeded', message: 'Client exceeded query rate limit' },
        { type: 'blocked_domain_query', message: 'Query for blocked domain' },
        { type: 'upstream_failure', message: 'Upstream DNS server returned error' },
        { type: 'acl_denied', message: 'Query denied by access control list' },
        { type: 'malformed_query', message: 'Received malformed DNS query' },
        { type: 'query_timeout', message: 'Query timed out waiting for response' }
    ];

    const domains = ['ad.doubleclick.net', 'tracker.example.com', 'malware.bad.com', 'phishing.evil.net'];
    const clientIps = ['192.168.1.100', '10.0.0.50', '172.16.0.100', '192.168.1.200'];

    const events: SecurityEvent[] = [];
    const now = Date.now();

    for (let i = 0; i < count; i++) {
        const eventInfo = eventTypes[Math.floor(Math.random() * eventTypes.length)];

        events.push({
            timestamp: new Date(now - i * 5000 - Math.random() * 2000).toISOString(),
            event_type: eventInfo.type,
            client_ip: clientIps[Math.floor(Math.random() * clientIps.length)],
            domain: domains[Math.floor(Math.random() * domains.length)],
            message: eventInfo.message,
            details: {
                reason: 'Policy violation',
                rule: 'block-ads'
            }
        });
    }

    return events;
}

// Top Domains
export const mockTopDomains: TopDomain[] = [
    { domain: 'www.google.com', count: 15678, percentage: 12.7 },
    { domain: 'api.github.com', count: 12456, percentage: 10.1 },
    { domain: 'cdn.jsdelivr.net', count: 9876, percentage: 8.0 },
    { domain: 'fonts.googleapis.com', count: 8765, percentage: 7.1 },
    { domain: 'www.youtube.com', count: 7654, percentage: 6.2 },
    { domain: 'api.twitter.com', count: 6543, percentage: 5.3 },
    { domain: 'graph.facebook.com', count: 5432, percentage: 4.4 },
    { domain: 'aws.amazon.com', count: 4321, percentage: 3.5 },
    { domain: 'storage.googleapis.com', count: 3210, percentage: 2.6 },
    { domain: 'cdn.cloudflare.com', count: 2345, percentage: 1.9 }
];

// Top Clients
export const mockTopClients: TopClient[] = [
    { ip: '192.168.1.100', queries: 23456, blocked: 123, rate_limited: 5, avg_response_ms: 8.2 },
    { ip: '192.168.1.105', queries: 18765, blocked: 89, rate_limited: 2, avg_response_ms: 10.5 },
    { ip: '10.0.0.50', queries: 15432, blocked: 234, rate_limited: 12, avg_response_ms: 12.3 },
    { ip: '172.16.0.100', queries: 12345, blocked: 56, rate_limited: 0, avg_response_ms: 9.1 },
    { ip: '192.168.1.200', queries: 9876, blocked: 178, rate_limited: 8, avg_response_ms: 11.7 },
    { ip: '10.0.0.51', queries: 7654, blocked: 34, rate_limited: 1, avg_response_ms: 7.8 },
    { ip: '192.168.2.50', queries: 5432, blocked: 12, rate_limited: 0, avg_response_ms: 14.2 },
    { ip: '172.16.0.200', queries: 4321, blocked: 67, rate_limited: 3, avg_response_ms: 10.0 }
];

// Upstream Health
export const mockUpstreamHealth: UpstreamHealth[] = [
    {
        name: 'cloudflare',
        address: '1.1.1.1:53',
        status: 'healthy',
        success_rate: 99.8,
        avg_latency_ms: 15.2,
        total_requests: 45678,
        failed_requests: 91,
        last_success_at: new Date(Date.now() - 2000).toISOString(),
        last_failure_at: new Date(Date.now() - 3600000).toISOString()
    },
    {
        name: 'google',
        address: '8.8.8.8:53',
        status: 'healthy',
        success_rate: 99.5,
        avg_latency_ms: 23.1,
        total_requests: 34567,
        failed_requests: 172,
        last_success_at: new Date(Date.now() - 3000).toISOString(),
        last_failure_at: new Date(Date.now() - 7200000).toISOString()
    },
    {
        name: 'quad9',
        address: '9.9.9.9:53',
        status: 'degraded',
        success_rate: 95.2,
        avg_latency_ms: 125.8,
        total_requests: 23456,
        failed_requests: 1126,
        last_success_at: new Date(Date.now() - 5000).toISOString(),
        last_failure_at: new Date(Date.now() - 60000).toISOString()
    },
    {
        name: 'opendns',
        address: '208.67.222.222:53',
        status: 'healthy',
        success_rate: 99.1,
        avg_latency_ms: 35.6,
        total_requests: 12345,
        failed_requests: 111,
        last_success_at: new Date(Date.now() - 4000).toISOString(),
        last_failure_at: new Date(Date.now() - 1800000).toISOString()
    }
];

// Alerts
export const mockAlerts: Alert[] = [
    {
        id: 'alert-001',
        severity: 'warning',
        rule_name: 'upstream_high_latency',
        message: "Upstream 'quad9' response time > 100ms",
        timestamp: Math.floor((Date.now() - 300000) / 1000),
        context: { upstream: 'quad9', latency_ms: 125 },
        acknowledged: false
    },
    {
        id: 'alert-002',
        severity: 'info',
        rule_name: 'cache_cleared',
        message: 'Cache was manually cleared by admin',
        timestamp: Math.floor((Date.now() - 900000) / 1000),
        context: { cleared_entries: 12456 },
        acknowledged: true
    },
    {
        id: 'alert-003',
        severity: 'warning',
        rule_name: 'high_block_rate',
        message: 'Block rate exceeded 15% in last 5 minutes',
        timestamp: Math.floor((Date.now() - 1200000) / 1000),
        context: { block_rate: 17.5, threshold: 15 },
        acknowledged: false
    },
    {
        id: 'alert-004',
        severity: 'critical',
        rule_name: 'upstream_down',
        message: "Upstream 'backup-dns' is unreachable",
        timestamp: Math.floor((Date.now() - 1800000) / 1000),
        context: { upstream: 'backup-dns', consecutive_failures: 10 },
        acknowledged: true
    },
    {
        id: 'alert-005',
        severity: 'info',
        rule_name: 'config_reloaded',
        message: 'Configuration reloaded successfully',
        timestamp: Math.floor((Date.now() - 3600000) / 1000),
        context: { path: '/etc/lazydns/config.yaml' },
        acknowledged: true
    }
];

// Helper to format uptime
export function formatUptime(seconds: number): string {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;

    const parts: string[] = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);

    return parts.join(' ');
}

// Helper to format numbers with K/M suffix
export function formatNumber(num: number): string {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    }
    if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

// Helper to format time ago
export function formatTimeAgo(isoString: string): string {
    const now = Date.now();
    const then = new Date(isoString).getTime();
    const diff = Math.floor((now - then) / 1000);

    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

// Helper to get status color class
export function getStatusColor(status: 'healthy' | 'degraded' | 'down'): string {
    switch (status) {
        case 'healthy': return 'text-green-400';
        case 'degraded': return 'text-yellow-400';
        case 'down': return 'text-red-400';
    }
}

// Helper to get severity color class
export function getSeverityColor(severity: 'info' | 'warning' | 'critical'): string {
    switch (severity) {
        case 'info': return 'text-blue-400';
        case 'warning': return 'text-yellow-400';
        case 'critical': return 'text-red-400';
    }
}

export function getSeverityBgColor(severity: 'info' | 'warning' | 'critical'): string {
    switch (severity) {
        case 'info': return 'bg-blue-900/30 border-blue-700';
        case 'warning': return 'bg-yellow-900/30 border-yellow-700';
        case 'critical': return 'bg-red-900/30 border-red-700';
    }
}
