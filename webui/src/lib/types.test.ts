// Unit tests for type definitions and utility functions

import { describe, it, expect } from 'vitest';

// Test type interfaces by creating valid objects
describe('DashboardOverview type', () => {
    it('should define valid dashboard overview structure', () => {
        const overview = {
            uptime_seconds: 3600,
            version: '1.0.0',
            stats: {
                total_queries: 1000,
                qps_1min: 15.5,
                qps_5min: 12.3,
                cache_hit_rate: 75.0,
                avg_response_time_ms: 5.2
            },
            upstream_summary: {
                total: 4,
                healthy: 3,
                degraded: 1,
                down: 0
            },
            recent_alerts: 2
        };

        expect(overview.uptime_seconds).toBe(3600);
        expect(overview.stats.total_queries).toBe(1000);
        expect(overview.upstream_summary.healthy).toBe(3);
    });
});

describe('QueryStats type', () => {
    it('should define valid query stats structure', () => {
        const stats = {
            total_queries: 50000,
            qps_1min: 25.5,
            qps_5min: 20.0,
            cache_hit_rate: 80.5,
            avg_response_time_ms: 3.2
        };

        expect(stats.total_queries).toBeGreaterThan(0);
        expect(stats.cache_hit_rate).toBeLessThanOrEqual(100);
        expect(stats.cache_hit_rate).toBeGreaterThanOrEqual(0);
    });
});

describe('CacheStats type', () => {
    it('should calculate hit rate correctly', () => {
        const stats = {
            size: 10000,
            hits: 7500,
            misses: 2500,
            evictions: 100,
            expirations: 50,
            hit_rate: 75.0
        };

        const calculatedRate = (stats.hits / (stats.hits + stats.misses)) * 100;
        expect(calculatedRate).toBe(stats.hit_rate);
    });
});

describe('QueryLogEntry type', () => {
    it('should define valid query log entry structure', () => {
        const entry = {
            timestamp: '2026-01-30T12:00:00Z',
            query_id: 12345,
            client_ip: '192.168.1.100',
            protocol: 'udp',
            qname: 'example.com',
            qtype: 'A',
            qclass: 'IN',
            rcode: 'NOERROR',
            answer_count: 1,
            response_time_ms: 5,
            cached: false,
            upstream: '8.8.8.8:53',
            answers: ['93.184.216.34']
        };

        expect(entry.qname).toBe('example.com');
        expect(entry.protocol).toMatch(/^(udp|tcp|doh|dot|doq)$/);
    });

    it('should handle nullable fields', () => {
        const entry = {
            timestamp: '2026-01-30T12:00:00Z',
            query_id: 12346,
            client_ip: null,
            protocol: 'tcp',
            qname: 'test.com',
            qtype: 'AAAA',
            qclass: 'IN',
            rcode: null,
            answer_count: null,
            response_time_ms: null,
            cached: null,
            upstream: null,
            answers: null
        };

        expect(entry.client_ip).toBeNull();
        expect(entry.rcode).toBeNull();
    });
});

describe('UpstreamSummary type', () => {
    it('should have consistent totals', () => {
        const summary = {
            total: 5,
            healthy: 3,
            degraded: 1,
            down: 1
        };

        expect(summary.healthy + summary.degraded + summary.down).toBe(summary.total);
    });
});

describe('TopDomain type', () => {
    it('should define valid top domain structure', () => {
        const domain = {
            domain: 'google.com',
            count: 500,
            percentage: 25.5
        };

        expect(domain.domain).toBeTruthy();
        expect(domain.count).toBeGreaterThanOrEqual(0);
        expect(domain.percentage).toBeGreaterThanOrEqual(0);
        expect(domain.percentage).toBeLessThanOrEqual(100);
    });
});

describe('LatencyDistribution type', () => {
    it('should define valid latency distribution structure', () => {
        const distribution = {
            buckets: [
                { label: '<1ms', count: 500, percentage: 50.0 },
                { label: '1-10ms', count: 300, percentage: 30.0 },
                { label: '10-50ms', count: 150, percentage: 15.0 },
                { label: '50-100ms', count: 40, percentage: 4.0 },
                { label: '100-500ms', count: 8, percentage: 0.8 },
                { label: '500ms-1s', count: 2, percentage: 0.2 },
                { label: '>1s', count: 0, percentage: 0.0 }
            ],
            p50_ms: 0.8,
            p95_ms: 25.0,
            p99_ms: 75.0,
            avg_ms: 5.5
        };

        expect(distribution.buckets).toHaveLength(7);
        
        const totalPercentage = distribution.buckets.reduce((sum, b) => sum + b.percentage, 0);
        expect(totalPercentage).toBeCloseTo(100, 1);
    });

    it('should have ordered percentiles', () => {
        const distribution = {
            p50_ms: 5.0,
            p95_ms: 25.0,
            p99_ms: 50.0
        };

        expect(distribution.p50_ms).toBeLessThanOrEqual(distribution.p95_ms);
        expect(distribution.p95_ms).toBeLessThanOrEqual(distribution.p99_ms);
    });
});

describe('UpstreamHealth type', () => {
    it('should define valid upstream health structure', () => {
        const health = {
            address: '8.8.8.8:53',
            tag: 'google-primary',
            status: 'healthy',
            success_rate: 99.5,
            avg_response_time_ms: 25.3,
            queries: 10000,
            successes: 9950,
            failures: 50,
            last_success: '2026-01-30T12:00:00Z'
        };

        expect(health.status).toMatch(/^(healthy|degraded|down|unknown)$/);
        expect(health.success_rate).toBeLessThanOrEqual(100);
        expect(health.successes + health.failures).toBe(health.queries);
    });
});

describe('Alert type', () => {
    it('should define valid alert structure', () => {
        const alert = {
            id: 'alert-123',
            level: 'warning',
            message: 'High error rate detected',
            timestamp: '2026-01-30T12:00:00Z',
            acknowledged: false
        };

        expect(alert.level).toMatch(/^(info|warning|error|critical)$/);
        expect(typeof alert.acknowledged).toBe('boolean');
    });
});

// Utility function tests
describe('Utility functions', () => {
    it('should format uptime correctly', () => {
        const formatUptime = (seconds: number): string => {
            const days = Math.floor(seconds / 86400);
            const hours = Math.floor((seconds % 86400) / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            
            if (days > 0) return `${days}d ${hours}h`;
            if (hours > 0) return `${hours}h ${minutes}m`;
            return `${minutes}m`;
        };

        expect(formatUptime(3600)).toBe('1h 0m');
        expect(formatUptime(90000)).toBe('1d 1h');
        expect(formatUptime(300)).toBe('5m');
    });

    it('should format numbers with K/M suffixes', () => {
        const formatNumber = (value: number): string => {
            if (value >= 1000000) return (value / 1000000).toFixed(1) + 'M';
            if (value >= 1000) return (value / 1000).toFixed(1) + 'K';
            return value.toString();
        };

        expect(formatNumber(500)).toBe('500');
        expect(formatNumber(1500)).toBe('1.5K');
        expect(formatNumber(1500000)).toBe('1.5M');
    });

    it('should format percentages correctly', () => {
        const formatPercent = (value: number): string => {
            return value.toFixed(1) + '%';
        };

        expect(formatPercent(75.5)).toBe('75.5%');
        expect(formatPercent(100)).toBe('100.0%');
        expect(formatPercent(0)).toBe('0.0%');
    });

    it('should format response times correctly', () => {
        const formatLatency = (ms: number): string => {
            if (ms < 1) return '<1ms';
            if (ms < 1000) return `${ms.toFixed(0)}ms`;
            return `${(ms / 1000).toFixed(1)}s`;
        };

        expect(formatLatency(0.5)).toBe('<1ms');
        expect(formatLatency(25)).toBe('25ms');
        expect(formatLatency(1500)).toBe('1.5s');
    });
});
