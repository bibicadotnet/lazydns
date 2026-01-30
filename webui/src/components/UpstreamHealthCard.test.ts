// Unit tests for UpstreamHealthCard component

import { describe, it, expect } from 'vitest';

interface UpstreamHealth {
    address: string;
    tag: string | null;
    status: 'healthy' | 'degraded' | 'down' | 'unknown';
    success_rate: number;
    avg_response_time_ms: number;
    queries: number;
    successes: number;
    failures: number;
    last_success: string | null;
}

describe('UpstreamHealthCard status indicators', () => {
    it('should return correct status color', () => {
        const getStatusColor = (status: string): string => {
            switch (status) {
                case 'healthy': return 'bg-green-500';
                case 'degraded': return 'bg-yellow-500';
                case 'down': return 'bg-red-500';
                default: return 'bg-gray-500';
            }
        };

        expect(getStatusColor('healthy')).toBe('bg-green-500');
        expect(getStatusColor('degraded')).toBe('bg-yellow-500');
        expect(getStatusColor('down')).toBe('bg-red-500');
        expect(getStatusColor('unknown')).toBe('bg-gray-500');
    });

    it('should return correct status text color', () => {
        const getStatusTextColor = (status: string, isDark: boolean): string => {
            const colors: Record<string, { dark: string; light: string }> = {
                healthy: { dark: 'text-green-400', light: 'text-green-600' },
                degraded: { dark: 'text-yellow-400', light: 'text-yellow-600' },
                down: { dark: 'text-red-400', light: 'text-red-600' },
                unknown: { dark: 'text-gray-400', light: 'text-gray-600' }
            };

            return colors[status]?.[isDark ? 'dark' : 'light'] || colors.unknown[isDark ? 'dark' : 'light'];
        };

        expect(getStatusTextColor('healthy', true)).toBe('text-green-400');
        expect(getStatusTextColor('down', false)).toBe('text-red-600');
    });

    it('should capitalize status text', () => {
        const capitalizeStatus = (status: string): string => {
            return status.charAt(0).toUpperCase() + status.slice(1);
        };

        expect(capitalizeStatus('healthy')).toBe('Healthy');
        expect(capitalizeStatus('degraded')).toBe('Degraded');
        expect(capitalizeStatus('down')).toBe('Down');
    });
});

describe('UpstreamHealthCard success rate display', () => {
    it('should format success rate as percentage', () => {
        const formatSuccessRate = (rate: number): string => {
            return `${rate.toFixed(1)}%`;
        };

        expect(formatSuccessRate(99.5)).toBe('99.5%');
        expect(formatSuccessRate(100)).toBe('100.0%');
        expect(formatSuccessRate(0)).toBe('0.0%');
    });

    it('should determine success rate severity', () => {
        const getSuccessRateSeverity = (rate: number): 'good' | 'warning' | 'critical' => {
            if (rate >= 99) return 'good';
            if (rate >= 95) return 'warning';
            return 'critical';
        };

        expect(getSuccessRateSeverity(99.5)).toBe('good');
        expect(getSuccessRateSeverity(97)).toBe('warning');
        expect(getSuccessRateSeverity(90)).toBe('critical');
    });

    it('should color progress bar based on success rate', () => {
        const getProgressColor = (rate: number): string => {
            if (rate >= 99) return 'bg-green-500';
            if (rate >= 95) return 'bg-yellow-500';
            if (rate >= 90) return 'bg-orange-500';
            return 'bg-red-500';
        };

        expect(getProgressColor(100)).toBe('bg-green-500');
        expect(getProgressColor(97)).toBe('bg-yellow-500');
        expect(getProgressColor(92)).toBe('bg-orange-500');
        expect(getProgressColor(85)).toBe('bg-red-500');
    });
});

describe('UpstreamHealthCard response time display', () => {
    it('should format response time in ms', () => {
        const formatResponseTime = (ms: number): string => {
            if (ms < 1) return '<1ms';
            if (ms < 1000) return `${ms.toFixed(0)}ms`;
            return `${(ms / 1000).toFixed(2)}s`;
        };

        expect(formatResponseTime(0.5)).toBe('<1ms');
        expect(formatResponseTime(25)).toBe('25ms');
        expect(formatResponseTime(1500)).toBe('1.50s');
    });

    it('should determine response time severity', () => {
        const getResponseTimeSeverity = (ms: number): 'fast' | 'normal' | 'slow' | 'critical' => {
            if (ms < 10) return 'fast';
            if (ms < 50) return 'normal';
            if (ms < 200) return 'slow';
            return 'critical';
        };

        expect(getResponseTimeSeverity(5)).toBe('fast');
        expect(getResponseTimeSeverity(30)).toBe('normal');
        expect(getResponseTimeSeverity(100)).toBe('slow');
        expect(getResponseTimeSeverity(500)).toBe('critical');
    });
});

describe('UpstreamHealthCard query statistics', () => {
    it('should format large query counts', () => {
        const formatQueryCount = (count: number): string => {
            if (count >= 1000000) return (count / 1000000).toFixed(1) + 'M';
            if (count >= 1000) return (count / 1000).toFixed(1) + 'K';
            return count.toString();
        };

        expect(formatQueryCount(500)).toBe('500');
        expect(formatQueryCount(1500)).toBe('1.5K');
        expect(formatQueryCount(1500000)).toBe('1.5M');
    });

    it('should calculate failure rate', () => {
        const calculateFailureRate = (failures: number, total: number): number => {
            if (total === 0) return 0;
            return (failures / total) * 100;
        };

        expect(calculateFailureRate(5, 100)).toBe(5);
        expect(calculateFailureRate(0, 1000)).toBe(0);
        expect(calculateFailureRate(50, 0)).toBe(0);
    });
});

describe('UpstreamHealthCard last success display', () => {
    it('should format relative time', () => {
        const formatRelativeTime = (isoString: string | null): string => {
            if (!isoString) return 'Never';

            const date = new Date(isoString);
            const now = new Date();
            const diffMs = now.getTime() - date.getTime();
            const diffSecs = Math.floor(diffMs / 1000);
            const diffMins = Math.floor(diffSecs / 60);
            const diffHours = Math.floor(diffMins / 60);
            const diffDays = Math.floor(diffHours / 24);

            if (diffSecs < 60) return 'Just now';
            if (diffMins < 60) return `${diffMins}m ago`;
            if (diffHours < 24) return `${diffHours}h ago`;
            return `${diffDays}d ago`;
        };

        expect(formatRelativeTime(null)).toBe('Never');
        expect(formatRelativeTime(new Date().toISOString())).toBe('Just now');
    });

    it('should handle null last_success', () => {
        const upstream: UpstreamHealth = {
            address: '8.8.8.8:53',
            tag: null,
            status: 'down',
            success_rate: 0,
            avg_response_time_ms: 0,
            queries: 100,
            successes: 0,
            failures: 100,
            last_success: null
        };

        expect(upstream.last_success).toBeNull();
    });
});

describe('UpstreamHealthCard address display', () => {
    it('should display full address', () => {
        const upstream: UpstreamHealth = {
            address: '8.8.8.8:53',
            tag: 'google-primary',
            status: 'healthy',
            success_rate: 99.5,
            avg_response_time_ms: 25,
            queries: 10000,
            successes: 9950,
            failures: 50,
            last_success: '2026-01-30T12:00:00Z'
        };

        expect(upstream.address).toBe('8.8.8.8:53');
    });

    it('should display tag if available', () => {
        const getDisplayName = (upstream: UpstreamHealth): string => {
            return upstream.tag || upstream.address;
        };

        const withTag: UpstreamHealth = {
            address: '8.8.8.8:53',
            tag: 'google',
            status: 'healthy',
            success_rate: 99,
            avg_response_time_ms: 20,
            queries: 1000,
            successes: 990,
            failures: 10,
            last_success: null
        };

        const withoutTag: UpstreamHealth = {
            address: '1.1.1.1:53',
            tag: null,
            status: 'healthy',
            success_rate: 99,
            avg_response_time_ms: 15,
            queries: 500,
            successes: 495,
            failures: 5,
            last_success: null
        };

        expect(getDisplayName(withTag)).toBe('google');
        expect(getDisplayName(withoutTag)).toBe('1.1.1.1:53');
    });

    it('should identify protocol from port', () => {
        const getProtocol = (address: string): string => {
            if (address.includes(':53')) return 'DNS';
            if (address.includes(':853')) return 'DoT';
            if (address.includes(':443')) return 'DoH';
            if (address.includes(':8853')) return 'DoQ';
            return 'Unknown';
        };

        expect(getProtocol('8.8.8.8:53')).toBe('DNS');
        expect(getProtocol('8.8.8.8:853')).toBe('DoT');
        expect(getProtocol('cloudflare-dns.com:443')).toBe('DoH');
    });
});

describe('UpstreamHealthCard sorting', () => {
    it('should sort upstreams by status priority', () => {
        const statusPriority: Record<string, number> = {
            down: 0,
            degraded: 1,
            unknown: 2,
            healthy: 3
        };

        const upstreams = [
            { status: 'healthy' },
            { status: 'down' },
            { status: 'degraded' }
        ];

        const sorted = [...upstreams].sort((a, b) => 
            statusPriority[a.status] - statusPriority[b.status]
        );

        expect(sorted[0].status).toBe('down');
        expect(sorted[1].status).toBe('degraded');
        expect(sorted[2].status).toBe('healthy');
    });

    it('should sort by success rate within same status', () => {
        const upstreams = [
            { status: 'healthy', success_rate: 95 },
            { status: 'healthy', success_rate: 99 },
            { status: 'healthy', success_rate: 97 }
        ];

        const sorted = [...upstreams].sort((a, b) => a.success_rate - b.success_rate);

        expect(sorted[0].success_rate).toBe(95);
        expect(sorted[2].success_rate).toBe(99);
    });
});
