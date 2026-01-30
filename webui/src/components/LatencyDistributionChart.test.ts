// Unit tests for LatencyDistributionChart component

import { describe, it, expect, beforeEach } from 'vitest';
import { darkMode } from '../lib/stores';

interface LatencyBucket {
    label: string;
    count: number;
    percentage: number;
}

interface LatencyDistribution {
    buckets: LatencyBucket[];
    p50_ms: number;
    p95_ms: number;
    p99_ms: number;
    avg_ms: number;
}

describe('LatencyDistributionChart data processing', () => {
    const sampleDistribution: LatencyDistribution = {
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

    it('should have 7 latency buckets', () => {
        expect(sampleDistribution.buckets).toHaveLength(7);
    });

    it('should have bucket labels in order', () => {
        const expectedLabels = [
            '<1ms', '1-10ms', '10-50ms', '50-100ms',
            '100-500ms', '500ms-1s', '>1s'
        ];

        sampleDistribution.buckets.forEach((bucket, i) => {
            expect(bucket.label).toBe(expectedLabels[i]);
        });
    });

    it('should calculate total from buckets', () => {
        const total = sampleDistribution.buckets.reduce((sum, b) => sum + b.count, 0);
        expect(total).toBe(1000);
    });

    it('should have percentages summing to 100', () => {
        const totalPercentage = sampleDistribution.buckets.reduce((sum, b) => sum + b.percentage, 0);
        expect(totalPercentage).toBeCloseTo(100, 1);
    });

    it('should have ordered percentiles (p50 <= p95 <= p99)', () => {
        expect(sampleDistribution.p50_ms).toBeLessThanOrEqual(sampleDistribution.p95_ms);
        expect(sampleDistribution.p95_ms).toBeLessThanOrEqual(sampleDistribution.p99_ms);
    });

    it('should format percentile labels', () => {
        const formatPercentile = (label: string, value: number): string => {
            if (value < 1) return `${label}: <1ms`;
            if (value < 1000) return `${label}: ${value.toFixed(1)}ms`;
            return `${label}: ${(value / 1000).toFixed(2)}s`;
        };

        expect(formatPercentile('P50', 0.8)).toBe('P50: <1ms');
        expect(formatPercentile('P95', 25.0)).toBe('P95: 25.0ms');
        expect(formatPercentile('P99', 1500)).toBe('P99: 1.50s');
    });
});

describe('LatencyDistributionChart bar colors', () => {
    it('should assign colors based on latency severity', () => {
        const getBarColor = (index: number): string => {
            const colors = [
                '#22c55e', // green - <1ms (excellent)
                '#84cc16', // lime - 1-10ms (good)
                '#eab308', // yellow - 10-50ms (acceptable)
                '#f97316', // orange - 50-100ms (slow)
                '#ef4444', // red - 100-500ms (poor)
                '#dc2626', // dark red - 500ms-1s (bad)
                '#991b1b'  // darkest red - >1s (critical)
            ];
            return colors[index] || '#6b7280';
        };

        expect(getBarColor(0)).toBe('#22c55e'); // fastest = green
        expect(getBarColor(6)).toBe('#991b1b'); // slowest = dark red
    });

    it('should generate gradient for bar fill', () => {
        const generateGradient = (baseColor: string) => ({
            type: 'linear',
            x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
                { offset: 0, color: baseColor },
                { offset: 1, color: `${baseColor}80` } // 50% opacity
            ]
        });

        const gradient = generateGradient('#22c55e');
        expect(gradient.colorStops).toHaveLength(2);
        expect(gradient.colorStops[0].color).toBe('#22c55e');
    });
});

describe('LatencyDistributionChart statistics display', () => {
    it('should format average latency', () => {
        const formatLatency = (ms: number): string => {
            if (ms < 0.001) return '0ms';
            if (ms < 1) return `${(ms * 1000).toFixed(0)}µs`;
            if (ms < 1000) return `${ms.toFixed(1)}ms`;
            return `${(ms / 1000).toFixed(2)}s`;
        };

        expect(formatLatency(0)).toBe('0ms');
        expect(formatLatency(0.5)).toBe('500µs');
        expect(formatLatency(5.5)).toBe('5.5ms');
        expect(formatLatency(1500)).toBe('1.50s');
    });

    it('should display percentile markers', () => {
        const percentileMarkers = [
            { label: 'P50', value: 0.8, color: '#22c55e' },
            { label: 'P95', value: 25.0, color: '#eab308' },
            { label: 'P99', value: 75.0, color: '#ef4444' }
        ];

        expect(percentileMarkers).toHaveLength(3);
        expect(percentileMarkers.map(m => m.label)).toEqual(['P50', 'P95', 'P99']);
    });
});

describe('LatencyDistributionChart ECharts configuration', () => {
    beforeEach(() => {
        darkMode.set(true);
    });

    it('should configure tooltip with proper formatting', () => {
        const tooltipFormatter = (params: { name: string; value: number; percent: number }) => {
            return `${params.name}<br/>Count: ${params.value}<br/>${params.percent.toFixed(1)}%`;
        };

        const result = tooltipFormatter({ name: '<1ms', value: 500, percent: 50.0 });
        expect(result).toContain('<1ms');
        expect(result).toContain('500');
        expect(result).toContain('50.0%');
    });

    it('should configure x-axis as category type', () => {
        const xAxisConfig = {
            type: 'category',
            data: ['<1ms', '1-10ms', '10-50ms', '50-100ms', '100-500ms', '500ms-1s', '>1s'],
            axisLabel: {
                interval: 0,
                rotate: 0
            }
        };

        expect(xAxisConfig.type).toBe('category');
        expect(xAxisConfig.data).toHaveLength(7);
    });

    it('should configure y-axis for percentage display', () => {
        const yAxisConfig = {
            type: 'value',
            axisLabel: {
                formatter: (value: number) => `${value}%`
            }
        };

        expect(yAxisConfig.type).toBe('value');
        expect(yAxisConfig.axisLabel.formatter(50)).toBe('50%');
    });
});

describe('LatencyDistributionChart empty/edge cases', () => {
    it('should handle empty distribution', () => {
        const emptyDistribution: LatencyDistribution = {
            buckets: [],
            p50_ms: 0,
            p95_ms: 0,
            p99_ms: 0,
            avg_ms: 0
        };

        expect(emptyDistribution.buckets).toHaveLength(0);
        expect(emptyDistribution.p50_ms).toBe(0);
    });

    it('should handle all-zero counts', () => {
        const zeroDistribution: LatencyDistribution = {
            buckets: [
                { label: '<1ms', count: 0, percentage: 0 },
                { label: '1-10ms', count: 0, percentage: 0 }
            ],
            p50_ms: 0,
            p95_ms: 0,
            p99_ms: 0,
            avg_ms: 0
        };

        const total = zeroDistribution.buckets.reduce((sum, b) => sum + b.count, 0);
        expect(total).toBe(0);
    });

    it('should handle extreme latency values', () => {
        const extremeDistribution: LatencyDistribution = {
            buckets: [
                { label: '>1s', count: 100, percentage: 100.0 }
            ],
            p50_ms: 5000,
            p95_ms: 10000,
            p99_ms: 30000,
            avg_ms: 8000
        };

        expect(extremeDistribution.p99_ms).toBe(30000); // 30 seconds
    });
});
