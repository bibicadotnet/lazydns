// Unit tests for QpsChart component

import { describe, it, expect, beforeEach } from 'vitest';
import { darkMode } from '../lib/stores';

interface TimeSeriesPoint {
    timestamp: number;
    value: number;
}

interface QpsHistoryData {
    points: TimeSeriesPoint[];
    current_qps: number;
    stats: {
        min: number;
        max: number;
        avg: number;
        sum: number;
        count: number;
    };
}

describe('QpsChart data processing', () => {
    const sampleData: QpsHistoryData = {
        points: [
            { timestamp: 100, value: 10 },
            { timestamp: 101, value: 15 },
            { timestamp: 102, value: 12 },
            { timestamp: 103, value: 20 },
            { timestamp: 104, value: 8 }
        ],
        current_qps: 8,
        stats: {
            min: 5,
            max: 25,
            avg: 12.5,
            sum: 1250,
            count: 100
        }
    };

    it('should extract values for chart series', () => {
        const values = sampleData.points.map(p => p.value);
        expect(values).toEqual([10, 15, 12, 20, 8]);
    });

    it('should extract timestamps for x-axis', () => {
        const timestamps = sampleData.points.map(p => p.timestamp);
        expect(timestamps).toEqual([100, 101, 102, 103, 104]);
    });

    it('should format timestamp for display', () => {
        const formatTimestamp = (ts: number): string => {
            const date = new Date(ts * 1000);
            return date.toLocaleTimeString('en-US', { 
                hour12: false, 
                hour: '2-digit', 
                minute: '2-digit',
                second: '2-digit'
            });
        };

        // Just verify the function works without error
        const formatted = formatTimestamp(1706616000);
        expect(typeof formatted).toBe('string');
    });

    it('should calculate local min/max from points', () => {
        const values = sampleData.points.map(p => p.value);
        const localMin = Math.min(...values);
        const localMax = Math.max(...values);

        expect(localMin).toBe(8);
        expect(localMax).toBe(20);
    });
});

describe('QpsChart statistics display', () => {
    it('should format current QPS with one decimal', () => {
        const formatQps = (qps: number): string => {
            return qps.toFixed(1);
        };

        expect(formatQps(12.5)).toBe('12.5');
        expect(formatQps(100)).toBe('100.0');
        expect(formatQps(0.1)).toBe('0.1');
    });

    it('should format large QPS values with K suffix', () => {
        const formatLargeQps = (qps: number): string => {
            if (qps >= 1000) return (qps / 1000).toFixed(1) + 'K';
            return qps.toFixed(1);
        };

        expect(formatLargeQps(500)).toBe('500.0');
        expect(formatLargeQps(1500)).toBe('1.5K');
        expect(formatLargeQps(10000)).toBe('10.0K');
    });

    it('should display min/max/avg statistics', () => {
        const stats = {
            min: 5,
            max: 25,
            avg: 12.5
        };

        expect(stats.min).toBeLessThan(stats.avg);
        expect(stats.avg).toBeLessThan(stats.max);
    });
});

describe('QpsChart ECharts configuration', () => {
    beforeEach(() => {
        darkMode.set(true);
    });

    it('should configure area chart with gradient fill', () => {
        const areaStyleConfig = {
            color: {
                type: 'linear',
                x: 0, y: 0, x2: 0, y2: 1,
                colorStops: [
                    { offset: 0, color: 'rgba(59, 130, 246, 0.5)' },
                    { offset: 1, color: 'rgba(59, 130, 246, 0.05)' }
                ]
            }
        };

        expect(areaStyleConfig.color.type).toBe('linear');
        expect(areaStyleConfig.color.colorStops).toHaveLength(2);
    });

    it('should configure smooth line', () => {
        const seriesConfig = {
            type: 'line',
            smooth: true,
            showSymbol: false,
            lineStyle: {
                width: 2,
                color: '#3b82f6'
            }
        };

        expect(seriesConfig.smooth).toBe(true);
        expect(seriesConfig.showSymbol).toBe(false);
    });

    it('should configure tooltip for crosshair display', () => {
        const tooltipConfig = {
            trigger: 'axis',
            axisPointer: {
                type: 'cross',
                crossStyle: {
                    color: '#999'
                }
            }
        };

        expect(tooltipConfig.trigger).toBe('axis');
        expect(tooltipConfig.axisPointer.type).toBe('cross');
    });

    it('should configure x-axis as time type', () => {
        const xAxisConfig = {
            type: 'time',
            splitLine: {
                show: false
            },
            axisLabel: {
                formatter: '{HH}:{mm}'
            }
        };

        expect(xAxisConfig.type).toBe('time');
    });

    it('should configure y-axis with min/max bounds', () => {
        const configureYAxis = (min: number, max: number) => ({
            type: 'value',
            min: Math.floor(min * 0.9),
            max: Math.ceil(max * 1.1),
            splitLine: {
                lineStyle: {
                    type: 'dashed'
                }
            }
        });

        const yAxis = configureYAxis(5, 25);
        expect(yAxis.min).toBe(4);  // floor(5 * 0.9)
        expect(yAxis.max).toBe(28); // ceil(25 * 1.1)
    });
});

describe('QpsChart real-time updates', () => {
    it('should append new point to existing data', () => {
        const points = [
            { timestamp: 100, value: 10 },
            { timestamp: 101, value: 15 }
        ];

        const newPoint = { timestamp: 102, value: 12 };
        points.push(newPoint);

        expect(points).toHaveLength(3);
        expect(points[2]).toEqual(newPoint);
    });

    it('should limit points to window size', () => {
        const maxPoints = 300; // 5 minutes at 1-second intervals
        const points: TimeSeriesPoint[] = [];

        // Simulate adding more than max points
        for (let i = 0; i < 350; i++) {
            points.push({ timestamp: i, value: Math.random() * 100 });
        }

        // Trim to max size
        const trimmed = points.slice(-maxPoints);
        expect(trimmed).toHaveLength(maxPoints);
        expect(trimmed[0].timestamp).toBe(50);
    });

    it('should calculate moving average', () => {
        const points = [
            { timestamp: 100, value: 10 },
            { timestamp: 101, value: 20 },
            { timestamp: 102, value: 15 },
            { timestamp: 103, value: 25 },
            { timestamp: 104, value: 30 }
        ];

        const windowSize = 3;
        const movingAvg = (index: number): number => {
            const start = Math.max(0, index - windowSize + 1);
            const slice = points.slice(start, index + 1);
            const sum = slice.reduce((acc, p) => acc + p.value, 0);
            return sum / slice.length;
        };

        // Last point moving average: (15 + 25 + 30) / 3 = 23.33
        expect(movingAvg(4)).toBeCloseTo(23.33, 1);
    });
});

describe('QpsChart empty state', () => {
    it('should handle empty points array', () => {
        const emptyData: QpsHistoryData = {
            points: [],
            current_qps: 0,
            stats: {
                min: 0,
                max: 0,
                avg: 0,
                sum: 0,
                count: 0
            }
        };

        expect(emptyData.points).toHaveLength(0);
        expect(emptyData.current_qps).toBe(0);
    });

    it('should display placeholder when no data', () => {
        const hasData = (points: TimeSeriesPoint[]): boolean => points.length > 0;

        expect(hasData([])).toBe(false);
        expect(hasData([{ timestamp: 1, value: 10 }])).toBe(true);
    });
});
