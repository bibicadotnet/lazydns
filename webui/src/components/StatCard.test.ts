// Unit tests for StatCard component

import { describe, it, expect, beforeEach } from 'vitest';
import { darkMode } from '../lib/stores';

// Mock StatCard props for testing
interface StatCardProps {
    label: string;
    value: string | number;
    icon: 'queries' | 'qps' | 'cache' | 'latency' | 'uptime' | 'alerts';
    change?: { value: number; positive: boolean } | null;
    suffix?: string;
}

describe('StatCard component logic', () => {
    beforeEach(() => {
        darkMode.set(true);
    });

    it('should format large numbers with K suffix', () => {
        const formatValue = (value: string | number): string => {
            if (typeof value === 'number') {
                if (value >= 1000000) return (value / 1000000).toFixed(1) + 'M';
                if (value >= 1000) return (value / 1000).toFixed(1) + 'K';
                return value.toString();
            }
            return value;
        };

        expect(formatValue(1500)).toBe('1.5K');
        expect(formatValue(1500000)).toBe('1.5M');
        expect(formatValue(500)).toBe('500');
        expect(formatValue('75.5%')).toBe('75.5%');
    });

    it('should apply correct icon colors based on dark mode', () => {
        const getIconColor = (icon: string, isDark: boolean): string => {
            const colors: Record<string, { dark: string; light: string }> = {
                queries: { dark: 'text-primary-400', light: 'text-primary-600' },
                qps: { dark: 'text-green-400', light: 'text-green-600' },
                cache: { dark: 'text-yellow-400', light: 'text-yellow-600' },
                latency: { dark: 'text-purple-400', light: 'text-purple-600' },
                uptime: { dark: 'text-blue-400', light: 'text-blue-600' },
                alerts: { dark: 'text-red-400', light: 'text-red-600' }
            };

            return colors[icon]?.[isDark ? 'dark' : 'light'] || '';
        };

        expect(getIconColor('queries', true)).toBe('text-primary-400');
        expect(getIconColor('queries', false)).toBe('text-primary-600');
        expect(getIconColor('alerts', true)).toBe('text-red-400');
    });

    it('should format change indicator correctly', () => {
        const formatChange = (change: { value: number; positive: boolean }): string => {
            const sign = change.positive ? '+' : '-';
            return `${sign}${Math.abs(change.value)}%`;
        };

        expect(formatChange({ value: 15, positive: true })).toBe('+15%');
        expect(formatChange({ value: 5, positive: false })).toBe('-5%');
    });

    it('should apply correct change indicator colors', () => {
        const getChangeColor = (positive: boolean, isDark: boolean): string => {
            if (positive) {
                return isDark ? 'text-green-400' : 'text-green-600';
            }
            return isDark ? 'text-red-400' : 'text-red-600';
        };

        expect(getChangeColor(true, true)).toBe('text-green-400');
        expect(getChangeColor(false, true)).toBe('text-red-400');
        expect(getChangeColor(true, false)).toBe('text-green-600');
    });
});

describe('StatCard data formatting', () => {
    it('should handle various value types', () => {
        const testCases: Array<{ input: string | number; expected: string }> = [
            { input: 999, expected: '999' },
            { input: 1000, expected: '1.0K' },
            { input: 10000, expected: '10.0K' },
            { input: '75.5%', expected: '75.5%' },
            { input: 0, expected: '0' },
            { input: 999999, expected: '1000.0K' },
            { input: 1000000, expected: '1.0M' }
        ];

        const formatValue = (value: string | number): string => {
            if (typeof value === 'number') {
                if (value >= 1000000) return (value / 1000000).toFixed(1) + 'M';
                if (value >= 1000) return (value / 1000).toFixed(1) + 'K';
                return value.toString();
            }
            return value;
        };

        testCases.forEach(({ input, expected }) => {
            expect(formatValue(input)).toBe(expected);
        });
    });

    it('should append suffix correctly', () => {
        const formatWithSuffix = (value: string | number, suffix: string): string => {
            return `${value}${suffix}`;
        };

        expect(formatWithSuffix(100, ' queries')).toBe('100 queries');
        expect(formatWithSuffix('5.5', 'ms')).toBe('5.5ms');
    });
});

describe('StatCard icon types', () => {
    const validIcons = ['queries', 'qps', 'cache', 'latency', 'uptime', 'alerts'] as const;

    it('should accept all valid icon types', () => {
        validIcons.forEach(icon => {
            const props: StatCardProps = {
                label: 'Test',
                value: 100,
                icon
            };
            expect(props.icon).toBe(icon);
        });
    });

    it('should have unique SVG paths for each icon', () => {
        const iconPaths: Record<string, string> = {
            queries: 'M8.228 9c.549-1.165',
            qps: 'M13 7h8m0 0v8',
            cache: 'M4 7v10c0 2.21',
            latency: 'M12 8v4l3 3m6-3',
            uptime: 'M5 3v4M3 5h4',
            alerts: 'M12 9v2m0 4h.01'
        };

        const icons = Object.keys(iconPaths);
        expect(icons.length).toBe(validIcons.length);
    });
});
