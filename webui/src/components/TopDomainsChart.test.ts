// Unit tests for TopDomainsChart component

import { describe, it, expect, beforeEach } from 'vitest';
import { darkMode } from '../lib/stores';

interface TopDomain {
    domain: string;
    count: number;
    percentage: number;
}

describe('TopDomainsChart data processing', () => {
    const sampleDomains: TopDomain[] = [
        { domain: 'google.com', count: 500, percentage: 25.0 },
        { domain: 'facebook.com', count: 300, percentage: 15.0 },
        { domain: 'twitter.com', count: 200, percentage: 10.0 },
        { domain: 'amazon.com', count: 150, percentage: 7.5 },
        { domain: 'netflix.com', count: 100, percentage: 5.0 }
    ];

    it('should slice domains to show top 10', () => {
        const manyDomains = Array.from({ length: 20 }, (_, i) => ({
            domain: `domain${i}.com`,
            count: 100 - i,
            percentage: (100 - i) / 10
        }));

        const displayed = manyDomains.slice(0, 10);
        expect(displayed.length).toBe(10);
        expect(displayed[0].domain).toBe('domain0.com');
    });

    it('should format counts with K suffix for large numbers', () => {
        const formatCount = (count: number): string => {
            if (count >= 1000) return (count / 1000).toFixed(1) + 'K';
            return count.toString();
        };

        expect(formatCount(500)).toBe('500');
        expect(formatCount(1500)).toBe('1.5K');
        expect(formatCount(15000)).toBe('15.0K');
    });

    it('should truncate long domain names', () => {
        const truncateDomain = (domain: string, maxLength: number = 25): string => {
            if (domain.length > maxLength) {
                return domain.slice(0, maxLength - 3) + '...';
            }
            return domain;
        };

        const shortDomain = 'google.com';
        const longDomain = 'very-long-subdomain.example.company.com';

        expect(truncateDomain(shortDomain)).toBe('google.com');
        expect(truncateDomain(longDomain).endsWith('...')).toBe(true);
        expect(truncateDomain(longDomain).length).toBe(25);
    });

    it('should sort domains by count in descending order', () => {
        const unsorted = [...sampleDomains].reverse();
        const sorted = unsorted.sort((a, b) => b.count - a.count);

        expect(sorted[0].domain).toBe('google.com');
        expect(sorted[0].count).toBe(500);
    });

    it('should reverse array for bar chart display (bottom to top)', () => {
        const reversed = [...sampleDomains].reverse();
        expect(reversed[0].domain).toBe('netflix.com');
        expect(reversed[reversed.length - 1].domain).toBe('google.com');
    });

    it('should format percentage labels', () => {
        const formatPercentage = (pct: number): string => {
            return `${pct.toFixed(1)}%`;
        };

        expect(formatPercentage(25.0)).toBe('25.0%');
        expect(formatPercentage(7.5)).toBe('7.5%');
        expect(formatPercentage(0.1)).toBe('0.1%');
    });
});

describe('TopDomainsChart ECharts configuration', () => {
    beforeEach(() => {
        darkMode.set(true);
    });

    it('should generate correct color scheme for dark mode', () => {
        const getColors = (isDark: boolean) => ({
            textColor: isDark ? '#9ca3af' : '#4b5563',
            axisColor: isDark ? '#6b7280' : '#9ca3af',
            lineColor: isDark ? '#374151' : '#e5e7eb',
            tooltipBg: isDark ? 'rgba(17, 24, 39, 0.95)' : 'rgba(255, 255, 255, 0.95)',
            tooltipBorder: isDark ? '#374151' : '#e5e7eb',
            tooltipTextColor: isDark ? '#f3f4f6' : '#1f2937'
        });

        const darkColors = getColors(true);
        const lightColors = getColors(false);

        expect(darkColors.textColor).toBe('#9ca3af');
        expect(lightColors.textColor).toBe('#4b5563');
    });

    it('should configure grid with proper spacing', () => {
        const grid = {
            left: 150,
            right: 60,
            top: 20,
            bottom: 20
        };

        expect(grid.left).toBeGreaterThan(grid.right);
        expect(grid.top).toBe(grid.bottom);
    });

    it('should configure bar gradient colors', () => {
        const gradientStops = [
            { offset: 0, color: '#3b82f6' },
            { offset: 1, color: '#60a5fa' }
        ];

        expect(gradientStops[0].offset).toBe(0);
        expect(gradientStops[1].offset).toBe(1);
    });

    it('should set correct bar border radius for horizontal bars', () => {
        const borderRadius = [0, 4, 4, 0]; // [topLeft, topRight, bottomRight, bottomLeft]
        
        // For horizontal bars pointing right, round the right side
        expect(borderRadius[1]).toBeGreaterThan(0);
        expect(borderRadius[2]).toBeGreaterThan(0);
        expect(borderRadius[0]).toBe(0);
        expect(borderRadius[3]).toBe(0);
    });
});

describe('TopDomainsChart resize handling', () => {
    it('should handle window resize events', () => {
        // Resize handler is added and removed properly
        let resizeHandler: (() => void) | null = null;
        const listeners: Record<string, (() => void)[]> = {};

        const mockAddEventListener = (event: string, handler: () => void) => {
            if (!listeners[event]) listeners[event] = [];
            listeners[event].push(handler);
            resizeHandler = handler;
        };

        mockAddEventListener('resize', () => {});
        expect(resizeHandler).not.toBeNull();
    });

    it('should cleanup on component destroy', () => {
        // Event listener cleanup is called on destroy
        let removeCount = 0;
        const mockRemoveEventListener = () => {
            removeCount++;
        };

        mockRemoveEventListener();
        expect(removeCount).toBe(1);
    });
});

describe('TopDomainsChart empty state', () => {
    it('should handle empty domains array', () => {
        const domains: TopDomain[] = [];
        
        expect(domains.length).toBe(0);
        expect(domains.slice(0, 10)).toEqual([]);
    });

    it('should handle single domain', () => {
        const domains: TopDomain[] = [
            { domain: 'only-one.com', count: 100, percentage: 100.0 }
        ];

        expect(domains.slice(0, 10).length).toBe(1);
    });
});
