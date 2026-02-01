// Unit tests for utility functions

import { describe, it, expect } from 'vitest';
import {
    formatUptime,
    formatNumber,
    formatTimeAgo,
    getStatusColor,
    getSeverityColor,
    getSeverityBgColor
} from './utils';

describe('formatUptime', () => {
    it('should format seconds only', () => {
        expect(formatUptime(45)).toBe('45s');
    });

    it('should format minutes and seconds', () => {
        expect(formatUptime(125)).toBe('2m 5s');
    });

    it('should format hours, minutes and seconds', () => {
        expect(formatUptime(3661)).toBe('1h 1m 1s');
    });

    it('should format days, hours, minutes and seconds', () => {
        expect(formatUptime(90061)).toBe('1d 1h 1m 1s');
    });

    it('should handle zero seconds', () => {
        expect(formatUptime(0)).toBe('0s');
    });

    it('should handle large uptime', () => {
        expect(formatUptime(86400 * 30)).toBe('30d');
    });
});

describe('formatNumber', () => {
    it('should format small numbers', () => {
        expect(formatNumber(123)).toBe('123');
    });

    it('should format thousands', () => {
        expect(formatNumber(1234)).toBe('1.2K');
        expect(formatNumber(5678)).toBe('5.7K');
    });

    it('should format millions', () => {
        expect(formatNumber(1234567)).toBe('1.2M');
        expect(formatNumber(9876543)).toBe('9.9M');
    });

    it('should handle edge cases', () => {
        expect(formatNumber(1000)).toBe('1.0K');
        expect(formatNumber(1000000)).toBe('1.0M');
    });
});

describe('formatTimeAgo', () => {
    it('should handle null/undefined', () => {
        expect(formatTimeAgo(null)).toBe('Never');
        const undefinedResult = formatTimeAgo(undefined as any);
        expect(undefinedResult).toBe('Never');
    });

    it('should handle empty string', () => {
        const emptyResult = formatTimeAgo('');
        expect(emptyResult).toBe('Never');
    });

    it('should handle invalid timestamp', () => {
        expect(formatTimeAgo('invalid')).toBe('Never');
    });

    it('should handle zero timestamp', () => {
        expect(formatTimeAgo(0)).toBe('Never');
    });

    it('should handle old timestamps (< 1 billion seconds)', () => {
        expect(formatTimeAgo(999999999)).toBe('Never');
    });

    it('should format seconds ago', () => {
        const now = Math.floor(Date.now() / 1000);
        expect(formatTimeAgo(now - 30)).toBe('30s ago');
    });

    it('should format minutes ago', () => {
        const now = Math.floor(Date.now() / 1000);
        expect(formatTimeAgo(now - 300)).toBe('5m ago');
    });

    it('should format hours ago', () => {
        const now = Math.floor(Date.now() / 1000);
        expect(formatTimeAgo(now - 7200)).toBe('2h ago');
    });

    it('should format days ago', () => {
        const now = Math.floor(Date.now() / 1000);
        expect(formatTimeAgo(now - 86400 * 3)).toBe('3d ago');
    });

    it('should format ISO string timestamps', () => {
        const now = new Date();
        const isoString = now.toISOString();
        expect(formatTimeAgo(isoString)).toBe('0s ago');
    });

    it('should handle future timestamps', () => {
        const future = Math.floor(Date.now() / 1000) + 1000;
        expect(formatTimeAgo(future)).toBe('Just now');
    });
});

describe('getStatusColor', () => {
    it('should return green for healthy', () => {
        expect(getStatusColor('healthy')).toBe('text-green-400');
    });

    it('should return yellow for degraded', () => {
        expect(getStatusColor('degraded')).toBe('text-yellow-400');
    });

    it('should return red for down', () => {
        expect(getStatusColor('down')).toBe('text-red-400');
    });
});

describe('getSeverityColor', () => {
    it('should return blue for info', () => {
        expect(getSeverityColor('info')).toBe('text-blue-400');
    });

    it('should return yellow for warning', () => {
        expect(getSeverityColor('warning')).toBe('text-yellow-400');
    });

    it('should return red for critical', () => {
        expect(getSeverityColor('critical')).toBe('text-red-400');
    });
});

describe('getSeverityBgColor', () => {
    it('should return blue background for info', () => {
        expect(getSeverityBgColor('info')).toBe('bg-blue-900/30 border-blue-700');
    });

    it('should return yellow background for warning', () => {
        expect(getSeverityBgColor('warning')).toBe('bg-yellow-900/30 border-yellow-700');
    });

    it('should return red background for critical', () => {
        expect(getSeverityBgColor('critical')).toBe('bg-red-900/30 border-red-700');
    });
});
