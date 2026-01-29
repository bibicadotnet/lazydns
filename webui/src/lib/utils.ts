// Utility functions for LazyDNS WebUI

/**
 * Format uptime in seconds to human readable string
 */
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

/**
 * Format numbers with K/M suffix
 */
export function formatNumber(num: number): string {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    }
    if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

/**
 * Format timestamp to relative time ago
 * Accepts ISO string or Unix seconds
 */
export function formatTimeAgo(timestamp: string | number | null): string {
    if (timestamp === null || timestamp === undefined) return 'Never';

    const now = Date.now();
    let then: number;
    
    if (typeof timestamp === 'number') {
        // Unix seconds - convert to milliseconds
        then = timestamp * 1000;
    } else {
        then = new Date(timestamp).getTime();
    }
    
    const diff = Math.floor((now - then) / 1000);

    if (diff < 0) return 'Just now';
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

/**
 * Get status color class for upstream health
 */
export function getStatusColor(status: 'healthy' | 'degraded' | 'down'): string {
    switch (status) {
        case 'healthy': return 'text-green-400';
        case 'degraded': return 'text-yellow-400';
        case 'down': return 'text-red-400';
    }
}

/**
 * Get severity color class for alerts
 */
export function getSeverityColor(severity: 'info' | 'warning' | 'critical'): string {
    switch (severity) {
        case 'info': return 'text-blue-400';
        case 'warning': return 'text-yellow-400';
        case 'critical': return 'text-red-400';
    }
}

/**
 * Get severity background color class for alerts
 */
export function getSeverityBgColor(severity: 'info' | 'warning' | 'critical'): string {
    switch (severity) {
        case 'info': return 'bg-blue-900/30 border-blue-700';
        case 'warning': return 'bg-yellow-900/30 border-yellow-700';
        case 'critical': return 'bg-red-900/30 border-red-700';
    }
}
