// Svelte stores for global state management

import { writable, derived } from 'svelte/store';
import type { Alert, QueryLogEntry, SecurityEvent } from './types';
import { mockAlerts, generateQueryLogs, generateSecurityEvents } from './mock';

// Theme store
export const darkMode = writable(true);

// Live data toggle
export const isLiveMode = writable(true);

// Alerts store
export const alerts = writable<Alert[]>(mockAlerts);

// Unacknowledged alerts count
export const unacknowledgedAlerts = derived(alerts, $alerts =>
    $alerts.filter(a => !a.acknowledged).length
);

// Query logs store (for live streaming)
export const queryLogs = writable<QueryLogEntry[]>(generateQueryLogs(100));

// Security events store
export const securityEvents = writable<SecurityEvent[]>(generateSecurityEvents(50));

// Selected time window
export const selectedTimeWindow = writable<'1m' | '5m' | '1h' | '24h'>('1h');

// Top navigation collapsed state (default true = collapsed)
export const topNavCollapsed = writable(false);
export const sidebarCollapsed = writable(true);

// Notification store for toast messages
interface Notification {
    id: string;
    type: 'success' | 'error' | 'info' | 'warning';
    message: string;
    duration?: number;
}

function createNotificationStore() {
    const { subscribe, update } = writable<Notification[]>([]);

    return {
        subscribe,
        add: (notification: Omit<Notification, 'id'>) => {
            const id = crypto.randomUUID();
            const newNotification = { ...notification, id };
            update(n => [...n, newNotification]);

            // Auto-remove after duration
            const duration = notification.duration ?? 5000;
            if (duration > 0) {
                setTimeout(() => {
                    update(n => n.filter(item => item.id !== id));
                }, duration);
            }

            return id;
        },
        remove: (id: string) => {
            update(n => n.filter(item => item.id !== id));
        },
        clear: () => {
            update(() => []);
        }
    };
}

export const notifications = createNotificationStore();

// Simulate live data updates
let liveUpdateInterval: ReturnType<typeof setInterval> | null = null;

export function startLiveUpdates() {
    if (liveUpdateInterval) return;

    liveUpdateInterval = setInterval(() => {
        // Add new query log
        const newLog = generateQueryLogs(1)[0];
        queryLogs.update(logs => [newLog, ...logs.slice(0, 499)]);

        // Occasionally add security event
        if (Math.random() < 0.1) {
            const newEvent = generateSecurityEvents(1)[0];
            securityEvents.update(events => [newEvent, ...events.slice(0, 199)]);
        }
    }, 1000);
}

export function stopLiveUpdates() {
    if (liveUpdateInterval) {
        clearInterval(liveUpdateInterval);
        liveUpdateInterval = null;
    }
}

// Subscribe to live mode changes
isLiveMode.subscribe(live => {
    if (live) {
        startLiveUpdates();
    } else {
        stopLiveUpdates();
    }
});
