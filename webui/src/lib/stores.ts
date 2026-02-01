// Svelte stores for global state management

import { writable, derived } from 'svelte/store';
import type { Alert, QueryLogEntry, SecurityEvent } from './types';

// Theme store - with localStorage persistence
function createDarkModeStore() {
    // Get initial value from localStorage or default to true
    const initialValue = typeof window !== 'undefined' 
        ? localStorage.getItem('darkMode') === 'false' ? false : true
        : true;
    
    const { subscribe, set, update } = writable<boolean>(initialValue);

    return {
        subscribe,
        set: (value: boolean) => {
            set(value);
            if (typeof window !== 'undefined') {
                localStorage.setItem('darkMode', String(value));
            }
        },
        toggle: () => {
            update(v => {
                const newValue = !v;
                if (typeof window !== 'undefined') {
                    localStorage.setItem('darkMode', String(newValue));
                }
                return newValue;
            });
        }
    };
}

export const darkMode = createDarkModeStore();

// Live data toggle
export const isLiveMode = writable(true);

// Alerts store - initialized empty, populated from API
export const alerts = writable<Alert[]>([]);

// Unacknowledged alerts count
export const unacknowledgedAlerts = derived(alerts, $alerts =>
    $alerts.filter(a => !a.acknowledged).length
);

// Query logs store (for live streaming)
export const queryLogs = writable<QueryLogEntry[]>([]);

// Security events store
export const securityEvents = writable<SecurityEvent[]>([]);

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

// Live data updates - these should be driven by SSE streams from the API
// The SSE connection logic is handled in the components that need real-time data

// Start/stop functions kept for API compatibility but now do nothing
// Real-time updates are handled via SSE streams in components
export function startLiveUpdates() {
    // No-op: Live updates now use SSE streams
}

export function stopLiveUpdates() {
    // No-op: Live updates now use SSE streams
}

// Subscribe to live mode changes
isLiveMode.subscribe(_live => {
    // SSE streams are managed by individual components
});
