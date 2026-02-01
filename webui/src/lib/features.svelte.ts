// Server features state
import api from './api';

interface ServerFeatures {
    admin: boolean;
    metrics: boolean;
    audit: boolean;
}

export const features = $state<ServerFeatures>({
    admin: false,
    metrics: false,
    audit: false,
});

let initialized = false;

export async function loadServerFeatures() {
    if (initialized) return;
    
    try {
        const serverFeatures = await api.getServerFeatures();
        Object.assign(features, serverFeatures);
        initialized = true;
    } catch (error) {
        console.error('Failed to load server features:', error);
        // Default to all features disabled on error
    }
}
