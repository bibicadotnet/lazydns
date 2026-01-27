<script lang="ts">
    import type { SecurityEvent } from "../lib/types";
    import { formatTimeAgo } from "../lib/mock";

    export let events: SecurityEvent[];
    export let maxHeight: string = "600px";

    type EventType = SecurityEvent["event_type"];

    const eventTypeLabels: Record<
        EventType,
        { label: string; color: string; icon: string }
    > = {
        rate_limit_exceeded: {
            label: "Rate Limited",
            color: "text-yellow-400",
            icon: "⚡",
        },
        blocked_domain_query: {
            label: "Blocked",
            color: "text-red-400",
            icon: "🚫",
        },
        upstream_failure: {
            label: "Upstream Fail",
            color: "text-orange-400",
            icon: "⚠️",
        },
        acl_denied: { label: "ACL Denied", color: "text-red-400", icon: "🔒" },
        malformed_query: {
            label: "Malformed",
            color: "text-purple-400",
            icon: "❓",
        },
        query_timeout: { label: "Timeout", color: "text-gray-400", icon: "⏱️" },
    };

    function formatTime(timestamp: string): string {
        return new Date(timestamp).toLocaleTimeString("en-US", {
            hour12: false,
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
        });
    }
</script>

<div class="overflow-y-auto space-y-2" style="max-height: {maxHeight}">
    {#each events as event (event.timestamp + (event.client_ip || "") + (event.domain || ""))}
        <div
            class="card p-4 border-l-4 border-yellow-500 hover:bg-gray-700/30 transition-colors"
        >
            <div class="flex items-start justify-between">
                <div class="flex items-start gap-3">
                    <span class="text-xl"
                        >{eventTypeLabels[event.event_type].icon}</span
                    >
                    <div>
                        <div class="flex items-center gap-2 mb-1">
                            <span
                                class="font-medium {eventTypeLabels[
                                    event.event_type
                                ].color}"
                            >
                                {eventTypeLabels[event.event_type].label}
                            </span>
                            <span class="text-xs text-gray-500">
                                {formatTime(event.timestamp)}
                            </span>
                        </div>
                        <p class="text-sm text-gray-300">{event.message}</p>
                        <div
                            class="flex items-center gap-4 mt-2 text-xs text-gray-400"
                        >
                            {#if event.client_ip}
                                <span class="flex items-center gap-1">
                                    <svg
                                        class="w-3 h-3"
                                        fill="none"
                                        stroke="currentColor"
                                        viewBox="0 0 24 24"
                                    >
                                        <path
                                            stroke-linecap="round"
                                            stroke-linejoin="round"
                                            stroke-width="2"
                                            d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
                                        />
                                    </svg>
                                    {event.client_ip}
                                </span>
                            {/if}
                            {#if event.domain}
                                <span class="flex items-center gap-1 font-mono">
                                    <svg
                                        class="w-3 h-3"
                                        fill="none"
                                        stroke="currentColor"
                                        viewBox="0 0 24 24"
                                    >
                                        <path
                                            stroke-linecap="round"
                                            stroke-linejoin="round"
                                            stroke-width="2"
                                            d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9"
                                        />
                                    </svg>
                                    {event.domain}
                                </span>
                            {/if}
                        </div>
                    </div>
                </div>
                <span class="text-xs text-gray-500 whitespace-nowrap">
                    {formatTimeAgo(event.timestamp)}
                </span>
            </div>
        </div>
    {:else}
        <div class="text-center py-12 text-gray-500">
            <svg
                class="w-12 h-12 mx-auto mb-3 opacity-50"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
            >
                <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="1.5"
                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
            </svg>
            <p>No security events</p>
        </div>
    {/each}
</div>
