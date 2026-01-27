<script lang="ts">
    import type { UpstreamHealth } from "../lib/types";
    import { formatTimeAgo } from "../lib/mock";
    import { darkMode } from "../lib/stores";

    export let upstreams: UpstreamHealth[];
</script>

<div class="card">
    <div class="card-header">
        <h3
            class="font-semibold flex items-center gap-2 {$darkMode
                ? 'text-white'
                : 'text-gray-900'}"
        >
            <svg
                class="w-5 h-5 {$darkMode ? 'text-gray-400' : 'text-gray-500'}"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
            >
                <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"
                />
            </svg>
            Upstream Health
        </h3>
    </div>

    <div
        class="divide-y {$darkMode ? 'divide-gray-700/50' : 'divide-gray-200'}"
    >
        {#each upstreams as upstream}
            <div
                class="px-5 py-4 flex items-center justify-between transition-colors {$darkMode
                    ? 'hover:bg-gray-700/30'
                    : 'hover:bg-gray-50'}"
            >
                <div class="flex items-center gap-3">
                    <div class="relative">
                        <div
                            class="w-3 h-3 rounded-full"
                            class:bg-green-500={upstream.status === "healthy"}
                            class:bg-yellow-500={upstream.status === "degraded"}
                            class:bg-red-500={upstream.status === "down"}
                        ></div>
                        {#if upstream.status === "healthy"}
                            <div
                                class="absolute inset-0 w-3 h-3 rounded-full bg-green-500 animate-ping opacity-75"
                            ></div>
                        {/if}
                    </div>
                    <div>
                        <div
                            class="font-medium {$darkMode
                                ? 'text-white'
                                : 'text-gray-900'}"
                        >
                            {upstream.name}
                        </div>
                        <div
                            class="text-sm {$darkMode
                                ? 'text-gray-400'
                                : 'text-gray-700'}"
                        >
                            {upstream.address}
                        </div>
                    </div>
                </div>

                <div class="flex items-center gap-6 text-sm">
                    <div class="text-right">
                        <div
                            class={$darkMode
                                ? "text-gray-400"
                                : "text-gray-700"}
                        >
                            Latency
                        </div>
                        <div
                            class="font-medium"
                            class:text-green-600={upstream.avg_latency_ms < 50}
                            class:text-yellow-600={upstream.avg_latency_ms >=
                                50 && upstream.avg_latency_ms < 100}
                            class:text-red-600={upstream.avg_latency_ms >= 100}
                        >
                            {upstream.avg_latency_ms.toFixed(1)}ms
                        </div>
                    </div>

                    <div class="text-right">
                        <div
                            class={$darkMode
                                ? "text-gray-400"
                                : "text-gray-700"}
                        >
                            Success
                        </div>
                        <div
                            class="font-medium"
                            class:text-green-600={upstream.success_rate >= 99}
                            class:text-yellow-600={upstream.success_rate >=
                                95 && upstream.success_rate < 99}
                            class:text-red-600={upstream.success_rate < 95}
                        >
                            {upstream.success_rate.toFixed(1)}%
                        </div>
                    </div>

                    <div class="text-right w-20">
                        <div
                            class={$darkMode
                                ? "text-gray-400"
                                : "text-gray-700"}
                        >
                            Last OK
                        </div>
                        <div
                            class={$darkMode
                                ? "text-gray-300"
                                : "text-gray-700"}
                        >
                            {upstream.last_success_at
                                ? formatTimeAgo(upstream.last_success_at)
                                : "Never"}
                        </div>
                    </div>
                </div>
            </div>
        {/each}
    </div>
</div>
