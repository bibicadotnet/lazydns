<script lang="ts">
    import type { UpstreamHealth } from "../lib/types";
    import { formatTimeAgo } from "../lib/mock";

    export let upstreams: UpstreamHealth[];
</script>

<div class="card">
    <div class="card-header">
        <h3 class="font-semibold text-white flex items-center gap-2">
            <svg
                class="w-5 h-5 text-gray-400"
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

    <div class="divide-y divide-gray-700/50">
        {#each upstreams as upstream}
            <div
                class="px-5 py-4 flex items-center justify-between hover:bg-gray-700/30 transition-colors"
            >
                <div class="flex items-center gap-3">
                    <div class="relative">
                        <div
                            class="w-3 h-3 rounded-full"
                            class:bg-green-400={upstream.status === "healthy"}
                            class:bg-yellow-400={upstream.status === "degraded"}
                            class:bg-red-400={upstream.status === "down"}
                        ></div>
                        {#if upstream.status === "healthy"}
                            <div
                                class="absolute inset-0 w-3 h-3 rounded-full bg-green-400 animate-ping opacity-75"
                            ></div>
                        {/if}
                    </div>
                    <div>
                        <div class="font-medium text-white">
                            {upstream.name}
                        </div>
                        <div class="text-sm text-gray-400">
                            {upstream.address}
                        </div>
                    </div>
                </div>

                <div class="flex items-center gap-6 text-sm">
                    <div class="text-right">
                        <div class="text-gray-400">Latency</div>
                        <div
                            class="font-medium"
                            class:text-green-400={upstream.avg_latency_ms < 50}
                            class:text-yellow-400={upstream.avg_latency_ms >=
                                50 && upstream.avg_latency_ms < 100}
                            class:text-red-400={upstream.avg_latency_ms >= 100}
                        >
                            {upstream.avg_latency_ms.toFixed(1)}ms
                        </div>
                    </div>

                    <div class="text-right">
                        <div class="text-gray-400">Success</div>
                        <div
                            class="font-medium"
                            class:text-green-400={upstream.success_rate >= 99}
                            class:text-yellow-400={upstream.success_rate >=
                                95 && upstream.success_rate < 99}
                            class:text-red-400={upstream.success_rate < 95}
                        >
                            {upstream.success_rate.toFixed(1)}%
                        </div>
                    </div>

                    <div class="text-right w-20">
                        <div class="text-gray-400">Last OK</div>
                        <div class="text-gray-300">
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
