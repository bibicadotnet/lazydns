<script lang="ts">
    import TopDomainsChart from "../components/TopDomainsChart.svelte";
    import TopClientsChart from "../components/TopClientsChart.svelte";
    import LatencyDistributionChart from "../components/LatencyDistributionChart.svelte";
    import UpstreamPerformanceTable from "../components/UpstreamPerformanceTable.svelte";
    import {
        mockTopDomains,
        mockTopClients,
        mockUpstreamHealth,
        mockLatencyDistribution,
    } from "../lib/mock";
    import { selectedTimeWindow } from "../lib/stores";
    import type { TimeWindow } from "../lib/types";

    const timeWindows: { value: TimeWindow; label: string }[] = [
        { value: "1m", label: "1 Minute" },
        { value: "5m", label: "5 Minutes" },
        { value: "1h", label: "1 Hour" },
        { value: "24h", label: "24 Hours" },
    ];

    // Latency percentiles (mock data)
    const latencyPercentiles = {
        p50: 8.2,
        p95: 25.6,
        p99: 48.3,
        max: 125.8,
    };
</script>

<div class="space-y-6">
    <!-- Page Header -->
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold text-white">Metrics</h1>
            <p class="text-gray-400 mt-1">
                DNS performance analytics and statistics
            </p>
        </div>

        <!-- Time Window Selector -->
        <div class="flex items-center gap-2 bg-gray-800 rounded-lg p-1">
            {#each timeWindows as tw}
                <button
                    on:click={() => ($selectedTimeWindow = tw.value)}
                    class="px-4 py-2 rounded-lg text-sm font-medium transition-all"
                    class:bg-primary-600={$selectedTimeWindow === tw.value}
                    class:text-white={$selectedTimeWindow === tw.value}
                    class:text-gray-400={$selectedTimeWindow !== tw.value}
                    class:hover:text-white={$selectedTimeWindow !== tw.value}
                >
                    {tw.label}
                </button>
            {/each}
        </div>
    </div>

    <!-- Latency Percentiles -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div class="card p-4">
            <div class="flex items-center justify-between">
                <div>
                    <div class="text-sm text-gray-400">P50 Latency</div>
                    <div class="text-2xl font-bold text-green-400 mt-1">
                        {latencyPercentiles.p50}ms
                    </div>
                </div>
                <div
                    class="w-12 h-12 rounded-full bg-green-900/30 flex items-center justify-center"
                >
                    <span class="text-green-400 font-bold">50</span>
                </div>
            </div>
        </div>

        <div class="card p-4">
            <div class="flex items-center justify-between">
                <div>
                    <div class="text-sm text-gray-400">P95 Latency</div>
                    <div class="text-2xl font-bold text-yellow-400 mt-1">
                        {latencyPercentiles.p95}ms
                    </div>
                </div>
                <div
                    class="w-12 h-12 rounded-full bg-yellow-900/30 flex items-center justify-center"
                >
                    <span class="text-yellow-400 font-bold">95</span>
                </div>
            </div>
        </div>

        <div class="card p-4">
            <div class="flex items-center justify-between">
                <div>
                    <div class="text-sm text-gray-400">P99 Latency</div>
                    <div class="text-2xl font-bold text-orange-400 mt-1">
                        {latencyPercentiles.p99}ms
                    </div>
                </div>
                <div
                    class="w-12 h-12 rounded-full bg-orange-900/30 flex items-center justify-center"
                >
                    <span class="text-orange-400 font-bold">99</span>
                </div>
            </div>
        </div>

        <div class="card p-4">
            <div class="flex items-center justify-between">
                <div>
                    <div class="text-sm text-gray-400">Max Latency</div>
                    <div class="text-2xl font-bold text-red-400 mt-1">
                        {latencyPercentiles.max}ms
                    </div>
                </div>
                <div
                    class="w-12 h-12 rounded-full bg-red-900/30 flex items-center justify-center"
                >
                    <svg
                        class="w-6 h-6 text-red-400"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                    >
                        <path
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            stroke-width="2"
                            d="M5 10l7-7m0 0l7 7m-7-7v18"
                        />
                    </svg>
                </div>
            </div>
        </div>
    </div>

    <!-- Charts Row 1 -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TopDomainsChart
            domains={mockTopDomains}
            title="Top 10 Domains ({$selectedTimeWindow})"
        />
        <TopClientsChart clients={mockTopClients} />
    </div>

    <!-- Latency Distribution -->
    <LatencyDistributionChart data={mockLatencyDistribution} />

    <!-- Upstream Performance Table -->
    <UpstreamPerformanceTable upstreams={mockUpstreamHealth} />

    <!-- Additional Stats -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <!-- Query Type Distribution -->
        <div class="card">
            <div class="card-header">
                <h3 class="font-semibold text-white">Query Types</h3>
            </div>
            <div class="card-body space-y-3">
                {#each [{ type: "A", count: 456789, color: "bg-blue-500" }, { type: "AAAA", count: 234567, color: "bg-purple-500" }, { type: "CNAME", count: 123456, color: "bg-green-500" }, { type: "MX", count: 56789, color: "bg-yellow-500" }, { type: "TXT", count: 34567, color: "bg-pink-500" }, { type: "Other", count: 12345, color: "bg-gray-500" }] as item}
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-3">
                            <div class="w-3 h-3 rounded {item.color}"></div>
                            <span class="text-gray-300">{item.type}</span>
                        </div>
                        <div class="flex items-center gap-3">
                            <div
                                class="w-24 bg-gray-700 rounded-full h-2 overflow-hidden"
                            >
                                <div
                                    class="h-full rounded-full {item.color}"
                                    style="width: {(item.count / 456789) *
                                        100}%"
                                ></div>
                            </div>
                            <span class="text-sm text-gray-400 w-16 text-right">
                                {(item.count / 1000).toFixed(1)}K
                            </span>
                        </div>
                    </div>
                {/each}
            </div>
        </div>

        <!-- Response Codes -->
        <div class="card">
            <div class="card-header">
                <h3 class="font-semibold text-white">Response Codes</h3>
            </div>
            <div class="card-body space-y-3">
                {#each [{ code: "NOERROR", count: 1123456, color: "bg-green-500", pct: 91.2 }, { code: "NXDOMAIN", count: 56789, color: "bg-yellow-500", pct: 4.6 }, { code: "SERVFAIL", count: 23456, color: "bg-red-500", pct: 1.9 }, { code: "REFUSED", count: 12345, color: "bg-orange-500", pct: 1.0 }, { code: "Other", count: 16012, color: "bg-gray-500", pct: 1.3 }] as item}
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-3">
                            <div class="w-3 h-3 rounded {item.color}"></div>
                            <span class="text-gray-300">{item.code}</span>
                        </div>
                        <div class="flex items-center gap-3">
                            <span class="text-sm text-gray-400"
                                >{item.pct}%</span
                            >
                            <span class="text-sm text-gray-500 w-16 text-right">
                                {(item.count / 1000).toFixed(1)}K
                            </span>
                        </div>
                    </div>
                {/each}
            </div>
        </div>

        <!-- Protocol Distribution -->
        <div class="card">
            <div class="card-header">
                <h3 class="font-semibold text-white">Protocols</h3>
            </div>
            <div class="card-body space-y-3">
                {#each [{ proto: "UDP", count: 789012, color: "bg-blue-500", pct: 64.0 }, { proto: "TCP", count: 234567, color: "bg-cyan-500", pct: 19.0 }, { proto: "DoT (TLS)", count: 123456, color: "bg-green-500", pct: 10.0 }, { proto: "DoH", count: 56789, color: "bg-yellow-500", pct: 4.6 }, { proto: "DoQ", count: 29630, color: "bg-purple-500", pct: 2.4 }] as item}
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-3">
                            <div class="w-3 h-3 rounded {item.color}"></div>
                            <span class="text-gray-300">{item.proto}</span>
                        </div>
                        <div class="flex items-center gap-3">
                            <div
                                class="w-24 bg-gray-700 rounded-full h-2 overflow-hidden"
                            >
                                <div
                                    class="h-full rounded-full {item.color}"
                                    style="width: {item.pct}%"
                                ></div>
                            </div>
                            <span class="text-sm text-gray-400 w-12 text-right">
                                {item.pct}%
                            </span>
                        </div>
                    </div>
                {/each}
            </div>
        </div>
    </div>
</div>
