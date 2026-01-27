<script lang="ts">
    import StatCard from "../components/StatCard.svelte";
    import UpstreamHealthCard from "../components/UpstreamHealthCard.svelte";
    import AlertsList from "../components/AlertsList.svelte";
    import QpsChart from "../components/QpsChart.svelte";
    import {
        mockDashboardOverview,
        mockUpstreamHealth,
        generateQpsTimeSeries,
        formatUptime,
        formatNumber,
    } from "../lib/mock";
    import { alerts, darkMode } from "../lib/stores";

    const overview = mockDashboardOverview;
    const upstreams = mockUpstreamHealth;

    // Generate initial QPS data
    let qpsData = generateQpsTimeSeries(60);

    // Update QPS data periodically
    setInterval(() => {
        const newPoint = {
            timestamp: new Date().toISOString(),
            value: 200 + Math.random() * 100,
        };
        qpsData = [...qpsData.slice(1), newPoint];
    }, 5000);
</script>

<div class="space-y-6">
    <!-- Page Header -->
    <div class="flex items-center justify-between">
        <div>
            <h1
                class="text-2xl font-bold {$darkMode
                    ? 'text-white'
                    : 'text-gray-900'}"
            >
                Dashboard
            </h1>
            <p class="{$darkMode ? 'text-gray-400' : 'text-gray-600'} mt-1">
                Real-time DNS server monitoring
            </p>
        </div>
        <div
            class="flex items-center gap-2 text-sm {$darkMode
                ? 'text-gray-400'
                : 'text-gray-600'}"
        >
            <span class="w-2 h-2 rounded-full bg-green-500"></span>
            <span>v{overview.version}</span>
        </div>
    </div>

    <!-- Stats Grid -->
    <div
        class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4"
    >
        <StatCard
            label="Total Queries"
            value={formatNumber(overview.stats.total_queries)}
            icon="queries"
            change={{ value: 12.5, positive: true }}
        />
        <StatCard
            label="QPS (1min)"
            value={overview.stats.qps_1min.toFixed(1)}
            icon="qps"
            change={{ value: 5.2, positive: true }}
        />
        <StatCard
            label="Cache Hit Rate"
            value={overview.stats.cache_hit_rate.toFixed(1)}
            suffix="%"
            icon="cache"
            change={{ value: 2.1, positive: true }}
        />
        <StatCard
            label="Avg Latency"
            value={overview.stats.avg_response_time_ms.toFixed(1)}
            suffix="ms"
            icon="latency"
            change={{ value: 3.5, positive: false }}
        />
        <StatCard
            label="Uptime"
            value={formatUptime(overview.uptime_seconds)}
            icon="uptime"
        />
        <StatCard
            label="Active Alerts"
            value={overview.recent_alerts}
            icon="alerts"
        />
    </div>

    <!-- QPS Chart -->
    <QpsChart data={qpsData} title="QPS Trend (Last Hour)" />

    <!-- Bottom Grid: Upstream Health + Alerts -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <UpstreamHealthCard {upstreams} />
        <AlertsList alerts={$alerts} limit={5} />
    </div>

    <!-- Upstream Summary Cards -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div class="card p-4 flex items-center justify-between">
            <div>
                <div
                    class="text-2xl font-bold {$darkMode
                        ? 'text-white'
                        : 'text-gray-900'}"
                >
                    {overview.upstream_summary.total}
                </div>
                <div
                    class="text-sm {$darkMode
                        ? 'text-gray-400'
                        : 'text-gray-600'}"
                >
                    Total Upstreams
                </div>
            </div>
            <div
                class="w-12 h-12 rounded-full flex items-center justify-center {$darkMode
                    ? 'bg-gray-700/50'
                    : 'bg-gray-100'}"
            >
                <svg
                    class="w-6 h-6 {$darkMode
                        ? 'text-gray-400'
                        : 'text-gray-500'}"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                >
                    <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"
                    />
                </svg>
            </div>
        </div>

        <div class="card p-4 flex items-center justify-between">
            <div>
                <div
                    class="text-2xl font-bold {$darkMode
                        ? 'text-green-400'
                        : 'text-green-600'}"
                >
                    {overview.upstream_summary.healthy}
                </div>
                <div
                    class="text-sm {$darkMode
                        ? 'text-gray-400'
                        : 'text-gray-600'}"
                >
                    Healthy
                </div>
            </div>
            <div
                class="w-12 h-12 rounded-full flex items-center justify-center {$darkMode
                    ? 'bg-green-900/30'
                    : 'bg-green-100'}"
            >
                <svg
                    class="w-6 h-6 {$darkMode
                        ? 'text-green-400'
                        : 'text-green-600'}"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                >
                    <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M5 13l4 4L19 7"
                    />
                </svg>
            </div>
        </div>

        <div class="card p-4 flex items-center justify-between">
            <div>
                <div
                    class="text-2xl font-bold {$darkMode
                        ? 'text-yellow-400'
                        : 'text-yellow-600'}"
                >
                    {overview.upstream_summary.degraded}
                </div>
                <div
                    class="text-sm {$darkMode
                        ? 'text-gray-400'
                        : 'text-gray-600'}"
                >
                    Degraded
                </div>
            </div>
            <div
                class="w-12 h-12 rounded-full flex items-center justify-center {$darkMode
                    ? 'bg-yellow-900/30'
                    : 'bg-yellow-100'}"
            >
                <svg
                    class="w-6 h-6 {$darkMode
                        ? 'text-yellow-400'
                        : 'text-yellow-600'}"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                >
                    <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                    />
                </svg>
            </div>
        </div>

        <div class="card p-4 flex items-center justify-between">
            <div>
                <div
                    class="text-2xl font-bold {$darkMode
                        ? 'text-red-400'
                        : 'text-red-600'}"
                >
                    {overview.upstream_summary.down}
                </div>
                <div
                    class="text-sm {$darkMode
                        ? 'text-gray-400'
                        : 'text-gray-600'}"
                >
                    Down
                </div>
            </div>
            <div
                class="w-12 h-12 rounded-full flex items-center justify-center {$darkMode
                    ? 'bg-red-900/30'
                    : 'bg-red-100'}"
            >
                <svg
                    class="w-6 h-6 {$darkMode
                        ? 'text-red-400'
                        : 'text-red-600'}"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                >
                    <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M6 18L18 6M6 6l12 12"
                    />
                </svg>
            </div>
        </div>
    </div>
</div>
