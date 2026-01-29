<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import StatCard from "../components/StatCard.svelte";
  import UpstreamHealthCard from "../components/UpstreamHealthCard.svelte";
  import AlertsList from "../components/AlertsList.svelte";
  import QpsChart from "../components/QpsChart.svelte";
  import {
    api,
    type DashboardOverviewResponse,
    type UpstreamHealthItem,
    type Alert,
  } from "../lib/api";
  import { formatUptime, formatNumber } from "../lib/utils";
  import { alerts as alertsStore, darkMode } from "../lib/stores";
  import type { UpstreamHealth, TimeSeriesPoint } from "../lib/types";

  // Reactive state
  let loading = true;
  let error: string | null = null;
  let overview: DashboardOverviewResponse | null = null;
  let upstreams: UpstreamHealth[] = [];
  let qpsData: TimeSeriesPoint[] = [];
  let currentQps = 0;
  let recentAlerts: Alert[] = [];

  // Computed upstream summary
  $: upstreamSummary = {
    total: upstreams.length,
    healthy: upstreams.filter((u) => u.status === "healthy").length,
    degraded: upstreams.filter((u) => u.status === "degraded").length,
    down: upstreams.filter((u) => u.status === "down").length,
  };

  // Convert API upstream to UI format
  function convertUpstream(item: UpstreamHealthItem): UpstreamHealth {
    return {
      name: item.tag || item.address,
      address: item.address,
      status:
        item.status === "healthy"
          ? "healthy"
          : item.status === "degraded"
            ? "degraded"
            : "down",
      success_rate: item.success_rate,
      avg_latency_ms: item.avg_response_time_ms,
      total_requests: item.queries,
      failed_requests: item.failures,
      last_success_at: item.last_success,
      last_failure_at: null,
    };
  }

  async function fetchData() {
    try {
      const [overviewRes, upstreamRes, qpsRes, alertsRes] = await Promise.all([
        api.getDashboardOverview(),
        api.getUpstreamHealth(),
        api.getQpsHistory(),
        api.getRecentAlerts().catch(() => ({ alerts: [], total: 0 })),
      ]);

      overview = overviewRes;
      upstreams = upstreamRes.upstreams.map(convertUpstream);
      qpsData = qpsRes.points;
      currentQps = qpsRes.current_qps;
      recentAlerts = alertsRes.alerts || [];

      // Update global store with real alerts
      alertsStore.set(recentAlerts);

      error = null;
    } catch (e) {
      error = e instanceof Error ? e.message : "Failed to fetch data";
      console.error("Dashboard fetch error:", e);
    } finally {
      loading = false;
    }
  }

  let refreshInterval: ReturnType<typeof setInterval>;

  onMount(() => {
    fetchData();
    // Refresh every 5 seconds
    refreshInterval = setInterval(fetchData, 5000);
  });

  onDestroy(() => {
    if (refreshInterval) {
      clearInterval(refreshInterval);
    }
  });
</script>

<div class="space-y-6">
  <!-- Page Header -->
  <div class="flex items-center justify-between">
    <div>
      <h1
        class="text-2xl font-bold {$darkMode ? 'text-white' : 'text-gray-900'}"
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
      {#if loading}
        <span class="w-2 h-2 rounded-full bg-yellow-500 animate-pulse"></span>
        <span>Loading...</span>
      {:else if error}
        <span class="w-2 h-2 rounded-full bg-red-500"></span>
        <span>Error</span>
      {:else}
        <span class="w-2 h-2 rounded-full bg-green-500"></span>
        <span>{overview?.status || "running"}</span>
      {/if}
    </div>
  </div>

  {#if error}
    <div class="card p-4 bg-red-500/10 border border-red-500/20 text-red-400">
      <p>Error: {error}</p>
      <button
        class="mt-2 px-4 py-2 bg-red-500/20 hover:bg-red-500/30 rounded"
        on:click={fetchData}
      >
        Retry
      </button>
    </div>
  {:else}
    <!-- Stats Grid -->
    <div
      class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4"
    >
      <StatCard
        label="Total Queries"
        value={formatNumber(overview?.metrics.total_queries ?? 0)}
        icon="queries"
      />
      <StatCard label="QPS" value={currentQps.toFixed(1)} icon="qps" />
      <StatCard
        label="Cache Hit Rate"
        value={(overview?.metrics.cache_hit_rate ?? 0).toFixed(1)}
        suffix="%"
        icon="cache"
      />
      <StatCard
        label="Unique Domains"
        value={formatNumber(overview?.metrics.unique_domains ?? 0)}
        icon="latency"
      />
      <StatCard
        label="Uptime"
        value={formatUptime(overview?.uptime_secs ?? 0)}
        icon="uptime"
      />
      <StatCard
        label="Active Alerts"
        value={overview?.recent_alerts ?? 0}
        icon="alerts"
      />
    </div>

    <!-- QPS Chart -->
    <QpsChart data={qpsData} title="QPS Trend (Last Hour)" />

    <!-- Bottom Grid: Upstream Health + Alerts -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <UpstreamHealthCard {upstreams} />
      <AlertsList alerts={recentAlerts} limit={5} />
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
            {upstreamSummary.total}
          </div>
          <div class="text-sm {$darkMode ? 'text-gray-400' : 'text-gray-600'}">
            Total Upstreams
          </div>
        </div>
        <div
          class="w-12 h-12 rounded-full flex items-center justify-center {$darkMode
            ? 'bg-gray-700/50'
            : 'bg-gray-100'}"
        >
          <svg
            class="w-6 h-6 {$darkMode ? 'text-gray-400' : 'text-gray-500'}"
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
            {upstreamSummary.healthy}
          </div>
          <div class="text-sm {$darkMode ? 'text-gray-400' : 'text-gray-600'}">
            Healthy
          </div>
        </div>
        <div
          class="w-12 h-12 rounded-full flex items-center justify-center {$darkMode
            ? 'bg-green-900/30'
            : 'bg-green-100'}"
        >
          <svg
            class="w-6 h-6 {$darkMode ? 'text-green-400' : 'text-green-600'}"
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
            {upstreamSummary.degraded}
          </div>
          <div class="text-sm {$darkMode ? 'text-gray-400' : 'text-gray-600'}">
            Degraded
          </div>
        </div>
        <div
          class="w-12 h-12 rounded-full flex items-center justify-center {$darkMode
            ? 'bg-yellow-900/30'
            : 'bg-yellow-100'}"
        >
          <svg
            class="w-6 h-6 {$darkMode ? 'text-yellow-400' : 'text-yellow-600'}"
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
            {upstreamSummary.down}
          </div>
          <div class="text-sm {$darkMode ? 'text-gray-400' : 'text-gray-600'}">
            Down
          </div>
        </div>
        <div
          class="w-12 h-12 rounded-full flex items-center justify-center {$darkMode
            ? 'bg-red-900/30'
            : 'bg-red-100'}"
        >
          <svg
            class="w-6 h-6 {$darkMode ? 'text-red-400' : 'text-red-600'}"
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
  {/if}
</div>
