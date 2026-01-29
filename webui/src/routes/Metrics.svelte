<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import TopDomainsChart from "../components/TopDomainsChart.svelte";
  import TopClientsChart from "../components/TopClientsChart.svelte";
  import LatencyDistributionChart from "../components/LatencyDistributionChart.svelte";
  import UpstreamPerformanceTable from "../components/UpstreamPerformanceTable.svelte";
  import { api, type UpstreamHealthItem } from "../lib/api";
  import { selectedTimeWindow, darkMode } from "../lib/stores";
  import type {
    TimeWindow,
    TopDomain,
    TopClient,
    UpstreamHealth,
    LatencyDistribution,
  } from "../lib/types";

  const timeWindows: { value: TimeWindow; label: string }[] = [
    { value: "1m", label: "1 Minute" },
    { value: "5m", label: "5 Minutes" },
    { value: "1h", label: "1 Hour" },
    { value: "24h", label: "24 Hours" },
  ];

  // Reactive state
  let topDomains: TopDomain[] = [];
  let topClients: TopClient[] = [];
  let upstreams: UpstreamHealth[] = [];
  let latencyData: LatencyDistribution[] = [];
  let latencyPercentiles = {
    p50: 0,
    p95: 0,
    p99: 0,
    max: 0,
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
      const [domainsRes, clientsRes, upstreamRes, latencyRes] =
        await Promise.all([
          api.getTopDomains(10),
          api.getTopClients(10),
          api.getUpstreamHealth(),
          api.getLatencyDistribution(),
        ]);

      topDomains = domainsRes.domains.map((d) => ({
        domain: d.key,
        count: d.count,
        percentage: 0, // Will be calculated in component
      }));

      topClients = clientsRes.clients.map((c) => ({
        ip: c.key,
        queries: c.count,
        blocked: 0,
        rate_limited: 0,
        avg_response_ms: 0,
      }));

      upstreams = upstreamRes.upstreams.map(convertUpstream);

      // Convert latency buckets
      latencyData = latencyRes.distribution.buckets.map((b) => ({
        bucket: b.label,
        count: b.count,
        percentage:
          latencyRes.distribution.total > 0
            ? (b.count / latencyRes.distribution.total) * 100
            : 0,
      }));

      latencyPercentiles = {
        p50: latencyRes.distribution.p50_ms,
        p95: latencyRes.distribution.p95_ms,
        p99: latencyRes.distribution.p99_ms,
        max: latencyRes.distribution.max_ms,
      };
    } catch (e) {
      console.error("Metrics fetch error:", e);
    }
  }

  let refreshInterval: ReturnType<typeof setInterval>;

  onMount(() => {
    fetchData();
    // Refresh every 10 seconds
    refreshInterval = setInterval(fetchData, 10000);
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
        Metrics
      </h1>
      <p class="{$darkMode ? 'text-gray-400' : 'text-gray-600'} mt-1">
        DNS performance analytics and statistics
      </p>
    </div>

    <!-- Time Window Selector -->
    <div
      class="flex items-center gap-2 rounded-lg p-1 {$darkMode
        ? 'bg-gray-800'
        : 'bg-gray-100'}"
    >
      {#each timeWindows as tw}
        <button
          on:click={() => ($selectedTimeWindow = tw.value)}
          class="px-4 py-2 rounded-lg text-sm font-medium transition-all"
          class:bg-primary-600={$selectedTimeWindow === tw.value}
          class:text-white={$selectedTimeWindow === tw.value}
          class:text-gray-400={$selectedTimeWindow !== tw.value && $darkMode}
          class:text-gray-600={$selectedTimeWindow !== tw.value && !$darkMode}
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
          <div class="text-sm {$darkMode ? 'text-gray-400' : 'text-gray-500'}">
            P50 Latency
          </div>
          <div
            class="text-2xl font-bold {$darkMode
              ? 'text-green-400'
              : 'text-green-600'} mt-1"
          >
            {latencyPercentiles.p50}ms
          </div>
        </div>
        <div
          class="w-12 h-12 rounded-full flex items-center justify-center {$darkMode
            ? 'bg-green-900/30'
            : 'bg-green-100'}"
        >
          <span
            class="{$darkMode ? 'text-green-400' : 'text-green-600'} font-bold"
            >50</span
          >
        </div>
      </div>
    </div>

    <div class="card p-4">
      <div class="flex items-center justify-between">
        <div>
          <div class="text-sm {$darkMode ? 'text-gray-400' : 'text-gray-500'}">
            P95 Latency
          </div>
          <div
            class="text-2xl font-bold {$darkMode
              ? 'text-yellow-400'
              : 'text-yellow-600'} mt-1"
          >
            {latencyPercentiles.p95}ms
          </div>
        </div>
        <div
          class="w-12 h-12 rounded-full flex items-center justify-center {$darkMode
            ? 'bg-yellow-900/30'
            : 'bg-yellow-100'}"
        >
          <span
            class="{$darkMode
              ? 'text-yellow-400'
              : 'text-yellow-600'} font-bold">95</span
          >
        </div>
      </div>
    </div>

    <div class="card p-4">
      <div class="flex items-center justify-between">
        <div>
          <div class="text-sm {$darkMode ? 'text-gray-400' : 'text-gray-500'}">
            P99 Latency
          </div>
          <div
            class="text-2xl font-bold {$darkMode
              ? 'text-orange-400'
              : 'text-orange-600'} mt-1"
          >
            {latencyPercentiles.p99}ms
          </div>
        </div>
        <div
          class="w-12 h-12 rounded-full flex items-center justify-center {$darkMode
            ? 'bg-orange-900/30'
            : 'bg-orange-100'}"
        >
          <span
            class="{$darkMode
              ? 'text-orange-400'
              : 'text-orange-600'} font-bold">99</span
          >
        </div>
      </div>
    </div>

    <div class="card p-4">
      <div class="flex items-center justify-between">
        <div>
          <div class="text-sm {$darkMode ? 'text-gray-400' : 'text-gray-500'}">
            Max Latency
          </div>
          <div
            class="text-2xl font-bold {$darkMode
              ? 'text-red-400'
              : 'text-red-600'} mt-1"
          >
            {latencyPercentiles.max}ms
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
      domains={topDomains}
      title="Top 10 Domains ({$selectedTimeWindow})"
    />
    <TopClientsChart clients={topClients} />
  </div>

  <!-- Latency Distribution -->
  <LatencyDistributionChart data={latencyData} />

  <!-- Upstream Performance Table -->
  <UpstreamPerformanceTable {upstreams} />

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
              <div class="w-24 bg-gray-700 rounded-full h-2 overflow-hidden">
                <div
                  class="h-full rounded-full {item.color}"
                  style="width: {(item.count / 456789) * 100}%"
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
              <span class="text-sm text-gray-400">{item.pct}%</span>
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
              <div class="w-24 bg-gray-700 rounded-full h-2 overflow-hidden">
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
