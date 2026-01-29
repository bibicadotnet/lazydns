<script lang="ts">
  import type { UpstreamHealth } from "../lib/types";
  import { formatTimeAgo } from "../lib/utils";
  import { darkMode } from "../lib/stores";

  export let upstreams: UpstreamHealth[];
</script>

<div class="card">
  <div class="card-header">
    <h3
      class="font-semibold {$darkMode
        ? 'text-white'
        : 'text-gray-900'} flex items-center gap-2"
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
          d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
        />
      </svg>
      Upstream Performance
    </h3>
  </div>

  <div class="table-container">
    <table class="table">
      <thead>
        <tr>
          <th>Status</th>
          <th>Name</th>
          <th>Address</th>
          <th>Latency</th>
          <th>Success Rate</th>
          <th>Requests</th>
          <th>Failed</th>
          <th>Last Success</th>
          <th>Last Failure</th>
        </tr>
      </thead>
      <tbody>
        {#each upstreams as upstream}
          <tr>
            <td>
              <div class="flex items-center gap-2">
                <div
                  class="w-2.5 h-2.5 rounded-full"
                  class:bg-green-400={upstream.status === "healthy"}
                  class:bg-yellow-400={upstream.status === "degraded"}
                  class:bg-red-400={upstream.status === "down"}
                ></div>
                <span
                  class="text-xs font-medium uppercase"
                  class:text-green-400={upstream.status === "healthy"}
                  class:text-yellow-400={upstream.status === "degraded"}
                  class:text-red-400={upstream.status === "down"}
                >
                  {upstream.status}
                </span>
              </div>
            </td>
            <td class="font-medium {$darkMode ? 'text-white' : 'text-gray-900'}"
              >{upstream.name}</td
            >
            <td
              class="font-mono text-sm {$darkMode
                ? 'text-gray-400'
                : 'text-gray-700'}">{upstream.address}</td
            >
            <td>
              <div class="flex items-center gap-2">
                <div
                  class="w-16 {$darkMode
                    ? 'bg-gray-700'
                    : 'bg-gray-200'} rounded-full h-2 overflow-hidden"
                >
                  <div
                    class="h-full rounded-full transition-all"
                    class:bg-green-500={upstream.avg_latency_ms < 50}
                    class:bg-yellow-500={upstream.avg_latency_ms >= 50 &&
                      upstream.avg_latency_ms < 100}
                    class:bg-red-500={upstream.avg_latency_ms >= 100}
                    style="width: {Math.min(100, upstream.avg_latency_ms / 2)}%"
                  ></div>
                </div>
                <span
                  class="text-sm font-medium"
                  class:text-green-400={upstream.avg_latency_ms < 50}
                  class:text-yellow-400={upstream.avg_latency_ms >= 50 &&
                    upstream.avg_latency_ms < 100}
                  class:text-red-400={upstream.avg_latency_ms >= 100}
                >
                  {upstream.avg_latency_ms.toFixed(1)}ms
                </span>
              </div>
            </td>
            <td>
              <span
                class="font-medium"
                class:text-green-400={upstream.success_rate >= 99}
                class:text-yellow-400={upstream.success_rate >= 95 &&
                  upstream.success_rate < 99}
                class:text-red-400={upstream.success_rate < 95}
              >
                {upstream.success_rate.toFixed(1)}%
              </span>
            </td>
            <td class={$darkMode ? "text-gray-300" : "text-gray-700"}>
              {upstream.total_requests.toLocaleString()}
            </td>
            <td>
              <span class="text-red-600">
                {upstream.failed_requests.toLocaleString()}
              </span>
            </td>
            <td class="text-sm {$darkMode ? 'text-gray-400' : 'text-gray-700'}">
              {upstream.last_success_at
                ? formatTimeAgo(upstream.last_success_at)
                : "-"}
            </td>
            <td class="text-sm {$darkMode ? 'text-gray-400' : 'text-gray-700'}">
              {upstream.last_failure_at
                ? formatTimeAgo(upstream.last_failure_at)
                : "-"}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>
