<script lang="ts">
  import type { Alert } from "../lib/types";
  import { getSeverityColor, formatTimeAgo } from "../lib/utils";
  import { darkMode } from "../lib/stores";

  export let alerts: Alert[];
  export let limit: number = 5;

  $: displayedAlerts = alerts.slice(0, limit);
</script>

<div class="card h-full flex flex-col">
  <div class="card-header flex items-center justify-between">
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
          d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
        />
      </svg>
      Recent Alerts
    </h3>
    <span class="text-sm {$darkMode ? 'text-gray-400' : 'text-gray-500'}"
      >{alerts.length} total</span
    >
  </div>

  <div
    class="flex-1 overflow-y-auto divide-y {$darkMode
      ? 'divide-gray-700/50'
      : 'divide-gray-200'}"
  >
    {#if displayedAlerts.length === 0}
      <div
        class="p-8 text-center {$darkMode ? 'text-gray-500' : 'text-gray-400'}"
      >
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
            d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
        <p>No alerts</p>
      </div>
    {:else}
      {#each displayedAlerts as alert}
        <div
          class="px-5 py-3 transition-colors border-l-4 {$darkMode
            ? 'hover:bg-gray-700/30'
            : 'hover:bg-gray-50'}"
          class:border-blue-500={alert.severity === "info"}
          class:border-yellow-500={alert.severity === "warning"}
          class:border-red-500={alert.severity === "critical"}
          class:opacity-60={alert.acknowledged}
        >
          <div class="flex items-start justify-between gap-3">
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2 mb-1">
                <span
                  class="text-xs font-semibold uppercase tracking-wide {getSeverityColor(
                    alert.severity,
                  )}"
                >
                  {alert.severity}
                </span>
                <span
                  class="text-xs {$darkMode
                    ? 'text-gray-500'
                    : 'text-gray-400'}"
                >
                  {formatTimeAgo(alert.timestamp)}
                </span>
              </div>
              <p
                class="text-sm {$darkMode ? 'text-gray-200' : 'text-gray-700'}"
              >
                {alert.message}
              </p>
            </div>
            {#if alert.acknowledged}
              <svg
                class="w-4 h-4 text-green-500 flex-shrink-0"
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
            {/if}
          </div>
        </div>
      {/each}
    {/if}
  </div>

  <div
    class="px-5 py-3 border-t {$darkMode
      ? 'border-gray-700'
      : 'border-gray-200'}"
  >
    <a
      href="#/admin"
      class="text-sm transition-colors {$darkMode
        ? 'text-primary-400 hover:text-primary-300'
        : 'text-primary-600 hover:text-primary-500'}"
    >
      View all alerts →
    </a>
  </div>
</div>
