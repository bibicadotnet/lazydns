<script lang="ts">
  import { darkMode } from "../lib/stores";

  export let label: string;
  export let value: string | number;
  export let icon:
    | "queries"
    | "qps"
    | "cache"
    | "latency"
    | "uptime"
    | "alerts" = "queries";
  export let change: { value: number; positive: boolean } | null = null;
  export let suffix: string = "";
</script>

<div class="stat-card">
  <div class="flex items-start justify-between">
    <span class="stat-label">{label}</span>
    <div
      class="w-10 h-10 rounded-lg flex items-center justify-center {$darkMode
        ? 'bg-gray-700/50'
        : 'bg-gray-100'}"
    >
      {#if icon === "queries"}
        <svg
          class="w-5 h-5 {$darkMode ? 'text-primary-400' : 'text-primary-600'}"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
      {:else if icon === "qps"}
        <svg
          class="w-5 h-5 {$darkMode ? 'text-green-400' : 'text-green-600'}"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"
          />
        </svg>
      {:else if icon === "cache"}
        <svg
          class="w-5 h-5 {$darkMode ? 'text-yellow-400' : 'text-yellow-600'}"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"
          />
        </svg>
      {:else if icon === "latency"}
        <svg
          class="w-5 h-5 {$darkMode ? 'text-purple-400' : 'text-purple-600'}"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
      {:else if icon === "uptime"}
        <svg
          class="w-5 h-5 {$darkMode ? 'text-blue-400' : 'text-blue-600'}"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z"
          />
        </svg>
      {:else if icon === "alerts"}
        <svg
          class="w-5 h-5 {$darkMode ? 'text-red-400' : 'text-red-600'}"
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
      {/if}
    </div>
  </div>

  <div class="mt-auto">
    <span class="stat-value">{value}{suffix}</span>

    {#if change}
      <div class={change.positive ? "stat-change-up" : "stat-change-down"}>
        {#if change.positive}
          <svg
            class="w-4 h-4"
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
        {:else}
          <svg
            class="w-4 h-4"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M19 14l-7 7m0 0l-7-7m7 7V3"
            />
          </svg>
        {/if}
        <span>{Math.abs(change.value)}% vs last hour</span>
      </div>
    {/if}
  </div>
</div>
