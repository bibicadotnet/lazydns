<script lang="ts">
  import {
    unacknowledgedAlerts,
    isLiveMode,
    alerts,
    notifications,
    darkMode,
  } from "../lib/stores";
  import { getSeverityColor } from "../lib/utils";

  let showAlertDropdown = false;

  function toggleLiveMode() {
    isLiveMode.update((v) => !v);
    notifications.add({
      type: "info",
      message: $isLiveMode ? "Live updates disabled" : "Live updates enabled",
    });
  }

  function acknowledgeAlert(id: string) {
    alerts.update((list) =>
      list.map((a) => (a.id === id ? { ...a, acknowledged: true } : a)),
    );
  }

  function handleClickOutside(event: MouseEvent) {
    const target = event.target as HTMLElement;
    if (!target.closest(".alert-dropdown")) {
      showAlertDropdown = false;
    }
  }
</script>

<svelte:window on:click={handleClickOutside} />

<header
  class="h-16 border-b flex items-center justify-between px-6 sticky top-0 z-30 transition-colors duration-200 {$darkMode
    ? 'bg-gray-900 border-gray-800'
    : 'bg-white border-gray-200'}"
>
  <!-- Page Title / Breadcrumb -->
  <div class="flex items-center gap-4">
    <h1
      class="text-xl font-semibold {$darkMode ? 'text-white' : 'text-gray-900'}"
    >
      DNS Server Management
    </h1>
  </div>

  <!-- Right Side Actions -->
  <div class="flex items-center gap-4">
    <!-- Live Mode Toggle -->
    <button
      on:click={toggleLiveMode}
      class="flex items-center gap-2 px-3 py-1.5 rounded-lg transition-colors border {$isLiveMode
        ? $darkMode
          ? 'bg-green-900 bg-opacity-30 text-green-400 border-green-700'
          : 'bg-green-50 text-green-700 border-green-300'
        : $darkMode
          ? 'bg-gray-800 text-gray-400 border-gray-700'
          : 'bg-gray-100 text-gray-600 border-gray-300'}"
    >
      <span class="relative flex h-2.5 w-2.5">
        {#if $isLiveMode}
          <span
            class="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"
          ></span>
        {/if}
        <span
          class="relative inline-flex rounded-full h-2.5 w-2.5"
          class:bg-green-400={$isLiveMode}
          class:bg-gray-500={!$isLiveMode}
        ></span>
      </span>
      <span class="text-sm font-medium">
        {$isLiveMode ? "Live" : "Paused"}
      </span>
    </button>

    <!-- Alerts Dropdown -->
    <div class="relative alert-dropdown">
      <button
        on:click|stopPropagation={() =>
          (showAlertDropdown = !showAlertDropdown)}
        class="relative p-2 rounded-lg transition-colors {$darkMode
          ? 'text-gray-400 hover:text-white hover:bg-gray-800'
          : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'}"
      >
        <svg
          class="w-6 h-6"
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
        {#if $unacknowledgedAlerts > 0}
          <span
            class="absolute -top-1 -right-1 w-5 h-5 bg-red-500 rounded-full text-xs font-bold text-white flex items-center justify-center"
          >
            {$unacknowledgedAlerts}
          </span>
        {/if}
      </button>

      {#if showAlertDropdown}
        <div
          class="absolute right-0 mt-2 w-96 rounded-xl shadow-2xl overflow-hidden {$darkMode
            ? 'bg-gray-800 border border-gray-700'
            : 'bg-white border border-gray-200'}"
        >
          <div
            class="px-4 py-3 border-b flex items-center justify-between {$darkMode
              ? 'border-gray-700'
              : 'border-gray-200'}"
          >
            <h3
              class="font-semibold {$darkMode ? 'text-white' : 'text-gray-900'}"
            >
              Alerts
            </h3>
            <span
              class="text-sm {$darkMode ? 'text-gray-400' : 'text-gray-500'}"
              >{$unacknowledgedAlerts} unread</span
            >
          </div>
          <div class="max-h-96 overflow-y-auto">
            {#each $alerts.slice(0, 10) as alert}
              <div
                class="px-4 py-3 border-b transition-colors {$darkMode
                  ? 'border-gray-700/50 hover:bg-gray-700/50'
                  : 'border-gray-100 hover:bg-gray-50'}"
                class:opacity-60={alert.acknowledged}
              >
                <div class="flex items-start justify-between gap-3">
                  <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-2">
                      <span
                        class="text-xs font-medium uppercase {getSeverityColor(
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
                        {new Date(alert.timestamp * 1000).toLocaleTimeString()}
                      </span>
                    </div>
                    <p
                      class="text-sm mt-1 truncate {$darkMode
                        ? 'text-gray-200'
                        : 'text-gray-700'}"
                    >
                      {alert.message}
                    </p>
                  </div>
                  {#if !alert.acknowledged}
                    <button
                      on:click|stopPropagation={() =>
                        acknowledgeAlert(alert.id)}
                      class="p-1 {$darkMode
                        ? 'text-gray-400 hover:text-white'
                        : 'text-gray-500 hover:text-gray-900'}"
                      title="Mark as read"
                    >
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
                          d="M5 13l4 4L19 7"
                        />
                      </svg>
                    </button>
                  {/if}
                </div>
              </div>
            {/each}
          </div>
          <a
            href="#/admin"
            class="block px-4 py-3 text-center text-sm transition-colors {$darkMode
              ? 'text-primary-400 hover:text-primary-300 hover:bg-gray-700/50'
              : 'text-primary-600 hover:text-primary-500 hover:bg-gray-50'}"
          >
            View all alerts
          </a>
        </div>
      {/if}
    </div>

    <!-- User Menu -->
    <div
      class="flex items-center gap-3 pl-4 border-l {$darkMode
        ? 'border-gray-700'
        : 'border-gray-200'}"
    >
      <div
        class="w-8 h-8 rounded-full bg-gradient-to-br from-primary-500 to-purple-600 flex items-center justify-center text-white font-medium text-sm"
      >
        A
      </div>
      <span class="text-sm {$darkMode ? 'text-gray-300' : 'text-gray-700'}"
        >Admin</span
      >
    </div>
  </div>
</header>
