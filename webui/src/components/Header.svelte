<script lang="ts">
    import {
        unacknowledgedAlerts,
        isLiveMode,
        alerts,
        notifications,
    } from "../lib/stores";
    import { getSeverityColor } from "../lib/mock";

    let showAlertDropdown = false;

    function toggleLiveMode() {
        isLiveMode.update((v) => !v);
        notifications.add({
            type: "info",
            message: $isLiveMode
                ? "Live updates disabled"
                : "Live updates enabled",
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
    class="h-16 bg-gray-900 border-b border-gray-800 flex items-center justify-between px-6 sticky top-0 z-30"
>
    <!-- Page Title / Breadcrumb -->
    <div class="flex items-center gap-4">
        <h1 class="text-xl font-semibold text-white">DNS Server Management</h1>
    </div>

    <!-- Right Side Actions -->
    <div class="flex items-center gap-4">
        <!-- Live Mode Toggle -->
        <button
            on:click={toggleLiveMode}
            class="flex items-center gap-2 px-3 py-1.5 rounded-lg transition-colors border {$isLiveMode
                ? 'bg-green-900 bg-opacity-30 text-green-400 border-green-700'
                : 'bg-gray-800 text-gray-400 border-gray-700'}"
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
                class="relative p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
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
                    class="absolute right-0 mt-2 w-96 bg-gray-800 border border-gray-700 rounded-xl shadow-2xl overflow-hidden"
                >
                    <div
                        class="px-4 py-3 border-b border-gray-700 flex items-center justify-between"
                    >
                        <h3 class="font-semibold text-white">Alerts</h3>
                        <span class="text-sm text-gray-400"
                            >{$unacknowledgedAlerts} unread</span
                        >
                    </div>
                    <div class="max-h-96 overflow-y-auto">
                        {#each $alerts.slice(0, 10) as alert}
                            <div
                                class="px-4 py-3 border-b border-gray-700/50 hover:bg-gray-700/50 transition-colors"
                                class:opacity-60={alert.acknowledged}
                            >
                                <div
                                    class="flex items-start justify-between gap-3"
                                >
                                    <div class="flex-1 min-w-0">
                                        <div class="flex items-center gap-2">
                                            <span
                                                class="text-xs font-medium uppercase {getSeverityColor(
                                                    alert.severity,
                                                )}"
                                            >
                                                {alert.severity}
                                            </span>
                                            <span class="text-xs text-gray-500">
                                                {new Date(
                                                    alert.timestamp,
                                                ).toLocaleTimeString()}
                                            </span>
                                        </div>
                                        <p
                                            class="text-sm text-gray-200 mt-1 truncate"
                                        >
                                            {alert.message}
                                        </p>
                                    </div>
                                    {#if !alert.acknowledged}
                                        <button
                                            on:click|stopPropagation={() =>
                                                acknowledgeAlert(alert.id)}
                                            class="text-gray-400 hover:text-white p-1"
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
                        class="block px-4 py-3 text-center text-sm text-primary-400 hover:text-primary-300 hover:bg-gray-700/50 transition-colors"
                    >
                        View all alerts
                    </a>
                </div>
            {/if}
        </div>

        <!-- User Menu -->
        <div class="flex items-center gap-3 pl-4 border-l border-gray-700">
            <div
                class="w-8 h-8 rounded-full bg-gradient-to-br from-primary-500 to-purple-600 flex items-center justify-center text-white font-medium text-sm"
            >
                A
            </div>
            <span class="text-sm text-gray-300">Admin</span>
        </div>
    </div>
</header>
