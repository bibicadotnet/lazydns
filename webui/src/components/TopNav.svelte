<script lang="ts">
    import { link } from "svelte-spa-router";
    import active from "svelte-spa-router/active";
    import { topNavCollapsed } from "../lib/stores";

    const navItems = [
        { path: "/", icon: "dashboard", label: "Dashboard" },
        { path: "/audit", icon: "logs", label: "Audit Logs" },
        { path: "/metrics", icon: "chart", label: "Metrics" },
        { path: "/admin", icon: "settings", label: "Admin" },
    ];

    function toggleNav() {
        topNavCollapsed.update((v) => !v);
    }
</script>

<nav
    class="fixed top-0 left-0 right-0 h-16 bg-gray-900 border-b border-gray-800 flex items-center px-4 gap-4 z-40"
>
    <!-- Logo -->
    <div class="flex items-center gap-3 flex-shrink-0">
        <div
            class="w-8 h-8 rounded-lg bg-gradient-to-br from-primary-500 to-blue-600 flex items-center justify-center"
        >
            <svg
                class="w-5 h-5 text-white"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
            >
                <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"
                />
            </svg>
        </div>
        <span class="text-lg font-bold text-gradient hidden sm:inline"
            >LazyDNS</span
        >
    </div>

    <!-- Navigation Items -->
    <div
        class="flex items-center gap-1 transition-all duration-300 overflow-hidden"
        class:w-auto={!$topNavCollapsed}
        class:w-0={$topNavCollapsed}
    >
        {#each navItems as item}
            <a
                href={item.path}
                use:link
                use:active={{ path: item.path, className: "nav-link-active" }}
                class="nav-link-top whitespace-nowrap"
                title={item.label}
            >
                {#if item.icon === "dashboard"}
                    <svg
                        class="w-5 h-5 flex-shrink-0"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                    >
                        <path
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            stroke-width="2"
                            d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z"
                        />
                    </svg>
                {:else if item.icon === "logs"}
                    <svg
                        class="w-5 h-5 flex-shrink-0"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                    >
                        <path
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            stroke-width="2"
                            d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                        />
                    </svg>
                {:else if item.icon === "chart"}
                    <svg
                        class="w-5 h-5 flex-shrink-0"
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
                {:else if item.icon === "settings"}
                    <svg
                        class="w-5 h-5 flex-shrink-0"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                    >
                        <path
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            stroke-width="2"
                            d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
                        />
                        <path
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            stroke-width="2"
                            d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                        />
                    </svg>
                {/if}
                {#if !$topNavCollapsed}
                    <span class="hidden md:inline text-sm">{item.label}</span>
                {/if}
            </a>
        {/each}
    </div>

    <!-- Spacer -->
    <div class="flex-1" />

    <!-- Toggle Button -->
    <button
        on:click={toggleNav}
        class="flex items-center justify-center p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
        title={$topNavCollapsed ? "Expand menu" : "Collapse menu"}
    >
        <svg
            class="w-5 h-5 transition-transform duration-300"
            class:rotate-180={!$topNavCollapsed}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
        >
            <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M4 6h16M4 12h16M4 18h16"
            />
        </svg>
    </button>
</nav>

<style>
    :global(.nav-link-top) {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.5rem 0.75rem;
        border-radius: 0.5rem;
        color: #9ca3af;
        transition: all 0.3s ease;
        font-size: 0.875rem;
    }

    :global(.nav-link-top:hover) {
        color: white;
        background-color: #1f2937;
    }

    :global(.nav-link-top.nav-link-active) {
        color: white;
        background: linear-gradient(
            to right,
            rgba(var(--primary-500), 0.2),
            rgba(59, 130, 246, 0.2)
        );
        border: 1px solid rgba(var(--primary-500), 0.3);
    }
</style>
