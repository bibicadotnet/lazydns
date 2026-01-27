<script lang="ts">
    import QueryLogTable from "../components/QueryLogTable.svelte";
    import SecurityEventList from "../components/SecurityEventList.svelte";
    import { queryLogs, securityEvents, isLiveMode } from "../lib/stores";

    type TabType = "queries" | "security";
    let activeTab: TabType = "queries";
    let searchQuery = "";
    let autoScroll = true;

    // Filters
    let filterRcode = "all";
    let filterProtocol = "all";
    let filterEventType = "all";

    $: filteredQueryLogs = $queryLogs.filter((log) => {
        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            if (
                !log.qname.toLowerCase().includes(q) &&
                !log.client_ip?.toLowerCase().includes(q)
            ) {
                return false;
            }
        }
        if (filterRcode !== "all" && log.rcode !== filterRcode) return false;
        if (
            filterProtocol !== "all" &&
            log.protocol.toLowerCase() !== filterProtocol
        )
            return false;
        return true;
    });

    $: filteredSecurityEvents = $securityEvents.filter((event) => {
        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            if (
                !event.domain?.toLowerCase().includes(q) &&
                !event.client_ip?.toLowerCase().includes(q) &&
                !event.message.toLowerCase().includes(q)
            ) {
                return false;
            }
        }
        if (filterEventType !== "all" && event.event_type !== filterEventType)
            return false;
        return true;
    });

    function exportCsv() {
        // Simplified CSV export
        const headers = [
            "Timestamp",
            "Client",
            "Protocol",
            "Domain",
            "Type",
            "Result",
            "Latency",
        ];
        const rows = filteredQueryLogs.map((log) => [
            log.timestamp,
            log.client_ip || "",
            log.protocol,
            log.qname,
            log.qtype,
            log.rcode || "",
            log.response_time_ms?.toString() || "",
        ]);

        const csv = [headers.join(","), ...rows.map((r) => r.join(","))].join(
            "\n",
        );
        const blob = new Blob([csv], { type: "text/csv" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `query-logs-${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
    }
</script>

<div class="space-y-6">
    <!-- Page Header -->
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold text-white">Audit Logs</h1>
            <p class="text-gray-400 mt-1">
                Real-time query and security event monitoring
            </p>
        </div>
    </div>

    <!-- Tabs -->
    <div class="flex items-center gap-1 border-b border-gray-700">
        <button
            on:click={() => (activeTab = "queries")}
            class="px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-px"
            class:border-primary-500={activeTab === "queries"}
            class:text-primary-400={activeTab === "queries"}
            class:border-transparent={activeTab !== "queries"}
            class:text-gray-400={activeTab !== "queries"}
            class:hover:text-gray-200={activeTab !== "queries"}
        >
            <span class="flex items-center gap-2">
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
                        d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                    />
                </svg>
                Query Logs
                <span class="px-2 py-0.5 rounded-full bg-gray-700 text-xs">
                    {$queryLogs.length}
                </span>
            </span>
        </button>
        <button
            on:click={() => (activeTab = "security")}
            class="px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-px"
            class:border-primary-500={activeTab === "security"}
            class:text-primary-400={activeTab === "security"}
            class:border-transparent={activeTab !== "security"}
            class:text-gray-400={activeTab !== "security"}
            class:hover:text-gray-200={activeTab !== "security"}
        >
            <span class="flex items-center gap-2">
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
                        d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                    />
                </svg>
                Security Events
                <span
                    class="px-2 py-0.5 rounded-full bg-yellow-900/50 text-yellow-400 text-xs"
                >
                    {$securityEvents.length}
                </span>
            </span>
        </button>
    </div>

    <!-- Toolbar -->
    <div class="card p-4">
        <div class="flex flex-wrap items-center gap-4">
            <!-- Search -->
            <div class="flex-1 min-w-[200px]">
                <div class="relative">
                    <svg
                        class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                    >
                        <path
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            stroke-width="2"
                            d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
                        />
                    </svg>
                    <input
                        type="text"
                        placeholder="Search domains, IPs..."
                        bind:value={searchQuery}
                        class="input pl-10"
                    />
                </div>
            </div>

            {#if activeTab === "queries"}
                <!-- RCODE Filter -->
                <select bind:value={filterRcode} class="select w-36">
                    <option value="all">All Results</option>
                    <option value="NOERROR">NOERROR</option>
                    <option value="NXDOMAIN">NXDOMAIN</option>
                    <option value="SERVFAIL">SERVFAIL</option>
                    <option value="REFUSED">REFUSED</option>
                </select>

                <!-- Protocol Filter -->
                <select bind:value={filterProtocol} class="select w-36">
                    <option value="all">All Protocols</option>
                    <option value="udp">UDP</option>
                    <option value="tcp">TCP</option>
                    <option value="tls">TLS (DoT)</option>
                    <option value="doh">DoH</option>
                    <option value="doq">DoQ</option>
                </select>
            {:else}
                <!-- Event Type Filter -->
                <select bind:value={filterEventType} class="select w-44">
                    <option value="all">All Events</option>
                    <option value="rate_limit_exceeded">Rate Limited</option>
                    <option value="blocked_domain_query">Blocked Domain</option>
                    <option value="upstream_failure">Upstream Failure</option>
                    <option value="acl_denied">ACL Denied</option>
                    <option value="malformed_query">Malformed Query</option>
                    <option value="query_timeout">Query Timeout</option>
                </select>
            {/if}

            <!-- Live Toggle -->
            <label class="flex items-center gap-2 cursor-pointer">
                <input
                    type="checkbox"
                    bind:checked={$isLiveMode}
                    class="w-4 h-4 rounded border-gray-600 bg-gray-700 text-primary-500 focus:ring-primary-500"
                />
                <span class="text-sm text-gray-300">Live Stream</span>
            </label>

            <!-- Auto Scroll -->
            <label class="flex items-center gap-2 cursor-pointer">
                <input
                    type="checkbox"
                    bind:checked={autoScroll}
                    class="w-4 h-4 rounded border-gray-600 bg-gray-700 text-primary-500 focus:ring-primary-500"
                />
                <span class="text-sm text-gray-300">Auto-scroll</span>
            </label>

            <!-- Export Button -->
            {#if activeTab === "queries"}
                <button on:click={exportCsv} class="btn-secondary text-sm">
                    <span class="flex items-center gap-2">
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
                                d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                            />
                        </svg>
                        Export CSV
                    </span>
                </button>
            {/if}
        </div>

        <!-- Stats bar -->
        <div
            class="mt-4 pt-4 border-t border-gray-700 flex items-center gap-6 text-sm text-gray-400"
        >
            {#if activeTab === "queries"}
                <span
                    >Showing <strong class="text-white"
                        >{filteredQueryLogs.length}</strong
                    >
                    of {$queryLogs.length} queries</span
                >
            {:else}
                <span
                    >Showing <strong class="text-white"
                        >{filteredSecurityEvents.length}</strong
                    >
                    of {$securityEvents.length} events</span
                >
            {/if}
            {#if $isLiveMode}
                <span class="flex items-center gap-1">
                    <span
                        class="w-2 h-2 rounded-full bg-green-400 animate-pulse"
                    ></span>
                    Streaming live data
                </span>
            {/if}
        </div>
    </div>

    <!-- Content -->
    <div class="card">
        {#if activeTab === "queries"}
            <QueryLogTable
                logs={filteredQueryLogs}
                maxHeight="calc(100vh - 400px)"
            />
        {:else}
            <div class="p-4">
                <SecurityEventList
                    events={filteredSecurityEvents}
                    maxHeight="calc(100vh - 400px)"
                />
            </div>
        {/if}
    </div>
</div>
