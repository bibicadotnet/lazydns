<script lang="ts">
    import type { QueryLogEntry } from "../lib/types";
    import { darkMode } from "../lib/stores";

    export let logs: QueryLogEntry[];
    export let maxHeight: string = "600px";

    function getRcodeColor(rcode: string | null): string {
        if (!rcode) return $darkMode ? "text-gray-400" : "text-gray-500";
        switch (rcode) {
            case "NOERROR":
                return "text-green-500";
            case "NXDOMAIN":
                return "text-yellow-500";
            case "SERVFAIL":
                return "text-red-500";
            case "REFUSED":
                return "text-red-500";
            default:
                return $darkMode ? "text-gray-400" : "text-gray-500";
        }
    }

    function getProtocolBadge(protocol: string): string {
        switch (protocol.toLowerCase()) {
            case "udp":
                return "badge-gray";
            case "tcp":
                return "badge-info";
            case "tls":
            case "dot":
                return "badge-success";
            case "doh":
            case "https":
                return "badge-warning";
            case "doq":
                return "badge-success";
            default:
                return "badge-gray";
        }
    }

    function formatTime(timestamp: string): string {
        return new Date(timestamp).toLocaleTimeString("en-US", {
            hour12: false,
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
        });
    }

    function truncateDomain(domain: string, maxLen: number = 30): string {
        if (domain.length <= maxLen) return domain;
        return domain.slice(0, maxLen - 3) + "...";
    }
</script>

<div class="table-container overflow-y-auto" style="max-height: {maxHeight}">
    <table class="table">
        <thead class="sticky top-0 z-10">
            <tr>
                <th class="w-24">Time</th>
                <th class="w-28">Client</th>
                <th class="w-16">Proto</th>
                <th>Domain</th>
                <th class="w-16">Type</th>
                <th class="w-24">Result</th>
                <th class="w-20">Latency</th>
                <th class="w-24">Source</th>
            </tr>
        </thead>
        <tbody>
            {#each logs as log (log.query_id + log.timestamp)}
                <tr class="group">
                    <td
                        class="font-mono text-xs {$darkMode
                            ? 'text-gray-400'
                            : 'text-gray-700'}"
                    >
                        {formatTime(log.timestamp)}
                    </td>
                    <td
                        class="font-mono text-xs {$darkMode
                            ? 'text-gray-300'
                            : 'text-gray-700'}"
                    >
                        {log.client_ip || "-"}
                    </td>
                    <td>
                        <span class={getProtocolBadge(log.protocol)}>
                            {log.protocol.toUpperCase()}
                        </span>
                    </td>
                    <td
                        class="font-mono text-sm {$darkMode
                            ? 'text-white'
                            : 'text-gray-900'}"
                        title={log.qname}
                    >
                        {truncateDomain(log.qname)}
                    </td>
                    <td>
                        <span class="badge-info">{log.qtype}</span>
                    </td>
                    <td>
                        <div class="flex items-center gap-2">
                            <span class={getRcodeColor(log.rcode)}>
                                {log.rcode || "-"}
                            </span>
                            {#if log.answer_count !== null && log.answer_count > 0}
                                <span class="text-xs text-gray-500">
                                    ({log.answer_count})
                                </span>
                            {/if}
                        </div>
                    </td>
                    <td class="text-sm">
                        {#if log.response_time_ms !== null}
                            <span
                                class:text-green-400={log.response_time_ms < 20}
                                class:text-yellow-400={log.response_time_ms >=
                                    20 && log.response_time_ms < 50}
                                class:text-red-400={log.response_time_ms >= 50}
                            >
                                {log.response_time_ms}ms
                            </span>
                        {:else}
                            <span class="text-gray-500">-</span>
                        {/if}
                    </td>
                    <td class="text-sm">
                        {#if log.cached}
                            <span class="badge-success">CACHE</span>
                        {:else if log.upstream}
                            <span
                                class={$darkMode
                                    ? "text-gray-400"
                                    : "text-gray-700"}>{log.upstream}</span
                            >
                        {:else}
                            <span
                                class={$darkMode
                                    ? "text-gray-500"
                                    : "text-gray-400"}>-</span
                            >
                        {/if}
                    </td>
                </tr>
            {:else}
                <tr>
                    <td
                        colspan="8"
                        class="text-center py-8 {$darkMode
                            ? 'text-gray-500'
                            : 'text-gray-700'}"
                    >
                        No query logs available
                    </td>
                </tr>
            {/each}
        </tbody>
    </table>
</div>
