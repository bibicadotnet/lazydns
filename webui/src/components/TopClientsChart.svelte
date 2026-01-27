<script lang="ts">
    import { onMount, onDestroy } from "svelte";
    import * as echarts from "echarts";
    import type { TopClient } from "../lib/types";

    export let clients: TopClient[];

    let chartContainer: HTMLDivElement;
    let chart: echarts.ECharts | null = null;

    function initChart() {
        if (!chartContainer) return;

        chart = echarts.init(chartContainer, "dark");

        updateChart();
    }

    function updateChart() {
        if (!chart) return;

        const topClients = clients.slice(0, 8);

        const option: echarts.EChartsOption = {
            backgroundColor: "transparent",
            tooltip: {
                trigger: "item",
                backgroundColor: "rgba(17, 24, 39, 0.95)",
                borderColor: "#374151",
                textStyle: { color: "#f3f4f6" },
                formatter: (params: any) => {
                    const client = topClients[params.dataIndex];
                    return `
            <div class="font-medium">${client.ip}</div>
            <div>Queries: ${client.queries.toLocaleString()}</div>
            <div>Blocked: ${client.blocked}</div>
            <div>Avg Latency: ${client.avg_response_ms.toFixed(1)}ms</div>
          `;
                },
            },
            legend: {
                type: "scroll",
                orient: "vertical",
                right: 10,
                top: "center",
                textStyle: {
                    color: "#9ca3af",
                    fontSize: 11,
                },
            },
            series: [
                {
                    type: "pie",
                    radius: ["45%", "70%"],
                    center: ["35%", "50%"],
                    avoidLabelOverlap: false,
                    itemStyle: {
                        borderRadius: 6,
                        borderColor: "#1f2937",
                        borderWidth: 2,
                    },
                    label: {
                        show: false,
                    },
                    emphasis: {
                        label: {
                            show: true,
                            fontSize: 14,
                            fontWeight: "bold",
                            color: "#fff",
                        },
                    },
                    labelLine: {
                        show: false,
                    },
                    data: topClients.map((client, i) => ({
                        value: client.queries,
                        name: client.ip,
                        itemStyle: {
                            color: [
                                "#3b82f6",
                                "#8b5cf6",
                                "#ec4899",
                                "#f97316",
                                "#10b981",
                                "#06b6d4",
                                "#6366f1",
                                "#84cc16",
                            ][i % 8],
                        },
                    })),
                },
            ],
        };

        chart.setOption(option);
    }

    function handleResize() {
        chart?.resize();
    }

    onMount(() => {
        initChart();
        window.addEventListener("resize", handleResize);
    });

    onDestroy(() => {
        window.removeEventListener("resize", handleResize);
        chart?.dispose();
    });

    $: if (chart && clients) {
        updateChart();
    }
</script>

<div class="card">
    <div class="card-header">
        <h3 class="font-semibold text-white">Top Clients</h3>
    </div>
    <div class="card-body">
        <div bind:this={chartContainer} class="w-full h-80"></div>
    </div>
</div>
