<script lang="ts">
    import { onMount, onDestroy } from "svelte";
    import * as echarts from "echarts";
    import type { LatencyDistribution } from "../lib/types";

    export let data: LatencyDistribution[];

    let chartContainer: HTMLDivElement;
    let chart: echarts.ECharts | null = null;

    function initChart() {
        if (!chartContainer) return;

        chart = echarts.init(chartContainer, "dark");

        updateChart();
    }

    function updateChart() {
        if (!chart) return;

        const option: echarts.EChartsOption = {
            backgroundColor: "transparent",
            tooltip: {
                trigger: "axis",
                axisPointer: { type: "shadow" },
                backgroundColor: "rgba(17, 24, 39, 0.95)",
                borderColor: "#374151",
                textStyle: { color: "#f3f4f6" },
                formatter: (params: any) => {
                    const item = params[0];
                    return `
            <div class="font-medium">${item.axisValue}</div>
            <div>Count: ${item.value.toLocaleString()}</div>
            <div>Percentage: ${data[item.dataIndex].percentage.toFixed(1)}%</div>
          `;
                },
            },
            grid: {
                left: 60,
                right: 30,
                top: 30,
                bottom: 40,
            },
            xAxis: {
                type: "category",
                data: data.map((d) => d.bucket),
                axisLabel: {
                    color: "#6b7280",
                    fontSize: 11,
                },
                axisLine: { lineStyle: { color: "#374151" } },
                axisTick: { show: false },
            },
            yAxis: {
                type: "value",
                axisLabel: {
                    color: "#6b7280",
                    fontSize: 11,
                    formatter: (value: number) => {
                        if (value >= 1000)
                            return (value / 1000).toFixed(0) + "K";
                        return value.toString();
                    },
                },
                axisLine: { show: false },
                axisTick: { show: false },
                splitLine: {
                    lineStyle: { color: "#374151", type: "dashed" },
                },
            },
            series: [
                {
                    type: "bar",
                    data: data.map((d, i) => ({
                        value: d.count,
                        itemStyle: {
                            color:
                                i < 2
                                    ? "#10b981"
                                    : i < 4
                                      ? "#f59e0b"
                                      : "#ef4444",
                            borderRadius: [4, 4, 0, 0],
                        },
                    })),
                    barWidth: "60%",
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

    $: if (chart && data) {
        updateChart();
    }
</script>

<div class="card">
    <div class="card-header flex items-center justify-between">
        <h3 class="font-semibold text-white">Response Time Distribution</h3>
        <div class="flex items-center gap-4 text-xs">
            <span class="flex items-center gap-1">
                <span class="w-3 h-3 rounded bg-green-500"></span>
                <span class="text-gray-400">Fast (&lt;10ms)</span>
            </span>
            <span class="flex items-center gap-1">
                <span class="w-3 h-3 rounded bg-yellow-500"></span>
                <span class="text-gray-400">Normal (10-50ms)</span>
            </span>
            <span class="flex items-center gap-1">
                <span class="w-3 h-3 rounded bg-red-500"></span>
                <span class="text-gray-400">Slow (&gt;50ms)</span>
            </span>
        </div>
    </div>
    <div class="card-body">
        <div bind:this={chartContainer} class="w-full h-64"></div>
    </div>
</div>
