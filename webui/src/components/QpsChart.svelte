<script lang="ts">
    import { onMount, onDestroy } from "svelte";
    import * as echarts from "echarts";
    import type { TimeSeriesPoint } from "../lib/types";

    export let data: TimeSeriesPoint[];
    export let title: string = "QPS Trend";
    export let color: string = "#3b82f6";

    let chartContainer: HTMLDivElement;
    let chart: echarts.ECharts | null = null;

    function initChart() {
        if (!chartContainer) return;

        chart = echarts.init(chartContainer, "dark");

        const option: echarts.EChartsOption = {
            backgroundColor: "transparent",
            title: {
                text: title,
                left: 0,
                textStyle: {
                    color: "#9ca3af",
                    fontSize: 14,
                    fontWeight: 500,
                },
            },
            tooltip: {
                trigger: "axis",
                backgroundColor: "rgba(17, 24, 39, 0.95)",
                borderColor: "#374151",
                textStyle: {
                    color: "#f3f4f6",
                },
                formatter: (params: any) => {
                    const point = params[0];
                    const time = new Date(point.axisValue).toLocaleTimeString();
                    return `<div class="font-medium">${time}</div>
                  <div class="text-primary-400">${point.value.toFixed(1)} qps</div>`;
                },
            },
            grid: {
                left: 50,
                right: 20,
                top: 50,
                bottom: 30,
            },
            xAxis: {
                type: "category",
                data: data.map((d) => d.timestamp),
                axisLabel: {
                    formatter: (value: string) => {
                        const date = new Date(value);
                        return `${date.getHours()}:${String(date.getMinutes()).padStart(2, "0")}`;
                    },
                    color: "#6b7280",
                    fontSize: 11,
                },
                axisLine: {
                    lineStyle: { color: "#374151" },
                },
                axisTick: { show: false },
                splitLine: { show: false },
            },
            yAxis: {
                type: "value",
                axisLabel: {
                    color: "#6b7280",
                    fontSize: 11,
                },
                axisLine: { show: false },
                axisTick: { show: false },
                splitLine: {
                    lineStyle: {
                        color: "#374151",
                        type: "dashed",
                    },
                },
            },
            series: [
                {
                    data: data.map((d) => d.value),
                    type: "line",
                    smooth: true,
                    symbol: "none",
                    lineStyle: {
                        width: 2,
                        color: color,
                    },
                    areaStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: `${color}40` },
                            { offset: 1, color: `${color}05` },
                        ]),
                    },
                },
            ],
        };

        chart.setOption(option);
    }

    function updateChart() {
        if (!chart) return;

        chart.setOption({
            xAxis: {
                data: data.map((d) => d.timestamp),
            },
            series: [
                {
                    data: data.map((d) => d.value),
                },
            ],
        });
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
    <div class="card-body">
        <div bind:this={chartContainer} class="w-full h-64"></div>
    </div>
</div>
