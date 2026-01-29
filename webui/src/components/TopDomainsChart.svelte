<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import * as echarts from "echarts";
  import type { TopDomain } from "../lib/types";
  import { darkMode } from "../lib/stores";

  export let domains: TopDomain[];
  export let title: string = "Top Domains";

  let chartContainer: HTMLDivElement;
  let chart: echarts.ECharts | null = null;
  let isDark = true;

  darkMode.subscribe((value) => {
    isDark = value;
    if (chart) {
      chart.dispose();
      initChart();
    }
  });

  function initChart() {
    if (!chartContainer) return;

    chart = echarts.init(chartContainer, isDark ? "dark" : undefined);

    updateChart();
  }

  function updateChart() {
    if (!chart) return;

    const textColor = isDark ? "#9ca3af" : "#4b5563";
    const axisColor = isDark ? "#6b7280" : "#9ca3af";
    const lineColor = isDark ? "#374151" : "#e5e7eb";
    const tooltipBg = isDark
      ? "rgba(17, 24, 39, 0.95)"
      : "rgba(255, 255, 255, 0.95)";
    const tooltipBorder = isDark ? "#374151" : "#e5e7eb";
    const tooltipTextColor = isDark ? "#f3f4f6" : "#1f2937";

    const option: echarts.EChartsOption = {
      backgroundColor: "transparent",
      tooltip: {
        trigger: "axis",
        axisPointer: { type: "shadow" },
        backgroundColor: tooltipBg,
        borderColor: tooltipBorder,
        textStyle: { color: tooltipTextColor },
      },
      grid: {
        left: 150,
        right: 60,
        top: 20,
        bottom: 20,
      },
      xAxis: {
        type: "value",
        axisLabel: {
          color: axisColor,
          fontSize: 11,
          formatter: (value: number) => {
            if (value >= 1000) return (value / 1000).toFixed(1) + "K";
            return value.toString();
          },
        },
        axisLine: { show: false },
        axisTick: { show: false },
        splitLine: {
          lineStyle: { color: lineColor, type: "dashed" },
        },
      },
      yAxis: {
        type: "category",
        data: domains
          .slice(0, 10)
          .map((d) => d.domain)
          .reverse(),
        axisLabel: {
          color: textColor,
          fontSize: 11,
          formatter: (value: string) => {
            if (value.length > 25) return value.slice(0, 22) + "...";
            return value;
          },
        },
        axisLine: { show: false },
        axisTick: { show: false },
      },
      series: [
        {
          type: "bar",
          data: domains
            .slice(0, 10)
            .map((d) => d.count)
            .reverse(),
          barWidth: "60%",
          itemStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
              { offset: 0, color: "#3b82f6" },
              { offset: 1, color: "#60a5fa" },
            ]),
            borderRadius: [0, 4, 4, 0],
          },
          label: {
            show: true,
            position: "right",
            color: textColor,
            fontSize: 11,
            formatter: (params: any) => {
              const domain = domains.slice(0, 10).reverse()[params.dataIndex];
              return `${domain.percentage.toFixed(1)}%`;
            },
          },
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

  $: if (chart && domains) {
    updateChart();
  }
</script>

<div class="card">
  <div class="card-header">
    <h3 class="font-semibold {isDark ? 'text-white' : 'text-gray-900'}">
      {title}
    </h3>
  </div>
  <div class="card-body">
    <div bind:this={chartContainer} class="w-full h-80"></div>
  </div>
</div>
