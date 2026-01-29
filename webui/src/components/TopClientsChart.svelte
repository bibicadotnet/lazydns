<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import * as echarts from "echarts";
  import type { TopClient } from "../lib/types";
  import { darkMode } from "../lib/stores";

  export let clients: TopClient[];

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

    const topClients = clients.slice(0, 8);

    const tooltipBg = isDark
      ? "rgba(17, 24, 39, 0.95)"
      : "rgba(255, 255, 255, 0.95)";
    const tooltipBorder = isDark ? "#374151" : "#e5e7eb";
    const tooltipTextColor = isDark ? "#f3f4f6" : "#1f2937";
    const legendColor = isDark ? "#9ca3af" : "#4b5563";
    const borderColor = isDark ? "#1f2937" : "#f3f4f6";
    const emphasisColor = isDark ? "#fff" : "#1f2937";

    const option: echarts.EChartsOption = {
      backgroundColor: "transparent",
      tooltip: {
        trigger: "item",
        backgroundColor: tooltipBg,
        borderColor: tooltipBorder,
        textStyle: { color: tooltipTextColor },
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
          color: legendColor,
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
            borderColor: borderColor,
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
              color: emphasisColor,
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
    <h3 class="font-semibold {isDark ? 'text-white' : 'text-gray-900'}">
      Top Clients
    </h3>
  </div>
  <div class="card-body">
    <div bind:this={chartContainer} class="w-full h-80"></div>
  </div>
</div>
