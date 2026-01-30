# LazyDNS WebUI (WIP)

A real-time dashboard for monitoring and managing LazyDNS server operations.

## Overview

LazyDNS WebUI is a Svelte-based frontend application that provides a comprehensive dashboard for DNS server monitoring, analytics, and administration. It offers real-time metrics, security event tracking, upstream health monitoring, and alert management.

## Features

### Real-Time Monitoring

- **Live Dashboard**: Real-time overview of server status, metrics, and performance
- **Query Metrics**: Track total queries, queries per second (QPS), and query trends
- **Cache Analytics**: Monitor cache hit rates, efficiency, and optimization
- **Latency Distribution**: Visualize response time distribution with percentile analysis

### Advanced Analytics

- **Top Domains**: Identify the most frequently queried domains
- **Top Clients**: Track client activity and query patterns
- **QPS History**: Time-series data of queries per second over configurable windows
- **Latency Percentiles**: P50, P95, P99 latency metrics with detailed breakdowns

### Upstream Management

- **Upstream Health**: Real-time health status of configured DNS upstreams
- **Success Rates**: Monitor success and failure rates for each upstream
- **Response Times**: Track average response times and performance metrics
- **Status Indicators**: Visual indicators for healthy, degraded, and down status

### Alert Management

- **Rule-Based Alerts**: Customizable alerting based on predefined rules
- **Alert History**: Track recent alerts with severity levels
- **Acknowledgment**: Mark and acknowledge alerts
- **Real-Time Notifications**: Live alert streaming via SSE

### Security

- **Security Events**: Monitor rate limiting, blocked queries, and ACL denials
- **Event Tracking**: Detailed logs of security-related incidents
- **Real-Time Streaming**: Live security event updates

### User Experience

- **Dark Mode**: Comfortable viewing with automatic dark/light theme switching
- **Responsive Design**: Optimized for desktop and tablet viewing
- **Interactive Charts**: ECharts-based visualizations with tooltips and interactions
- **Real-Time Updates**: WebSocket and Server-Sent Events (SSE) for live data

## Technology Stack

### Frontend

- **Framework**: [Svelte 4](https://svelte.dev/) - Lightweight reactive component framework
- **Build Tool**: [Vite](https://vitejs.dev/) - Fast build tool and dev server
- **Styling**: [Tailwind CSS](https://tailwindcss.com/) - Utility-first CSS framework
- **Charting**: [ECharts](https://echarts.apache.org/) - Powerful visualization library
- **Routing**: [svelte-spa-router](https://github.com/ItalyPaleAle/svelte-spa-router) - SPA routing

### Testing

- **Unit Testing**: [Vitest](https://vitest.dev/) - Lightning-fast unit test framework
- **Component Testing**: [@testing-library/svelte](https://testing-library.com/svelte) - DOM testing utilities
- **Test Environment**: [jsdom](https://github.com/jsdom/jsdom) - JavaScript DOM implementation

### Backend Integration

- **API Communication**: Fetch API for REST endpoints
- **WebSocket**: Real-time metric streaming
- **SSE**: Server-Sent Events for query logs and security events

## Project Structure

```
webui/
├── src/
│   ├── components/          # Reusable Svelte components
│   │   ├── StatCard.svelte              # Statistics card display
│   │   ├── TopDomainsChart.svelte       # Top domains visualization
│   │   ├── TopClientsChart.svelte       # Top clients visualization
│   │   ├── QpsChart.svelte              # QPS trend chart
│   │   ├── LatencyDistributionChart.svelte # Latency histogram
│   │   ├── UpstreamHealthCard.svelte    # Upstream status cards
│   │   ├── UpstreamPerformanceTable.svelte # Upstream metrics table
│   │   └── AlertsList.svelte            # Alerts display
│   ├── lib/
│   │   ├── stores.ts        # Svelte stores for global state
│   │   ├── types.ts         # TypeScript type definitions
│   │   └── api.ts           # API communication utilities
│   ├── routes/
│   │   ├── Dashboard.svelte # Main dashboard view
│   │   ├── Analytics.svelte # Advanced analytics page
│   │   └── Settings.svelte  # Configuration page
│   ├── App.svelte           # Root component
│   ├── main.ts              # Application entry point
│   └── app.css              # Global styles
├── public/                  # Static assets
├── package.json
├── vite.config.ts          # Vite configuration
├── tsconfig.json           # TypeScript configuration
└── README.md
```

## Development Setup

### Prerequisites

- Node.js 16+ and npm

### Installation

1. Navigate to the webui directory:

```bash
cd webui
```

2. Install dependencies:

```bash
npm install
```

3. Start the development server:

```bash
npm run dev
```

The application will be available at `http://localhost:5173` by default.

### API Proxy

The development server includes a proxy configuration that forwards API requests to the backend server:

```
/api → http://127.0.0.1:8080
```

Ensure the LazyDNS backend server is running on `http://127.0.0.1:8080`.

## Building

### Development Build

```bash
npm run dev
```

### Production Build

```bash
npm run build
```

The built files will be output to the `dist/` directory.

### Preview Build

```bash
npm run preview
```

## Testing

### Type Checking

Run TypeScript and Svelte type checking:

```bash
npm run check
```

### Run Tests

Execute all unit and component tests:

```bash
npm test
```

### Watch Mode

Run tests in watch mode for development:

```bash
npm run test:watch
```

### Coverage Report

Generate test coverage report:

```bash
npm run test:coverage
```

## Test Files

### Backend Integration Tests

- **[tests/web_api_test.rs](../tests/web_api_test.rs)**: API endpoint structure and response validation (15 tests)

### Frontend Unit Tests

- **[src/lib/stores.test.ts](src/lib/stores.test.ts)**: Svelte store state management tests (18 tests)
- **[src/lib/types.test.ts](src/lib/types.test.ts)**: Type definitions and utility functions (15 tests)
- **[src/components/StatCard.test.ts](src/components/StatCard.test.ts)**: Statistics card component logic (8 tests)
- **[src/components/TopDomainsChart.test.ts](src/components/TopDomainsChart.test.ts)**: Domain analytics visualization (14 tests)
- **[src/components/LatencyDistributionChart.test.ts](src/components/LatencyDistributionChart.test.ts)**: Latency histogram component (16 tests)
- **[src/components/QpsChart.test.ts](src/components/QpsChart.test.ts)**: QPS trend visualization (17 tests)
- **[src/components/UpstreamHealthCard.test.ts](src/components/UpstreamHealthCard.test.ts)**: Upstream health status display (17 tests)

**Total: 105 frontend tests + 15 backend API tests**

## API Endpoints

The WebUI communicates with the following API endpoints:

### Dashboard & Metrics

- `GET /api/dashboard/overview` - Server status and overview metrics
- `GET /api/metrics/top-domains` - Top queried domains
- `GET /api/metrics/top-clients` - Top client IPs
- `GET /api/metrics/latency` - Latency distribution analysis
- `GET /api/metrics/qps` - Queries per second history
- `GET /api/metrics/upstream-health` - Upstream server health status

### Alerts

- `GET /api/alerts/recent` - Recent alerts and notifications

### Streaming

- `GET /api/audit/query-logs/stream` - Real-time query log stream (SSE)
- `GET /api/audit/security/stream` - Real-time security events (SSE)
- `WS /ws/metrics` - WebSocket for live metrics updates

## Configuration

### Theme

The application supports automatic light/dark mode switching based on system preferences. Users can manually toggle the theme using the theme switcher in the navigation.

### Time Windows

Supported time windows for analytics:

- 1 minute (1m)
- 5 minutes (5m)
- 1 hour (1h)
- 24 hours (24h)

### Chart Configuration

- **Chart Refresh Interval**: Configurable via environment or settings
- **Data Points**: Limited to prevent memory issues with large datasets
- **Zoom & Pan**: Interactive chart interactions enabled

## Customization

### Adding New Components

1. Create a new `.svelte` file in `src/components/`:

```svelte
<script lang="ts">
  export let prop: string;
</script>

<div>
  {prop}
</div>

<style>
  /* Component styles */
</style>
```

2. Import and use in pages:

```svelte
<script lang="ts">
  import MyComponent from '../components/MyComponent.svelte';
</script>

<MyComponent prop="value" />
```

### Adding New Routes

1. Create a new `.svelte` file in `src/routes/`:
2. Add route configuration in `src/App.svelte`

### Styling

The project uses Tailwind CSS for styling. Customize the theme in `tailwind.config.js`:

```js
module.exports = {
  theme: {
    extend: {
      colors: {
        primary: "#3b82f6",
        // Custom colors
      },
    },
  },
};
```

## Troubleshooting

### API Connection Issues

- Ensure the backend server is running on `http://127.0.0.1:8080`
- Check browser console for CORS errors
- Verify API endpoint paths are correct

### Build Errors

- Clear `node_modules` and reinstall: `rm -rf node_modules && npm install`
- Clear build cache: `rm -rf dist/`
- Check Node.js version compatibility

### Type Checking Errors

- Run `npm run check` to identify issues
- Ensure all imports are properly typed
- Check `.ts` files in `src/lib/types.ts` for type definitions

## Performance Optimization

### Bundle Size

- Code splitting for vendor libraries
- Lazy loading of route components
- Tree shaking of unused code

### Runtime Performance

- Svelte's reactive compilation for minimal overhead
- Virtual scrolling for large lists (if needed)
- Debounced API calls for real-time data

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Mobile browsers (responsive design)

## Contributing

To contribute to the WebUI:

1. Create a feature branch
2. Make your changes with tests
3. Run `npm run check` and `npm test` to verify
4. Submit a pull request

## License

This project is licensed under the same license as LazyDNS.

## Support

For issues and questions:

- Check the main LazyDNS documentation
- Review existing GitHub issues
- Submit new issues with detailed descriptions

## Resources

- [Svelte Documentation](https://svelte.dev/docs)
- [Vite Guide](https://vitejs.dev/guide/)
- [Tailwind CSS Docs](https://tailwindcss.com/docs)
- [ECharts Documentation](https://echarts.apache.org/en/index.html)
- [Vitest Documentation](https://vitest.dev/)
