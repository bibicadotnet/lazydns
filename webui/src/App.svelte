<script lang="ts">
  import Router from "svelte-spa-router";
  import TopNav from "./components/TopNav.svelte";
  import Header from "./components/Header.svelte";
  import Notifications from "./components/Notifications.svelte";
  import Dashboard from "./routes/Dashboard.svelte";
  import AuditLogs from "./routes/AuditLogs.svelte";
  import Metrics from "./routes/Metrics.svelte";
  import Admin from "./routes/Admin.svelte";

  const routes = {
    "/": Dashboard,
    "/audit": AuditLogs,
    "/metrics": Metrics,
    "/admin": Admin,
  };
</script>

<div class="min-h-screen flex flex-col">
  <TopNav />

  <div class="flex-1 flex flex-col pt-16">
    <Header />

    <main class="flex-1 p-6 overflow-auto">
      <Router {routes} />
    </main>
  </div>
</div>

<Notifications />
