<script lang="ts">
  import { notifications, darkMode } from "../lib/stores";

  function getIcon(type: string) {
    switch (type) {
      case "success":
        return "✓";
      case "error":
        return "✕";
      case "warning":
        return "⚠";
      default:
        return "ℹ";
    }
  }

  function getBgColor(type: string, isDark: boolean) {
    if (isDark) {
      switch (type) {
        case "success":
          return "bg-green-900/90 border-green-700";
        case "error":
          return "bg-red-900/90 border-red-700";
        case "warning":
          return "bg-yellow-900/90 border-yellow-700";
        default:
          return "bg-blue-900/90 border-blue-700";
      }
    } else {
      switch (type) {
        case "success":
          return "bg-green-50 border-green-300";
        case "error":
          return "bg-red-50 border-red-300";
        case "warning":
          return "bg-yellow-50 border-yellow-300";
        default:
          return "bg-blue-50 border-blue-300";
      }
    }
  }

  function getIconColor(type: string, isDark: boolean) {
    if (isDark) {
      switch (type) {
        case "success":
          return "text-green-400";
        case "error":
          return "text-red-400";
        case "warning":
          return "text-yellow-400";
        default:
          return "text-blue-400";
      }
    } else {
      switch (type) {
        case "success":
          return "text-green-600";
        case "error":
          return "text-red-600";
        case "warning":
          return "text-yellow-600";
        default:
          return "text-blue-600";
      }
    }
  }
</script>

<div class="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
  {#each $notifications as notification (notification.id)}
    <div
      class="flex items-center gap-3 px-4 py-3 rounded-lg border backdrop-blur-sm shadow-xl animate-slide-in {getBgColor(
        notification.type,
        $darkMode,
      )}"
      role="alert"
    >
      <span class="text-lg {getIconColor(notification.type, $darkMode)}"
        >{getIcon(notification.type)}</span
      >
      <span class="text-sm {$darkMode ? 'text-white' : 'text-gray-800'}"
        >{notification.message}</span
      >
      <button
        on:click={() => notifications.remove(notification.id)}
        class="ml-2 transition-colors {$darkMode
          ? 'text-gray-400 hover:text-white'
          : 'text-gray-500 hover:text-gray-900'}"
      >
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
            d="M6 18L18 6M6 6l12 12"
          />
        </svg>
      </button>
    </div>
  {/each}
</div>

<style>
  @keyframes slide-in {
    from {
      transform: translateX(100%);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }

  .animate-slide-in {
    animation: slide-in 0.3s ease-out;
  }
</style>
