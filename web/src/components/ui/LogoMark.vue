<script setup lang="ts">
/**
 * Inline PandaPass vault-shield logo.
 *
 * Uses `currentColor` and CSS variables so it adapts to light and dark
 * palettes without a separate asset. The original assets/logo.svg stays
 * untouched.
 */
</script>

<template>
  <svg
    class="logo-mark"
    viewBox="0 0 64 64"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    role="img"
    aria-label="PandaPass"
  >
    <!-- Shield / vault: protection -->
    <path
      d="M32 4 54 11v18c0 14.2-9 24.4-22 31C19 53.4 10 43.2 10 29V11L32 4Z"
      fill="currentColor"
      stroke="var(--accent)"
      stroke-width="4"
      stroke-linejoin="round"
    />
    <!-- Keyhole: lock + the "P" of PandaPass -->
    <path
      d="M32 22a7 7 0 0 0-7 7c0 3 1.9 5.6 4.6 6.6L28 44h8l-1.6-8.4A7 7 0 0 0 39 29a7 7 0 0 0-7-7Z"
      fill="var(--accent)"
    />
    <!-- Floor line: vault / strongroom -->
    <path d="M22 51h20" stroke="var(--accent)" stroke-width="3" stroke-linecap="round" />
  </svg>
</template>

<style scoped>
.logo-mark {
  width: 24px;
  height: 24px;
  display: block;
  color: var(--text);
}

.brand-large .logo-mark {
  width: 40px;
  height: 40px;
}
</style>