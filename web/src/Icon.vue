<script setup lang="ts">
withDefaults(defineProps<{name?: string}>(), {name:'server'})
const paths: Record<string,string> = {
 shield:'M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7l-9-4 M8 12l3 3 5-6',
 server:'M4 3h16v7H4z M4 14h16v7H4z M7 6.5h.01 M7 17.5h.01 M11 6.5h6 M11 17.5h6',
 grid:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
 layers:'m12 3 10 5-10 5L2 8l10-5 M2 12l10 5 10-5 M2 16l10 5 10-5',
 activity:'M2 12h4l3-9 6 18 3-9h4', search:'M21 21l-6-6 M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0',
 refresh:'M20 7v5h-5 M4 17v-5h5 M6 6a8 8 0 0 1 13 3 M18 18a8 8 0 0 1-13-3',
 plus:'M12 5v14 M5 12h14', arrow:'m14 6-6 6 6 6', logout:'M9 3H3v18h6 M9 12h12 M16 7l5 5-5 5',
 lock:'M5 10h14v11H5z M8 10V7a4 4 0 0 1 8 0v3', alert:'M12 3 2 21h20L12 3 M12 9v5 M12 17h.01',
 check:'m4 12 5 5L20 6', clock:'M12 7v5l4 2 M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0'
}
</script>
<template><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path :d="paths[name] ?? paths.server"/></svg></template>
