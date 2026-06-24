<script lang="ts">
  export let data: { activeLimit: number; rejections: number }[] = [];

  const width = 500;
  const height = 200;
  const paddingX = 25;
  const paddingY = 25;

  // React to data changes to calculate coordinates
  $: maxVal = Math.max(10, ...data.map((d) => Math.max(d.activeLimit, d.rejections)));

  $: activePoints = data.map((d, i) => {
    const x = paddingX + (i / (data.length - 1 || 1)) * (width - 2 * paddingX);
    const y = height - paddingY - (d.activeLimit / maxVal) * (height - 2 * paddingY);
    return { x, y };
  });

  $: rejectionPoints = data.map((d, i) => {
    const x = paddingX + (i / (data.length - 1 || 1)) * (width - 2 * paddingX);
    const y = height - paddingY - (d.rejections / maxVal) * (height - 2 * paddingY);
    return { x, y };
  });

  // Generates cubic bezier curves path string for smooth visual curves
  function getBezierPath(points: { x: number; y: number }[]) {
    if (points.length === 0) return "";
    let d = `M ${points[0].x} ${points[0].y}`;
    for (let i = 0; i < points.length - 1; i++) {
      const curr = points[i];
      const next = points[i + 1];
      const cpX1 = curr.x + (next.x - curr.x) / 3;
      const cpY1 = curr.y;
      const cpX2 = curr.x + (2 * (next.x - curr.x)) / 3;
      const cpY2 = next.y;
      d += ` C ${cpX1} ${cpY1}, ${cpX2} ${cpY2}, ${next.x} ${next.y}`;
    }
    return d;
  }

  $: activePath = getBezierPath(activePoints);
  $: rejectionPath = getBezierPath(rejectionPoints);
</script>

<div class="relative w-full h-full flex flex-col justify-between">
  <!-- Chart SVG -->
  <div class="w-full flex-1 min-h-0">
    <svg
      viewBox="0 0 500 200"
      preserveAspectRatio="xMidYMid meet"
      class="w-full h-full overflow-visible"
    >
      <defs>
        <!-- Cyan neon glow filter -->
        <filter id="cyan-glow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="5" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>

        <!-- Red neon glow filter -->
        <filter id="red-glow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="5" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      <!-- Grid lines -->
      {#each Array(4) as _, idx}
        {@const y = paddingY + idx * ((height - 2 * paddingY) / 3)}
        <line
          x1={paddingX}
          y1={y}
          x2={width - paddingX}
          y2={y}
          stroke="var(--color-outline-variant)"
          stroke-dasharray="3,3"
          opacity="0.2"
        />
      {/each}

      <!-- Rejections Glowing Line (Background Glow + Foreground Line) -->
      {#if rejectionPath}
        <path
          d={rejectionPath}
          fill="none"
          stroke="var(--color-error)"
          stroke-width="3"
          stroke-linecap="round"
          filter="url(#red-glow)"
          opacity="0.9"
        />
      {/if}

      <!-- Active Limit Glowing Line (Background Glow + Foreground Line) -->
      {#if activePath}
        <path
          d={activePath}
          fill="none"
          stroke="var(--color-primary)"
          stroke-width="3"
          stroke-linecap="round"
          filter="url(#cyan-glow)"
          opacity="0.9"
        />
      {/if}

      <!-- Data Dots on Hover or highlight -->
      {#each activePoints as pt}
        <circle cx={pt.x} cy={pt.y} r="3" fill="var(--color-primary)" opacity="0.8" />
      {/each}
      {#each rejectionPoints as pt}
        <circle cx={pt.x} cy={pt.y} r="3" fill="var(--color-error)" opacity="0.8" />
      {/each}
    </svg>
  </div>
</div>
