<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  // @ts-ignore
  import createGlobe from "https://esm.sh/cobe@0.6.3";

  export let markers = [
    { id: "sf", location: [37.78, -122.44] },
    { id: "london", location: [51.51, -0.13] },
    { id: "tokyo", location: [35.68, 139.65] },
    { id: "paris", location: [48.86, 2.35] },
    { id: "sydney", location: [-33.87, 151.21] },
    { id: "nyc", location: [40.71, -74.01] },
  ];
  export let speed = 0.003;
  export let className = "";

  let canvasRef: HTMLCanvasElement;
  let globe: any;
  let phi = 0;
  let isPointerInteracting = false;
  let pointerInteractionMovement = 0;
  let width = 0;

  onMount(() => {
    const initGlobe = () => {
      if (!canvasRef || !canvasRef.parentElement) return;
      width = canvasRef.parentElement.offsetWidth;
      if (width === 0) {
        setTimeout(initGlobe, 100);
        return;
      }

      globe = createGlobe(canvasRef, {
        devicePixelRatio: 2,
        width: width * 2,
        height: width * 2,
        phi: 0,
        theta: 0.2,
        dark: 1, // SOC Theme
        diffuse: 1.5,
        mapSamples: 16000,
        mapBrightness: 8,
        baseColor: [0.05, 0.05, 0.1], // Dark slate
        markerColor: [0.9, 0.2, 0.2], // Fallback marker color
        glowColor: [0.1, 0.1, 0.3], // Blueish glow
        markerElevation: 0.08,
        markers: markers.map((m) => ({ location: m.location, size: m.size || 0.05, color: m.color })),
        onRender: (state: any) => {
          if (!isPointerInteracting) {
            phi += speed;
          }
          state.phi = phi + pointerInteractionMovement;
          
          const r = width / 2;
          const cx = width / 2;
          const cy = width / 2;
          
          const markersElements = document.querySelectorAll(".globe-marker");
          markersElements.forEach((el, idx) => {
            const m = markers[idx];
            if (!m) return;
            
            const lat = m.location[0] * (Math.PI / 180);
            const lon = m.location[1] * (Math.PI / 180);
            
            // Cartesian coordinates
            const x = Math.cos(lat) * Math.sin(-lon);
            const y = Math.sin(-lat);
            const z = Math.cos(lat) * Math.cos(-lon);
            
            // Rotate Y (longitude)
            const x_rot = x * Math.cos(state.phi) - z * Math.sin(state.phi);
            const z_rot = x * Math.sin(state.phi) + z * Math.cos(state.phi);
            
            // Rotate X (latitude/tilt)
            const y_rot = y * Math.cos(state.theta) - z_rot * Math.sin(state.theta);
            const z_final = y * Math.sin(state.theta) + z_rot * Math.cos(state.theta);
            
            const htmlEl = el as HTMLElement;
            if (z_final > 0) {
              const screenX = cx + x_rot * r * 0.88;
              const screenY = cy - y_rot * r * 0.88;
              
              htmlEl.style.left = `${screenX}px`;
              htmlEl.style.top = `${screenY}px`;
              htmlEl.style.opacity = "1";
              htmlEl.style.display = "flex";
            } else {
              htmlEl.style.opacity = "0";
              htmlEl.style.display = "none";
            }
          });
        },
      });

      setTimeout(() => {
        if (canvasRef) canvasRef.style.opacity = "1";
      }, 100);
    };

    initGlobe();

    return () => {
      if (globe) globe.destroy();
    };
  });
</script>

<div
  class={`relative aspect-square select-none ${className} flex items-center justify-center`}
  bind:clientWidth={width}
>
  <canvas
    bind:this={canvasRef}
    style="width: 100%; height: 100%; contain: layout paint size; opacity: 0; transition: opacity 1s ease;"
    on:pointerdown={(e) => {
      isPointerInteracting = true;
      if (canvasRef) canvasRef.style.cursor = "grabbing";
    }}
    on:pointerup={() => {
      isPointerInteracting = false;
      if (canvasRef) canvasRef.style.cursor = "grab";
    }}
    on:pointerout={() => {
      isPointerInteracting = false;
      if (canvasRef) canvasRef.style.cursor = "grab";
    }}
    on:pointermove={(e) => {
      if (isPointerInteracting) {
        pointerInteractionMovement += e.movementX / 200;
      }
    }}
  ></canvas>

  {#each markers as m}
    <div
      class="globe-marker absolute pointer-events-none flex items-center gap-2 px-2 py-1 bg-slate-900/90 backdrop-blur border border-slate-700/50 rounded shadow-lg transition-opacity duration-150"
      style="transform: translate(-50%, -100%); display: none; opacity: 0;"
    >
      <span class="w-2 h-2 rounded-full {m.colorClass || 'bg-red-500 shadow-[0_0_8px_#ef4444]'} animate-pulse"></span>
      <span class="font-mono text-[10px] font-bold tracking-widest text-slate-100 uppercase"
        >{m.country || 'ID'} | {m.countFormatted || '1'}</span
      >
    </div>
  {/each}
</div>

<style>
  canvas {
    cursor: grab;
  }
</style>
