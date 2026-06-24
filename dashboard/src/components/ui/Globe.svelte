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
        markerColor: [0.9, 0.2, 0.2], // Red markers
        glowColor: [0.1, 0.1, 0.3], // Blueish glow
        markerElevation: 0.05,
        markers: markers.map((m) => ({ location: m.location, size: 0.05 })),
        onRender: (state: any) => {
          if (!isPointerInteracting) {
            phi += speed;
          }
          state.phi = phi + pointerInteractionMovement;
          // Keep markers synced with rotation
          const markersElements = document.querySelectorAll(".globe-marker");
          markersElements.forEach((el, i) => {
            const mPhi = (markers[i].location[1] * Math.PI) / 180;
            const dist = Math.cos(state.phi + mPhi);
            (el as HTMLElement).style.opacity = dist > 0 ? "1" : "0";
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

  {#each markers as m, i}
    <div
      class="globe-marker absolute pointer-events-none flex items-center gap-2 px-2 py-1 bg-slate-900/80 backdrop-blur border border-slate-700/50 rounded shadow-lg transition-opacity duration-300"
      style="bottom: 20%; left: {10 + i * 15}%; transform: translate(-50%, 0);"
    >
      <span class="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_8px_#ef4444] animate-pulse"></span>
      <span class="font-mono text-[10px] font-bold tracking-widest text-red-500 uppercase"
        >{m.action || "BLOCK"}</span
      >
      <span class="pl-2 border-l border-slate-600 text-[10px] text-slate-300">
        {m.count || 1} Req
      </span>
    </div>
  {/each}
</div>

<style>
  canvas {
    cursor: grab;
  }
</style>
