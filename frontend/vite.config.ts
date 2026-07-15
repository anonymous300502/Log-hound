import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies /api to the Rust API (default 127.0.0.1:8080). In
// production the API serves the built assets from frontend/dist itself, so the
// same relative /api paths work in both modes (PLAN.md §10, §11).
const API_TARGET = process.env.LOGHOUND_API ?? "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: API_TARGET, changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
