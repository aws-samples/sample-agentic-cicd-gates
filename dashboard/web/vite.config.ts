import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", chunkSizeWarningLimit: 1500 },
  server: { proxy: { "/api": "http://127.0.0.1:8642", "/auth-config": "http://127.0.0.1:8642" } },
});
