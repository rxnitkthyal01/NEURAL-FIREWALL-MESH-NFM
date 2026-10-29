import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": process.env.NFM_DASHBOARD_API ?? "http://127.0.0.1:8080",
    },
  },
});
