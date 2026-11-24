/**
 * HookVault Server Entrypoint
 */

import { createServer } from "node:http";
import { createApp } from "./app.js";

const app = createApp();
const port = Number(process.env["PORT"] ?? 3000);

const server = createServer(async (req, res) => {
  try {
    const url = `http://${req.headers.host || "localhost"}${req.url}`;
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
      if (value) {
        if (Array.isArray(value)) {
          for (const v of value) headers.append(key, v);
        } else {
          headers.set(key, value);
        }
      }
    }

    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const body =
      req.method !== "GET" && req.method !== "HEAD" && chunks.length > 0
        ? Buffer.concat(chunks)
        : undefined;

    const request = new Request(url, {
      method: req.method,
      headers,
      body,
    });

    const response = await app.fetch(request);
    res.statusCode = response.status;
    for (const [key, value] of response.headers.entries()) {
      res.setHeader(key, value);
    }
    const arrayBuffer = await response.arrayBuffer();
    res.end(Buffer.from(arrayBuffer));
  } catch {
    res.statusCode = 500;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ error: { code: "INTERNAL_SERVER_ERROR", message: "Server error" } }));
  }
});

if (process.env["NODE_ENV"] !== "test" && !process.env["VITEST"]) {
  server.listen(port, () => {
    console.log(`HookVault server listening on port ${port}`);
  });
}

export default app;
export { createApp, server };
