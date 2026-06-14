import { defineConfig, type Plugin, type Connect } from 'vite'
import path from 'path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import type { ServerResponse } from 'http'

const HF_ENDPOINT = 'https://router.huggingface.co/v1/chat/completions'
const DEFAULT_MODEL = 'meta-llama/Llama-3.1-8B-Instruct'

/**
 * Dev-only API route that proxies chat completions to Hugging Face using a
 * server-side token (HUGGINGFACE_ACCESS_TOKEN). The key is read from the
 * server environment and is never exposed to the browser. Supports streaming.
 */
function serverSideLlmProxy(): Plugin {
  return {
    name: 'sentineliq-llm-proxy',
    configureServer(server) {
      const handler: Connect.NextHandleFunction = async (req, res: ServerResponse) => {
        if (req.method !== 'POST') {
          res.statusCode = 405
          res.end(JSON.stringify({ error: 'Method not allowed' }))
          return
        }

        const token = process.env.HUGGINGFACE_ACCESS_TOKEN
        if (!token) {
          res.statusCode = 500
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify({ error: 'HUGGINGFACE_ACCESS_TOKEN is not set on the server.' }))
          return
        }

        try {
          const body = await readJson(req)
          const stream = body.stream !== false
          const upstream = await fetch(HF_ENDPOINT, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({
              model: body.model || DEFAULT_MODEL,
              temperature: typeof body.temperature === 'number' ? body.temperature : 0.2,
              max_tokens: body.max_tokens || 1200,
              stream,
              messages: body.messages || [],
            }),
          })

          if (!upstream.ok || !upstream.body) {
            const errText = await upstream.text().catch(() => '')
            res.statusCode = upstream.status || 502
            res.setHeader('Content-Type', 'application/json')
            res.end(JSON.stringify({ error: `Upstream HTTP ${upstream.status} — ${errText.slice(0, 300)}` }))
            return
          }

          // Pipe the upstream SSE/JSON straight back to the browser.
          res.statusCode = 200
          res.setHeader('Content-Type', stream ? 'text/event-stream' : 'application/json')
          res.setHeader('Cache-Control', 'no-cache')
          const reader = upstream.body.getReader()
          while (true) {
            const { done, value } = await reader.read()
            if (done) break
            res.write(value)
          }
          res.end()
        } catch (err) {
          res.statusCode = 500
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify({ error: (err as Error).message }))
        }
      }

      server.middlewares.use('/api/llm/chat', handler)
    },
  }
}

function readJson(req: Connect.IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let data = ''
    req.on('data', (chunk) => {
      data += chunk
      if (data.length > 5_000_000) reject(new Error('Payload too large'))
    })
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {})
      } catch (e) {
        reject(e)
      }
    })
    req.on('error', reject)
  })
}

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    serverSideLlmProxy(),
  ],
  resolve: {
    alias: {
      // Alias @ to the src directory
      '@': path.resolve(__dirname, './src'),
    },
  },

  // File types to support raw imports. Never add .css, .tsx, or .ts files to this.
  assetsInclude: ['**/*.svg'],
})
