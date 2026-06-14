import express from 'express'
import helper from 'orion-build-utils'

const app = express()

app.get('/health', (_req, res) => {
  res.json({ ok: true, helperLoaded: Boolean(helper) })
})

app.get('/admin/export', (_req, res) => {
  res.json({ simulated: true })
})

app.listen(3000)

