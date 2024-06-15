import express from 'express'
import { PORT } from './config.js'

const app = express()

app.get('/', (req, res) => {
  res.send('<h1>Hello World! Node Application 💪</h1>')
})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
