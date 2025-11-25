// Minimal test to verify server can start
import express from "express";

const app = express();
app.use(express.json());

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => {
  res.send('Test server running');
});

const port = process.env.PORT || 10000;
app.listen(port, () => {
  console.log(`Test server running on port ${port}`);
  console.log(`Health check: http://localhost:${port}/health`);
});
