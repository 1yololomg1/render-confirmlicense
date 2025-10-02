import express from "express";

const app = express();
app.use(express.json());

// Debug endpoint to check environment variables
app.get('/debug', (req, res) => {
  const debugInfo = {
    hasSharedSecret: !!process.env.SHARED_SECRET,
    sharedSecretLength: process.env.SHARED_SECRET ? process.env.SHARED_SECRET.length : 0,
    sharedSecretPreview: process.env.SHARED_SECRET ? 
      process.env.SHARED_SECRET.substring(0, 8) + '...' : 'NOT SET',
    nodeEnv: process.env.NODE_ENV,
    timestamp: new Date().toISOString()
  };
  
  res.json(debugInfo);
});

// Test authentication endpoint
app.post('/test-auth', (req, res) => {
  const providedKey = req.get('x-app-secret');
  const expectedKey = process.env.SHARED_SECRET;
  
  const result = {
    providedKey: providedKey ? providedKey.substring(0, 8) + '...' : 'NOT PROVIDED',
    expectedKey: expectedKey ? expectedKey.substring(0, 8) + '...' : 'NOT SET',
    keysMatch: providedKey === expectedKey,
    providedLength: providedKey ? providedKey.length : 0,
    expectedLength: expectedKey ? expectedKey.length : 0,
    timestamp: new Date().toISOString()
  };
  
  res.json(result);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Debug server on ${port}`));

