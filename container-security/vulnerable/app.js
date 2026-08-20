const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/orders', (req, res) => {
  res.json({
    service: 'orders',
    hostname: require('os').hostname(),
    message: 'Orders service is running (v3 - task def fix verified)'
  });
});

app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

app.listen(PORT, () => {
  console.log(`Orders service listening on port ${PORT}`);
});
