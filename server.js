const express = require('express');
const path = require('path');

const app = express();
const PORT = 3333;

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n  simple-test pentest app running at http://localhost:${PORT}\n`);
});
