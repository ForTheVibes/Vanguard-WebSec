const express = require("express");
const app = express();

app.get("/", (req, res) => {
  res.sendFile("/html/index.html", { root: __dirname });
});

app.get("/result", (req, res) => {
  res.sendFile("/html/result.html", { root: __dirname });
});

app.get("/history", (req, res) => {
  res.sendFile("/html/history.html", { root: __dirname });
});

app.get("/conf", (req, res) => {
  res.sendFile("/html/conf.html", { root: __dirname });
});

app.use(express.static(__dirname))

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`FrontEnd server has started on port ${PORT}`);
  console.log(`Web App Hosted at http://localhost:${PORT}`);
});
