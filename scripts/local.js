import server from "../api/index.js";
const port = Number(process.env.PORT) || 3000;
server.listen(port, () => console.log(`MX-UI: http://localhost:${port}`));
