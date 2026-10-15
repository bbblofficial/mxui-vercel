process.env.MXUI_MEMORY ||= "1"; // local dev: in-memory store (lost on restart)
const { default: server } = await import("../api/index.js");
const port = Number(process.env.PORT) || 3000;
server.listen(port, () => console.log(`MX-UI: http://localhost:${port}`));
