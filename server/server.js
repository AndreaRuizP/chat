const WebSocket = require("ws");

const wss = new WebSocket.Server({ port: 3000 });

console.log("Servidor WebSocket corriendo en ws://localhost:3000");

wss.on("connection", (ws) => {
    console.log("Cliente conectado");

    ws.on("message", (data) => {
        wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(data.toString());
            }
        });
    });
});
