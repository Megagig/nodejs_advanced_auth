import http from "http";
import app from "./app";
import { connectDB } from "./config/db";


async function startServer() {
    await connectDB();

    const server = http.createServer(app);

    server.listen(process.env.PORT, () => {
        console.log(`Server running on port ${process.env.PORT}`);
    });
}

startServer().catch((error) => {
    console.error("Error starting server", error);
    process.exit(1);
});
