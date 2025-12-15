import express from "express";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";

dotenv.config();

const app = express();

app.use(express.json());
app.use(cookieParser());

app.get("/health", (req, res) => {
    res.json({ status: "OK" });
});

export default app;
