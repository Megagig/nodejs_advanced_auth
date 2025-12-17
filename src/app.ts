import express from "express";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.routes";
import userRoutes from "./routes/user.routes";
import adminRoutes from "./routes/admin.routes";
dotenv.config();

const app = express();

app.set("trust proxt", 1);

app.use(express.json());
app.use(cookieParser());

app.get("/health", (req, res) => {
    res.json({ status: "OK" });
});

//Register Routes in App
app.use("/auth", authRoutes);
app.use("/user", userRoutes)
app.use("/admin", adminRoutes)

export default app;
