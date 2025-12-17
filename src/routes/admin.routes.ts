import { Request, Response, Router } from "express";
import { requireAuth } from "../middlewares/requireAuth";
import { requireRole } from "../middlewares/requireRole";
import { User } from "../models/user.model";

const router = Router();

router.get(
    "/users",
    requireAuth,
    requireRole("admin"),
    async (req: Request, res: Response) => {
        const users = await User.find({}, {
            email: 1,
            role: 1,
            isEmailVerified: 1,
            createdAt: 1,
        }).sort({ createdAt: -1 });

        res.json(users);
    }
);

export default router;
