import { Router } from "express";
import {
    registerHandler,
    loginHandler,
    verifyEmailHandler,
    refreshHandler,
    logoutHandler,
} from "../controllers/auth/auth.controller";

const router = Router();

router.post("/register", registerHandler);
router.post("/login", loginHandler);
router.get("/verify-email", verifyEmailHandler);
router.post("/refresh", refreshHandler);
router.post("/logout", logoutHandler);



export default router;
