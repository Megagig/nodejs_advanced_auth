import { Router } from "express";
import {
    registerHandler,
    loginHandler,
    verifyEmailHandler,
    refreshHandler,
    logoutHandler,
    forgotPasswordHandler,
    resetPasswordHandler,
    googleOAuthStartHandler,
    googleOAuthCallbackHandler,
    setupTwoFactorHandler,
    verifyTwoFactorHandler,
} from "../controllers/auth/auth.controller";
import { requireAuth } from "../middlewares/requireAuth";

const router = Router();

router.post("/register", registerHandler);
router.post("/login", loginHandler);
router.get("/verify-email", verifyEmailHandler);
router.post("/refresh", refreshHandler);
router.post("/logout", logoutHandler);
router.post("/forgot-password", forgotPasswordHandler);
router.post("/reset-password", resetPasswordHandler);
router.get("/google", googleOAuthStartHandler);
router.get(
    "/google/callback",
    googleOAuthCallbackHandler
);
router.post(
    "/2fa/setup",
    requireAuth,
    setupTwoFactorHandler
);
router.post(
    "/2fa/verify",
    requireAuth,
    verifyTwoFactorHandler
);








export default router;
