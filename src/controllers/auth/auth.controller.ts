// src/controllers/auth/auth.controller.ts
import { Request, Response } from "express";
import { User } from "../../models/user.model"; // Mongoose User model
import { checkPassword, hashPassword } from "../../lib/hash"; // Custom hashing utility
import { registerSchema, loginSchema } from "./auth.schema"; // Zod validation schema
import jwt from "jsonwebtoken";
import { sendEmail } from "../../lib/email";
import { createAccessToken, createRefreshToken, verifyRefreshToken } from "../../lib/token";
import crypto from 'crypto';
import { getGoogleClient } from "../../lib/googleClient";
import { authenticator } from "otplib";


function getAppBaseUrl(): string {
    return `${process.env.APP_BASE_URL || "http://localhost:5000"}`;
}


export const registerHandler = async (req: Request, res: Response) => {
    try {
        // 1. Validation using Zod's safeParse
        const result = registerSchema.safeParse(req.body);

        if (!result.success) {
            // If validation fails (e.g., short password, invalid email)
            return res.status(400).json({
                message: "Invalid data",
                // Flatten provides a clean array of validation errors
                errors: result.error.flatten(),
            });
        }

        // Extract validated and typed data
        const { email, password, name } = result.data;

        // 2. Normalize Email
        const normalizedEmail = email.toLowerCase().trim();

        // 3. Check for Existing User (Uniqueness Check)
        // Find a user in the DB with the normalized email
        const existingUser = await User.findOne({ email: normalizedEmail });

        if (existingUser) {
            // Security Check: If the user exists, immediately return a 409 Conflict.
            return res.status(409).json({
                message: "This email is already in use. Please try with a different email.",
            });
        }
        // 4. Hash the Password
        const passwordHash = await hashPassword(password);

        // 5. Create the new User document
        const newlyCreatedUser = await User.create({
            email: normalizedEmail,
            passwordHash: passwordHash,
            name: name,
            // Default properties from the model are explicitly set for clarity:
            role: "user",
            isEmailVerified: false,
            twoFactorEnabled: false,
        });

        // 6. Send Verification Email (Next step in the video)
        // Payload: We only need the user's ID to know who is being verified
        const verifyToken = jwt.sign(
            { sub: newlyCreatedUser._id }, // Sub (subject) is the user ID
            process.env.JWT_ACCESS_SECRET!, // Use a secret key
            { expiresIn: "1d" } // Token expires in 1 day
        );


        // Construct Verification URL (Helper function)
        function getAppBaseUrl(): string {
            // Uses environment variables to construct the base URL
            return `${process.env.APP_BASE_URL || "http://localhost:5000"}`;
        }

        const verifyURL = `${getAppBaseUrl()}/auth/verify-email?token=${verifyToken}`;
        // Final step of the registration logic
        // Call sendEmail
        await sendEmail({
            to: newlyCreatedUser.email,
            subject: "Verify Your Email",
            html: `
    <p>Please verify your email by clicking this link:</p>
    <p><a href="${verifyURL}">Verify Email</a></p>
  `,
        });

        // Final successful response to the client
        return res.status(201).json({
            message: "User registered! Verification email sent.",
            user: {
                id: newlyCreatedUser._id,
                email: newlyCreatedUser.email,
                role: newlyCreatedUser.role,
                isEmailVerified: newlyCreatedUser.isEmailVerified

            }
        });
        // - Generate JWT tokens and set cookies


    } catch (error) {
        // Catch any unexpected server errors
        console.error(error);
        return res.status(500).json({ message: "An unexpected server error occurred." });
    }
};

//The verifyEmailHandler (The Endpoint)

// src/controllers/auth/auth.controller.ts
export const verifyEmailHandler = async (req: Request, res: Response) => {
    // Get token from the URL query parameters: /verify-email?token=...
    const token = req.query.token as string | undefined;

    if (!token) {
        return res.status(400).json({ message: "Verification token is missing." });
    }

    try {
        // 1. Verify the JWT Token
        // Decrypts the token using the same secret key
        const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET as string) as { sub: string };
        const userId = payload.sub; // The user ID we stored in the token's 'sub' field

        // 2. Find the User
        const user = await User.findById(userId);

        if (!user) {
            return res.status(400).json({ message: "User not found or token invalid." });
        }

        // 3. Check Verification Status
        if (user.isEmailVerified) {
            // User is already verified, no action needed
            return res.status(200).json({ message: "Email is already verified." });
        }

        // 4. Update the User Status
        user.isEmailVerified = true; // Set the flag to true
        await user.save(); // Save the updated document to MongoDB

        // 5. Success Response
        return res.status(200).json({ message: "Email is now verified. You can login." });

    } catch (error) {
        // This catch block handles JWT expiration or tampering errors
        console.error("Verification error:", error);
        return res.status(400).json({ message: "Invalid or expired verification token." });
    }
};


// lOGIN ENDPOINT

export const loginHandler = async (req: Request, res: Response) => {
    try {
        // 1. Validate Request Body (using loginSchema and safeParse)
        const result = loginSchema.safeParse(req.body);

        if (!result.success) {
            return res.status(400).json({
                message: "Invalid login data",
            });
        }

        const { email, password, twoFactorCode } = result.data;
        // Normalize email
        const normalizedEmail = email.toLowerCase().trim();

        // 2. Find User
        const user = await User.findOne({ email: normalizedEmail });
        if (!user) {
            return res.status(400).json({ message: "Invalid email or password." });
        }

        // 3. Password Check (using the new checkPassword utility)
        const isPasswordValid = await checkPassword(password, user.passwordHash);
        if (!isPasswordValid) {
            return res.status(400).json({ message: "Invalid email or password." });
        }

        // 4. Email Verification Check (Authorization/Access check)
        if (!user.isEmailVerified) {
            return res.status(403).json({
                message: "Please verify your email before logging in."
            });
        }

        //TOW FACTOR GUARD
        if (user.twoFactorEnabled) {
            if (!twoFactorCode || typeof twoFactorCode !== 'string') {
                return res.status(400).json({
                    message: "Two-factor code is required",
                });
            }

            if (!user.twoFactorSecret) {
                return res.status(400).json({
                    message: "Two-factor misconfigured for this account",
                });
            }
            // verify the code using otplib
            const isValidCode = authenticator.check(
                twoFactorCode,
                user.twoFactorSecret
            );

            if (!isValidCode) {
                return res.status(400).json({
                    message: "Invalid two-factor code",
                });
            }
        }


        // 5. Token Creation and Cookie Setting (Detailed below)
        const accessToken = createAccessToken(user._id.toString(), user.role, user.tokenVersion);
        const refreshToken = createRefreshToken(user._id.toString(), user.tokenVersion);

        // Set Refresh Token in an HTTP-Only Cookie
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true, // Prevents client-side JavaScript access (security!)
            secure: process.env.NODE_ENV === "production", // Only use 'Secure' in prod (HTTPS)
            sameSite: "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days (as calculated in transcript)
        });

        // 6. Success Response
        return res.status(200).json({
            message: "Login successfully done.",
            accessToken, // Sent back in the JSON response
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                isEmailVerified: user.isEmailVerified,
                twoFactorEnabled: user.twoFactorEnabled,
            },
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            message: "Internal server error",
        });
    }
};

//REFRESH TOKEN HANDLER ENDPOINT
export const refreshHandler = async (req: Request, res: Response) => {
    try {
        // 1. Get Token from HTTP-only Cookie
        const token = req.cookies.refreshToken as string | undefined;

        if (!token) {
            return res.status(401).json({ message: "Refresh token missing." }); // Unauthorized
        }

        // 2. Verify Token and Get Payload
        // Uses the dedicated refresh secret
        const payload = verifyRefreshToken(token) as { sub: string, tokenVersion: number };

        // 3. Find User by ID
        const user = await User.findById(payload.sub);

        if (!user) {
            return res.status(401).json({ message: "User not found." });
        }

        // 4. Token Version Check (Token Invalidation) - CRITICAL SECURITY CHECK
        // If the user's stored tokenVersion (bumped on password reset/logout) 
        // does not match the tokenVersion inside the JWT payload, invalidate it.
        if (user.tokenVersion !== payload.tokenVersion) {
            return res.status(401).json({ message: "Refresh token invalidated." });
        }

        // 5. Generate New Tokens
        const newAccessToken = createAccessToken(user._id.toString(), user.role, user.tokenVersion);
        const newRefreshToken = createRefreshToken(user._id.toString(), user.tokenVersion);

        // 6. Set New Refresh Token in Cookie (Rotate tokens)
        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        // 7. Success Response
        return res.status(200).json({
            message: "Token refreshed.",
            accessToken: newAccessToken
        });

    } catch (error) {
        // Handles expired or invalid JWT (e.g., signature mismatch)
        return res.status(401).json({ message: "Invalid or expired refresh token." });
    }
};

//LOGOUT ENDPOINT
export const logoutHandler = (req: Request, res: Response) => {
    // Clear the HTTP-only cookie by name and path
    res.clearCookie("refreshToken", { path: "/" });

    return res.status(200).json({ message: "Logged out successfully." });
};

//Forgot Password Handler

export const forgotPasswordHandler = async (req: Request, res: Response) => {
    const email = (req.body.email as string)?.toLowerCase().trim();

    if (!email) {
        return res.status(400).json({ message: "Email is required." });
    }
    const normalizedEmail = email.toLowerCase();

    try {
        const user = await User.findOne({ email: normalizedEmail });

        // SECURITY TRICK: Always return a generic success message
        // to prevent malicious users from knowing if an email exists in the DB.
        const genericSuccess = res.json({
            message: "If an account with this email exists, we will send a reset link."
        });

        if (!user) {
            return genericSuccess;
        }

        // 1. Generate Raw Token (Secure Random Bytes)
        const rawToken = crypto.randomBytes(32).toString("hex");

        // 2. Hash Token (Only store the hash in the DB, never the raw token)
        const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

        // 3. Set Reset Fields on User Document
        user.resetPasswordToken = tokenHash; // Store the secure hash
        // Set a short expiry (15 minutes)
        user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000);
        await user.save();

        // 4. Construct Reset URL (Use the RAW token here)
        const resetURL = `${getAppBaseUrl()}/auth/reset-password?token=${rawToken}`;

        // 5. Send Email
        await sendEmail({
            to: user.email,
            subject: "Password Reset Request",
            html: `<p>Click the link below to reset your password:</p>
             <p><a href="${resetURL}">${resetURL}</a></p>`,
        });

        return genericSuccess;

    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal server error." });
    }
};

//Reset Password Handler
export const resetPasswordHandler = async (req: Request, res: Response) => {
    const { token, password } = req.body as { token: string, password: string };

    if (!token) {
        return res.status(400).json({ message: "Reset token is missing." });
    }
    if (!password || password.length < 6) {
        return res.status(400).json({ message: "Password must be at least 6 characters long." });
    }

    try {
        // 1. Hash the incoming token (the raw token from the URL)
        const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

        // 2. Find User by Token Hash and Expiry Date
        const user = await User.findOne({
            resetPasswordToken: tokenHash, // Check if the token hash matches
            resetPasswordExpires: { $gt: Date.now() }, // Check if the expiry date is in the future
        });

        if (!user) {
            return res.status(400).json({ message: "Invalid or expired token." });
        }

        // 3. Hash New Password
        const newPasswordHash = await hashPassword(password);

        // 4. Update User Document
        user.passwordHash = newPasswordHash;

        // 5. Clear Reset Fields (Crucial: Token can only be used once)
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        // 6. Invalidate all existing sessions (CRITICAL SECURITY STEP)
        user.tokenVersion += 1; // Bump token version to invalidate all current refresh tokens

        await user.save();

        // 7. Success Response
        return res.status(200).json({ message: "Password reset successfully." });

    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal server error." });
    }
};

//Google Authentication
export async function googleOAuthStartHandler(
    req: Request,
    res: Response
) {
    try {
        const client = getGoogleClient();

        const url = client.generateAuthUrl({
            access_type: "offline",
            prompt: "consent",
            scope: [
                "openid",
                "email",
                "profile",
            ],
        });

        res.redirect(url);
    } catch (error) {
        res.status(500).json({
            message: "Could not start Google OAuth",
        });
    }
}

//Google OAuth Callback Handler

export async function googleOAuthCallbackHandler(
    req: Request,
    res: Response
) {
    const code = req.query.code as string | undefined;

    if (!code) {
        return res.status(400).json({
            message: "Authorization code missing",
        });
    }

    try {
        const client = getGoogleClient();
        // 1. Exchange the code for tokens
        const { tokens } = await client.getToken(code);

        if (!tokens.id_token) {
            return res.status(400).json({
                message: "Google ID token missing",
            });
        }
        // 2. Verify the ID Token to get user profile info
        const ticket = await client.verifyIdToken({
            idToken: tokens.id_token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload(); // Contains email, name, picture, etc.

        if (!payload?.email || !payload.email_verified) {
            return res.status(400).json({
                message: "Google email not verified",
            });
        }

        const email = payload.email.toLowerCase().trim();

        // 3. Find or Create the User in our DB
        let user = await User.findOne({ email });

        if (user) {
            // If user exists but wasn't verified, mark as true (Google verified them)
            if (!user.isEmailVerified) {
                user.isEmailVerified = true;
                await user.save();
            }
        } else {
            // Create a new user with a random password since they use Google
            const randomPassword = crypto.randomBytes(16).toString("hex");
            const passwordHash = await hashPassword(randomPassword);

            user = await User.create({
                email,
                passwordHash,
                role: "user",
                isEmailVerified: true, // Auto-verified via Google
                twoFactorEnabled: false,
            });

        }
        //  4. Generate our own JWT Access / Refresh tokens
        const accessToken = createAccessToken(
            user._id.toString(),
            user.role,
            user.tokenVersion
        );

        const refreshToken = createRefreshToken(
            user._id.toString(),
            user.tokenVersion
        );
        // 5. Set Refresh Token in Cookie
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        // 6. Success! Return data to frontend
        res.json({
            message: "Google login successful",
            accessToken,
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                isEmailVerified: user.isEmailVerified,
            },
        });

    } catch (error) {
        res.status(500).json({
            message: "Google authentication failed",
        });
    }
}

//SETUP 2FA ENDPOINT

export async function setupTwoFactorHandler(
    req: Request,
    res: Response
) {

    const authReq = req as any
    const authUser = authReq.user
    if (!authUser) {
        return res.status(401).json({
            message: "User not authenticated",
        });
    }

    try {
        const user = await User.findById(authUser.id);

        if (!user) {
            return res.status(404).json({
                message: "User not found",
            });
        }

        const secret = authenticator.generateSecret();

        const issuer = "Node-Advanced-App";

        const otpAuthUrl = authenticator.keyuri(
            user.email,
            issuer,
            secret
        );

        user.twoFactorSecret = secret;
        user.twoFactorEnabled = false; // IMPORTANT
        await user.save();

        res.json({
            message: "Two-factor setup initiated",
            otpAuthUrl,
            secret, // for testing only
        });

    } catch (error) {
        res.status(500).json({
            message: "Failed to setup two-factor authentication",
        });
    }
}

//VERIFY 2FA SETUP
export async function verifyTwoFactorHandler(
    req: Request,
    res: Response
) {
    const authReq = req as any
    const authUser = authReq.user
    if (!authUser) {
        return res.status(401).json({
            message: "Not authenticated"
        });
    }
    const { code } = req.body as { code?: string }
    if (!code) {
        return res.status(400).json({
            message: "Two factor code is required",
        });
    }
    try {
        const user = await User.findById(authUser.id);

        if (!user) {
            return res.status(404).json({
                message: "User not found",
            });
        }

        if (!user.twoFactorSecret) {
            return res.status(400).json({
                message: "Two-factor setup not completed",
            });
        }

        const isValid = authenticator.check(
            code,
            user.twoFactorSecret
        );

        if (!isValid) {
            return res.status(400).json({
                message: "Invalid two-factor code",
            });
        }

        user.twoFactorEnabled = true;
        await user.save();

        res.json({
            message: "Two-factor authentication enabled successfully",
            twoFactorEnabled: true,
        });

    } catch (error) {
        res.status(500).json({
            message: "Failed to verify two-factor authentication",
        });
    }
}










