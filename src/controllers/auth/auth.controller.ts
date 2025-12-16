// src/controllers/auth/auth.controller.ts
import { Request, Response } from "express";
import { User } from "../../models/user.model"; // Mongoose User model
import { checkPassword, hashPassword } from "../../lib/hash"; // Custom hashing utility
import { registerSchema, loginSchema } from "./auth.schema"; // Zod validation schema
import jwt from "jsonwebtoken";
import { sendEmail } from "../../lib/email";
import { createAccessToken, createRefreshToken, verifyRefreshToken } from "../../lib/token";


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

        const { email, password } = result.data;
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