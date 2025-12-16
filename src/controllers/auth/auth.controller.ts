// src/controllers/auth/auth.controller.ts
import { Request, Response } from "express";
import { User } from "../../models/user.model"; // Mongoose User model
import { hashPassword } from "../../lib/hash"; // Custom hashing utility
import { registerSchema } from "./auth.schema"; // Zod validation schema
import jwt from "jsonwebtoken";
import { sendEmail } from "../../lib/email";


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

        const verifyURL = `${getAppBaseUrl()}/verify-email?token=${verifyToken}`;
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