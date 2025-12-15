// src/controllers/auth/auth.controller.ts
import { Request, Response } from "express";
import { User } from "../../models/user.model"; // Mongoose User model
// import { hashPassword } from "../../lib/hash"; // Custom hashing utility (to be created)
import { registerSchema } from "./auth.schema"; // Zod validation schema

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

    } catch (error) {
        // Catch any unexpected server errors
        console.error(error);
        return res.status(500).json({ message: "An unexpected server error occurred." });
    }
};