// src/models/user.model.ts
import { Schema, model, Document } from "mongoose";

// Interface for TypeScript to know the shape of the User document
export interface IUser extends Document {
    name: string;
    email: string;
    passwordHash: string;
    role: "user" | "admin";
    isEmailVerified: boolean;
    twoFactorEnabled: boolean;
    twoFactorSecret?: string;
    tokenVersion: number;
    resetPasswordToken?: string;
    resetPasswordExpires?: Date;
}

const UserSchema = new Schema<IUser>(
    {
        // User email
        email: {
            type: String,
            required: true,
            unique: true, // MongoDB will enforce that no two users can have the same email
            lowercase: true, // Store all emails in lowercase for consistency
            trim: true, // Remove leading/trailing spaces
        },

        // Hashed password
        passwordHash: {
            type: String,
            required: true,
        },

        // User name
        name: {
            type: String,
        },
        // User role
        role: {
            type: String,
            enum: ["user", "admin"], // Only allow these two values
            default: "user",
        },

        // Email verification status
        isEmailVerified: {
            type: Boolean,
            default: false,
        },
        // Two-factor authentication enabled or not
        twoFactorEnabled: {
            type: Boolean,
            default: false,
        },

        // Two-factor secret (used for OTP generation)
        twoFactorSecret: {
            type: String,
            default: undefined, // Explicitly set to undefined if not used
        },
        // Used to invalidate refresh tokens
        tokenVersion: {
            type: Number,
            default: 0,
        },
        // Reset password token
        resetPasswordToken: {
            type: String,
            default: undefined,
        },
        // Reset password token expiry
        resetPasswordExpires: {
            type: Date,
            default: undefined,
        },
    },
    {
        timestamps: true, // Adds 'createdAt' and 'updatedAt' fields automatically
    }
);

// Export the Mongoose Model
export const User = model<IUser>("User", UserSchema);