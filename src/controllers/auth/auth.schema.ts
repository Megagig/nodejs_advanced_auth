// src/controllers/auth/auth.schema.ts
import { z } from "zod";

// Define the schema for the registration request body
export const registerSchema = z.object({
    email: z.string().email("Invalid email format"), // Must be a string and a valid email format
    password: z.string().min(6, "Password must be at least 6 characters"), // Must be a string with a minimum length of 6
    name: z.string().min(3, "Name must be at least 3 characters"), // Must be a string with a minimum length of 3
});

// Export a TypeScript type generated from the Zod schema for strong typing
export type RegisterInput = z.infer<typeof registerSchema>;