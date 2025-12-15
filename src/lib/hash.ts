// src/lib/hash.ts
import bcrypt from "bcryptjs";

// Generates a hash from the raw password
export const hashPassword = async (password: string): Promise<string> => {
    // 1. Generate Salt: A random string added to the password before hashing.
    // The 'salt' ensures that two identical passwords produce two different hashes.
    // 10 is the cost factor (higher is more secure but slower).
    const salt = await bcrypt.genSalt(10);

    // 2. Hash Password: Combines the raw password and the salt.
    const hashedPassword = await bcrypt.hash(password, salt);

    return hashedPassword;
};