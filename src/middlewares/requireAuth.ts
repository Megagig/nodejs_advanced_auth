// src/middleware/requireAuth.ts
import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken } from '../lib/token';
import { User } from "../models/user.model";

// This interface is needed to augment the Express Request object
interface AuthRequest extends Request {
    user?: {
        id: string;
        email: string;
        name: string;
        role: 'user' | 'admin';
        isEmailVerified: boolean;
    };
}

export const requireAuth = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers.authorization;

        // 1. Check for Authorization Header format (Bearer Token)
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message: "You are not authenticated (Missing or Malformed Token)." });
        }

        // 2. Extract Token
        const token = authHeader.split(' ')[1]; // "Bearer [Token]" -> takes the Token part

        // 3. Verify Access Token and Get Payload
        const payload = verifyAccessToken(token); // sub, role, tokenVersion

        // 4. Find User in DB
        const user = await User.findById(payload.sub);
        if (!user) {
            return res.status(401).json({ message: "User not found." });
        }

        // 5. Token Invalidation Check
        if (user.tokenVersion !== payload.tokenVersion) {
            return res.status(401).json({ message: "Token invalidated (Password/Reset)." });
        }

        // 6. Attach User Object to Request (Crucial Step)
        req.user = {
            id: user._id.toString(),
            email: user.email,
            name: user.name,
            role: user.role,
            isEmailVerified: user.isEmailVerified
        };

        // 7. Proceed to Next Handler/Middleware
        next();

    } catch (error) {
        // Catch JWT verification errors (e.g., expired token)
        return res.status(401).json({ message: "Invalid token." });
    }
};