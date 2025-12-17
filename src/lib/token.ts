import jwt from "jsonwebtoken";

//Access Token (Short-Lived)
// src/lib/token.ts (excerpt)
// ... JWT imports

export const createAccessToken = (userId: string, role: "user" | "admin" = "user", tokenVersion: number) => {
    const payload = { sub: userId, role, tokenVersion };
    return jwt.sign(
        payload,
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "30m" } // Short-lived (e.g., 30 minutes)
    );
};

//Verify access token
export const verifyAccessToken = (token: string) => {
    return jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
        sub: string;
        role: 'user' | 'admin';
        tokenVersion: number;
    }
}
//Refresh Token (Long-Lived)
export const createRefreshToken = (userId: string, tokenVersion: number) => {
    const payload = { sub: userId, tokenVersion };
    return jwt.sign(
        payload,
        process.env.JWT_REFRESH_SECRET as string,
        { expiresIn: "7d" } // Long-lived (e.g., 7 days)
    );
};


//JWT Verification Utility
export const verifyRefreshToken = (token: string) => {
    return jwt.verify(
        token,
        process.env.JWT_REFRESH_SECRET!// Use the Refresh Secret
    ) as { sub: string, tokenVersion: number };
};