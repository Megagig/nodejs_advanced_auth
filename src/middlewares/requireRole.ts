import { Request, Response, NextFunction } from "express"

// Takes the required role (e.g., 'admin') as an argument
export const requireRole = (requiredRole: 'user' | 'admin') => {

    // Returns the actual Express middleware function
    return (req: Request, res: Response, next: NextFunction) => {
        const authReq = req as any;
        const authUser = authReq.user;

        // Check 1: User must be authenticated first (req.user must be present)
        if (!authUser) {
            // This case should ideally be caught by requireAuth first, 
            // but is a safety net.
            return res.status(401).json({ message: "Authentication required." });
        }

        // Check 2: Role Authorization
        if (authUser.role !== requiredRole) {
            // 403 Forbidden: User is authenticated but lacks permission
            return res.status(403).json({
                message: "You do not have the correct role to access this route."
            });
        }

        // If both checks pass, proceed
        next();
    };
};