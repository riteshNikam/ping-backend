import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { ACCESS_TOKEN_SECRET } from '../env';

interface AuthRequest extends Request {
  user?: {
    userId: string;
  };
}

const authenticateToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'Access token is missing' });
        }

        // Verify token
        jwt.verify(token, ACCESS_TOKEN_SECRET, (error, decoded: any) => {
            if (error) {
                return res.status(403).json({ message: 'Invalid or expired token' });
            }

            req.user = { userId: decoded.userId };
        })

        // Move to the next function (the controller)
        next();


    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}

export { AuthRequest, authenticateToken };