import query from "../config/database";
import { Response } from "express";
import { v4 as uuidv4 } from "uuid";
import { AuthRequest } from "../middlewares/auth.middleware";

const getMe = async (req: AuthRequest, res: Response) => {
    try {
        // Get the userId that was attached by the authenticateToken middleware
        const userId = req.user?.userId;

        const result = await query("SELECT id, username, email FROM users WHERE id = $1", [userId]);

        res.status(200).json({ user: result.rows[0] });

    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

const updatePassword = async (req: Request, res: Response) => {};

const requestPasswordReset = async (req: Request, res: Response) => {}; 

const resetPassword = async (req: Request, res: Response) => {};

const verifyEmail = async (req: Request, res: Response) => {};  

const deleteAccount = async (req: Request, res: Response) => {};

export { getMe, updatePassword, requestPasswordReset, resetPassword, verifyEmail, deleteAccount };