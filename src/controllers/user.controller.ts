import query from "../config/database";
import { Response } from "express";
import { v4 as uuidv4 } from "uuid";
import { AuthRequest } from "../middlewares/auth.middleware";
import bcrypt from "bcrypt";

const getMe = async (req: AuthRequest, res: Response) => {
    try {
        // Get the userId that was attached by the authenticateToken middleware
        const userId = req.user?.userId;

        const result = await query("SELECT * FROM users WHERE id = $1", [userId]);

        res.status(200).json({ user: result.rows[0] });

    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

const updatePassword = async (req: AuthRequest, res: Response) => {
    try {
        // Get old and new password from request body
        const { oldPassword, newPassword } = req.body;

        // Validate input
        if (!oldPassword || !newPassword) {
            return res.status(400).json({ message: 'Old password and new password are required' });
        }

        // Get the userId that was attached by the authenticateToken middleware
        const userId = req.user?.userId;

        const userResult = (await query("SELECT password_hash FROM users WHERE id = $1" ,[userId]));

        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const storedPasswordHashResult = userResult.rows[0].password_hash;

        // Check if the old password matches
        const isMatch = await bcrypt.compare(oldPassword, storedPasswordHashResult);

        if (!isMatch) {
            return res.status(400).json({ message: 'Old password is incorrect' });
        }

        // Hash the new password
        const saltRounds = 10;
        const newHashedPassword = await bcrypt.hash(newPassword, saltRounds);

        await query('UPDATE users SET password_hash = $1 WHERE id = $2 RETURNING id, username, email', [newHashedPassword, userId]);

        // SECURITY: Revoke all existing sessions (Logout from all other devices)
        // This ensures a hacker cannot keep using an old session
        await query('DELETE FROM refresh_tokens WHERE user_id = $1', [userId]);

        // Clear the current refresh cookie (force the current user to re-login too)
        res.clearCookie('refreshToken', { httpOnly: true, secure: true, sameSite: 'strict' });

        res.status(200).json({ message: 'Password updated successfully. Please log in again with your new password.' });

        // Update the password in the database

    } catch (error) {
        console.log('Error:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

const requestPasswordReset = async (req: Request, res: Response) => {}; // will require email service

const resetPassword = async (req: Request, res: Response) => {}; // will require email service

const deleteAccount = async (req: Request, res: Response) => {};

export { getMe, updatePassword, requestPasswordReset, resetPassword, deleteAccount };