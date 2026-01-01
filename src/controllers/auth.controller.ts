
import query from "../config/database";
import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { ACCESS_TOKEN_SECRET } from "../env";
import { v4 as uuidv4 } from "uuid";
import * as crypto from "crypto"
import sendEmail from "../utils/email.util";

const register = async (req: Request, res: Response) => {
    try {
        const { username, email, password } = req.body;

        // Validation checksP
        // username, email, and password are all required
        if (!username || !email || !password) {
            return res.status(400).send({
                message: "Username, email, and password are required."
            });
        }

        // Check if user with the same email or username already exists
        const existingUser = await query(
            "SELECT * FROM users WHERE email = $1 OR username = $2",
            [email, username]
        );

        // If user exists, return conflict error
        if (existingUser.rows.length > 0) {
            return res.status(409).send({
                message: "User with the same email or username already exists."
            });
        } 

        // Make hash of the password before storing
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        if (!hashedPassword) {
            return res.status(500).send({
                message: "Error hashing password."
            });
        }

        // Insert new user into the database
        const result = await query(
            "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email, created_at, updated_at, is_deleted",
            [username, email, hashedPassword]
        );

        // Generate toke for email verification
        const token = crypto.randomBytes(32).toString('hex');

        // Store verification token in the database
        await query("INSERT INTO email_verifications (user_id, token, expires_at) VALUES ($1, $2, $3)" ,[result.rows[0].id, token, new Date(Date.now() + 24 * 60 * 60 * 1000)]); // Token valid for 24 hours

        // Creating verification link
        const verificationLink = `http://localhost:4200/verify-email?token=${token}`;

        // Send verification email

        try {
              await sendEmail({
                email: email,
                subject: "Verify your email",
                message: `
                            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
                                <h2 style="color: #4f46e5;">Welcome to Ping!</h2>
                                <p>You're almost there! Click the button below to verify your email address.</p>
                                <a href="${verificationLink}" 
                                style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold;">
                                Verify My Account
                                </a>
                                <p style="margin-top: 20px; font-size: 12px; color: #64748b;">
                                If you didn't create an account, you can safely ignore this email.
                                </p>
                            </div>
                        `
            });
        } catch (error) {
            console.error('Email failed to send:', error);
            return res.status(201).json({
                message: 'User registered, but we couldn\'t send the verification email. Please request a resend.'
            });
        }
        
        // return the created user
        return res.status(201).send({
            message: "User registered successfully! Please check your email to verify your account.",
        });

    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

const verifyEmail = async (req: Request, res: Response) => {
    try {
        // Get token from request body
        const { emailToken } = req.body;

        // Validate input
        if (!emailToken) {
            return res.status(400).json({ message: 'Verification token is required' });
        }

        // Check if token is valid
        const tokenResult = await query("SELECT * FROM email_verifications WHERE token = $1 AND expires_at > NOW()", [emailToken]);

        if (tokenResult.rowCount === 0) {
            return res.status(400).json({ message: "Invalid or expired verification token." });
        }

        const userId = tokenResult.rows[0].user_id;

        // Update user's is_verified status
        await query("UPDATE users SET is_verified = TRUE WHERE id = $1", [userId]);

        // Delete the used token
        await query("DELETE FROM email_verifications WHERE token = $1", [emailToken]);

        return res.status(200).json({ message: "Email verified successfully." });

    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}

const login = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        // Find user by email ( email will always be unique )
        const user = await query("SELECT * FROM users WHERE email = $1", [email]);

        // If user not found then return 404
        if (user.rows.length === 0) {
            return res.status(404).send({
                message: "User not found."
            });
        }

        // Compare provided password with stored hash
        const isPasswordValid = await bcrypt.compare(password, user.rows[0].password_hash);

        if (!isPasswordValid) {
            return res.status(401).send({
                message: "Invalid password."
            });
        }

        // Creating short lived access token
        const accessToken = jwt.sign(
            { userId: user.rows[0].id },
            ACCESS_TOKEN_SECRET,
            { expiresIn: '15m' }
        );

        // Generate Long-Lived Refresh Token (The "ID Card")
        const refreshToken = uuidv4(); // A simple unique string
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7); // 7 days from now

        // Delete existing refresh tokens for the user
        await query('DELETE FROM refresh_tokens WHERE user_id = $1', [user.rows[0].id]);

        // Save Refresh Token to PostgreSQL
        await query(
            'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
            [user.rows[0].id, refreshToken, expiresAt]
        );

        // store refresh token in httpOnly cookie
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,    // Prevents JavaScript access (XSS protection)
            secure: true,      // Only sent over HTTPS (Important for Azure)
            sameSite: 'strict', // Prevents CSRF attacks
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days in milliseconds
        });

        return res.json({
            accessToken,
            user: { id: user.rows[0].id, username: user.rows[0].username, email: user.rows[0].email }
        });

    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

const logout = async (req: Request, res: Response) => {
    try {
        // Get refresh token from cookies
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return res.status(400).send({ message: "No refresh token provided." });
        }

        // Delete refresh token from database
        await query("DELETE FROM refresh_tokens WHERE token = $1", [refreshToken]);

        // Clear the cookie
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
        });

        // Success response
        return res.status(200).send({ message: "Logged out successfully." });

    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }    
};

const refreshToken = async (req: Request, res: Response) => {
    try {
        // Get refresh token from cookies
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return res.status(400).send({ message: "No refresh token provided." });
        }

        // Check if refresh token exists in database
        const result = await query("SELECT * FROM refresh_tokens WHERE token = $1", [refreshToken])

        // If token doesn't exist or is expired, clear cookie and reject
        if (!result.rows[0].token || new Date() > new Date(result.rows[0].expires_at)) {
            // Cleanup DB if it existed but was expired
            await query('DELETE FROM refresh_tokens WHERE id = $1', [result.rows[0].id]);
            res.clearCookie('refreshToken');
            return res.status(403).json({ message: 'Invalid or expired session' });
        }

        // ROTATION: Delete the old token immediately
        await query('DELETE FROM refresh_tokens WHERE id = $1', [result.rows[0].id]);

        // Generate new Access Token (JWT)
        const accessToken = jwt.sign(
            { userId: result.rows[0].user_id },
            ACCESS_TOKEN_SECRET,
            { expiresIn: '15m' }
        );

        // Generate new Refresh Token (UUID)
        const newRefreshToken = uuidv4();
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

        // Save the new Refresh Token to DB
        await query(
            'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
            [result.rows[0].user_id, newRefreshToken, expiresAt]
        );

        // Update the secure cookie with the NEW token
        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: true, 
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        // Send only the access token back in JSON
        return res.json({ accessToken });

    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }
};


const getMe = async (req: Request, res: Response) => {};

const updatePassword = async (req: Request, res: Response) => {};

const requestPasswordReset = async (req: Request, res: Response) => {}; 

const resetPassword = async (req: Request, res: Response) => {};

const deletAccount = async (req: Request, res: Response) => {};

export { register, login, logout, refreshToken, verifyEmail };