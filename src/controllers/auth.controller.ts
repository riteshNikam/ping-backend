
import query from "../config/database";
import { Request, Response } from "express";
import { CreateUserInput } from "../types/user.type";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { ACCESS_TOKEN_SECRET } from "../env";
import { v4 as uuidv4 } from "uuid";

const register = async (req: Request, res: Response) => {
    try {
        const { username, email, password_hash }: CreateUserInput = req.body;

        // Validation checks
        // username, email, and password are all required
        if (!username || !email || !password_hash) {
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
        const hashedPassword = await bcrypt.hash(password_hash, saltRounds);

        if (!hashedPassword) {
            return res.status(500).send({
                message: "Error hashing password."
            });
        }

        // Insert new user into the database
        const result = await query(
            "INSERT INTO users (username, email, password_hash, created_at, updated_at, deleted) VALUES ($1, $2, $3, NOW(), NOW(), false) RETURNING id, username, email, created_at, updated_at, deleted",
            [username, email, hashedPassword]
        );

        // return the created user (excluding password_hash)
        return res.status(201).send({
            message: "User registered successfully!",
            user: result.rows[0],
        });

    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

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

const verifyEmail = async (req: Request, res: Response) => {};  

const deletAccount = async (req: Request, res: Response) => {};

export { register, login, logout, refreshToken };