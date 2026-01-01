import express from "express";
import { getMe, updatePassword } from "../controllers/user.controller";
import { authenticateToken } from "../middlewares/auth.middleware";

const router = express.Router();

router.get('/me', authenticateToken, getMe);

router.post('/update-password', authenticateToken, updatePassword); // Placeholder, should call updatePassword

export default router;