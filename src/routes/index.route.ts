import express, { Request, Response } from "express";

const router = express.Router();

router.get('/api', (req: Request, res: Response) => {
  res.status(200).send({
    success: 'true',
    message: 'Welcome to Node.js + PostgreSQL',
    version: '1.0.0',
  });
});

export default router;