import express, { Response, Request } from "express";

const app = express();
const PORT = 3000;

app.get('/', async (req: Request, res: Response) => {
    res.send("Hello, World");
});

export { app, PORT };