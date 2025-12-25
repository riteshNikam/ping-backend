import express from "express";
import router from "./routes/index.route";
import productRouter from "./routes/product.routes";
import authRouter from "./routes/auth.route";
import userRouter from "./routes/user.route";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();
const PORT = 3000;

app.use(express.urlencoded({extended: true}))
app.use(express.json())
app.use(cors());
app.use(cookieParser());
app.use(router);
app.use('/api', productRouter);
app.use('/api', authRouter);
app.use('/api', userRouter);

export { app, PORT };
