
import query from "../config/database";
import { Request, Response } from "express";

const createProduct = async (req: Request, res: Response) => { 
    const { product_name, quantity, price } = req.body;
    const { rows } = await query(
    "INSERT INTO products (productName, quantity, price) VALUES ($1, $2, $3)",
        [product_name, quantity, price]
    );

    res.status(201).send({
        message: "Product added successfully!",
        body: {
            product: { product_name, quantity, price }
        },
    });
}

export { createProduct };