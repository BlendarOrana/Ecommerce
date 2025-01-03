import express from 'express';
import dotenv from 'dotenv';
import authRoutes from './routes/auth.route.js';
import { connectDb } from './lib/db.js';


dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;
console.log(process.env.PORT);

app.use(express.json());

app.use("/api/auth",authRoutes);


app.listen( PORT, ()=>{
    console.log("Server is running on port "+PORT);
})

connectDb();

