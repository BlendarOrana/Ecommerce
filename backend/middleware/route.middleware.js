import jwt from 'jsonwebtoken';
import  User  from '../models/user.model.js';
import dotenv from 'dotenv';
dotenv.config();


export const protectRoute = async (req, res, next) => {

    try {
        const accessToken = req.cookies.accessToken;

        if (!accessToken) {
            return res.status(401).json({ message: "no token" });
        }

        const decoded  = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
        const user = await User.findById(decoded.userId).select("-password");

        req.userId = user;
        
        next();
    } catch (error) {
        console.log("Error in protectRoute", error.message);
        res.status(401).json({ message: "Unauthorized" });
        
    }
}