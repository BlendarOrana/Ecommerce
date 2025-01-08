import jwt from 'jsonwebtoken';
import  User  from '../models/user.model.js';
import dotenv from 'dotenv';
import e from 'express';
dotenv.config();


export const protectRoute = async (req, res, next) => {

    try {
        const accessToken = req.cookies.accessToken;

        if (!accessToken) {
            return res.status(401).json({ message: "no token" });
        }

   try {
    const decoded  = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    const user = await User.findById(decoded.userId).select("-password");

    if (!user) {
        return res.status(401).json({ message: "User not found" });
    }

    req.userId = user;
    
    next();
    
   } catch (error) {
    if(error.name === "TokenExpiredError"){
        return res.status(401).json({message:"Token expired"})
    }
    throw error
   }

    }
    
    catch (error) {
        console.log("Error in protectRoute", error.message);
        res.status(401).json({ message: "Unauthorized" });
        
    }
}

export const adminRoute = async (req, res, next) => {

if(req.user && req.user.role === "admin"){
    next();

}
else{
    return res.status(403).json({message:"Not authorized as an admin"})
}
}