import User from "../models/user.model.js";
import bcrypt from "bcryptjs"
import { generateTokens, storeRefreshToken, setCookies } from "../middleware/auth.middleware.js";
import { redis } from "../lib/redis.js";
import jwt from "jsonwebtoken";






export const signup = async (req, res) => {
    console.log("Request Body:", req.body); 

    const { name, email, password } = req.body;

try {
    if(!name || !email || !password){
        return res.status(400).json({message:"All fields are required"})
    }
    if(password.length < 8){
        return res.status(400).json({message:"Password must be at least 8 characters long"})
    }
    const existingUser = await User.findOne({email})

    if (existingUser) return res.status(400).json({message:"User already exists"})
    

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password,salt);


    const user = await User.create({ name, email, password: hashedPassword });

    const {accessToken, refreshToken} = generateTokens(user._id)
    await storeRefreshToken(user._id,refreshToken);

    setCookies(res,accessToken,refreshToken);


    res.status(201).json({message:"User created successfully",user:{
        name: user.name,
        email: user.email,
        role: user.role
    }})

} catch (error) {
    
}

}

export const login = async (req, res) => {

    const { email, password } = req.body;

    try {
        if(!email || !password){
            return res.status(400).json({message:"All fields are required"})
        }
        const user = await User.findOne({email});

        if(!user) return res.status(400).json({message:"Invalid credentials"})

        const isMatch = await bcrypt.compare(password,user.password);

        if(!isMatch) return res.status(400).json({message:"Invalid credentials"})

        const {accessToken, refreshToken} = generateTokens(user._id)
        await storeRefreshToken(user._id,refreshToken);

        setCookies(res,accessToken,refreshToken);

        res.status(200).json({message:"Login successful",user:{
            name: user.name,
            email: user.email,
            role: user.role
        }})

    } catch (error) {
        res.status(500).json({message:"Something went wrong login auth.controller.js"})
    }



}

export const logout = async (req, res) => {

    try {
        const refreshToken = req.cookies.refreshToken;
        if(refreshToken){
            const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
            await redis.del(`refresh_token:${decoded.userId}`);
        }
        res.clearCookie("accessToken");
        res.clearCookie("refreshToken");
        res.json({message:"Logged out successfully"})   

        
    } catch (error) {
        res.status(500).json({message:" Something went wrong logout auth.controller.js"})
        
    }
}

export const refreshToken = async (req, res) => {

    try {

        const refreshToken = req.cookies.refreshToken
        if(!refreshToken) return res.status(401).json({message:"No refresh token provided"});
    
    
            const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
            const storedToken = await redis.get(`refresh_token:${decoded.userId}`);
    
    
            if(storedToken !== refreshToken){
                return res.status(401).json({message:"Unauthorized"});
            }
            const accessToken = jwt.sign({userId: decoded.userId}, process.env.ACCESS_TOKEN_SECRET, {expiresIn:"30m"})
            res.cookie("accessToken", accessToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "strict",
                maxAge: 30 * 60 * 1000, // 30 minutes
              });
              res.json({message:"Refresh token successful"})
        
    } catch (error) {
        res.status(500).json({message:"Something went wrong refresh-token auth.controller.js"})
        
    }
  
}

export const getProfile = async (req, res) => {
    try {
        const user = await User.findById(req.userId).select("-password");
        res.json({user})
    } catch (error) {
        res.status(500).json({message:"Something went wrong getProfile auth.controller.js"})
    }
}