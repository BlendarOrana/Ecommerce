import User from "../models/user.model.js";
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import { redis } from "../lib/redis.js";


const generateTokens = (userId) => {
const accessToken = jwt.sign({userId},process.env.ACCESS_TOKEN_SECRET,{expiresIn:"30m"});
const refreshToken = jwt.sign({userId},process.env.REFRESH_TOKEN_SECRET,{expiresIn:"7d"});

return {accessToken,refreshToken};

};

const storeRefreshToken = async(userId,refreshToken)=>{
    await redis.set(`refresh_token:${userId}`,refreshToken,"EX",7*24*60*60);
}


const setCookies = (res,accessToken,refreshToken)=>{
    res.cookie("accessToken",accessToken, {
        httpOnly:true,
        secure: process.env.NODE_ENV === "production",
        sameSite:"strict",
        maxAge: 30*60*1000,
    
    })
    res.cookie("refreshToken",refreshToken, {
        httpOnly:true,
        secure: process.env.NODE_ENV === "production",
        sameSite:"strict",
        maxAge: 7*24*60*60*1000,
    
    })
}





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
    res.send("singup controller called")
}

export const logout = async (req, res) => {
    res.send("singup controller called")
}