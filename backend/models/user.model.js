import mongoose from "mongoose";

const userSchema = new mongoose.Schema({


    name: {
        type: String,
        required: [true,"name is required"]
    },
    email: {
        type: String,
        required: [true,"email is required"],
        unique: true,
        lowercase: true,
        trim:true
    },
    password: {
        type: String,
        required: [true,"password is required"],
        minlength: [8,"password must be at least 8 characters long"]
    },
    cartItems:[
        {
            quantity:{
                type: Number,
                default:1
            },
            product:{
                type: mongoose.Schema.Types.ObjectId,
                ref:"Product"
            }
        }
    ],
    role:{
        type: String,
        enum:["customer","admin"],
        default:"customer"
    }


},{timestamps:true})

const User = mongoose.model("User",userSchema);

export default User;