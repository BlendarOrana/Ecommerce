import Product from '../models/product.model.js'


export const  getAllProducts  = async (req, res) => {

    try {
        const product = await Product.find({});

        res.json({product});

        
    } catch (error) {
        console.log("Error in getAllProducts", error.message);
        res.status(500).json({message: "Server Error", error: error.message});
        
    }
    
}