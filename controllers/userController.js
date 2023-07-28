const User=require('../models/user');
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');
const config=require('../utils/config')

const SECRET_KEY=config.SECRET_KEY;

const userController={
    signup:async(req,res)=>{
        try{
            const {name,email,password} = req.body;
            //check if the user already exists
            const existingUser=await User.findOne({email});

            if(existingUser){
                return res.status(409).json({message:'USer already exists'});
            }
            //hash the password before savingg
            const hashedPassword =await bcrypt.hash(password,10);

            //create new USer

            const newUser=new User({
                name,
                email,
                password :hashedPassword,
            });

            //save the user
            await newUser.save();

            res.status(201).json({message:"User created success"})

        }
        catch(error){
            console.error('Error signing up user',error)
            res.status(500).json({message:'signup111'})
        }
    },

    signin:async(req,res)=>{
        try{
            const {email,password}=req.body;

            //find the user by email
            const user=await User.findOne({email});

            if(!user){
                return res.status(401).json({message: 'Authentication Failed'});
            }
            //compare passwords

            const passwordMatch=await bcrypt.compare(password,user.password);

            if(!passwordMatch)
            {
                return res.status(401).json({message: 'Authentication Failed'});
            }

            //generate and send the jwt token 

            const token=jwt.sign({userId:user._id},SECRET_KEY,{expiresIn:'1h'});
            res.json({token});
        }
        catch(error)
        {
            console.log('Error signing in user', error);
            res.status(500).json({message: 'Internal Server error'});
        }
    },

}

module.exports=userController;
