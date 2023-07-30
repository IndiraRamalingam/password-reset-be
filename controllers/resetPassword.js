const User = require('../models/user');
const bcrypt=require('bcrypt');
const randomstring=require('randomstring');
const sendMail = require('../nodemailer/sendMail');


const resetPassword ={
    sendToken : async(req,res)=>{
    try
    {
        const{email} = req.body;

    let userDB = await User.findOne({ email: email });
    if (!userDB)
      return res.status(400).send({ message: "Invalid User email provided" });
    //creating random string and bcrypt to hash the token
    let token = randomstring.generate({
      length: 32,
      charset: "alphanumeric",
    });

    //creating expiry after 1 hour
    let expiry = new Date(Date.now() + 3600 * 1000);

    //updating users collection with resetToken and resetExpiry Time
    const resetUpdateDB = await User.findOneAndUpdate(
      { email: email },
      {
          resetToken: token,
          resetExpiry: expiry,        
      },
      {new:true},
    );

 // let link = `http://localhost:5173/reset_password/${token}`;
    let link = `https://bright-kataifi-acf1c9.netlify.app/reset_password/${token}`;       

    await sendMail(userDB.email, "Password Reset App - Reset your password", `<p>Hello! <i>${email}</i>, You have requested to reset your password.</p>
    <p>Please click the following link to reset your password: <i>${link}</i></p>`);
    res.status(200).send({
      message: `Reset link sent to mail ${userDB.email} and link is ${link}`,
    });

    }
    catch(error)
    {
        console.log("Send Token Failed in Email "+error)
    }
  },

  verifyAndUpdatePassword : async(req,res)=>{
    try{
      const{token,password} = req.body;

       let userDB=await User.findOne({ resetToken: token });

        //checking token is present in db is the token sent by the user or not
        const isTokenValid = userDB.resetToken === token;

        //checking if the time limit to change the password has the expired
        const isntExpired = userDB.resetExpiry > Date.now();

        if (isTokenValid && isntExpired) {
            
          const hashedNewPassword = await bcrypt.hash(password, 10);

          //deleting the token and expiry time after updating password
          const updatePasswordDB = await User.findOneAndUpdate(
            { resetToken: token },
               { 
                password: hashedNewPassword,
                resetToken: undefined,
                resetExpiry: undefined,                
               },
            { new: true }
          );

          res.status(200).send({ success: "password updated successfully" });
        } else res.status(400).send({ Error: "Invalid Link or Expired !!!" });

          }
          catch(error)
          {
            console.log("Update password failed in backend", error);
          }
        }

}

module.exports=resetPassword;
