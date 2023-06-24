const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const nodemailer = require("nodemailer");
const generateToken = require("../config/generateToken");

//@description     Get or Search all users
//@route           GET /api/user?search=
//@access          Public

const allUsers = asyncHandler(async (req, res) => {
  const keyword = req.query.search
    ? {
        $or: [
          { name: { $regex: req.query.search, $options: "i" } }, //case insensitive
          { email: { $regex: req.query.search, $options: "i" } },
        ],
      }
    : {};

  const users = await User.find(keyword).find({ _id: { $ne: req.user._id } });
  //not including the logged in user
  //console.log(users, 'matching search users');
  res.send(users);
});

//@description     Auth/login the user
//@route           POST /api/user/login
//@access          Public

const authUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  
  if(!user){
    res.status(401);
    throw new Error("Invalid Email or Password");
  }

  let iscorrectPassword = await user.matchPassword(password);

  if (!iscorrectPassword) {
    await User.updateOne({ _id: user.id }, { $inc: { passwordAttempts: +1 } });

    if (Number(user.passwordAttempts) === 5) {
      res.status(401);
      throw new Error("User blocked");
    }

    if (Number(user.passwordAttempts) === 2) {

      const transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465,
        secure: true,
        auth: {
          // TODO: replace `user` and `pass` values from <https://forwardemail.net>
          user: process.env.NODEMAILER,
          pass: process.env.NODEMAILER_PASS,
        },
      });

      const mailOptions = {
        from: process.env.NODEMAILER,
        to: email.toLowerCase(),
        subject: "Wrong Password Attempts",
        html: "<p>You will be blocked after two more unsuccessful password attempts.</p><br/><p>Regards,</p><p><b>Team Chat-Assessment</b></p>",
      };

      await transporter.sendMail(mailOptions, (err, _info) => {
        if (err) {
          console.log(err);
        } else {
          console.log("_info from Nodemailer", _info);
        }
      });
    }
  }

  if (Number(user.passwordAttempts) === 5) {
    res.status(401);
    throw new Error("User deactivated");
  }

  if (user && iscorrectPassword) {
    //instance method available on docs of certain collection

    await User.updateOne({ _id: user.id }, { $set: { passwordAttempts: 0 } });

    res.json({
      _id: user._id,
      name: user.name,
      email: user.email,
      isAdmin: user.isAdmin,
      token: generateToken(user._id),
    });
  } else {
    res.status(401);
    throw new Error("Invalid Email or Password");
  }
});

//@description     Register new user
//@route           POST /api/user/
//@access          Public

const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    res.status(400);
    throw new Error("Please Enter all the Feilds");
  }

  const userExists = await User.findOne({ email });

  if (userExists) {
    res.status(400);
    throw new Error("User already exists");
  }

  const user = await User.create({
    name,
    email,
    password, //mongoose mw to encrypt it before saving(creating) this doc in db//pre-save hook MW
  });

  //console.log("created user on signup",user)

  if (user) {
    res.status(201).json({
      _id: user._id,
      name: user.name,
      email: user.email,
      isAdmin: user.isAdmin,
      token: generateToken(user._id),
    });
  } else {
    res.status(400);
    throw new Error("User not found");
  }
});

module.exports = { registerUser, authUser, allUsers };
