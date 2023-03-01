const User = require("../models/userModel");
const validator = require("validator");
const bcrypt = require("bcrypt");
const sendMail = require("../utils/email");
const crypto = require("crypto");

exports.signUp = async (req, res) => {
  try {
    // 1- check if the email entered is valid
    let email = req.body.email;
    if (!validator.isEmail(email)) {
      return res.status(400).json({ message: "Please enter a valid email" });
    }
    // 2- check if the email is already in use
    // findOne , return the first document that matches the condition
    const checkEmail = await User.findOne({ email: req.body.email });
    if (checkEmail) {
      return res.status(409).json({ message: "Email already in use" });
    }
    // 3- check if the password and passwordConfirm are the same
    let pass = req.body.password;
    let passConfirm = req.body.passwordConfirm;
    if (pass !== passConfirm) {
      return res
        .status(400)
        .json({ message: "Password and passwordConfirm are not the same" });
    }

    //const hashedPassword = await bcrypt.hash(pass, 12);

    // if everything is ok, create a new user
    const newUser = await User.create({
      fullName: req.body.fullName,
      email: req.body.email,
      //password: hashedPassword,
      password: req.body.password,
    });
    res
      .status(201)
      .json({ message: "User created successfully", data: { newUser } });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
};

exports.login = async (req, res) => {
  try {
    // 1- check if the user email exist in the database
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    // 2- check if the entered password is matching with the hashed stored password

    // const isMatch = await bcrypt.compare(req.body.password, user.password);
    // if (!isMatch) {
    //   return res.status(400).json({ message: "Incorrect user and password" });
    // }
    if (!(await user.checkPassword(req.body.password, user.password))) {
      return res.status(401).json({ message: "Incorrect user and password" });
    }

    // 3- if everything is ok, Log the user in
    res.status(200).json({ message: "User logged in successfully" });
  } catch (err) {
    console.log(err);
  }
};

exports.forgotpassword = async (req, res) => {
  try {
    // 1- Check if the user with the provided email exist
    //const user = await User.findOne({$or: [{email: req.body.email},{phoneNumber: req.body.phoneNumber}]})
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return res
        .status(404)
        .json({ message: "The user with the provided email does not exist." });
    }

    // 2- create the reset token to be sended via email
    const resetToken = user.generatePasswordResetToken();
    await user.save({ validateBeforeSave: false });
    //3- send the token via the email
    // http://127.0.0.1:3000/api/auth/resetPassword/5f9c1b1b8b1b8c1b8b1b8b1b
    // 3.1 create this url

    const url = `${req.protocol}://${req.get(
      "host"
    )}/api/auth/resetPassword/${resetToken}`;
    const msg = `Forgot your password? Reset it by visiting the following link: ${url}`;

    try {
      await sendMail({
        email: user.email,
        subject: "Your password reset token (valid for 10 min)",
        message: msg,
      });
      res.status(200).json({
        status: "success",
        message: "the reset link was delivered to your email successfully",
      });
    } catch (err) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });
      return res.status(500).json({
        message: "There was an error sending the email. Try again later!",
      });
    }
  } catch (err) {
    console.log(err);
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const hashedToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        message: "Token is invalid or has expired , Please request a new one",
      });
    }

    if (req.body.password.length < 8) {
      return res
        .status(400)
        .json({ message: "Password must be at least 8 characters" });
    }

    if (req.body.password !== req.body.passwordConfirm) {
      return res
        .status(400)
        .json({ message: "Password and passwordConfirm are not the same" });
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.passwordChangeAt = Date.now();
    await user.save();
    return res.status(200).json({ message: "Password changed successfully" });
  } catch (err) {
    console.log(err);
  }
};
