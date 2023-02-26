const User = require("../models/userModel");
const validator = require("validator");
const bcrypt = require("bcrypt");

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
