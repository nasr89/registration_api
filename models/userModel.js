const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: [true, "Please enter your full name"],
      trim: true,
    },
    email: {
      type: String,
      required: [true, "Please enter your email"],
      trim: true,
      unique: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: [true, "Please enter your password"],
      trim: true,
      minlength: [8, "Minimum password length is 8 characters"],
      maxlength: [30, "Maximum password length is 30 characters"],
    },

    passwordConfirm: {
      type: String,
      required: [true, "Please confirm your password"],
      trim: true,
      minlength: [8, "Minimum password length is 8 characters"],
      maxlength: [30, "Maximum password length is 30 characters"],
    },
  },
  { timestamps: true }
);

// This function will run before the user is saved to the database
// Automated function
userSchema.pre("save", async function (next) {
  try {
    // Check if the password is modified
    if (!this.isModified("password")) return next();
    // Hash the password
    this.password = await bcrypt.hash(this.password, 12);
    // Delete the passwordConfirm field
    this.passwordConfirm = undefined;
  } catch (err) {
    console.log(err);
  }
});

// this function will always return 1 value: true or false
userSchema.methods.checkPassword = async function (
  enteredPassword,
  userPassword
) {
  return await bcrypt.compare(enteredPassword, userPassword);
};

module.exports = mongoose.model("User", userSchema);
