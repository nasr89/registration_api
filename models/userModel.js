const mongoose = require("mongoose");
const bcrypt = require("bcrypt");// lal 2esas lt2ili metel password whashing mnesta3mel bc
const crypto = require("crypto"); // lal 2esas l5afife whiyye built in bel nodejs
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
    passwordChangeAt: Date,
    passwordResetToken: String,
    passwordResetExpires:Date,

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

// This function will create a random reset token
userSchema.methods.generatePasswordResetToken = function(){
  const resetToken = crypto.randomBytes(32).toString("hex"); // will be sent via email

  //saved in the DB in a hashed way
  this.passwordResetToken = crypto
  .createHash("sha256")
  .update(resetToken)
  .digest("hex");

  // 10 min of validity
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

module.exports = mongoose.model("User", userSchema);
