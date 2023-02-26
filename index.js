const express = require("express");
const app = express();

// Importing the function to connect to the database
const DB = require("./database").connectDB;

// Importing the routes
const authRouter = require("./routes/authRoutes");

// Connecting to the database
DB();

app.use(express.json());

// Using the routes
app.use("/api/auth", authRouter);

app.listen(process.env.PORT, () => {
  console.log(`Server is running on port ${process.env.PORT}`);
});
