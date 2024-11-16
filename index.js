require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const User = require("./models/User.js");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json()); // For parsing application/json

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err));

// User registration route
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const newUser = new User({
    email,
    password: hashedPassword,
  });

  try {
    await newUser.save();
    res.status(201).send("User registered");
  } catch (error) {
    res.status(500).json({ error: "Failed to register user" });
  }
});

// User login route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).send("User not found");
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).send("Invalid credentials");
  }

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });
  res.json({ token });
});

// Example of a protected route
app.get("/profile", async (req, res) => {
  const token = req.header("x-auth-token");
  if (!token) return res.status(401).send("Access denied");

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    const user = await User.findById(req.user.userId); // Get user details by ID
    if (!user) {
      return res.status(404).send("User not found");
    }

    // Return the full user details (email, name, etc.)
    res.json({
      user: {
        // Ensure user is returned as an object
        email: user.email,
        name: user.name, // Assuming you also want the name
      },
    });
  } catch (error) {
    res.status(400).send("Invalid token");
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
