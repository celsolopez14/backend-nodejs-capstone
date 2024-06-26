const express = require("express");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const connectToDatabase = require("../models/db");
const router = express.Router();
const dotenv = require("dotenv");
const pino = require("pino"); // Import Pino logger
const { body, validationResult } = require("express-validator");
dotenv.config();
const logger = pino(); // Create a Pino logger instance

const JWT_SECRET = `${process.env.JWT_SECRET}`;

router.post("/register", async (req, res, next) => {
  try {
    // Task 1: Connect to `secondChance` in MongoDB through `connectToDatabase` in `db.js`.
    const db = await connectToDatabase();
    // Task 2: Access MongoDB `users` collection
    const collection = db.collection("users");
    // Task 3: Check if user credentials already exists in the database and throw an error if they do
    const existingEmail = await collection.findOne({ email: req.body.email });
    if (existingEmail)
      return res.status(400).json({ error: "Email id already exists" });
    // Task 4: Create a hash to encrypt the password so that it is not readable in the database
    const salt = await bcryptjs.genSalt(10);
    const hash = await bcryptjs.hash(req.body.password, salt);
    // Task 5: Insert the user into the database
    const newUser = await collection.insertOne({
      email: req.body.email,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      password: hash,
      createdAt: new Date(),
    });
    // Task 6: Create JWT authentication if passwords match with user._id as payload
    const payload = {
      user: {
        id: newUser.insertedId,
      },
    };
    const authToken = jwt.sign(payload, JWT_SECRET);
    // Task 7: Log the successful registration using the logger
    logger.info("User registered successfully");
    // Task 8: Return the user email and the token as a JSON
    res.status(200).json({ email: req.body.email, authToken });
  } catch (e) {
    return res.status(500).send("Internal server error");
  }
});

router.post("/login", async (req, res) => {
  try {
    // Task 1: Connect to `secondChance` in MongoDB through `connectToDatabase` in `db.js`.
    const db = await connectToDatabase();
    // Task 2: Access MongoDB `users` collection
    const collection = db.collection("users");
    // Task 3: Check for user credentials in database
    const user = await collection.findOne({ email: req.body.email });
    if (user) {
      // Task 4: Check if the password matches the encrypted password and send appropriate message on mismatch
      const result = await bcryptjs.compare(req.body.password, user.password);
      if (!result) {
        logger.error("Passwords do not match");
        return res.status(404).json({ error: "Wrong password" });
      }
      // Task 5: Fetch user details from a database
      const userName = user.firstName;
      const userEmail = user.email;
      // Task 6: Create JWT authentication if passwords match with user._id as payload
      let payload = {
        user: {
          id: user._id.toString(),
        },
      };
      const authToken = jwt.sign(payload, JWT_SECRET);
      res.json({ authToken, userName, userEmail });
      // Task 7: Send appropriate message if the user is not found
    } else {
      logger.error("User not found");
      return res.status(404).json({ error: "User not found" });
    }
  } catch (e) {
    return res.status(500).send("Internal server error");
  }
});

router.put("/update", async (req, res) => {
  // Task 2: Validate the input using `validationResult` and return an appropriate message if you detect an error
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.error("Validation errors in update request", errors.array());
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    // Task 3: Check if `email` is present in the header and throw an appropriate error message if it is not present
    const { email } = req.headers;
    if (!email) {
      logger.error("Email not found in the request headers");
      res.status(400).json({ error: "Email not found in the request headers" });
    }
    // Task 4: Connect to MongoDB
    const db = await connectToDatabase();
    const collection = db.collection("users");
    // Task 5: Find the user credentials in database
    const existingUser = await collection.findOne({ email: email });
    if (!existingUser) {
      logger.error("There is no user with the credentials passed.");
      res
        .status(404)
        .json({ error: "There is no user with the credentials passed." });
    }
    // Task 6: Update the user credentials in the database
    existingUser.firstName = req.body.firstName;
    existingUser.updatedAt = new Date();
    const updatedUser = await collection.findOneAndUpdate(
      { email },
      { $set: existingUser },
      { returnDocument: "after" }
    );
    // Task 7: Create JWT authentication with `user._id` as a payload using the secret key from the .env file
    const payload = {
      user: {
        id: updatedUser._id.toString(),
      },
    };

    const authtoken = jwt.sign(payload, JWT_SECRET);
    res.json({ authtoken });
  } catch (e) {
    return res.status(500).send("Internal server error");
  }
});

module.exports = router;
