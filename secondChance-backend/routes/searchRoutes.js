const express = require("express");
const router = express.Router();
const connectToDatabase = require("../models/db");
const dotenv = require("dotenv");
dotenv.config();

// Search for items
router.get("/", async (req, res, next) => {
  try {
    // Task 1: Connect to MongoDB using connectToDatabase database. Remember to use the await keyword and store the connection in `db`
    const db = await connectToDatabase();

    const collection = db.collection(`${process.env.MONGO_COLLECTION}`);

    // Initialize the query object
    let query = {};

    // Add the name filter to the query if the name parameter is not empty
    if (req.query.name && req.query.name.trim() !== "") {
      query.name = { $regex: req.query.name, $options: "i" }; // Using regex for partial match, case-insensitive
    }

    // Task 3: Add other filters to the query
    if (req.query.category && req.query.category.trim() !== "") {
      query.category = { $regex: req.query.category, $options: "i" };
    }
    if (req.query.condition && req.query.condition.trim() !== "") {
      query.condition = { $regex: req.query.condition, $options: "i" };
    }
    if (req.query.age_years && req.query.age_years.trim() !== "") {
      query.age_years = { $lte: parseInt(req.query.age_years) };
    }

    // Task 4: Fetch filtered gifts using the find(query) method. Make sure to use await and store the result in the `items` constant
    const items = await collection.find(query).toArray();

    res.json(items);
  } catch (e) {
    next(e);
  }
});

module.exports = router;
