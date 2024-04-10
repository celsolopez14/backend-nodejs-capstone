const express = require("express");
const multer = require("multer");
// const path = require("path");
// const fs = require("fs");
const router = express.Router();
const connectToDatabase = require("../models/db");
const logger = require("../logger");
const dotenv = require("dotenv");

dotenv.config();
// Define the upload directory path
const directoryPath = "public/images";

const dbCollection = `${process.env.MONGO_COLLECTION}`;

// Set up storage for uploaded files
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, directoryPath); // Specify the upload directory
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname); // Use the original file name
  },
});

const upload = multer({ storage: storage });

// Get all secondChanceItems
router.get("/", async (req, res, next) => {
  logger.info("/ called");
  try {
    const db = await connectToDatabase();
    const collection = db.collection(dbCollection);
    const secondChanceItems = await collection.find({}).toArray();
    res.json(secondChanceItems);
  } catch (e) {
    logger.console.error("oops something went wrong", e);
    next(e);
  }
});

// Add a new item
router.post("/", upload.single("file"), async (req, res, next) => {
  try {
    const db = await connectToDatabase();
    const collection = db.collection(dbCollection);
    let secondChanceItem = req.body;
    const lastItemQuery = await collection.find().sort({ id: -1 }).limit(1);

    await lastItemQuery.forEach((item) => {
      secondChanceItem.id = (parseInt(item.id) + 1).toString();
    });

    secondChanceItem.date_added = Math.floor(new Date().getTime() / 1000);
    secondChanceItem = await collection.insertOne(secondChanceItem);
    res.status(201).json(secondChanceItem);
  } catch (e) {
    next(e);
  }
});

// Get a single secondChanceItem by ID
router.get("/:id", async (req, res, next) => {
  try {
    const db = await connectToDatabase();
    const collection = db.collection(dbCollection);
    const secondChanceItem = await collection.findOne({ id: req.params.id });

    if (!secondChanceItem){
      return res.status(404).send("secondChanceItem not found");
    }

    res.json(secondChanceItem);
  } catch (e) {
    next(e);
  }
});

// Update and existing item
router.put("/:id", async (req, res, next) => {
  try {
    const db = await connectToDatabase();
    const collection = db.collection(dbCollection);
    const secondChanceItem = await collection.findOne({ id: req.params.id });

    if (!secondChanceItem){
      return res.status(404).send("secondChanceItem not found");
    }

    secondChanceItem.category = req.body.category;
    secondChanceItem.condition = req.body.condition;
    secondChanceItem.age_days = req.body.age_days;
    secondChanceItem.description = req.body.description;
    secondChanceItem.age_years = Number(
      (secondChanceItem.age_days / 365).toFixed(1)
    );
    secondChanceItem.updatedAt = new Date();

    const updatepreloveItem = await collection.findOneAndUpdate(
      { id: req.params.id },
      { $set: secondChanceItem },
      { returnDocument: "after" }
    );

    if (updatepreloveItem) {
      res.json({ uploaded: "success" });
    } else {
      res.json({ uploaded: "failed" });
    }
  } catch (e) {
    next(e);
  }
});

// Delete an existing item
router.delete("/:id", async (req, res, next) => {
  try {
    const db = await connectToDatabase();
    const collection = db.collection(dbCollection);
    const secondChanceItem = await collection.findOne({ id: req.params.id });

    if (!secondChanceItem){
      return res.status(404).send("secondChanceItem not found");
    }

    await collection.deleteOne({ id: req.params.id });
    res.json({ deleted: "success" });
  } catch (e) {
    next(e);
  }
});

module.exports = router;
