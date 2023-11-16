const mongoose = require("mongoose");

const articlesSchema = new mongoose.Schema({
  id: {
    type: Number,
    required: [true, "ID is required"],
  },
  author: {
    type: String,
    required: [true, "Author is required"],
  },
  body: {
    type: String,
    required: [true, "Body is required"],
  },
  timestamp: {
    type: Date,
    required: [true, "Timestamp is required"],
  },
});

module.exports = articlesSchema;
