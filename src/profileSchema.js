const mongoose = require("mongoose");

const profileSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required']
  },
  email: {
    type: String,
    required: [true, 'Email is required']
  },
  zipcode: {
    type: Number,
    required: [true, 'Zipcode is required']
  },
  avatar: {
    type: String,
    required: [true, 'Zipcode is required']
  }, 
  phone: {
    type: String,
    required: [true, 'Phone is required']
  }, 
  dob: {
    type: String,
    required: [true, 'DOB is required']
  }
})

module.exports = profileSchema;