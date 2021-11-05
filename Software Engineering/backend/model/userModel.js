const mongoose = require('mongoose');

  const UserSchema = new mongoose.Schema({
    email: {type: String, required: true, unique: true},
    password: {type: String, required: true},
    name: {type: String, required: true},
    isStaff: {type: Boolean, required: true, default: false},
    isAdmin: {type: Boolean, required: true, default: false}
  })

  module.exports = mongoose.model('user', UserSchema)