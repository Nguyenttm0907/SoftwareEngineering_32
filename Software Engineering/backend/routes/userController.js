
const User = require('../model/userModel')

// Show the list of staff
const index = (req, res, next) => {
    User.find({isStaff : true})
    .then(response => {
        res.json({
            response
        })
    })
    .catch(error => {
        res.json({
            message: 'An error Occured!'
        })
    })
}

// Show single staff
const show = (req, res, next) => {
    let username = req.body.name
    let filter = {name: username}
    User.findOne(filter)
    .then(response => {
        res.json({
            response
        })
    })
    .catch(error => {
        res.json({
            message: 'An error Occured!'
        })
    })
}

// update an staff
const update = (req, res, next) => {
    let useremail = req.body.email
    let filter = {email : email}
    let updateData = {
        name: req.body.name,
        email: req.body.email,
        password : req.body.password
    }

    User.findOneAndUpdate(filter, {$set: updateData})
    .then(() => {
        res.json({
            message: 'User updated succsessfully!'
        })
    })
    .catch(error => {
        res.json({
            message: 'An error Occured!'
        })
    })
}

// delete an staff
const destroy = (req, res, next) => {
    let useremail = req.body.email
    filter = {email : useremail}
    User.findOneAndRemove(filter)
    .then(() => {
        res.json({
            message: 'User deleted successfully!'
        })
    })
    .catch(eror => {
        res.json({
            message: 'An error Occured!'
        })
    })
}

module.exports = {
    index, show, update, destroy
}