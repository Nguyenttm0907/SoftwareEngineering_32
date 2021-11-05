import express from 'express';
import data from './data';
import dotenv from 'dotenv';
import config from './config';
import orderRouter from './routes/orderRoutes.js';
dotenv.config();
const mongodbUrl = config.MONGODB_URL;
const app = express();
app.get("/api/products/:id", (req, res) => {
    const productId = req.params.id;
    let product = 0;
    if( 10 < productId && productId < 20){product = data.milktea.find(x => x.id === productId);}
    else if( 20 < productId && productId < 30){product = data.coffee.find(x => x.id === productId);}
    else if( 30 < productId && productId < 40){product = data.soda.find(x => x.id === productId);}
    else if( 40 < productId && productId < 50){product = data.juice.find(x => x.id === productId);}
    else if( 50 < productId && productId < 60){product = data.food.find(x => x.id === productId);}
    if (product)
        res.send(product);
    else
        res.status(404).send({msg: "Product Not Found."});
});

app.get("/api/products", (req, res) => {
    res.send([data.milktea, data.coffee, data.soda, data.juice, data.food]);
});
const mongoose = require('mongoose')
const userRoutes = require('./routes/userRoutes')
const morgan = require('morgan')
const bodyParser = require('body-parser')
mongoose.connect(mongodbUrl,{
    useNewUrlParser: true, useUnifiedTopology: true})
const db = mongoose.connection
db.on('erro', (err) => {
    console.log(err)
})
db.once('open',() => {
    console.log('DB connection ESstablished!')
})
app.use(morgan('dev'))
app.use(bodyParser.urlencoded({extended: true}))
app.use(bodyParser.json())
const PORT = process.env.PORT || 5000
app.listen(PORT, ()=>{
    console.log('Server started at http://localhost:5000}')
})
app.use(express.json())
app.use("/api/users", userRoutes)
app.use('/api/orders', orderRouter)
app.get('/api/config/paypal', (req, res) => {
    res.send(config.PAYPAL_CLIENT_ID || 'sb');
})
