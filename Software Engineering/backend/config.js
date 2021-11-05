export default {
    MONGODB_URL: process.env.MONGODB_URL || 'mongodb://localhost:27017/demo',
    JWT_SECRET: process.env.JWT_SECRET || 'somthingsecret',
    PAYPAL_CLIENT_ID: process.env.PAYPAL_CLIENT_ID || 'sb'
}