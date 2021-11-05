import mongoose from 'mongoose';
const orderSchema = new mongoose.Schema(
    {
        orderItems: [
            {
                name: {type: String, required: true},
                qty: {type: Number, required: true},
                image: {type: String, required: true},
                price: {type: Number, require: true}
            }
        ],
        shippingAddress: {
            FullName: {type: String, required: true},
            Address: {type: String, default: null},
            District: {type: String, default: null},
            City: {type: String, default: null},
            Province: {type: String, default: null},
            TableNumber: {type: String, default: null},
            RestaurantAddress: {type: String, default: null},
            Formtype: {type: String, required: true},
        },
        paymentMethod: {type: String, required: true},
        paymentResult: {
            id: String, 
            status: String, 
            update_time: String, 
            email_address: String
        },
        itemsPrice: {type: Number, required: true},
        shippingPrice: {type: Number, require: true},
        taxPrice: {type: Number, required: true},
        totalPrice: {type: Number, required: true},
        user: {type: mongoose.Schema.Types.ObjectId, ref: 'user', required: true},
        isPaid: {type: Boolean, default: false},
        paidAt: {type: Date},
        isDelivered: {type: Boolean, default: false},
        deliveredAt: {type: Date}
    },
    {
        timestamps: true
    }
);
const Order = mongoose.model('order', orderSchema);
export default Order;