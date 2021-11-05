import axios from "axios";
import Cookie from "js-cookie";
import { CART_ADD_ITEM, CART_REMOVE_ITEM } from "../constants/cartConstants";
import { CART_SAVE_PAYMENT_METHOD, CART_SAVE_SHIPPING_ADDRESS } from "../constants/cartConstants";
const addToCart = (productId, qty) => async (dispatch, getState) => {
    try {
        const {data} = await axios.get("/api/products/" + productId);
        dispatch({
            type: CART_ADD_ITEM, payload: {
                product: data.id,
                name: data.name,
                image: data.image,
                price: data.price,
                countInStock: data.countInStock,
                qty
            }
        });

        const {cart: {cartItems}} = getState();
        Cookie.set("cartItems", JSON.stringify(cartItems));
    
    } catch (error) {
        
    }
}

const removeFromCart = (productId) => (dispatch, getState) => {
    dispatch({ type: CART_REMOVE_ITEM, payload: productId});

    const {cart: {cartItems}} = getState();
    Cookie.set("cartItems", JSON.stringify(cartItems));
}

const saveShippingAddress = (data) => (dispatch, getState) => {
    dispatch({type: CART_SAVE_SHIPPING_ADDRESS, payload: data});
    const {cart: {shippingAddress}} = getState();
    Cookie.set("shippingAddress", JSON.stringify(shippingAddress));
};
const savePaymentMethod = (data) => (dispatch, getState) => {
    dispatch({type: CART_SAVE_PAYMENT_METHOD, payload: data});
    const {cart: {paymentMethod}} = getState();
    Cookie.set("paymentMethod", JSON.stringify(paymentMethod));
};

export {addToCart, removeFromCart, saveShippingAddress, savePaymentMethod}