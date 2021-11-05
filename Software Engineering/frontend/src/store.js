import {createStore, combineReducers, applyMiddleware, compose} from 'redux';
import Cookie from 'js-cookie';
import thunk from 'redux-thunk';
import { productDetailsReducer, productListReducer } from './reducers/productReducers';
import {cartReducer} from './reducers/cartReducers';
import { userRegisterReducer, userSigninReducer } from './reducers/userReducers';
import { orderCreateReducer, orderDetailsReducer, orderPayReducer, orderMineListReducer } from './reducers/orderReducers';


//const cartItems = JSON.parse(Cookie.get("cartItems")) || [];
//const initialState = { cart: {cartItems} };
//const userInfo = JSON.parse(Cookie.get("userInfo")) || null;

//const initialState = {cart: {cartItems},userSignin:{userInfo}};
const initialState = {    //Using Cookie.get to get value by name in browser cookie
    cart: {
        cartItems: Cookie.get('cartItems') ? JSON.parse(Cookie.get('cartItems')):[],
        shippingAddress: Cookie.get('shippingAddress') ? JSON.parse(Cookie.get('shippingAddress')):{},
        paymentMethod: Cookie.get('paymentMethod') ? JSON.parse(Cookie.get('paymentMethod')):'',
    },
    userSignin: {
        userInfo: Cookie.get('userInfo') ? JSON.parse(Cookie.get('userInfo')) : null,
    }
};

const reducer = combineReducers({
    productList: productListReducer,
    productDetails: productDetailsReducer,
    cart: cartReducer,
    userSignin: userSigninReducer,
    userRegister: userRegisterReducer,
    orderCreate: orderCreateReducer,
    orderDetails: orderDetailsReducer,
    orderPay: orderPayReducer,
    orderMineList: orderMineListReducer
})

const composeEnhancer = window.__REDUX_DEVTOOLS_EXTENSION_COMPOSE__ || compose;
const store = createStore(reducer, initialState, composeEnhancer(applyMiddleware(thunk)));

export default store;