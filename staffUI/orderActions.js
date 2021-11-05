import axios from "axios";
import Cookies from "js-cookie";
import { CART_EMPTY } from "../constants/cartConstants";
import { ORDER_CREATE_FAIL, ORDER_CREATE_REQUEST, ORDER_CREATE_SUCCESS, ORDER_DELIVER_FAIL, ORDER_DELIVER_REQUEST, ORDER_DELIVER_SUCCESS, ORDER_DETAILS_FAIL, ORDER_DETAILS_REQUEST, ORDER_DETAILS_SUCCESS, ORDER_MINE_LIST_FAIL, ORDER_MINE_LIST_REQUEST, ORDER_MINE_LIST_SUCCESS, ORDER_PAY_FAIL, ORDER_PAY_REQUEST, ORDER_PAY_SUCCESS, ORDER_STAFF_LIST_FAIL, ORDER_STAFF_LIST_REMOVE_FAIL, ORDER_STAFF_LIST_REMOVE_REQUEST, ORDER_STAFF_LIST_REMOVE_SUCCESS, ORDER_STAFF_LIST_REQUEST, ORDER_STAFF_LIST_SUCCESS } from "../constants/orderConstants";

const createOrder = (order) => async (dispatch, getState) => {
    dispatch({type: ORDER_CREATE_REQUEST, payload: order});
    try {
        const {userSignin:{userInfo}} = await getState();
        const {data} = await axios.post('/api/orders', order, {
            headers: {
                Authorization: `Bearer ${userInfo.token}`
            }
        });  
        dispatch({type: ORDER_CREATE_SUCCESS, payload: data.order});
        dispatch({type: CART_EMPTY});
        Cookies.remove('cartItems');
    }
    catch(error) {
        dispatch({
            type: ORDER_CREATE_FAIL,
            payload: 
                error.response && error.response.data.message ? error.response.data.message : error.message
        });
    }
};

const detailsOrder = (orderID) => async (dispatch, getState) => {
    dispatch({type: ORDER_DETAILS_REQUEST, payload: orderID});
    const {userSignin:{userInfo}} = getState();
    try {
        const {data} = await axios.get(`/api/orders/${orderID}` , {
            headers: {Authorization: `Bearer ${userInfo.token}`}
        });
        dispatch({type: ORDER_DETAILS_SUCCESS, payload: data});
    }
    catch(error) {
        const message = error.response && error.response.data.message ? error.response.data.message : error.message;
        dispatch({type: ORDER_DETAILS_FAIL, payload: message}); 
    }
};

const payOrder = (order, paymentResult) => async (dispatch, getState) => {
    dispatch({type: ORDER_PAY_REQUEST, payload: {order, paymentResult}});
    const {userSignin: {userInfo}} = getState();
    try {
        const {data} = axios.put(`/api/orders/${order._id}/pay`, paymentResult, {
            headers: {Authorization: `Bearer ${userInfo.token}`}
        });
        dispatch({type: ORDER_PAY_SUCCESS, payload: data});
    } 
    catch (error) {
        const message = error.response && error.response.data.message ? error.response.data.message : error.message;
        dispatch({type: ORDER_PAY_FAIL, payload: message});
    }
};

const listOrderMine = () => async (dispatch, getState) => {
    dispatch({type: ORDER_MINE_LIST_REQUEST});
    const {userSignin:{userInfo}} = getState();
    try {
        const {data} = await axios.get(`/api/orders/mine` , {
            headers: {Authorization: `Bearer ${userInfo.token}`}
        });
        dispatch({type: ORDER_MINE_LIST_SUCCESS, payload: data});
    }
    catch(error) {
        const message = error.response && error.response.data.message ? error.response.data.message : error.message;
        dispatch({type: ORDER_MINE_LIST_FAIL, payload: message}); 
    }
};
const listOrderStaff = () => async (dispatch, getState) => {
    dispatch({type: ORDER_STAFF_LIST_REQUEST});
    const {userSignin:{userInfo}} = getState();
    try {
        const {data} = await axios.get(`/api/orders/staff` , {
            headers: {Authorization: `Bearer ${userInfo.token}`}
        });
        dispatch({type: ORDER_STAFF_LIST_SUCCESS, payload: data});
    }
    catch(error) {
        const message = error.response && error.response.data.message ? error.response.data.message : error.message;
        dispatch({type: ORDER_STAFF_LIST_FAIL, payload: message}); 
    }
};

const removeOrderStaff = (order) => async (dispatch, getState) => {
    dispatch({type: ORDER_STAFF_LIST_REMOVE_REQUEST, payload: order});
    try {
        const {userSignin:{userInfo}} = getState();
        const {data} = await axios({
            method: 'delete',
            url: '/api/orders',
            data: order,
            headers: {
                    Authorization: `Bearer ${userInfo.token}`
                }
            }); 
        dispatch({type: ORDER_STAFF_LIST_REMOVE_SUCCESS, payload: data.order});
    }
    catch(error) {
        const message = error.response && error.response.data.message ? error.response.data.message : error.message;
        dispatch({type: ORDER_STAFF_LIST_REMOVE_FAIL, payload: message}); 
    }
}

const deliverOrder = (order) => async (dispatch, getState) => {
    dispatch({type: ORDER_DELIVER_REQUEST, payload: order});
    const {userSignin: {userInfo}} = getState();
    try {
        const {data} = await axios({
            method: 'put',
            url: `/api/orders/${order._id}/deliver`,
            data: order,
            headers: {
                    Authorization: `Bearer ${userInfo.token}`
                }
            }); 
        dispatch({type: ORDER_DELIVER_SUCCESS, payload: data});
    } 
    catch (error) {
        const message = error.response && error.response.data.message ? error.response.data.message : error.message;
        dispatch({type: ORDER_DELIVER_FAIL, payload: message});
    }
};
export {createOrder, detailsOrder, payOrder, listOrderMine, listOrderStaff, removeOrderStaff, deliverOrder};