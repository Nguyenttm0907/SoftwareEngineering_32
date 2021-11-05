import React, { useEffect } from 'react'
import { useDispatch, useSelector } from 'react-redux'
import { Link } from 'react-router-dom';
import { createOrder } from '../actions/orderActions';
import CheckOutSteps from '../components/CheckOutSteps'
import LoadingBox from '../components/LoadingBox';
import MessageBox from '../components/MessageBox';
import { ORDER_CREATE_RESET } from '../constants/orderConstants';


export default function PlaceOrderScreen(props) {
    const cart = useSelector((state) => state.cart);
    const {cartItems} = cart;
    if (!cart.paymentMethod) {
        props.history.push('/payment');
    }
    const orderCreate = useSelector((state) => state.orderCreate);
    const {loading, success, error, order} = orderCreate;
    const toPrice = (num) => Number(num.toFixed(2));
    cart.itemsPrice = toPrice(cart.cartItems.reduce((a,c) => a + c.qty*c.price, 0));
    cart.shippingPrice = cart.itemsPrice > 100 ? toPrice(0) : toPrice(5);
    cart.taxPrice = toPrice(0.1*cart.itemsPrice);
    cart.totalPrice = cart.itemsPrice + cart.shippingPrice + cart.taxPrice;
    const dispatch = useDispatch();
    const placeOrderHandler = () => {
        dispatch(createOrder({...cart, orderItems: cart.cartItems}));
    };
    useEffect(() => {
        if (success) {
            props.history.push(`/order/${order._id}`);
            dispatch({type: ORDER_CREATE_RESET});
        }
    }, [dispatch, order, props.history, success]);
  return(
    <div>
        <CheckOutSteps step1 step2 step3></CheckOutSteps>
        <div className="row top">
            <div className="col-2">
                <ul>
                    <li>
                        <div className="card card-body">
                            <h2>
                                Shipping
                            </h2>
                            { cart.shippingAddress.Formtype === "formDistant" ? (
                            <p>
                                <strong>Name:</strong> {cart.shippingAddress.FullName} <br></br>
                                <strong>Address:</strong> {cart.shippingAddress.Address}, {cart.shippingAddress.District}, {cart.shippingAddress.City}, {cart.shippingAddress.Province}
                            </p>) : (
                                <p>
                                <strong>Name:</strong> {cart.shippingAddress.FullName} <br></br>
                                <strong>Table No. </strong> {cart.shippingAddress.TableNumber}, <strong>at </strong> {cart.shippingAddress.RestaurantAddress}
                            </p>
                            )
                            }
                        </div>
                    </li>
                    <li>
                        <div className="card card-body">
                            <h2>
                                Payment
                            </h2>
                            <p>
                                <strong>Method:</strong> {cart.paymentMethod} <br></br>
                            </p>
                        </div>
                    </li>
                    <li>
                        <div className="card card-body">
                            <h2>
                                Order Items
                            </h2>
                            <ul>
                                {cartItems.map(item =>
                                    <li>
                                        <div className="row">
                                        <div>
                                            <img src={item.image} alt="product" className="small"/>
                                        </div>
                                        <div className="min-30">
                                            <div>
                                                <Link to={"/product/" + item.product}>
                                                {item.name}
                                                </Link>
                                            </div>
                                        </div>
                                        <div>
                                            {item.qty} x ${item.price} = ${item.qty * item.price}
                                        </div>
                                        </div>
                                    </li>)
                                }
                            </ul>
                        </div>
                    </li>
                </ul>

            </div>
        
        </div>
        <div>
            <div className="card card-body">
                <ul>
                    <li>
                        <h2>Order Summary</h2>
                    </li>
                    <li>
                        <div className="row">
                            <div>Items</div>
                            <div>${cart.itemsPrice}</div>
                        </div>
                    </li>
                    <li>
                        <div className="row">
                            <div>Shipping</div>
                            <div>${cart.shippingPrice}</div>
                        </div>
                    </li>
                    <li>
                        <div className="row">
                            <div>Tax</div>
                            <div>${cart.taxPrice}</div>
                        </div>
                    </li>
                    <li>
                        <div className="row">
                            <div><strong>Order Total</strong></div>
                            <div>${cart.totalPrice}</div>
                        </div>
                    </li>
                    <li>
                        <button type="button" onClick={placeOrderHandler} className="primary block" disabled={cart.cartItems.length === 0}>Place Order</button>
                    </li>
                    {loading && <LoadingBox></LoadingBox>}
                    {error && <MessageBox variant="danger">{error}</MessageBox>}
                </ul>

            </div>
        </div>
    </div>
   )

 }