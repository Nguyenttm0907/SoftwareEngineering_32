import axios from 'axios';
import React, { useEffect, useState } from 'react'
import { useDispatch, useSelector } from 'react-redux'
import { Link } from 'react-router-dom';
import { detailsOrder, payOrder } from '../actions/orderActions';
import LoadingBox from '../components/LoadingBox';
import MessageBox from '../components/MessageBox';
import {PayPalButton} from "react-paypal-button-v2"


export default function OrderScreen(props) {
    const orderId = props.match.params.id;
    const [sdkReady, setSdkReady] = useState(false);
    const orderDetails = useSelector(state => state.orderDetails);
    const {order, loading, error} = orderDetails;
    const orderPay = useSelector((state) => state.orderPay);
    const {loading: loadingPay, error: errorPay, success: successPay} = orderPay
    const dispatch = useDispatch();
    useEffect(() => {
        const addPayPalScript = async () => {
            const {data} = await axios.get('/api/config/paypal');
            const script = document.createElement('script');
            script.type="text/javascript";
            script.src=`https://www.paypal.com/sdk/js?client-id=${data}`;
            script.async = true;
            script.onload = () => {
                setSdkReady(true);
            };
            document.body.appendChild(script);
        };
        if (!order) {
            dispatch(detailsOrder(orderId));
        } else {
            if (!order.isPaid) {
                if (!window.paypal) {
                    addPayPalScript();
                } else {
                    setSdkReady(true);
                }
            }
        }
        dispatch(detailsOrder(orderId));
    }, [sdkReady]);
    const successPaymentHandler = (paymentResult) => {
        dispatch(payOrder(order, paymentResult));
    };
  return loading ? (<LoadingBox></LoadingBox>) : error ? (<MessageBox variant="danger">{error}</MessageBox>) : (
    <div>
        <h1>Order {order._id}</h1>
        <div className="row top">
            <div className="col-2">
                <ul>
                    <li>
                        <div className="card card-body">
                            <h2>
                                Shipping
                            </h2>
                            { order.shippingAddress.Formtype === "formDistant" ? (
                            <p>
                                <strong>Name:</strong> {order.shippingAddress.FullName} <br></br>
                                <strong>Address:</strong> {order.shippingAddress.Address}, {order.shippingAddress.District}, {order.shippingAddress.City}, {order.shippingAddress.Province}
                            </p>) : (
                                <p>
                                <strong>Name:</strong> {order.shippingAddress.FullName} <br></br>
                                <strong>Table No. </strong> {order.shippingAddress.TableNumber}, <strong>at </strong> {order.shippingAddress.RestaurantAddress}
                            </p>
                            )
                            }
                            {
                                order.isDelivered? 
                                <MessageBox variant="success">Delivered at {order.deliveredAt}</MessageBox>
                                :
                                <MessageBox variant="danger">Not Delivered</MessageBox>
                            }
                        </div>
                    </li>
                    <li>
                        <div className="card card-body">
                            <h2>
                                Payment
                            </h2>
                            <p>
                                <strong>Method:</strong> {order.paymentMethod} <br></br>
                            </p>
                            {
                                order.isPaid? 
                                <MessageBox variant="success">Paid at {order.paidAt}</MessageBox>
                                :
                                <MessageBox variant="danger">Not Paid</MessageBox>
                            }
                        </div>
                    </li>
                    <li>
                        <div className="card card-body">
                            <h2>
                                Order Items
                            </h2>
                            <ul>
                                {order.orderItems.map(item =>
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
                            <div>${order.itemsPrice}</div>
                        </div>
                    </li>
                    <li>
                        <div className="row">
                            <div>Shipping</div>
                            <div>${order.shippingPrice}</div>
                        </div>
                    </li>
                    <li>
                        <div className="row">
                            <div>Tax</div>
                            <div>${order.taxPrice}</div>
                        </div>
                    </li>
                    <li>
                        <div className="row">
                            <div><strong>Order Total</strong></div>
                            <div>${order.totalPrice}</div>
                        </div>
                    </li>
                    {
                        !order.isPaid &&  (
                            <li>
                                {
                                    !sdkReady ? (<LoadingBox></LoadingBox>) :
                                    (
                                        <>
                                        {errorPay && (<MessageBox variant="danger">{errorPay}</MessageBox>)}
                                        {loadingPay && <LoadingBox></LoadingBox>}
                                        <PayPalButton amount={order.totalPrice} onSuccess={successPaymentHandler}></PayPalButton>
                                        </>
                                    )
                                }
                            </li>
                        )
                    }
                </ul>

            </div>
        </div>
    </div>
   )

 }