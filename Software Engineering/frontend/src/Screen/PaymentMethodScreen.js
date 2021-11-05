import React, { useState } from 'react'
import { useDispatch, useSelector } from 'react-redux';
import { savePaymentMethod } from '../actions/cartActions';
import CheckOutSteps from '../components/CheckOutSteps'

/**
* @author
* @fundefault 
*/

export default function PaymentMethodScreen(props) {
    const cart = useSelector(state => state.cart);
    const {shippingAddress} = cart;
    if (!shippingAddress.Address && !shippingAddress.RestaurantAddress) {
        props.history.push('/shipping');
    }
    const [paymentMethod,setPaymentMethod] = useState('');
    const dispatch = useDispatch();
    const submitHandler = (e) => {
        e.preventDefault();
        dispatch(savePaymentMethod(paymentMethod));
        props.history.push('/placeorder');
    }
  return(
    <div>
        <CheckOutSteps step1 step2 step3></CheckOutSteps>
        <form className="formShippingAddress" onSubmit={submitHandler}>
            <div>
                <h1>Choose payment method</h1>
            </div>
            <div>
                <div>
                    <input type="radio" id="paypal" value="PayPal" name="paymentMethod" required onChange={(e)=>setPaymentMethod(e.target.value)}></input>
                    <label htmlFor="paypal">PayPal</label>
                </div>
            </div>
            <div>
                <div>
                    <input type="radio" id="card" value="Credit card / Debit card" name="paymentMethod" required onChange={(e)=>setPaymentMethod(e.target.value)}></input>
                    <label htmlFor="card">Credit card / Debit card</label>
                </div>
            </div>
            <div>
                <div>
                    <input type="radio" id="ondeliver" value="Cash on delivery" name="paymentMethod" required onChange={(e)=>setPaymentMethod(e.target.value)}></input>
                    <label htmlFor="ondeliver">Cash on delivery</label>
                </div>
            </div>
            <div>
                <button className="primary" type="submit">Proceed</button>
            </div>
        </form>
    </div>
   )

 }