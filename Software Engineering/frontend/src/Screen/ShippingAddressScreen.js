import React, { useState } from 'react'
import { useDispatch, useSelector } from 'react-redux';
import { saveShippingAddress } from '../actions/cartActions';
import CheckOutSteps from '../components/CheckOutSteps'

/**
* @author
* @function 
**/

export default function ShippingAddressScreen(props) {

  //const userSignin = useSelector((state) => state.userSignin);
  //const {userInfo} = userSignin;
  const cart = useSelector(state => state.cart);
  const {shippingAddress} = cart;
  //if (!userInfo) {
    //props.history.push('/');
  //}

  const [FullName, setFullName] = useState('');
  const [Address, setAddress] = useState('');
  const [District, setDistrict] = useState('');
  const [City, setCity] = useState('');
  const [Province, setProvince] = useState('');
  const [TableNumber, setTableNumber] = useState('');
  const [RestaurantAddress, setRestaurantAddress] = useState('');
  const [Formtype, setFormtype] = useState('formDistant');
  const dispatch = useDispatch();
  const submitHandler = (e) => {
    e.preventDefault();
    dispatch(saveShippingAddress({FullName, Address, District, City, Province, TableNumber, RestaurantAddress, Formtype}));
    props.history.push('/payment');
  };
  let formDistant = (
    <form name="formDistant" className="formShippingAddress" onSubmit={submitHandler}>
          <div>
            <h1>Shipping Address</h1>
          </div>
          <div>
            <label htmlFor="FullName">Full Name</label>
            <input type="text" id="FullName" placeholder="Enter full name" value={FullName} onChange={(e) => setFullName(e.target.value)} required></input>
          </div>
          <div>
            <label htmlFor="Address">Address</label>
            <input type="text" id="Address" placeholder="Enter Address" value={Address} onChange={(e) => setAddress(e.target.value)} required></input>
          </div>
          <div>
            <label htmlFor="District">District</label>
            <input type="text" id="District" placeholder="Enter District" value={District} onChange={(e) => setDistrict(e.target.value)} required></input>
          </div>
          <div>
            <label htmlFor="City">City</label>
            <input type="text" id="City" placeholder="Enter City" value={City} onChange={(e) => setCity(e.target.value)} required></input>
          </div>
          <div>
            <label htmlFor="Province">Province</label>
            <input type="text" id="Province" placeholder="Enter Province" value={Province} onChange={(e) => setProvince(e.target.value)} required></input>
          </div>
          <div>
            <label></label>
            <button className="primary" type="submit">
              Proceed
            </button>
          </div>
        </form>
  );
  let formOnSpot = (
    <form name="formOnSpot" className="formShippingAddress" onSubmit={submitHandler}>
          <div>
            <h1>Customer Address</h1>
          </div>
          <div>
            <label htmlFor="FullName">Full Name</label>
            <input type="text" id="FullName" placeholder="Enter full name" value={FullName} onChange={(e) => setFullName(e.target.value)} required></input>
          </div>
          <div>
            <label htmlFor="TableNumber">Table No.</label>
            <input type="text" id="TableNumber" placeholder="Enter Table No." value={TableNumber} onChange={(e) => setTableNumber(e.target.value)} required></input>
          </div>
          <div>
            <label htmlFor="RestaurantAddress">Restaurant address</label>
            <input type="text" id="RestaurantAddress" placeholder="Enter Restaurant Address" value={RestaurantAddress} onChange={(e) => setRestaurantAddress(e.target.value)} required></input>
          </div>
          <div>
            <label></label>
            <button className="primary" type="submit">
              Proceed
            </button>
          </div>
        </form>
  );
  let form = Formtype=="formDistant" ? formDistant : formOnSpot;
  return(
    <div>
        <CheckOutSteps step1></CheckOutSteps>
        <form className="formShippingAddress">
          <label for="Formtype">Choose a shipping type:  </label>
          <select name="Formtype" onChange={(e) => setFormtype(e.target.value)}>
            <option value="formDistant" selected="selected">Distant shipping</option>
            <option value="formOnSpot">On spot</option>
          </select>
        </form>
        {
          form
        }
    </div>
   )

 }