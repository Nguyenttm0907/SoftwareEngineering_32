import './App.css';
import React from "react";
import {BrowserRouter, Route, Link} from 'react-router-dom';
import HomeScreen from './Screen/HomeScreen';
import ProductScreen from './Screen/ProductScreen';
import CartScreen from './Screen/CartScreen';
import SigninScreen from './Screen/SigninScreen';
import RegisterScreen from './Screen/RegisterScreen';
import PaymentMethodScreen from './Screen/PaymentMethodScreen';
import PlaceOrderScreen from './Screen/PlaceOrderScreen';
import ShippingAddressScreen from './Screen/ShippingAddressScreen';
import TableScreen from './Screen/TableScreen';
import SearchScreen from './Screen/SearchScreen';
import { useSelector } from 'react-redux';
import OrderScreen from './Screen/OrderScreen';
import OrderHistoryScreen from './Screen/OrderHistoryScreen';
import LogOut from './Logout';


const breakPoints = [
    { width: 600, itemsToShow: 1},
  ];

const OpenSearch = () => {
  document.querySelector(".SearchBar").classList.add("open");
}
const CloseSearch = () => {
  document.querySelector(".SearchBar").classList.remove("open");
}

function App() {
    const userSignin = useSelector(state=>state.userSignin);
    const cart = useSelector((state) => state.cart);
    const {userInfo} = userSignin;
    const {cartItems} = cart;
    const searchPro = (e) => {
        e.preventDefault();
        var a = document.getElementById('key').value;
        window.location = "/search/" + a ;
      };
  return (
      <BrowserRouter>
    <div>
    <header className="header">                                                        
    <nav>

        <div className="LienLac">

            <div className="Link">
                <a href="https://www.facebook.com/profile.php?id=100005814451333"><i className="fab fa-facebook-f"></i></a>   
                <a href="#"><i className="fab fa-twitter"></i></a>
                <a href="#"><i className="fab fa-youtube"></i></a>
                <a href="#"><i className="fab fa-instagram"></i></a>
            </div>

            <div className="SDT">
                <span>Call 0918 029 376</span>
            </div>
        </div>


    
    
        <div className="DieuHuong">                                                             
            
            <Link to="/">
            <div href="#" className="Logo">
                <img src ="/Anh/bk.png" style={{width : '70px', height: '70 px'}}/>
                <li className="Name">
                    <span>Group 32</span>
                </li>
            </div>
            </Link>

           
            <ul className="Menu">
                <li><a><Link to="/">Home</Link></a></li>
                <li><a href="/#Pro1">Drink</a>
                    <span className="SaleLabel">Sale</span>
                </li>
                <li><a href="/#Pro5">Food</a>
                    <span className="SaleLabel">Sale</span>
                </li>
                <li><a><Link to="/book">Other</Link></a></li>
            </ul>

           
            <div className="Right">
                <a href="#" className="TimKiem" onClick={OpenSearch}><i className="fas fa-search"></i></a>
                {
                    userInfo ? (
                    <div className="dropdown">
                        <Link to="/profile"><i className="fas fa-user"></i></Link>
                        <ul className="dropdown-content">
                            <li class="name">Hello {userInfo.name}!</li>
                            <li><Link to="/profile">My Profile</Link></li>
                            <li><Link to="/cart">My Cart</Link></li>
                            <li><Link to="/orderhistory">Order History</Link></li>
                            <li><Link to=""><LogOut></LogOut></Link></li>
                        </ul>
                    </div>
                    ) :
                    <Link to="/signin"><i className="fas fa-user"></i></Link>
                }
                
                <a>
                    <Link to="/cart">
                        <i className="fas fa-shopping-cart">
                    {
                        <span className="SoLuongDonHang">{cartItems.length}</span>
                    }
                        </i>
                    </Link>
                </a>
            </div>
        </div>
    </nav>
    </header>
   

    <div className="SearchBar">                                                                                    
        <form className="SearchInput"  onSubmit={searchPro}>                                                                              
        <input type="text" placeholder="Search for drink and food..." name="key" id="key"/>  
        <a href="#" className="SearchCancel" onClick={CloseSearch}>                                            
                <i className="fas fa-times"></i>                                                                  
            </a>
        </form>
    </div>

    <div className="Page">
        <Route path="/signin" component={SigninScreen} />
        <Route path="/register" component={RegisterScreen} />
        <Route path="/product/:id" component={ProductScreen} />
        <Route path="/cart/:id?" component={CartScreen} />
        <Route path="/book" component={TableScreen}/>
        <Route path="/search/:id?" component={SearchScreen} />
        <Route path="/shipping" component={ShippingAddressScreen} />
        <Route path="/payment" component={PaymentMethodScreen} />
        <Route path="/placeorder" component={PlaceOrderScreen} />
        <Route path="/order/:id" component={OrderScreen} />
        <Route path="/orderhistory" component={OrderHistoryScreen} />
        <Route path="/" exact={true} component={HomeScreen} />
    </div>
    
    

    <footer className="footer">
        <div className="ServicesBox">
            <i className="fas fa-headphones-alt"></i>
            <span>Serve every day</span>
            <p>Open from 7am to 10pm</p>
        </div>
        <div className="ServicesBox">
            <i className="fas fa-shipping-fast"></i>
            <span>Home Delivery</span>
            <p>Free Shipping For within a radius of 2km</p>
        </div>
        <div className="ServicesBox">
            <i className="fas fa-store"></i>
            <span>Buy on spot</span>
            <p>268 Ly Thuong Kiet, district 10, Ho Chi Minh city</p>
        </div>
    </footer>
    </div>
    </BrowserRouter>
  );
}

export default App;
