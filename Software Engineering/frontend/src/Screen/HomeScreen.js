import React, { useEffect, useState } from 'react';
import {BrowserRouter, Route, Link} from 'react-router-dom';
import ReactDOM from "react-dom";
import Carousel from "react-elastic-carousel";
import data from '../../../frontend/src/data';
import axios from 'axios';
import { useDispatch, useSelector } from 'react-redux';
import { listProducts } from '../actions/productActions';

const breakPoints = [
    { width: 600, itemsToShow: 1},
  ];

function HomeScreen(props){

    const productList = useSelector(state => state.productList);
    const {products, loading, error} = productList;
    const dispatch = useDispatch();

    useEffect(() => {
        dispatch(listProducts());
        return () => {

        };
    }, [])

    return  loading ? <div>Loading...</div>:
    error ? <div>{error}</div>:
     <div>
        <div className="Slider">
        <Carousel breakPoints={breakPoints} enableAutoPlay autoPlaySpeed={2500}>
          <li className="Item1">
            <div className="slide Slide1">
                <div className="SlideContainer">
                    <div className="SlideText1">
                        <span>Combo for couple</span>
                        <strong>30% off with <font>code</font></strong>
                        <a href="#Pro1" className="SlideBuy">Buy now</a>
                    </div>
                </div>
            </div> 
          </li>
          <li className="Item2">
            <div className="slide Slide2">
                <div className="SlideContainer">
                    <div className="SlideText2">
                        <span>Combo for friends</span>
                        <strong>Buy Pizza <br/> bonus <font>Milk Tea</font></strong>
                        <a href="#Pro5" className="SlideBuy">Buy now</a>
                    </div>
                </div>
            </div>    
        </li>
        <li className="Item3">
            <div className="slide Slide3">
                <div className="SlideContainer">
                    <div className="SlideText3">
                        <span>Tropical drink</span>
                        <strong>30% off on <font>Tuesday</font></strong>
                        <a href="#Pro1" className="SlideBuy">Buy now</a>
                    </div>
                </div>
            </div> 
        </li>
        </Carousel>
      </div>


    <div className="main">
        <div className="Heading">
            <h2>Menu</h2>
        </div>
        <div className="Box">
            <li><a href="#Pro1"><img src="/Anh/TraSua5.jpg"  style={{width: '200px', height: '200px'}}/></a>
                <a>Milk Tea</a>
            </li>
            <li><a href="#Pro2"><img src="/Anh/Cafe0.jfif"  style={{width: '200px', height: '200px'}}/></a>
                <a>Coffee</a>
            </li>
            <li><a href="#Pro3"><img src="/Anh/Soda0.jpg "  style={{width: '200px', height: '200px'}}/></a>
                <a>Soda</a>
            </li>
            <li><a href="#Pro4"><img src="/Anh/SinhTo0.jfif"  style={{width: '200px', height: '200px'}}/></a>
                <a>Juice</a>
            </li>
            <li><a href="#Pro5"><img src="/Anh/DoAn1.jpg "  style={{width: '200px', height: '200px'}}/></a>
                <a>Food</a>
            </li>
        </div>
        

    

        <div className="Product">
            <strong id="Pro1" className="Pro1">MILK TEA</strong>
            <div className="ProBox BoxShadow1">
                {
                    data.milktea.map(pro =>
                        <li key={data.milktea.id}><a className="ProPic"><Link to={'/product/'+pro.id}><img src={pro.image}  style={{width: '200px', height: '200px'}}/></Link></a>
                            <a className="ProDuctName"><Link to={'/product/'+pro.id}>{pro.name}</Link></a>
                            <a className="ProDuctPrice">${pro.price}</a>
                        </li>)
                }
            </div>
            
            <br/><br/>

            <strong id="Pro2" className="Pro2">Coffee</strong>
            <div className="ProBox BoxShadow2">
            {
                    data.coffee.map(pro =>
                        <li key={data.coffee.id}><a className="ProPic"><Link to={'/product/'+pro.id}><img src={pro.image}  style={{width: '200px', height: '200px'}}/></Link></a>
                            <a  className="ProDuctName"><Link to={'/product/'+pro.id}>{pro.name}</Link></a>
                            <a className="ProDuctPrice">${pro.price}</a>
                        </li>)
                }
            </div>
            
            <br/><br/>

            <strong id="Pro3" className="Pro3">Soda</strong>
            <div className="ProBox BoxShadow3">
            {
                    data.soda.map(pro =>
                        <li key={data.soda.id}><a className="ProPic"><Link to={'/product/'+pro.id}><img src={pro.image}  style={{width: '200px', height: '200px'}}/></Link></a>
                        <a  className="ProDuctName"><Link to={'/product/'+pro.id}>{pro.name}</Link></a>
                        <a className="ProDuctPrice">${pro.price}</a>
                    </li>)
                }
            </div>
            
            <br/><br/>

            <strong id="Pro4" className="Pro4">Juice</strong>
            <div className="ProBox BoxShadow4">
            {
                    data.juice.map(pro =>
                        <li key={data.juice.id}><a className="ProPic"><Link to={'/product/'+pro.id}><img src={pro.image}  style={{width: '200px', height: '200px'}}/></Link></a>
                            <a  className="ProDuctName"><Link to={'/product/'+pro.id}>{pro.name}</Link></a>
                            <a className="ProDuctPrice">${pro.price}</a>
                        </li>)
                }
            </div>
            
            <br/><br/>

            <strong id="Pro5" className="Pro5">Food</strong>
            <div className="ProBox BoxShadow5">
            {
                    data.food.map(pro =>
                        <li key={data.food.id}><a className="ProPic"><Link to={'/product/'+pro.id}><img src={pro.image}  style={{width: '200px', height: '200px'}}/></Link></a>
                            <a  className="ProDuctName"><Link to={'/product/'+pro.id}>{pro.name}</Link></a>
                            <a className="ProDuctPrice">${pro.price}</a>
                        </li>)
                }
            </div>

        </div>
    </div>
    </div>
}
export default HomeScreen;