import React, { useEffect, useState } from 'react';
import {BrowserRouter, Route, Link} from 'react-router-dom';
import data from '../../../frontend/src/data';
import { useDispatch, useSelector } from 'react-redux';
import { listProducts } from '../actions/productActions';


function SearchScreen(props){

    const productList = useSelector(state => state.productList);
    const {products, loading, error} = productList;
    const dispatch = useDispatch();

    useEffect(() => {
        dispatch(listProducts());
        return () => {

        };
    }, [])

    const Key = props.match.params.id;

    return  loading ? <div>Loading...</div>:
    error ? <div>{error}</div>:
     <div>
    <div className="main">
        <div className="Heading">
            <h2>Search for key: "{Key}"</h2>
        </div>
        <div className="Product">
            <strong id="Pro1" className="Pro1">DRINK</strong>
            <div className="ProBox BoxShadow1">
                {
                    data.milktea.filter(pro => pro.name.toUpperCase().includes(Key.toUpperCase()) == true).map(pro =>
                        <li><a className="ProPic"><Link to={'/product/'+pro.id}><img src={pro.image}  style={{width: '200px', height: '200px'}}/></Link></a>
                            <a className="ProDuctName"><Link to={'/product/'+pro.id}>{pro.name}</Link></a>
                            <a className="ProDuctPrice">${pro.price}</a>
                        </li>)
                }
                {
                    data.coffee.filter(pro => pro.name.toUpperCase().includes(Key.toUpperCase()) == true).map(pro =>
                        <li><a className="ProPic"><Link to={'/product/'+pro.id}><img src={pro.image}  style={{width: '200px', height: '200px'}}/></Link></a>
                            <a className="ProDuctName"><Link to={'/product/'+pro.id}>{pro.name}</Link></a>
                            <a className="ProDuctPrice">${pro.price}</a>
                        </li>)
                }
                {
                    data.soda.filter(pro => pro.name.toUpperCase().includes(Key.toUpperCase()) == true).map(pro =>
                        <li><a className="ProPic"><Link to={'/product/'+pro.id}><img src={pro.image}  style={{width: '200px', height: '200px'}}/></Link></a>
                            <a className="ProDuctName"><Link to={'/product/'+pro.id}>{pro.name}</Link></a>
                            <a className="ProDuctPrice">${pro.price}</a>
                        </li>)
                }
                {
                    data.juice.filter(pro => pro.name.toUpperCase().includes(Key.toUpperCase()) == true).map(pro =>
                        <li><a className="ProPic"><Link to={'/product/'+pro.id}><img src={pro.image}  style={{width: '200px', height: '200px'}}/></Link></a>
                            <a className="ProDuctName"><Link to={'/product/'+pro.id}>{pro.name}</Link></a>
                            <a className="ProDuctPrice">${pro.price}</a>
                        </li>)
                }
            </div>
            
            <br/><br/>

            <strong id="Pro5" className="Pro5">Food</strong>
            <div className="ProBox BoxShadow5">
                {
                    data.food.filter(pro => pro.name.toUpperCase().includes(Key.toUpperCase()) == true).map(pro =>
                        <li><a className="ProPic"><Link to={'/product/'+pro.id}><img src={pro.image}  style={{width: '200px', height: '200px'}}/></Link></a>
                            <a className="ProDuctName"><Link to={'/product/'+pro.id}>{pro.name}</Link></a>
                            <a className="ProDuctPrice">${pro.price}</a>
                        </li>)
                }
            </div>

        </div>

        </div>
    </div>
}
export default SearchScreen;