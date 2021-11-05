import React, { useEffect, useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { detailsProduct } from '../actions/productActions';

function ProductScreen(props){
    const [qty, setQty] = useState(1);
    const productDetails = useSelector(state => state.productDetails);
    const {product, loading, error} = productDetails;
    const dispatch = useDispatch();

    useEffect(() => {
        dispatch(detailsProduct(props.match.params.id));
        return () => {
            //
        };
    }, []);

    const handleAddToCart = () => {
        props.history.push("/cart/" + props.match.params.id + "?qty=" + qty)
    }
    
    return <div>
    {loading ? <div>Loading...</div>:
    error ? <div>{error}</div>:
    <div className="Detail">
    <div className="ProBox BoxShadow1 detail">
        <div className="ProductView1">
            <a className="ProPic"><img src={product.image} alt="product" style={{width: '400px', height: '400px'}}/></a>
        </div>

        <div className="cartpro1">

            <div className="cartpro2">
                <div className="ProductView2">
                    <li  className="ProDuctName"><a>Name: </a></li>
                    <li className="ProDuctPrice"><a>Price: </a></li>
                    <li  className="ProDuctName"><a>Rate:  </a></li>
                    <li className="ProDuctPrice"><a>NumRate:</a></li>
                </div>   

                <div className="ProductView3">
                    <li  className="ProDuctName"><a>{product.name}</a></li>
                    <li className="ProDuctPrice"><a>${product.price}</a></li>
                    <li  className="ProDuctName"><a>{product.rating}</a></li>
                    <li className="ProDuctPrice"><a>{product.numReviews}</a></li>
                </div>  
            </div>

            <div className="ProductView4">
                <div className="ProDuctAdd">Quantity: &emsp; <select value={qty} onChange={(e) => {setQty(e.target.value)}}>
                    {[...Array(product.countInStock).keys()].map(x=>
                        <option key={x+1} value={x+1}>{x+1}</option>
                    )}
                    </select></div>
                {product.countInStock > 0 && <input onClick={handleAddToCart} type="submit" value="Add to cart"/>}                
            </div>  
        </div>  
    </div>
</div>
    }
    </div>
}
export default ProductScreen;