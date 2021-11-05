import React, { useEffect } from 'react'
import { useDispatch, useSelector } from 'react-redux'
import { listOrderStaff, removeOrderStaff } from '../actions/orderActions';
import LoadingBox from '../components/LoadingBox';
import MessageBox from '../components/MessageBox';
import ReactDOM from 'react-dom';
/**
* @author
* @function 
**/

export default function OrderStaffScreen(props) {
    const orderStaffList = useSelector((state) => state.orderStaffList);
    const {loading, error, orders} = orderStaffList;
    //const orderStaffListRemove = useSelector((state) => state.orderStaffListRemove);
    //const {loading: loadingRemove, error: errorRemove, success: successRemove} = orderStaffListRemove;
    const dispatch = useDispatch();
    useEffect(() => {
        dispatch(listOrderStaff());
    }, [dispatch]);
    const deleteHandler = (order) => {
        var r = confirm("Delete an order?");
        if (r == true) {
            dispatch(removeOrderStaff(order));
        } else {

        }  
    };
  return (
    <div>
        <h1>Order History</h1>
        {
            loading ? (<LoadingBox></LoadingBox>) : error ? (<MessageBox variant="danger">{error}</MessageBox>) : (
                <table className="table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>USER</th>
                            <th>DATE</th>
                            <th>TOTAL</th>
                            <th>PAID</th>
                            <th>DELIVERED</th>
                            <th>ACTIONS</th>
                        </tr>
                    </thead>
                    <tbody>
                        {
                            orders.map((order) => (
                                <tr key={order._id}>
                                    <td>{order._id}</td>
                                    <td>{order.shippingAddress.FullName}</td>
                                    <td>{order.createdAt}</td>
                                    <td>{order.totalPrice}</td>
                                    <td>{order.isPaid ? order.paidAt : 'No'}</td>
                                    <td>{order.isDelivered ? order.deliveredAt : 'No'}</td>
                                    <td>
                                        <button type="button" className="small" onClick={() => {props.history.push(`/order/${order._id}`)}}>
                                            Details
                                        </button>
                                    </td>
                                    <td>
                                        <button type="button" className="small" disabled={!order.isDelivered || !order.isPaid} onClick={() => deleteHandler(order)}>
                                            Delete
                                        </button>
                                    </td>
                                </tr>
                            ))
                        }
                    </tbody>
                </table>
            )
        }
    </div>
   )

 }