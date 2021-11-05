import React, { useEffect, useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { logout } from './actions/userAction';

function LogOut(props) {
  const userSignin = useSelector(state => state.userSignin);
  //const { loading, userInfo, error } = userSignin;
  const dispatch = useDispatch();
  //const redirect = props.location.search ? props.location.search.split("=")[1] : '/';
  useEffect(() => {
    if (userSignin==={}) {
      props.history.push('/');
    }
    return () => {
    };
  }, [userSignin]);
  const handle= (e) =>{
    e.preventDefault();
    dispatch(logout());
  }
  return <li onClick={handle} className="fas fa-power-off"></li>;
}
export default LogOut;