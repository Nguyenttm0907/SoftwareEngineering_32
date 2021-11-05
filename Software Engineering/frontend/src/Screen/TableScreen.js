import React from 'react';

function TableScreen(props){
    return  <div className="BOOK">
    <div className="book">                                                                                     
            <strong>BOOK TABLE</strong>
            <form>
                Phone:&ensp;&ensp;&ensp;&ensp;&ensp;    
                <input type="text" name="phone" id="phone "required/>
                <br></br><br/>
                Restaurant:&ensp; <select id="select">
                    <option>Dictrict 10, Ho Chi Minh city</option>
                    <option>Dictrict Thu Duc, Ho Chi Minh city</option>
                </select>       
                <br/><br/>
                Chairs:&ensp;&ensp;&ensp;&ensp;&ensp;
                <input type="text" name="chair" id="chair" required/>
                <br/><br/>
                &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;
                <input type="submit" value="BOOK"/>
            </form>
        </div>
    </div> 
}
export default TableScreen;