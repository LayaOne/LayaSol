pragma solidity ^0.4.24;

contract InfoContract {
    address owner;
	address center_public_key = 0xf3cc9ed32f425c3c3202539f400f5a5efc14d5cc;
	
    //公匙：0x60320b8a71bc314404ef7d194ad8cac0bee1e331
    //sha3(msg): 0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45 (web3.sha3("abc");)
    //签名后的数据：0xf4128988cbe7df8315440adde412a8955f7f5ff9a5468a791433727f82717a6753bd71882079522207060b681fbd3f5623ee7ed66e33fc8e581f442acbcf6ab800
    struct Storage4User {
		uint ts;					//the time when user login
		bool locked;				//user login
		address[] public_keys;		//public key of N storage node
	}
	
	/*
		User Game Data
	*/
	struct UserData {
		//the last time when data stored
		uint ts;
		
		//hash of user data
		bytes32 hash_of_data;
		
		//user origin data
		bytes data;
	}
	
	mapping (address => Storage4User) user_storages;		// user id => storage node's public key
	mapping (address => UserData) user_datas;				// user data
	
	//test
	uint valid_count_g;
	bytes32 a;
	address[] b;
	bytes32[] r_g;
	bytes32[] s_g;
	byte[] v_g;
	bytes32[] prefixedHash_g;
	address[] result;

	modifier onlyCenter(){
		require(msg.sender == center_public_key);
		_;
	}
	
	/// Modifiers are a convenient way to validate inputs to
    /// functions. `onlyBefore` is applied to `bid` below:
    /// The new function body is the modifier's body where
    /// `_` is replaced by the old function body.
    modifier onlyBefore(uint _time) { require(now < _time); _; }
    modifier onlyAfter(uint _time) { require(now > _time); _; }
	
	constructor (InfoContract) public {
		owner = msg.sender;
	}
	
	function get_var() public returns(uint, bytes32, address[], bytes32[], bytes32[], byte[], bytes32[], address[]){
		return (valid_count_g, a, b, r_g, s_g, v_g, prefixedHash_g, result);
	}

	/*
		Verification center publickey
	*/
	function verify_center_publickey(bytes data, bytes _signed_data) public returns(bool) {
		return center_public_key != address(0) && center_public_key == begin_decode(_signed_data, sha3(data));
	}
	
    /*
		Save center pubkey per 24h
    */
    function save_public_key(address _user_id, address[] _storage_node_pubkey) public onlyCenter {
		require(_storage_node_pubkey.length > 2, "Node pubkey length needs to be greater than 2");
		require(_storage_node_pubkey.length < 12, "Node pubkey length needs to be less than 12");
		require(_storage_node_pubkey.length % 2 == 1, "Node pubkey length needs to be odd");
		
		for (uint256 i = 0; i < _storage_node_pubkey.length; i++){
			//_storage_node_pubkey[i];
		}
		
		//if (s.)1 days
		
		user_storages[_user_id] = Storage4User(now, true, _storage_node_pubkey);
    }
    
	/*
		For test
	 */
	function get_storage_status(address _user_id) public view returns (uint, bool, address[]){
		Storage4User memory u = user_storages[_user_id];
		
		return (u.ts, u.locked, u.public_keys);
	}

    /*
        Verify data authenticity per 24h
    */
    function save_user_data(address _user_id, bytes _user_data, bytes _signed_data) public onlyCenter returns (bool){
        //bytes memory signedString =hex"045c9cd05593e8eaac8259930c01f15be304870a1bbbcf1e3325b97f1fdfc55b058d47fc7f2bacfbf129afb4395188895d7d58494337254b653601ce3f15ea0201";
        //bytes memory user_data = "abc";
		require(_signed_data.length > 0, "Len of signed data must be greater than 0");
		require(_signed_data.length % 65 == 0, "Len of signed data can be divisible by 65");
		
		Storage4User storage s = user_storages[_user_id];
		uint valid_count = 0;
		bytes32 origin_hash = keccak256(_user_data);

		for (uint256 i = 0; i < _signed_data.length; i += 65){
			address temp_address = begin_decode(slice(_signed_data, i, 65), origin_hash);
			
			for (uint256 j = 0; j < s.public_keys.length; j++){
				if(temp_address == s.public_keys[j]){
					valid_count++;
					break;
				}
			}
		}
		
		valid_count_g = valid_count;
		
		if(valid_count == 0 || (valid_count < (s.public_keys.length + 1) / 2)){
			//How to deal user data when verify failed
			return false;
		}
		
		user_datas[_user_id] = UserData(now, sha256(_user_data), _user_data);
		s.locked = false;

		return true;
	}
    
	/*
		Read User Game Data
	*/
	function get_user_data(address _user_id) public view returns (bytes, bytes32, uint){
		//msg.sender == publickey?
		
		UserData storage user = user_datas[_user_id];
		
		return (user.data, user.hash_of_data, user.ts);
	}
	
	/*
	function get_storage_status(address _user_id) public view returns(){
		//return s.locked;
	}
	*/
    //验签数据入口函数
    function begin_decode(bytes signed_data, bytes32 origin_hash) internal returns (address){
        bytes memory signedString = signed_data;
        
        bytes32  r = bytesToBytes32(slice(signedString, 0, 32));
        bytes32  s = bytesToBytes32(slice(signedString, 32, 32));
        byte  v = slice(signedString, 64, 1)[0];
        
        return ecrecoverDecode(r, s, v, origin_hash);
    }
    
    //将原始数据按段切割出来指定长度
    function slice(bytes memory data, uint start, uint len) internal pure returns (bytes){
        bytes memory b = new bytes(len);
        
        for(uint i = 0; i < len; i++){
            b[i] = data[i + start];
        }
        
        return b;
    }
    
    //使用ecrecover恢复公匙
    function ecrecoverDecode(bytes32 _r, bytes32 _s, byte _v1, bytes32 _origin_hash) internal returns (address addr){
        uint8 v = uint8(_v1);// + 27;
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 prefixedHash = keccak256(prefix, _origin_hash);
		
        addr = ecrecover(prefixedHash, v, _r, _s);
    }
    
    //bytes转换为bytes32
    function bytesToBytes32(bytes memory source) internal pure returns (bytes32 result) {
        assembly {
            result := mload(add(source, 32))
        }
    }
}