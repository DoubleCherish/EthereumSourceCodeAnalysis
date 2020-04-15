### ENS(以太坊域名服务)智能合约源码分析二

##### 0、简介

​		本次分享直接使用线上实际注册流程来分析最新注册以太坊域名的相关代码。本次主要分析最新的关于普通域名注册合约和普通域名迁移合约，短域名竞拍合约不再本次分析范围内。

##### 1、实际注册过程

​		先看张时序图来了解下域名注册和使用的流程：

![regis](C:\Users\Administrator\Desktop\ensdoc\regis.png)

​		①  在app.ens.domains网站挑选自己要注册的域名，点击注册后第一个交易详情分析。

![tx1](C:\Users\Administrator\Desktop\ensdoc\tx1.PNG)

​		首先第一个交易详情如上图，实际调用了`ETHRegistrarController`的`commit(byte32)`方法，下面对此方法进行分析。

```java
// ETHRegistrarController成员变量介绍

 // 最小注册时长
 uint constant public MIN_REGISTRATION_DURATION = 28 days;
 // 最短和最常commitment生存时间，一个commitment在>=min && < max时候才可用
 uint public minCommitmentAge;  //86400 uint256
 uint public maxCommitmentAge;  //60 uint256
 // commitment=>time
 mapping(bytes32=>uint) public commitments;



// 在ETHRegistrarController合约里面实际调用了下面这个方法
function commit(bytes32 commitment) public {
        require(commitments[commitment] + maxCommitmentAge < now);
        commitments[commitment] = now;
}


// ETHRegistrarController为用户提供了一个工具方法用来生成commitment
// 当然用户可以自己生成，这样免得和智能合约交互，速度更快。
// 在网站上注册域名时候显然是网站直接帮用户根据相关数据直接生成了commitment

function makeCommitment(string memory name, address owner, bytes32 secret) pure public returns(bytes32) {
        return makeCommitmentWithConfig(name, owner, secret, address(0), address(0));
}

function makeCommitmentWithConfig(string memory name, address owner, bytes32 secret, address resolver, address addr) pure public returns(bytes32) {
        bytes32 label = keccak256(bytes(name));
        if (resolver == address(0) && addr == address(0)) {
            return keccak256(abi.encodePacked(label, owner, secret));
        }
        require(resolver != address(0));
    	// 此方法相当于 web3.util.keccak256(label, owner, resolver, addr, secret);
        return keccak256(abi.encodePacked(label, owner, resolver, addr, secret));
}
```

上面贴出了ETHRegistrarController的属性变量和注册域名第一个交易调用的方法，下面进行逻辑分析。

​		1、commitment机制主要是为了使用户在提交一个域名注册请求的时候，在maxCommitmentAge时间段内不能再重复提交相同请求。

​		2、commitment会在注册时候被作为一个预定凭证消耗掉。

下面看看第二个交易的内容：

![tx2](C:\Users\Administrator\Desktop\ensdoc\tx2.PNG)

​		从交易中可以看出来调用了ETHRegistrarController的registerWithConfig方法，下面分析registerWithConfig方法源码内容。

![registerwithconfig](C:\Users\Administrator\Desktop\ensdoc\registerwithconfig.png)

```java
function registerWithConfig(string memory name, address owner, uint duration, bytes32 secret, address resolver, address addr) public payable {
    	// 内部调用有推荐者的注册方法
        registerWithReferrer(name, owner, duration, secret, address(0), resolver, addr);
}

function registerWithReferrer(string memory name, address owner, uint duration, bytes32 secret, address payable referrer, address resolver, address addr) public payable {
    	// 先使用原参数进行commitment生成
        bytes32 commitment = makeCommitmentWithConfig(name, owner, secret, resolver, addr);
        // 通过_consumeCommitment对commitment进行消费，返回注册费用或者回滚
    	uint cost = _consumeCommitment(name, duration, commitment);
	    // 对name进行keccak256编码为一个label
        bytes32 label = keccak256(bytes(name));
    	// 将label转化为uint256类型作为ERC721的tokenId
        uint256 tokenId = uint256(label);

        uint expires;
    	// 如果用户注册时候指定了解析器
        if(resolver != address(0)) {
            
            // 调用baseRegistrar的registrer方法
            expires = base.register(tokenId, address(this), duration);

            // 对label进行hash操作
            bytes32 nodehash = keccak256(abi.encodePacked(base.baseNode(), label));

            // 调用baseRegistrar的ens合约设置域名对应的解析器
            base.ens().setResolver(nodehash, resolver);

            // 配置解析器对应的地址
            if (addr != address(0)) {
                Resolver(resolver).setAddr(nodehash, addr);
            }

            // 将拥有者从本合约转给注册人
            base.reclaim(tokenId, owner);
            base.transferFrom(address(this), owner, tokenId);
        } else {
            // 如果注册时候没设置解析器，那么直接调用baseRegistrar的注册方法
            require(addr == address(0));
            expires = base.register(tokenId, owner, duration);
        }

        emit NameRegistered(name, label, owner, cost, expires);
	    // 如果注册消耗费用小于注册人转账的金额，那么退费
        // Refund any extra payment
        if(msg.value > cost) {
            msg.sender.transfer(msg.value - cost);
        }
	    // 如果有推荐人，那么给推荐人奖励
        _sendReferralFee(referrer, cost);
    }
```

​		以上就是ETHRegistrarController的registerWithConfig方法逻辑介绍，下面开始对其中涉及到的方法进行展开分析。

​		①_consumeCommitment()方法

```java
function _consumeCommitment(string memory name, uint duration, bytes32 commitment) internal returns (uint256) {
        // commitment在有效期内
        require(commitments[commitment] + minCommitmentAge <= now);
        require(commitments[commitment] + maxCommitmentAge > now);
    	// 判断name是否可注册，即长度是否符合条件、是否被别人已经注册了
        require(available(name));
		
    	// 从commitments的map中删除此commitment，相当于已经消耗
        delete(commitments[commitment]);
	    // 小于rentPrice根据name和注册时长估算注册费用
        uint cost = rentPrice(name, duration);
        require(duration >= MIN_REGISTRATION_DURATION);
        require(msg.value >= cost);
        return cost;
}

function available(string memory name) public view returns(bool) {
        bytes32 label = keccak256(bytes(name));
        return valid(name) && base.available(uint256(label));
}

function valid(string memory name) public pure returns(bool) {
        return name.strlen() >= 3;
}

// BaseRegistrarImplementation.available()方法
function available(uint256 id) public view returns(bool) {
       	// 如果被注册或者在其域名宽限期内都是不可注册状态
    	// 过期时间+宽限期(90day)
        return expiries[id] + GRACE_PERIOD < now;
}
```

​		② base.register()方法

```java
function register(uint256 id, address owner, uint duration) external returns(uint) {
      return _register(id, owner, duration, true);
}

function _register(uint256 id, address owner, uint duration, bool updateRegistry) internal live onlyController returns(uint) {
        // 判断tokenid是否可用
        require(available(id));
    	// 防止溢出
        require(now + duration + GRACE_PERIOD > now + GRACE_PERIOD); 
	    // 更新id对应的过期时间
        expiries[id] = now + duration;
    	// 判断是否域名以前存在，若存在说明过期了。下面都是ERC721相关方法
        if(_exists(id)) {
            // 先销毁id，其实这步主要清除一下前一个owner的遗留数据（如approval等等）
            _burn(id);
        }
    	// 再重新铸出id给owner
        _mint(owner, id);
    	// 判断是否需要更新注册器，如需要更新id对应子节点的owner为当前注册者
        if(updateRegistry) {
            ens.setSubnodeOwner(baseNode, bytes32(id), owner);
        }

        emit NameRegistered(id, owner, now + duration);
	    // 返回过期时间
        return now + duration;
}

```

其中涉及到的ERC721相关方法可以参考[ERC721.sol](<https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol>)

​		③ reclaim()

```java
function reclaim(uint256 id, address owner) external live {
        require(_isApprovedOrOwner(msg.sender, id));
        ens.setSubnodeOwner(baseNode, bytes32(id), owner);
}

function _isApprovedOrOwner(address spender, uint256 tokenId) internal view returns (bool) {
        address owner = ownerOf(tokenId);
        return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));
}
```

**小结**

​		至此为止一个域名就完整的注册下来了，但是还没设置解析器等组件，后面我们全局整体分析下ENS的新合约。

##### 3、合约全览

###### 3.1 ETHRegistrarController

​		先看此合约的类继承图：

![ethregistrarcontroller](C:\Users\Administrator\Desktop\ensdoc\ethregistrarcontroller.png)

源码：

```java
/**
 *Submitted for verification at Etherscan.io on 2020-01-29
*/

contract ETHRegistrarController is Ownable {
    using StringUtils for *;

    uint constant public MIN_REGISTRATION_DURATION = 28 days;

    bytes4 constant private INTERFACE_META_ID = bytes4(keccak256("supportsInterface(bytes4)"));
    bytes4 constant private COMMITMENT_CONTROLLER_ID = bytes4(
        keccak256("rentPrice(string,uint256)") ^
        keccak256("available(string)") ^
        keccak256("makeCommitment(string,address,bytes32)") ^
        keccak256("commit(bytes32)") ^
        keccak256("register(string,address,uint256,bytes32)") ^
        keccak256("renew(string,uint256)")
    );

    bytes4 constant private COMMITMENT_WITH_CONFIG_CONTROLLER_ID = bytes4(
        keccak256("registerWithConfig(string,address,uint256,bytes32,address,address)") ^
        keccak256("makeCommitmentWithConfig(string,address,bytes32,address,address)")
    );
    // 组合了BaseRegistrar 合约对象
    BaseRegistrar base;
    // 组合了PriceOracle 价格预估对象
    PriceOracle prices;
    // 下面对象已经介绍过，不再赘述
    uint public minCommitmentAge;
    uint public maxCommitmentAge;

    mapping(bytes32=>uint) public commitments;

    event NameRegistered(string name, bytes32 indexed label, address indexed owner, uint cost, uint expires);
    event NameRenewed(string name, bytes32 indexed label, uint cost, uint expires);
    event NewPriceOracle(address indexed oracle);
	// 构造函数
    constructor(BaseRegistrar _base, PriceOracle _prices, uint _minCommitmentAge, uint _maxCommitmentAge) public {
        require(_maxCommitmentAge > _minCommitmentAge);

        base = _base;
        prices = _prices;
        minCommitmentAge = _minCommitmentAge;
        maxCommitmentAge = _maxCommitmentAge;
    }
	// 此方法调用price合约进行估算注册费用
    function rentPrice(string memory name, uint duration) view public returns(uint) {
        bytes32 hash = keccak256(bytes(name));
        return prices.price(name, base.nameExpires(uint256(hash)), duration);
    }
    // 域名续期
    function renew(string calldata name, uint duration) external payable {
        uint cost = rentPrice(name, duration);
        require(msg.value >= cost);

        bytes32 label = keccak256(bytes(name));
        uint expires = base.renew(uint256(label), duration);

        if(msg.value > cost) {
            msg.sender.transfer(msg.value - cost);
        }
        emit NameRenewed(name, label, cost, expires);
    }
    
    // 以下方法上面已经介绍过，在这里只放方法的摘要
    function valid(string memory name) public pure returns(bool) {}

    function available(string memory name) public view returns(bool) {}

    function makeCommitment(string memory name, address owner, bytes32 secret) pure public returns(bytes32) {}

    function makeCommitmentWithConfig(string memory name, address owner, bytes32 secret, address resolver, address addr) pure public returns(bytes32) {}

    function commit(bytes32 commitment) public {}

    function registerWithConfig(string memory name, address owner, uint duration, bytes32 secret, address resolver, address addr) public payable {}

    function setPriceOracle(PriceOracle _prices) public onlyOwner {}

    function setCommitmentAges(uint _minCommitmentAge, uint _maxCommitmentAge) public onlyOwner {}

    function withdraw() public onlyOwner {}

    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {}

    function _consumeCommitment(string memory name, uint duration, bytes32 commitment) internal returns (uint256) {}
}
```

​		上面就是ETHRegistrarController对外暴露的方法。可以看出此合约主要是一个外观合约，其底层是大多调用BaseRegistrar完成。下面开始分析BaseRegistrar合约的实现合约。

###### 3.2BaseRegistrarImplementation

​		先来看张继承关系图：

![baseRegistrarImplement](C:\Users\Administrator\Desktop\ensdoc\baseRegistrarImplement.png)

源码分析：

```java
// File: @ensdomains/ethregistrar/contracts/BaseRegistrarImplementation.sol

pragma solidity ^0.5.0;
// 合约继承自ERC721(主要记得在这里可以使用ERC721内部方法)和BaseRegistrar
contract BaseRegistrarImplementation is BaseRegistrar, ERC721 {
    // 一个map记录着域名的过期时间
    mapping(uint256=>uint) expiries;

    bytes4 constant private INTERFACE_META_ID = 				        bytes4(keccak256("supportsInterface(bytes4)"));
    bytes4 constant private ERC721_ID = bytes4(
        keccak256("balanceOf(address)") ^
        keccak256("ownerOf(uint256)") ^
        keccak256("approve(address,uint256)") ^
        keccak256("getApproved(uint256)") ^
        keccak256("setApprovalForAll(address,bool)") ^
        keccak256("isApprovedForAll(address,address)") ^
        keccak256("transferFrom(address,address,uint256)") ^
        keccak256("safeTransferFrom(address,address,uint256)") ^
        keccak256("safeTransferFrom(address,address,uint256,bytes)")
    );
    bytes4 constant private RECLAIM_ID = bytes4(keccak256("reclaim(uint256,address)"));
	// 构造函数，传入ens合约和跟域名.eth
    constructor(ENS _ens, bytes32 _baseNode) public {
        ens = _ens;
        baseNode = _baseNode;
    }

    modifier live {
        require(ens.owner(baseNode) == address(this));
        _;
    }

    modifier onlyController {
        require(controllers[msg.sender]);
        _;
    }
    function ownerOf(uint256 tokenId) public view returns (address) {}

    // 添加一个Controller作为外观合约
    function addController(address controller) external onlyOwner {
        controllers[controller] = true;
        emit ControllerAdded(controller);
    }
    // Revoke controller permission for an address.
    function removeController(address controller) external onlyOwner {
        controllers[controller] = false;
        emit ControllerRemoved(controller);
    }
    // Set the resolver for the TLD this registrar manages.
    function setResolver(address resolver) external onlyOwner {
        ens.setResolver(baseNode, resolver);
    }

    // Returns the expiration timestamp of the specified id.
    function nameExpires(uint256 id) external view returns(uint) {
        return expiries[id];
    }

    // Returns true iff the specified name is available for registration.
    function available(uint256 id) public view returns(bool) {}

    /**
     * @dev Register a name.
     * @param id The token ID (keccak256 of the label).
     * @param owner The address that should own the registration.
     * @param duration Duration in seconds for the registration.
     */
    function register(uint256 id, address owner, uint duration) external returns(uint) {}

    /**
     * @dev Register a name, without modifying the registry.
     * @param id The token ID (keccak256 of the label).
     * @param owner The address that should own the registration.
     * @param duration Duration in seconds for the registration.
     */
    function registerOnly(uint256 id, address owner, uint duration) external returns(uint) {
      return _register(id, owner, duration, false);
    }

    function _register(uint256 id, address owner, uint duration, bool updateRegistry) internal live onlyController returns(uint) {}

    function renew(uint256 id, uint duration) external live onlyController returns(uint) {
        require(expiries[id] + GRACE_PERIOD >= now); // Name must be registered here or in grace period
        require(expiries[id] + duration + GRACE_PERIOD > duration + GRACE_PERIOD); // Prevent future overflow

        expiries[id] += duration;
        emit NameRenewed(id, expiries[id]);
        return expiries[id];
    }

    /**
     * @dev Reclaim ownership of a name in ENS, if you own it in the registrar.
     */
    function reclaim(uint256 id, address owner) external live {}

    function supportsInterface(bytes4 interfaceID) external view returns (bool) {}
}
```

​		可以看出，在外观合约即Controller中调用的续期、注册等操作实际是调用BaseRegistrarImplementation合约的相关方法进行实际修改数据。

###### 3.2.1OldBaseRegistrarImplment

​		以太坊域名服务器大致到现在分为三代，这个合约可以称之为第二代注册器。

​		源码如下：

```java
pragma solidity ^0.5.0;

import "@ensdomains/ens/contracts/ENS.sol";
import "@ensdomains/ens/contracts/Registrar.sol";
import "@ensdomains/ens/contracts/HashRegistrar.sol";
import "openzeppelin-solidity/contracts/token/ERC721/ERC721.sol";
import "./BaseRegistrar.sol";

contract OldBaseRegistrarImplementation is BaseRegistrar, ERC721 {
    // 迁移域名结束时期
    uint public transferPeriodEnds;

    // 前一代的注册器
    Registrar public previousRegistrar;

    // token的过期时间
    mapping(uint256=>uint) expiries;
    // 迁移锁定时期
    uint constant public MIGRATION_LOCK_PERIOD = 28 days;

    bytes4 constant private INTERFACE_META_ID = bytes4(keccak256("supportsInterface(bytes4)"));
    bytes4 constant private ERC721_ID = bytes4(
        keccak256("balanceOf(uint256)") ^
        keccak256("ownerOf(uint256)") ^
        keccak256("approve(address,uint256)") ^
        keccak256("getApproved(uint256)") ^
        keccak256("setApprovalForAll(address,bool)") ^
        keccak256("isApprovedForAll(address,address)") ^
        keccak256("transferFrom(address,address,uint256)") ^
        keccak256("safeTransferFrom(address,address,uint256)") ^
        keccak256("safeTransferFrom(address,address,uint256,bytes)")
    );
    bytes4 constant private RECLAIM_ID = bytes4(keccak256("reclaim(uint256,address)"));
	// 构造函数
    constructor(ENS _ens, HashRegistrar _previousRegistrar, bytes32 _baseNode, uint _transferPeriodEnds) public {
        // Require that people have time to transfer names over.
        require(_transferPeriodEnds > now + 2 * MIGRATION_LOCK_PERIOD);

        ens = _ens;
        baseNode = _baseNode;
        previousRegistrar = _previousRegistrar;
        transferPeriodEnds = _transferPeriodEnds;
    }

    modifier live {
        require(ens.owner(baseNode) == address(this));
        _;
    }

    modifier onlyController {
        require(controllers[msg.sender]);
        _;
    }
	// 方法和BaseRegistrarImplement相同的在下面省略函数体
    function ownerOf(uint256 tokenId) public view returns (address) {}

    function addController(address controller) external onlyOwner {}

    function removeController(address controller) external onlyOwner {}

    // Set the resolver for the TLD this registrar manages.
    function setResolver(address resolver) external onlyOwner {
        ens.setResolver(baseNode, resolver);
    }

    // 查询指定id的过期时间
    function nameExpires(uint256 id) external view returns(uint) {}

    function available(uint256 id) public view returns(bool) {}

    /**
     * @dev Register a name.
     */
    function register(uint256 id, address owner, uint duration) external returns(uint) {
      return _register(id, owner, duration, true);
    }

    /**
     * @dev Register a name.
     */
    function registerOnly(uint256 id, address owner, uint duration) external returns(uint) {}

    function _register(uint256 id, address owner, uint duration, bool updateRegistry) internal live onlyController returns(uint) {}

    function renew(uint256 id, uint duration) external live onlyController returns(uint) {
        require(expiries[id] + GRACE_PERIOD >= now); // Name must be registered here or in grace period
        require(expiries[id] + duration + GRACE_PERIOD > duration + GRACE_PERIOD); // Prevent future overflow

        expiries[id] += duration;
        emit NameRenewed(id, expiries[id]);
        return expiries[id];
    }

    function reclaim(uint256 id, address owner) external live {}
	// 这个方法是HashRegistrar合约调用用来转换各个entry的注册器
    function acceptRegistrarTransfer(bytes32 label, Deed deed, uint) external live {
        uint256 id = uint256(label);

        require(msg.sender == address(previousRegistrar));
        require(expiries[id] == 0);
        require(transferPeriodEnds > now);

        uint registrationDate;
        (,,registrationDate,,) = previousRegistrar.entries(label);
        require(registrationDate < now - MIGRATION_LOCK_PERIOD);

        address owner = deed.owner();

        // Destroy the deed and transfer the funds back to the registrant.
        deed.closeDeed(1000);

        // Register the name
        expiries[id] = transferPeriodEnds;
        _mint(owner, id);

        ens.setSubnodeOwner(baseNode, label, owner);

        emit NameMigrated(id, owner, transferPeriodEnds);
        emit NameRegistered(id, owner, transferPeriodEnds);
    }

    function supportsInterface(bytes4 interfaceID) external view returns (bool) {
        return interfaceID == INTERFACE_META_ID ||
               interfaceID == ERC721_ID ||
               interfaceID == RECLAIM_ID;
    }
}

```

**小结**

​		以上就是一个新的普通域名注册器新旧合约，合约中将一个域名作为一个ERC721 token发放给所有注册者。下面再来看看解析器和ens合约。

###### 3.3 Resolver合约

```java
contract ResolverBase {
    bytes4 private constant INTERFACE_META_ID = 0x01ffc9a7;

    function supportsInterface(bytes4 interfaceID) public pure returns(bool) {
        return interfaceID == INTERFACE_META_ID;
    }

    function isAuthorised(bytes32 node) internal view returns(bool);

    modifier authorised(bytes32 node) {
        require(isAuthorised(node));
        _;
    }
	// 将域名转换为实际地址一般使用这个方法
    function bytesToAddress(bytes memory b) internal pure returns(address payable a) {
        require(b.length == 20);
        assembly {
            a := div(mload(add(b, 32)), exp(256, 12))
        }
    }

    function addressToBytes(address a) internal pure returns(bytes memory b) {
        b = new bytes(20);
        assembly {
            mstore(add(b, 32), mul(a, exp(256, 12)))
        }
    }
}

contract NameResolver is ResolverBase {
    bytes4 constant private NAME_INTERFACE_ID = 0x691f3431;

    event NameChanged(bytes32 indexed node, string name);

    mapping(bytes32=>string) names;

    /**
     * Sets the name associated with an ENS node, for reverse records.
     * May only be called by the owner of that node in the ENS registry.
     * @param node The node to update.
     * @param name The name to set.
     */
    function setName(bytes32 node, string calldata name) external authorised(node) {
        names[node] = name;
        emit NameChanged(node, name);
    }

    /**
     * Returns the name associated with an ENS node, for reverse records.
     * Defined in EIP181.
     * @param node The ENS node to query.
     * @return The associated name.
     */
    function name(bytes32 node) external view returns (string memory) {
        return names[node];
    }

    function supportsInterface(bytes4 interfaceID) public pure returns(bool) {
        return interfaceID == NAME_INTERFACE_ID || super.supportsInterface(interfaceID);
    }
}
```



###### 3.4 ENS合约

​		先来看张类继承关系图：

![ens](C:\Users\Administrator\Desktop\ensdoc\ens.png)

源码分析：

```java
/**
 *Submitted for verification at Etherscan.io on 2020-01-29
*/

pragma solidity ^0.5.0;

contract ENSRegistry is ENS {
	// 每一条记录包含owner和解析器和ttl
    struct Record {
        address owner;
        address resolver;
        uint64 ttl;
    }
	// name与record的映射关系
    mapping (bytes32 => Record) records;
    // 地址对应操作员映射
    mapping (address => mapping(address => bool)) operators;

    // Permits modifications only by the owner of the specified node.
    modifier authorised(bytes32 node) {
        address owner = records[node].owner;
        require(owner == msg.sender || operators[owner][msg.sender]);
        _;
    }

    /**
     * @dev Constructs a new ENS registrar.
     */
    constructor() public {
        records[0x0].owner = msg.sender;
    }
	// 给一个域名创建记录
    function setRecord(bytes32 node, address owner, address resolver, uint64 ttl) external 	   {
        setOwner(node, owner);
        _setResolverAndTTL(node, resolver, ttl);
    }

    // 给子节点创建记录
    function setSubnodeRecord(bytes32 node, bytes32 label, address owner, address resolver, uint64 ttl) external {
        bytes32 subnode = setSubnodeOwner(node, label, owner);
        _setResolverAndTTL(subnode, resolver, ttl);
    }

    // 设置新的owner
    function setOwner(bytes32 node, address owner) public authorised(node) {
        _setOwner(node, owner);
        emit Transfer(node, owner);
    }

    function setSubnodeOwner(bytes32 node, bytes32 label, address owner) public authorised(node) returns(bytes32) {
        bytes32 subnode = keccak256(abi.encodePacked(node, label));
        _setOwner(subnode, owner);
        emit NewOwner(node, label, owner);
        return subnode;
    }
	// 给域名设置解析器
    function setResolver(bytes32 node, address resolver) public authorised(node) {
        emit NewResolver(node, resolver);
        records[node].resolver = resolver;
    }

    function setTTL(bytes32 node, uint64 ttl) public authorised(node) {
        emit NewTTL(node, ttl);
        records[node].ttl = ttl;
    }
	// 方便openSea类似应用售卖域名
    function setApprovalForAll(address operator, bool approved) external {
        operators[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function owner(bytes32 node) public view returns (address) {
        address addr = records[node].owner;
        if (addr == address(this)) {
            return address(0x0);
        }

        return addr;
    }

    function resolver(bytes32 node) public view returns (address) {
        return records[node].resolver;
    }

    function ttl(bytes32 node) public view returns (uint64) {
        return records[node].ttl;
    }


    function recordExists(bytes32 node) public view returns (bool) {
        return records[node].owner != address(0x0);
    }


    function isApprovedForAll(address owner, address operator) external view returns (bool)     {
        return operators[owner][operator];
    }

    function _setOwner(bytes32 node, address owner) internal {
        records[node].owner = owner;
    }

    function _setResolverAndTTL(bytes32 node, address resolver, uint64 ttl) internal {
        if(resolver != records[node].resolver) {
            records[node].resolver = resolver;
            emit NewResolver(node, resolver);
        }

        if(ttl != records[node].ttl) {
            records[node].ttl = ttl;
            emit NewTTL(node, ttl);
        }
    }
}
// fallBack合约
contract ENSRegistryWithFallback is ENSRegistry {
	// 集成老的ens合约，比如一代的ens合约
    ENS public old;

    /**
     * @dev Constructs a new ENS registrar.
     */
    constructor(ENS _old) public ENSRegistry() {
        old = _old;
    }
	// 以下方法大多都是判断在新的ens中有没有对应记录，没有就是旧ens合约中的信息
    function resolver(bytes32 node) public view returns (address) {
        if (!recordExists(node)) {
            return old.resolver(node);
        }

        return super.resolver(node);
    }

    function owner(bytes32 node) public view returns (address) {
        if (!recordExists(node)) {
            return old.owner(node);
        }

        return super.owner(node);
    }
    
    function ttl(bytes32 node) public view returns (uint64) {
        if (!recordExists(node)) {
            return old.ttl(node);
        }

        return super.ttl(node);
    }

    function _setOwner(bytes32 node, address owner) internal {
        address addr = owner;
        if (addr == address(0x0)) {
            addr = address(this);
        }

        super._setOwner(node, addr);
    }
}
```

###### 3.5 RegistrarMigration

```java
contract RegistrarMigration {
    using SafeMath for uint;

    bytes constant private UNUSED_SUBDOMAIN = hex'ffffffffffffffff';
	// 遗留的注册器，如HashRegistrar
    Registrar public legacyRegistrar;
    // 转移结束时期
    uint transferPeriodEnds;
    // 第二代注册器
    OldBaseRegistrarImplementation public oldRegistrar;
    // 最新注册器
    BaseRegistrarImplementation public newRegistrar;
    // 第一代ens实现类
    OldENS public oldENS;
    // 最新ens实现类
    ENS public newENS;
    // 新旧子域名注册器
    AbstractSubdomainRegistrar public oldSubdomainRegistrar;
    AbstractSubdomainRegistrar public newSubdomainRegistrar;
	// .eth
    bytes32 public baseNode;
	// 构造函数
    constructor(OldBaseRegistrarImplementation _old, BaseRegistrarImplementation _new, AbstractSubdomainRegistrar _oldSubdomainRegistrar, AbstractSubdomainRegistrar _newSubdomainRegistrar) public {
        oldRegistrar = _old;
        oldENS = OldENS(address(_old.ens()));
        baseNode = _old.baseNode();
        legacyRegistrar = _old.previousRegistrar();
        transferPeriodEnds = _old.transferPeriodEnds();
        oldSubdomainRegistrar = _oldSubdomainRegistrar;

        newRegistrar = _new;
        newENS = _new.ens();
        require(_new.baseNode() == baseNode);
        newSubdomainRegistrar = _newSubdomainRegistrar;
    }
	// 内部调用做迁移，参数为 域名 域名所有者 域名过期时间
    function doMigration(uint256 tokenId, address registrant, uint expires) internal {
        // 计算域名对应的node
        bytes32 node = keccak256(abi.encodePacked(baseNode, bytes32(tokenId)));
        // 从oldEns获取一次owner
        address controller = oldENS.owner(node);
	    // 如果注册者不等于旧子域名注册器且拥有者是个合约
        if(address(registrant) != address(oldSubdomainRegistrar) && hasCode(controller)) {
            // 只将其传递的域名迁移，不迁移对应子域名
            newRegistrar.registerOnly(tokenId, registrant, expires.sub(now));
            return;
        }

        // 在新的注册器中注册，并先设置拥有者为当前合约
        newRegistrar.register(tokenId, address(this), expires.sub(now));

        // 如果老的域名的解析器不为空，则在新ens合约设置其解析器
        address resolver = oldENS.resolver(node);
        if(resolver != address(0)) {
            newENS.setResolver(node, resolver);
        }
	    // 同上
        uint64 ttl = oldENS.ttl(node);
        if(ttl != 0) {
            newENS.setTTL(node, ttl);
        }
		// 如果域名注册者是旧子域名注册器
        if(address(registrant) == address(oldSubdomainRegistrar) && address(registrant) != address(0)) {
            // 从旧子域名注册器获取相关信息
            (string memory label, uint price,, uint referralFeePPM) = oldSubdomainRegistrar.query(bytes32(tokenId), string(UNUSED_SUBDOMAIN));
            address owner = oldSubdomainRegistrar.owner(bytes32(tokenId));
            if(bytes(label).length == 0) {
              revert("Unable to migrate domain on subdomain registrar");
            }

            // 批准新的子域名注册器为其操作者
            newRegistrar.approve(address(newSubdomainRegistrar), tokenId);
            // 新的子域名注册器配置域名相关信息
            newSubdomainRegistrar.configureDomainFor(label, price, referralFeePPM, address(uint160(owner)), address(0));
        } else {
            // 要不然就是普通注册者的域名
            
            // 在新的ens中设置node的拥有者为controller
            newENS.setOwner(node, controller);

            // 新注册器将拥域名转给注册者
            newRegistrar.transferFrom(address(this), registrant, tokenId);
        }

        // 使用当前合约从旧的ens合约中接管域名的权利，防止注册者在旧ens合约中再次操作
        oldENS.setSubnodeOwner(baseNode, bytes32(tokenId), address(this));
    }

   	// 迁移第二代注册器的域名到最新域名注册器，任何人都可以调用
    function migrate(uint256 tokenId) public {
        address registrant = oldRegistrar.ownerOf(tokenId);
        doMigration(tokenId, registrant, oldRegistrar.nameExpires(tokenId));
    }

    // 批量迁移第二代注册器中的域名
    function migrateAll(uint256[] calldata tokenIds) external {
        for(uint i = 0; i < tokenIds.length; i++) {
            migrate(tokenIds[i]);
        }
    }

    // 迁移第一代注册器中的域名到最新域名注册器中
    function migrateLegacy(bytes32 label) public {
        (Registrar.Mode mode, address deed, , ,) = legacyRegistrar.entries(label);
        require(mode == Registrar.Mode.Owned);
        address owner = Deed(deed).owner();
        doMigration(uint256(label), owner, transferPeriodEnds);
    }

   	// 批量迁移第一代注册器中的域名到最新域名注册器中
    function migrateAllLegacy(bytes32[] calldata labels) external {
        for(uint i = 0; i < labels.length; i++) {
            migrateLegacy(labels[i]);
        }
    }
	// 判断一个地址是否包含代码
    function hasCode(address addr) private view returns(bool ret) {
        assembly {
            ret := not(not(extcodesize(addr)))
        }
    }
}
```



