### 以太坊ENS(ethereum name service)智能合约分析(一)

##### 0. 简介

​		以太坊域名服务(ENS)是一个基于以太坊区块链、分布式的、开放的、可扩展的域名系统。ENS的主要工作是将人类可读的名称（alice.eth）映射为机器可读的符号（如以太坊地址、内容hash等）。

​		以太坊域名系统(ENS)功能类似于DNS，但是受限于以太坊区块链，所以和DNS有一些区别。顶级域名如".eth"等，所有者为一个叫注册器的智能合约，这个合约指定子域名的管理规则，任何人遵循这些规则的前提下都能获取到一个自己所属的域名。一个人在获取域名后可以配置自己的子域名如alice.eth的所有者同时是pay.alice.eth的所有者。

##### 1、ENS的架构图

​		ENS中有两大组件：注册器和解析器。

![ens-architecture](https://github.com/DoubleCherish/EthereumSourceCodeAnalysis/blob/master/enscontract/images/ens-architecture.png)

ENS注册器由一个只能合约组成，其内部维护了一个列表包括了所有的域名和子域名，同时存储了每个域名的三个关键信息：

		* 域名的拥有者
		* 域名对应的解析器
		* 缓存了域名下所有记录的生存时间

以太坊域名的所有者可能是一个普通账户也可能是一个智能合约，注册器也是一个普通拥有域名的合约，颁发子域名给那些遵循合约定义的规则的用户。

在ENS合约中，一个域名的所有者可以有下面权利：

* 给自己的域名设置解析器和ttl
* 将自己的域名转移给别人
* 改变子域名的所属关系

一个域名的解析一般分为两个步骤：① 首先询问ENS注册器对应域名的解析器地址 ② 再使用对应域名去解析器查询域名对应的实际地址是什么。步骤如下图

![resolver](https://github.com/DoubleCherish/EthereumSourceCodeAnalysis/blob/master/enscontract/images/resolver.png)

##### 2、初版ENS合约代码分析

​		这个版本的合约可能和ENS架构图中所述稍有差别，但是不影响理解。后续会分析最新版ENS相关合约代码，会更符合（1）中所描述的。

###### 2.1 ENS interface

```java
// 初版ENS合约接口
contract AbstractENS {
    function owner(bytes32 node) constant returns(address);
    function resolver(bytes32 node) constant returns(address);
    function ttl(bytes32 node) constant returns(uint64);
    function setOwner(bytes32 node, address owner);
    function setSubnodeOwner(bytes32 node, bytes32 label, address owner);
    function setResolver(bytes32 node, address resolver);
    function setTTL(bytes32 node, uint64 ttl);

    // Logged when the owner of a node assigns a new owner to a subnode.
    event NewOwner(bytes32 indexed node, bytes32 indexed label, address owner);

    // Logged when the owner of a node transfers ownership to a new account.
    event Transfer(bytes32 indexed node, address owner);

    // Logged when the resolver for a node changes.
    event NewResolver(bytes32 indexed node, address resolver);

    // Logged when the TTL of a node changes
    event NewTTL(bytes32 indexed node, uint64 ttl);
}
```

从上面接口可知，初版ENS实现合约会在其内部拥有一个`map(byte32=>record)`的变量记录着每个域名对应的结构体，结构体里面又存放着域名的ttl、解析器、拥有者等信息。

###### 2.2 Deed

​		旧版Deed，代表一个域名对应的契约，具体功能下面会讲到

```java
contract Deed {
    // 注册器
    address public registrar;
    address constant burn = 0xdead;
    // 创建时间
    uint public creationDate;
    // 契约拥有者
    address public owner;
    // 契约上一个拥有者
    address public previousOwner;
    // 契约价值
    uint public value;
    event OwnerChanged(address newOwner);
    event DeedClosed();
    bool active;


    modifier onlyRegistrar {
        if (msg.sender != registrar) throw;
        _;
    }

    modifier onlyActive {
        if (!active) throw;
        _;
    }

    function Deed(address _owner) payable {
        owner = _owner;
        registrar = msg.sender;
        creationDate = now;
        active = true;
        value = msg.value;
    }

    function setOwner(address newOwner) onlyRegistrar {
        if (newOwner == 0) throw;
        previousOwner = owner;  // This allows contracts to check who sent them the ownership
        owner = newOwner;
        OwnerChanged(newOwner);
    }

    function setRegistrar(address newRegistrar) onlyRegistrar {
        registrar = newRegistrar;
    }

    function setBalance(uint newValue, bool throwOnFailure) onlyRegistrar onlyActive {
        // Check if it has enough balance to set the value
        if (value < newValue) throw;
        value = newValue;
        // Send the difference to the owner
        if (!owner.send(this.balance - newValue) && throwOnFailure) throw;
    }

    /**
     * @dev Close a deed and refund a specified fraction of the bid value
     * @param refundRatio The amount*1/1000 to refund
     */
    function closeDeed(uint refundRatio) onlyRegistrar onlyActive {
        active = false;
        if (! burn.send(((1000 - refundRatio) * this.balance)/1000)) throw;
        DeedClosed();
        destroyDeed();
    }

    /**
     * @dev Close a deed and refund a specified fraction of the bid value
     */
    function destroyDeed() {
        if (active) throw;
        
        // Instead of selfdestruct(owner), invoke owner fallback function to allow
        // owner to log an event if desired; but owner should also be aware that
        // its fallback function can also be invoked by setBalance
        if(owner.send(this.balance)) {
            selfdestruct(burn);
        }
    }
}
```

###### 2.3 Registrar

​		下面是最初版本的竞拍注册器合约

```java
contract Registrar {
    // ens实现
    AbstractENS public ens;
    // 根节点.eth
    bytes32 public rootNode;
    
    mapping (bytes32 => entry) _entries;
    mapping (address => mapping(bytes32 => Deed)) public sealedBids;
    // 竞拍物状态
    enum Mode { Open, Auction, Owned, Forbidden, Reveal, NotYetAvailable }
	// 竞拍其
    uint32 constant totalAuctionLength = 5 days;
    // 揭价期
    uint32 constant revealPeriod = 48 hours;
   
    uint32 public constant launchLength = 8 weeks;
	// 最小竞拍价
    uint constant minPrice = 0.01 ether;
    // 注册器开启时间
    uint public registryStarted;

    event AuctionStarted(bytes32 indexed hash, uint registrationDate);
    event NewBid(bytes32 indexed hash, address indexed bidder, uint deposit);
    event BidRevealed(bytes32 indexed hash, address indexed owner, uint value, uint8 status);
    event HashRegistered(bytes32 indexed hash, address indexed owner, uint value, uint registrationDate);
    event HashReleased(bytes32 indexed hash, uint value);
    event HashInvalidated(bytes32 indexed hash, string indexed name, uint value, uint registrationDate);
	// 结构体，一个竞拍物Hash对应一个entry
    struct entry {
        Deed deed;// 一个entry对应一个契约
        uint registrationDate;
        uint value;
        uint highestBid;
    }

    // 域名状态转换
    //   Open -> Auction (startAuction)
    //   Auction -> Reveal
    //   Reveal -> Owned
    //   Reveal -> Open (if nobody bid)
    //   Owned -> Open (releaseDeed or invalidateName)
    function state(bytes32 _hash) constant returns (Mode) {
        var entry = _entries[_hash];
        
        if(!isAllowed(_hash, now)) {
            // 还不让注册
            return Mode.NotYetAvailable;
        } else if(now < entry.registrationDate) {
            // 给两天(48h)让大家暗拍
            if (now < entry.registrationDate - revealPeriod) {
                return Mode.Auction;
            } else {
                // 揭价时期
                return Mode.Reveal;
            }
        } else {
            // 如果开始竞拍之后，过了5天还没有人出价，那么开放注册
            if(entry.highestBid == 0) {
                return Mode.Open;
            } else {
                // 要不然就是已经被注册了
                return Mode.Owned;
            }
        }
    }

    modifier inState(bytes32 _hash, Mode _state) {
        if(state(_hash) != _state) throw;
        _;
    }

    modifier onlyOwner(bytes32 _hash) {
        if (state(_hash) != Mode.Owned || msg.sender != _entries[_hash].deed.owner()) throw;
        _;
    }

    modifier registryOpen() {
        if(now < registryStarted  || now > registryStarted + 4 years || ens.owner(rootNode) != address(this)) throw;
        _;
    }

    function entries(bytes32 _hash) constant returns (Mode, address, uint, uint, uint) {
        entry h = _entries[_hash];
        return (state(_hash), h.deed, h.registrationDate, h.value, h.highestBid);
    }

    /**
     * @dev Constructs a new Registrar, with the provided address as the owner of the root node.
     * @param _ens The address of the ENS
     * @param _rootNode The hash of the rootnode.
     */
    function Registrar(AbstractENS _ens, bytes32 _rootNode, uint _startDate) {
        ens = _ens;
        rootNode = _rootNode;
        registryStarted = _startDate > 0 ? _startDate : now;
    }

    ............................省略部分无关代码
    
    /** 
     * @dev Determines if a name is available for registration yet
     * 
     * Each name will be assigned a random date in which its auction 
     * can be started, from 0 to 13 weeks
     * 
     * @param _hash The hash to start an auction on
     * @param _timestamp The timestamp to query about
     */
     
    function isAllowed(bytes32 _hash, uint _timestamp) constant returns (bool allowed){
        return _timestamp > getAllowedTime(_hash);
    }

    /** 
     * @dev Returns available date for hash
     * 
     * @param _hash The hash to start an auction on
     */
    function getAllowedTime(bytes32 _hash) constant returns (uint timestamp) {
        return registryStarted + (launchLength*(uint(_hash)>>128)>>128);
        // right shift operator: a >> b == a / 2**b
    }
    /**
     * @dev Assign the owner in ENS, if we're still the registrar
     * @param _hash hash to change owner
     * @param _newOwner new owner to transfer to
     */
    function trySetSubnodeOwner(bytes32 _hash, address _newOwner) internal {
        if(ens.owner(rootNode) == address(this))
            ens.setSubnodeOwner(rootNode, _hash, _newOwner);        
    }

    /**
     * @dev Start an auction for an available hash
     *
     * Anyone can start an auction by sending an array of hashes that they want to bid for.
     * Arrays are sent so that someone can open up an auction for X dummy hashes when they
     * are only really interested in bidding for one. This will increase the cost for an
     * attacker to simply bid blindly on all new auctions. Dummy auctions that are
     * open but not bid on are closed after a week.
     *
     * @param _hash The hash to start an auction on
     */
    // 开启一个竞拍
    function startAuction(bytes32 _hash) registryOpen() {
        var mode = state(_hash);
        if(mode == Mode.Auction) return;
        if(mode != Mode.Open) throw;

        entry newAuction = _entries[_hash];
        newAuction.registrationDate = now + totalAuctionLength;
        newAuction.value = 0;
        newAuction.highestBid = 0;
        AuctionStarted(_hash, newAuction.registrationDate);
    }

    /**
     * @dev Start multiple auctions for better anonymity
     * @param _hashes An array of hashes, at least one of which you presumably want to bid on
     */
    function startAuctions(bytes32[] _hashes)  {
        for (uint i = 0; i < _hashes.length; i ++ ) {
            startAuction(_hashes[i]);
        }
    }

    /**
     * @dev Hash the values required for a secret bid
     * @param hash The node corresponding to the desired namehash
     * @param value The bid amount
     * @param salt A random value to ensure secrecy of the bid
     * @return The hash of the bid values
     */
    // 对暗拍的数据进行sha3 、 value无所谓，随便填
    function shaBid(bytes32 hash, address owner, uint value, bytes32 salt) constant returns (bytes32 sealedBid) {
        return sha3(hash, owner, value, salt);
    }

    /**
     * @dev Submit a new sealed bid on a desired hash in a blind auction
     *
     * Bids are sent by sending a message to the main contract with a hash and an amount. The hash
     * contains information about the bid, including the bidded hash, the bid amount, and a random
     * salt. Bids are not tied to any one auction until they are revealed. The value of the bid
     * itself can be masqueraded by sending more than the value of your actual bid. This is
     * followed by a 48h reveal period. Bids revealed after this period will be burned and the ether unrecoverable.
     * Since this is an auction, it is expected that most public hashes, like known domains and common dictionary
     * words, will have multiple bidders pushing the price up.
     *
     * @param sealedBid A sealedBid, created by the shaBid function
     */
     // 暗拍出价
    function newBid(bytes32 sealedBid) payable {

        if (address(sealedBids[msg.sender][sealedBid]) > 0 ) throw;
        if (msg.value < minPrice) throw;
        // creates a new hash contract with the owner
        Deed newBid = (new Deed).value(msg.value)(msg.sender); // 扣钱
        sealedBids[msg.sender][sealedBid] = newBid;
        NewBid(sealedBid, msg.sender, msg.value);
    }

    /**
     * @dev Start a set of auctions and bid on one of them
     *
     * This method functions identically to calling `startAuctions` followed by `newBid`,
     * but all in one transaction.
     * @param hashes A list of hashes to start auctions on.
     * @param sealedBid A sealed bid for one of the auctions.
     */
    function startAuctionsAndBid(bytes32[] hashes, bytes32 sealedBid) payable {
        startAuctions(hashes);
        newBid(sealedBid);
    }

    /**
     * @dev Submit the properties of a bid to reveal them
     * @param _hash The node in the sealedBid
     * @param _value The bid amount in the sealedBid
     * @param _salt The sale in the sealedBid
     */
    // 揭价阶段
    function unsealBid(bytes32 _hash, uint _value, bytes32 _salt) {
        bytes32 seal = shaBid(_hash, msg.sender, _value, _salt);
        Deed bid = sealedBids[msg.sender][seal];
        if (address(bid) == 0 ) throw;
        sealedBids[msg.sender][seal] = Deed(0);
        entry h = _entries[_hash];
        uint value = min(_value, bid.value());
        bid.setBalance(value, true);

        var auctionState = state(_hash);
        if(auctionState == Mode.Owned) {
            // 不及时揭价，已经被别人拿走，退还出价人当时的5%出价额   扣费都是为了防止恶意攻击者
            // Too late! Bidder loses their bid. Get's 0.5% back.
            bid.closeDeed(5);
            BidRevealed(_hash, msg.sender, value, 1);
        } else if(auctionState != Mode.Reveal) {
            // 如果不在揭露期，直接返回
            // Invalid phase
            throw;
        } else if (value < minPrice || bid.creationDate() > h.registrationDate - revealPeriod) {
            // 如果value小于最小竞拍价或者出价时间不在出价时间范围
            // 退还竞价者99.5%的额度
            // Bid too low or too late, refund 99.5%
            bid.closeDeed(995);
            BidRevealed(_hash, msg.sender, value, 0);
        } else if (value > h.highestBid) {
            // 如果value大于最高竞价
            // new winner
            // cancel the other bid, refund 99.5%
            // 如果有人是name的主人了，那么退还其99.5%的出价金额
            if(address(h.deed) != 0) {
                Deed previousWinner = h.deed;
                previousWinner.closeDeed(995);
            }

            // set new winner
            // per the rules of a vickery auction, the value becomes the previous highestBid
            // 将高的出价者的契约deed设置为entry的新契约，将最高价格更新，将h.value设置为第二高的value
            h.value = h.highestBid;  // will be zero if there's only 1 bidder
            h.highestBid = value;
            h.deed = bid;
            BidRevealed(_hash, msg.sender, value, 2);
        } else if (value > h.value) {
            // 要不然大家争夺第二高价位置
            // not winner, but affects second place
            h.value = value;
            bid.closeDeed(995);
            BidRevealed(_hash, msg.sender, value, 3);
        } else {
            // 要不然出价者既不高于最高出价者，也不高于第二出价者，那么退还其99.5%出价
            // bid doesn't affect auction
            bid.closeDeed(995);
            BidRevealed(_hash, msg.sender, value, 4);
        }
    }

    /**
     * @dev Cancel a bid
     * @param seal The value returned by the shaBid function
     */
     // 取消竞价
    function cancelBid(address bidder, bytes32 seal) {
        // 获取其出价的契约
        Deed bid = sealedBids[bidder][seal];
        
        // If a sole bidder does not `unsealBid` in time, they have a few more days
        // where they can call `startAuction` (again) and then `unsealBid` during
        // the revealPeriod to get back their bid value.
        // For simplicity, they should call `startAuction` within
        // 9 days (2 weeks - totalAuctionLength), otherwise their bid will be
        // cancellable by anyone.
        // 如果bid不存在，或者当前时间小于出价时间+19天 返回
        if (address(bid) == 0
            || now < bid.creationDate() + totalAuctionLength + 2 weeks) throw;
        // 出价存在且当前时间在出价19天之后，返还出价的5%
        // Send the canceller 0.5% of the bid, and burn the rest.
        bid.setOwner(msg.sender);
        bid.closeDeed(5);
        sealedBids[bidder][seal] = Deed(0);
        BidRevealed(seal, bidder, 0, 5);
    }

    /**
     * @dev Finalize an auction after the registration date has passed
     * @param _hash The hash of the name the auction is for
     */
    // 最终化竞拍品，也就是说尝试将竞拍的域名拿到自己名下
    function finalizeAuction(bytes32 _hash) onlyOwner(_hash) {
        entry h = _entries[_hash];
        // 将h的value设置为出价第二的value，最低为0.01ether  防止没人出价导致h.value为0
        // handles the case when there's only a single bidder (h.value is zero)
        h.value =  max(h.value, minPrice);
        // 将出价中多出的额度返还给最高出价者
        h.deed.setBalance(h.value, true);
        // 尝试将hash相关子节点的owner设为竞价获胜者
        trySetSubnodeOwner(_hash, h.deed.owner());
        HashRegistered(_hash, h.deed.owner(), h.value, h.registrationDate);
    }

    /**
     * @dev The owner of a domain may transfer it to someone else at any time.
     * @param _hash The node to transfer
     * @param newOwner The address to transfer ownership to
     */
    // 转移自己的name
    function transfer(bytes32 _hash, address newOwner) onlyOwner(_hash) {
        if (newOwner == 0) throw;

        entry h = _entries[_hash];
        h.deed.setOwner(newOwner);
        trySetSubnodeOwner(_hash, newOwner);
    }

    /**
     * @dev After some time, or if we're no longer the registrar, the owner can release
     *      the name and get their ether back.
     * @param _hash The node to release
     */
     // 释放域名
    function releaseDeed(bytes32 _hash) onlyOwner(_hash) {
        entry h = _entries[_hash];
        Deed deedContract = h.deed;
        // 如果h的注册时间小于一年，且当前注册器没更换，那么不允许释放域名
        if(now < h.registrationDate + 1 years && ens.owner(rootNode) == address(this)) throw;

        // 要不然就可以释放域名
        h.value = 0;
        h.highestBid = 0;
        h.deed = Deed(0);

        _tryEraseSingleNode(_hash);
        // 100%退还押金
        deedContract.closeDeed(1000);
        HashReleased(_hash, h.value);        
    }

    /**
     * @dev Submit a name 6 characters long or less. If it has been registered,
     * the submitter will earn 50% of the deed value. We are purposefully
     * handicapping the simplified registrar as a way to force it into being restructured
     * in a few years.
     * @param unhashedName An invalid name to search for in the registry.
     *
     */
    function invalidateName(string unhashedName) inState(sha3(unhashedName), Mode.Owned) {
        if (strlen(unhashedName) > 6 ) throw;
        bytes32 hash = sha3(unhashedName);

        entry h = _entries[hash];

        _tryEraseSingleNode(hash);

        if(address(h.deed) != 0) {
            // Reward the discoverer with 50% of the deed
            // The previous owner gets 50%
            h.value = max(h.value, minPrice);
            h.deed.setBalance(h.value/2, false);
            h.deed.setOwner(msg.sender);
            h.deed.closeDeed(1000);
        }

        HashInvalidated(hash, unhashedName, h.value, h.registrationDate);

        h.value = 0;
        h.highestBid = 0;
        h.deed = Deed(0);
    }

    /**
     * @dev Allows anyone to delete the owner and resolver records for a (subdomain of) a
     *      name that is not currently owned in the registrar. If passing, eg, 'foo.bar.eth',
     *      the owner and resolver fields on 'foo.bar.eth' and 'bar.eth' will all be cleared.
     * @param labels A series of label hashes identifying the name to zero out, rooted at the
     *        registrar's root. Must contain at least one element. For instance, to zero 
     *        'foo.bar.eth' on a registrar that owns '.eth', pass an array containing
     *        [sha3('foo'), sha3('bar')].
     */
    function eraseNode(bytes32[] labels) {
        if(labels.length == 0) throw;
        if(state(labels[labels.length - 1]) == Mode.Owned) throw;

        _eraseNodeHierarchy(labels.length - 1, labels, rootNode);
    }

    function _tryEraseSingleNode(bytes32 label) internal {
        if(ens.owner(rootNode) == address(this)) {
            ens.setSubnodeOwner(rootNode, label, address(this));
            var node = sha3(rootNode, label);
            ens.setResolver(node, 0);
            ens.setOwner(node, 0);
        }
    }

    function _eraseNodeHierarchy(uint idx, bytes32[] labels, bytes32 node) internal {
        // Take ownership of the node
        ens.setSubnodeOwner(node, labels[idx], address(this));
        node = sha3(node, labels[idx]);
        
        // Recurse if there's more labels
        if(idx > 0)
            _eraseNodeHierarchy(idx - 1, labels, node);

        // Erase the resolver and owner records
        ens.setResolver(node, 0);
        ens.setOwner(node, 0);
    }

    /**
     * @dev Transfers the deed to the current registrar, if different from this one.
     * Used during the upgrade process to a permanent registrar.
     * @param _hash The name hash to transfer.
     */
    function transferRegistrars(bytes32 _hash) onlyOwner(_hash) {
        var registrar = ens.owner(rootNode);
        if(registrar == address(this))
            throw;

        // Migrate the deed
        entry h = _entries[_hash];
        h.deed.setRegistrar(registrar);

        // Call the new registrar to accept the transfer
        Registrar(registrar).acceptRegistrarTransfer(_hash, h.deed, h.registrationDate);

        // Zero out the entry
        h.deed = Deed(0);
        h.registrationDate = 0;
        h.value = 0;
        h.highestBid = 0;
    }

    /**
     * @dev Accepts a transfer from a previous registrar; stubbed out here since there
     *      is no previous registrar implementing this interface.
     * @param hash The sha3 hash of the label to transfer.
     * @param deed The Deed object for the name being transferred in.
     * @param registrationDate The date at which the name was originally registered.
     */
    function acceptRegistrarTransfer(bytes32 hash, Deed deed, uint registrationDate) {}

}
```

以上是初版ENS竞价拍卖域名的合约，下次通过实例分享现在正在使用的域名合约。
