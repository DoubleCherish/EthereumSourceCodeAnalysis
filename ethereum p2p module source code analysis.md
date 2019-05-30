### ethereum p2p module source code analysis

##### 1、涉及到的源码文件

```java
package : go-ethereum/p2p/discover
		source file:
					database.go  内存或者持久化key-value数据库
					node.go   	 代表网络上一个主机
					table.go   	 实现Kad协议，通过udp进行数据沟通
					udp.go       实现udp数据传输服务，监听外部服务请求
					ntp.go       网络时间协议实现
package : go-ethereum/p2p
		 source file:
					dial.go       负责建立链接
					peer.go		  代表了一条创建好的网络链路
					protocol.go   
					rlpx.go       节点之间的加密链路
					server.go     p2p网络启动实现
```

##### 2、由总到分

总的来说从node.Start()--->p2p.server.Start()

```java
node.Start():
	/ Start create a live P2P node and starts running it.
func (n *Node) Start() error {
     ....
     ....
	// Initialize the p2p server. This creates the node key and
	// discovery databases.
	n.serverConfig = n.config.P2P //p2p网络配置
	n.serverConfig.PrivateKey = n.config.NodeKey() //节点私钥
	n.serverConfig.Name = n.config.NodeName() //节点名称
	if n.serverConfig.StaticNodes == nil {
		n.serverConfig.StaticNodes = n.config.StaticNodes() //加载节点静态节点
	}
	if n.serverConfig.TrustedNodes == nil {
		n.serverConfig.TrustedNodes = n.config.TrusterNodes() //加载信任节点
	}
	running := &p2p.Server{Config: n.serverConfig} //构造p2p.server结构体，填充config字段
	log.Info("Starting peer-to-peer node", "instance", n.serverConfig.Name)

	...............
	// Gather the protocols and start the freshly assembled P2P server
	for _, service := range services {
		running.Protocols = append(running.Protocols, service.Protocols()...)
	}
	if err := running.Start(); err != nil {  //开启p2p.Server
		if errno, ok := err.(syscall.Errno); ok && datadirInUseErrnos[uint(errno)] {
			return ErrDatadirUsed
		}
		return err
	}
	..............
}
```

---

p2p.Server.Start()

![1556528990671](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1556528990671.png)

跟踪方法如下：

```
1、discover.ListenUDP()-- > newUDP() --> udp.loop(),udp.readLoop(),newTable()-->tab.refreshLoop()-->tab.doRefresh()
-------------------------------------------------------------------------------------------
// ListenUDP returns a new table that listens for UDP packets on laddr.
func ListenUDP(priv *ecdsa.PrivateKey, laddr string, natm nat.Interface, nodeDBPath string, netrestrict *netutil.Netlist) (*Table, error) {
	addr, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		return nil, err
	}
	//拿到一个udp监听器实例
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	//调用newTable方法使用udp监听器创建一个table
	tab, _, err := newUDP(priv, conn, natm, nodeDBPath, netrestrict)
	if err != nil {
		return nil, err
	}
	log.Info("UDP listener up", "self", tab.self)
	return tab, nil
}
-------------------------------------------------------------------------------------------
func newUDP(priv *ecdsa.PrivateKey, c conn, natm nat.Interface, nodeDBPath string, netrestrict *netutil.Netlist) (*Table, *udp, error) {
	udp := &udp{
		conn:        c,
		priv:        priv,
		netrestrict: netrestrict, //白名单
		closing:     make(chan struct{}),
		gotreply:    make(chan reply), //回应包处理通道
		addpending:  make(chan *pending), //各种数据包 pending 队列
	}
	realaddr := c.LocalAddr().(*net.UDPAddr)
	if natm != nil {
		if !realaddr.IP.IsLoopback() {
			go nat.Map(natm, udp.closing, "udp", realaddr.Port, realaddr.Port, "ethereum discovery")
		}
		// TODO: react to external IP changes over time.
		if ext, err := natm.ExternalIP(); err == nil {
			realaddr = &net.UDPAddr{IP: ext, Port: realaddr.Port}
		}
	}
	// TODO: separate TCP port
	udp.ourEndpoint = makeEndpoint(realaddr, uint16(realaddr.Port))
	//调用newtable创建table结构体
	tab, err := newTable(udp, PubkeyID(&priv.PublicKey), realaddr, nodeDBPath)
	if err != nil {
		return nil, nil, err
	}
	udp.Table = tab

	go udp.loop()
	go udp.readLoop()
	return udp.Table, udp, nil
}
-------------------------------------------------------------------------------------------
// loop runs in its own goroutine. it keeps track of
// the refresh timer and the pending reply queue.
func (t *udp) loop() {
	var (
		plist        = list.New() //原生list
		timeout      = time.NewTimer(0)
		nextTimeout  *pending // head of plist when timeout was last reset
		contTimeouts = 0      // number of continuous timeouts to do NTP checks
		ntpWarnTime  = time.Unix(0, 0)
	)
	<-timeout.C // ignore first timeout
	defer timeout.Stop()
	//重设过期请求
	resetTimeout := func() {
		if plist.Front() == nil || nextTimeout == plist.Front().Value {
			return
		}
		// Start the timer so it fires when the next pending reply has expired.
		now := time.Now()
		for el := plist.Front(); el != nil; el = el.Next() {
			nextTimeout = el.Value.(*pending)
			if dist := nextTimeout.deadline.Sub(now); dist < 2*respTimeout {
				timeout.Reset(dist)
				return
			}
			// Remove pending replies whose deadline is too far in the
			// future. These can occur if the system clock jumped
			// backwards after the deadline was assigned.
			nextTimeout.errc <- errClockWarp
			plist.Remove(el)
		}
		nextTimeout = nil
		timeout.Stop()
	}

	for {
		resetTimeout()

		select {
		case <-t.closing:
			for el := plist.Front(); el != nil; el = el.Next() {
				el.Value.(*pending).errc <- errClosed
			}
			return
		//每次向外部节点发送一个请求就添加一个pending包
		case p := <-t.addpending: 
			p.deadline = time.Now().Add(respTimeout)
			plist.PushBack(p)
		//接收到外部回应以后遍历plist里面有没有匹配的值，
		case r := <-t.gotreply:
			var matched bool
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*pending)
				//如果回包的from地址和packageType相同，则匹配到
				if p.from == r.from && p.ptype == r.ptype {
					matched = true
					// Remove the matcher if its callback indicates
					// that all replies have been received. This is
					// required for packet types that expect multiple
					// reply packets.
					//调用相应pending请求的callback函数
					if p.callback(r.data) {
						p.errc <- nil
						plist.Remove(el)
					}
					// Reset the continuous timeout counter (time drift detection)
					contTimeouts = 0
				}
			}
			r.matched <- matched

		case now := <-timeout.C:
			nextTimeout = nil
			//删除过期请求
			// Notify and remove callbacks whose deadline is in the past.
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*pending)
				if now.After(p.deadline) || now.Equal(p.deadline) {
					p.errc <- errTimeout
					plist.Remove(el)
					contTimeouts++
				}
			}
			// If we've accumulated too many timeouts, do an NTP time sync check
			if contTimeouts > ntpFailureThreshold {
				if time.Since(ntpWarnTime) >= ntpWarningCooldown {
					ntpWarnTime = time.Now()
					go checkClockDrift()
				}
				contTimeouts = 0
			}
		}
	}
}
-------------------------------------------------------------------------------------------
// readLoop runs in its own goroutine. it handles incoming UDP packets.
func (t *udp) readLoop() {
	defer t.conn.Close()
	// Discovery packets are defined to be no larger than 1280 bytes.
	// Packets larger than this size will be cut at the end and treated
	// as invalid because their hash won't match.
	buf := make([]byte, 1280) //消息固定大小
	for {
		nbytes, from, err := t.conn.ReadFromUDP(buf)
		if netutil.IsTemporaryError(err) {
			// Ignore temporary read errors.
			log.Debug("Temporary UDP read error", "err", err)
			continue
		} else if err != nil {
			// Shut down the loop for permament errors.
			log.Debug("UDP read error", "err", err)
			return
		}
		t.handlePacket(from, buf[:nbytes]) //对消息进行解析
	}
}
func (t *udp) handlePacket(from *net.UDPAddr, buf []byte) error {
	packet, fromID, hash, err := decodePacket(buf) //对消息解码，返回相应的种类的包
	if err != nil {
		log.Debug("Bad discv4 packet", "addr", from, "err", err)
		return err
	}
	//调用相应包的处理函数
	err = packet.handle(t, from, fromID, hash)
	log.Trace("<< "+packet.name(), "addr", from, "err", err)
	return err
}
//解码函数
func decodePacket(buf []byte) (packet, NodeID, []byte, error) {
	if len(buf) < headSize+1 {
		return nil, NodeID{}, nil, errPacketTooSmall
	}
	hash, sig, sigdata := buf[:macSize], buf[macSize:headSize], buf[headSize:]
	shouldhash := crypto.Keccak256(buf[macSize:])
	if !bytes.Equal(hash, shouldhash) {
		return nil, NodeID{}, nil, errBadHash
	}
	fromID, err := recoverNodeID(crypto.Keccak256(buf[headSize:]), sig)
	if err != nil {
		return nil, NodeID{}, hash, err
	}
	var req packet
	switch ptype := sigdata[0]; ptype {
	case pingPacket: //ping包
		req = new(ping)
	case pongPacket: //pong包
		req = new(pong)
	case findnodePacket: //findnode请求包
		req = new(findnode)
	case neighborsPacket: //邻居回应包
		req = new(neighbors)
	default:
		return nil, fromID, hash, fmt.Errorf("unknown type: %d", ptype)
	}
	s := rlp.NewStream(bytes.NewReader(sigdata[1:]), 0)
	err = s.Decode(req)
	return req, fromID, hash, err
}
//以ping包函数为例分析
func (req *ping) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	//过期判断
	if expired(req.Expiration) {
		return errExpired
	}
	//回应pong包
	t.send(from, pongPacket, &pong{
		To:         makeEndpoint(from, req.From.TCP),
		ReplyTok:   mac,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	//调用处理replay函数对函数进行处理
	if !t.handleReply(fromID, pingPacket, req) {
		// Note: we're ignoring the provided IP address right now
		go t.bond(true, fromID, from, req.From.TCP)
	}
	return nil
}
func (t *udp) handleReply(from NodeID, ptype byte, req packet) bool {
	matched := make(chan bool, 1)
	select {
	//将ping写入通道gotreply等待处理回应
	case t.gotreply <- reply{from, ptype, req, matched}:
		// loop will handle it
		return <-matched
	case <-t.closing:
		return false
	}
}
-------------------------------------------------------------------------------------------
func newTable(t transport, ourID NodeID, ourAddr *net.UDPAddr, nodeDBPath string) (*Table, error) {
	// If no node database was given, use an in-memory one
	//创建db 无db创建内存型db
	db, err := newNodeDB(nodeDBPath, Version, ourID)
	if err != nil {
		return nil, err
	}
	tab := &Table{
		net:        t, //transport 接口实现为udp struct
		db:         db,
		self:       NewNode(ourID, ourAddr.IP, uint16(ourAddr.Port), 		  uint16(ourAddr.Port)),
		bonding:    make(map[NodeID]*bondproc), //bonding map
		bondslots:  make(chan struct{}, maxBondingPingPongs), //bond 最大数量
		refreshReq: make(chan chan struct{}), //刷新请求
		closeReq:   make(chan struct{}),
		closed:     make(chan struct{}),
	}
	//填充bond槽
	for i := 0; i < cap(tab.bondslots); i++ { 
		tab.bondslots <- struct{}{}
	}
	//给256个table.buckets创建实例
	for i := range tab.buckets {
		tab.buckets[i] = new(bucket)
	}
	//开始执行刷新循环
	go tab.refreshLoop()
	return tab, nil
}
-------------------------------------------------------------------------------------------
// refreshLoop schedules doRefresh runs and coordinates shutdown.
func (tab *Table) refreshLoop() {
	var (
		timer   = time.NewTicker(autoRefreshInterval)
		waiting []chan struct{} // accumulates waiting callers while doRefresh runs
		done    chan struct{}   // where doRefresh reports completion
	)
loop:
	for {
		select {
		case <-timer.C:
			if done == nil {
				done = make(chan struct{})
				go tab.doRefresh(done) //主要做doRefresh()操作
			}
		case req := <-tab.refreshReq:
			waiting = append(waiting, req)
			if done == nil {
				done = make(chan struct{})
				go tab.doRefresh(done)
			}
		case <-done:
			for _, ch := range waiting {
				close(ch)
			}
			waiting = nil
			done = nil
		case <-tab.closeReq:
			break loop
		}
	}

	if tab.net != nil {
		tab.net.close()
	}
	if done != nil {
		<-done
	}
	for _, ch := range waiting {
		close(ch)
	}
	tab.db.close()
	close(tab.closed)
}
------------------------------------------------------------------------------------------
//dorefresh 执行查找一个随机的目标来保持buckets充满，如果table为空，那么种子节点就会被插入
// doRefresh performs执行 a lookup for a random target to keep buckets
// full. seed nodes are inserted if the table is empty (initial
// bootstrap or discarded faulty peers).
func (tab *Table) doRefresh(done chan struct{}) {
	defer close(done)

	// The Kademlia paper specifies that the bucket refresh should
	// perform a lookup in the least recently used bucket. We cannot
	// adhere to this because the findnode target is a 512bit value
	// (not hash-sized) and it is not easily possible to generate a
	// sha3 preimage that falls into a chosen bucket.
	// We perform a lookup with a random target instead.
	var target NodeID
	rand.Read(target[:]) //使用加密算法填充一个随机的nodeId
	result := tab.lookup(target, false) //查找此节点，refreshIfEmpty待理解
	if len(result) > 0 {
		return
	}

	// The table is empty. Load nodes from the database and insert
	// them. This should yield a few previously seen nodes that are
	// (hopefully) still alive.
	seeds := tab.db.querySeeds(seedCount, seedMaxAge) //从数据库查找种子节点
	seeds = tab.bondall(append(seeds, tab.nursery...)) //并把代码写死的节点加入种子节点进行联系
	if len(seeds) == 0 {
		log.Debug("No discv4 seed nodes found")
	}
	for _, n := range seeds {
		age := log.Lazy{Fn: func() time.Duration { return time.Since(tab.db.lastPong(n.ID)) }}
		log.Trace("Found seed node in database", "id", n.ID, "addr", n.addr(), "age", age)
	}
	tab.mutex.Lock()
	//将所有seeds添加到buckets
	tab.stuff(seeds)
	tab.mutex.Unlock()

	// Finally, do a self lookup to fill up the buckets.
	tab.lookup(tab.self.ID, false)
}
------------------------------------------------------------------------------------------
//实际查找函数
func (tab *Table) lookup(targetID NodeID, refreshIfEmpty bool) []*Node {
	var (
		target         = crypto.Keccak256Hash(targetID[:])
		asked          = make(map[NodeID]bool) //是否已经查找过的节点
		seen           = make(map[NodeID]bool)
		reply          = make(chan []*Node, alpha)
		pendingQueries = 0
		result         *nodesByDistance //查询结果
	)
	// don't query further if we hit ourself.
	// unlikely to happen often in practice.
	asked[tab.self.ID] = true //把自己设置为已经询问

	for {
		tab.mutex.Lock()
		// generate initial result set
		//先遍历自己的bucket返回离target最近的16个节点
		result = tab.closest(target, bucketSize) //包含16个离target最近的节点
		tab.mutex.Unlock()
		if len(result.entries) > 0 || !refreshIfEmpty {
			break
		}
		// The result set is empty, all nodes were dropped, refresh.
		// We actually wait for the refresh to complete here. The very
		// first query will hit this case and run the bootstrapping
		// logic.
		<-tab.refresh()
		refreshIfEmpty = false
	}

	for {
		// ask the alpha closest nodes that we haven't asked yet
		for i := 0; i < len(result.entries) && pendingQueries < alpha; i++ {
			n := result.entries[i]
			if !asked[n.ID] {
				asked[n.ID] = true
				pendingQueries++
				go func() {
					// Find potential neighbors to bond with UDP
					r, err := tab.net.findnode(n.ID, n.addr(), targetID) //向最近的节点发送findnode请求，发送后会返回16个node离target最近的节点
					if err != nil {
						//利用某个节点查询目标节点，如果失败次数超过最大失败次数，那么删除此节点
						// Bump the failure counter to detect and evacuate non-bonded entries
						fails := tab.db.findFails(n.ID) + 1
						tab.db.updateFindFails(n.ID, fails)
						log.Trace("Bumping findnode failure counter", "id", n.ID, "failcount", fails)

						if fails >= maxFindnodeFailures {
							log.Trace("Too many findnode failures, dropping", "id", n.ID, "failcount", fails)
							tab.delete(n)
						}
					}
					//与一次结果进行bond操作，如果bond成功，则添加节点到自己buckets
					reply <- tab.bondall(r)
				}()
			}
		}
		if pendingQueries == 0 {
			// we have asked all closest nodes, stop the search
			break
		}
		// wait for the next reply
		//总共从16 * 16个离target最近的节点中再选16个更近的节点，不重复
		for _, n := range <-reply {
			if n != nil && !seen[n.ID] {
				seen[n.ID] = true
				result.push(n, bucketSize)
			}
		}
		pendingQueries--
	}
	return result.entries
}
------------------------------------------------------------------------------------------
2、srv.startListening()--> listenLoop()-->srv.setupConn()
func (srv *Server) startListening() error {
	// Launch the TCP listener.
	listener, err := net.Listen("tcp", srv.ListenAddr) //开启tcp监听端口
	if err != nil {
		return err
	}
	laddr := listener.Addr().(*net.TCPAddr)
	srv.ListenAddr = laddr.String()
	srv.listener = listener
	srv.loopWG.Add(1)
	go srv.listenLoop() //开启线程进行监听循环
	// Map the TCP listening port if NAT is configured.
	if !laddr.IP.IsLoopback() && srv.NAT != nil {
		srv.loopWG.Add(1)
		go func() {
			nat.Map(srv.NAT, srv.quit, "tcp", laddr.Port, laddr.Port, "ethereum p2p")
			srv.loopWG.Done()
		}()
	}
	return nil
}
------------------------------------------------------------------------------------------
// listenLoop runs in its own goroutine and accepts
// inbound connections.
func (srv *Server) listenLoop() {
	defer srv.loopWG.Done()
	log.Info("RLPx listener up", "self", srv.makeSelf(srv.listener, srv.ntab))

	// This channel acts as a semaphore limiting
	// active inbound connections that are lingering pre-handshake.
	// If all slots are taken, no further connections are accepted.
	tokens := maxAcceptConns
	if srv.MaxPendingPeers > 0 {
		tokens = srv.MaxPendingPeers
	}
	slots := make(chan struct{}, tokens)
	//填充接收槽
	for i := 0; i < tokens; i++ {
		slots <- struct{}{}
	}

	for {
		//使用接收槽进行for循环等待控制
		// Wait for a handshake slot before accepting.
		<-slots

		var (
			fd  net.Conn
			err error
		)
		//死循环等待外部连接，有连接以后跳出循环
		for {
			fd, err = srv.listener.Accept()
			if tempErr, ok := err.(tempError); ok && tempErr.Temporary() {
				log.Debug("Temporary read error", "err", err)
				continue
			} else if err != nil {
				log.Debug("Read error", "err", err)
				return
			}
			break
		}
		//如果地址不在访问限制表内，拒绝建立连接，释放槽位
		// Reject connections that do not match NetRestrict.
		if srv.NetRestrict != nil {
			if tcp, ok := fd.RemoteAddr().(*net.TCPAddr); ok && !srv.NetRestrict.Contains(tcp.IP) {
				log.Debug("Rejected conn (not whitelisted in NetRestrict)", "addr", fd.RemoteAddr())
				fd.Close()
				slots <- struct{}{}
				continue
			}
		}
		//监控需求
		fd = newMeteredConn(fd, true)
		log.Trace("Accepted connection", "addr", fd.RemoteAddr())

		// Spawn the handler. It will give the slot back when the connection
		// has been established.
		go func() {
			//建立连接释放槽位
			srv.setupConn(fd, inboundConn, nil)
			slots <- struct{}{}
		}()
	}
}
------------------------------------------------------------------------------------------
// setupConn runs the handshakes and attempts to add the connection
// as a peer. It returns when the connection has been added as a peer
// or the handshakes have failed.
func (srv *Server) setupConn(fd net.Conn, flags connFlag, dialDest *discover.Node) {
	// Prevent leftover pending conns from entering the handshake.
	srv.lock.Lock()
	running := srv.running
	srv.lock.Unlock()
	//server.transprot 实现是 newRPLX
	c := &conn{fd: fd, transport: srv.newTransport(fd), flags: flags, cont: make(chan error)}
	if !running {
		c.close(errServerStopped)
		return
	}
	// Run the encryption handshake.
	var err error
	if c.id, err = c.doEncHandshake(srv.PrivateKey, dialDest); err != nil {
		log.Trace("Failed RLPx handshake", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
		c.close(err)
		return
	}
	clog := log.New("id", c.id, "addr", c.fd.RemoteAddr(), "conn", c.flags)
	// For dialed connections, check that the remote public key matches.
	if dialDest != nil && c.id != dialDest.ID {
		c.close(DiscUnexpectedIdentity)
		clog.Trace("Dialed identity mismatch", "want", c, dialDest.ID)
		return
	}
	if err := srv.checkpoint(c, srv.posthandshake); err != nil {
		clog.Trace("Rejected peer before protocol handshake", "err", err)
		c.close(err)
		return
	}
	// Run the protocol handshake
	phs, err := c.doProtoHandshake(srv.ourHandshake)
	if err != nil {
		clog.Trace("Failed proto handshake", "err", err)
		c.close(err)
		return
	}
	if phs.ID != c.id {
		clog.Trace("Wrong devp2p handshake identity", "err", phs.ID)
		c.close(DiscUnexpectedIdentity)
		return
	}
	c.caps, c.name = phs.Caps, phs.Name
	if err := srv.checkpoint(c, srv.addpeer); err != nil {
		clog.Trace("Rejected peer", "err", err)
		c.close(err)
		return
	}
	// If the checks completed successfully, runPeer has now been
	// launched by run.
}
-------------------------------------------------------------------------------------------
3、srv.run()-->dialstate.newTasks()
```

第一次分享内容如上，下一次分析上层应用借助p2p层服务如何进行交易广播，区块广播，区块同步等内容。



