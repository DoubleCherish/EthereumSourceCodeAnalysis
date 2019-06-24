#### ethereum-p2p代码分析（v1.8.24）

本篇主要按p2p的主要逻辑进行代码分析

##### 1、开始分析主要代码

###### 1.1 server.Start()

```java
// Start starts running the server.
// Servers can not be re-used after stopping.
func (srv *Server) Start() (err error) {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if srv.running {
		return errors.New("server already running")
	}
	srv.running = true
	srv.log = srv.Config.Logger
	if srv.log == nil {
		srv.log = log.New()
	}
	if srv.NoDial && srv.ListenAddr == "" {
		srv.log.Warn("P2P server will be useless, neither dialing nor listening")
	}

	// static fields
	if srv.PrivateKey == nil {
		return errors.New("Server.PrivateKey must be set to a non-nil key")
	}
	if srv.newTransport == nil {
		srv.newTransport = newRLPX
	}
	if srv.Dialer == nil {
		srv.Dialer = TCPDialer{&net.Dialer{Timeout: defaultDialTimeout}}
	}
	srv.quit = make(chan struct{}) // 退出通道
	srv.addpeer = make(chan *conn) // 添加底层peer
	srv.delpeer = make(chan peerDrop) //删除peer
	srv.posthandshake = make(chan *conn) // 推送握手
	srv.addstatic = make(chan *enode.Node) //添加静态节点
	srv.removestatic = make(chan *enode.Node) //移除静态节点
	srv.addtrusted = make(chan *enode.Node) //添加信任节点
	srv.removetrusted = make(chan *enode.Node)
	srv.peerOp = make(chan peerOpFunc) //对peer做操作
	srv.peerOpDone = make(chan struct{}) // 操作完成通知通道
	// 开始创建一个本地节点
	if err := srv.setupLocalNode(); err != nil {
		return err
	}

	//-------------------------------------------------
	// 此部分进行接收内部连接   有一个新的连接来的时候与其握手后建立连接
	if srv.ListenAddr != "" {
		if err := srv.setupListening(); err != nil {
			return err
		}
	}
	//-------------------------------------------------

	//--------------------------------------------------
	//开启节点发现机制  主要用了udp和 table
	if err := srv.setupDiscovery(); err != nil {
		return err
	}
	//--------------------------------------------------

	dynPeers := srv.maxDialedConns()
	dialer := newDialState(srv.localnode.ID(), srv.StaticNodes, srv.BootstrapNodes, srv.ntab, dynPeers, srv.NetRestrict)
	srv.loopWG.Add(1)
	// 处理各个通道发来的数据  并定时跑任务 主要使用了dail.go
	go srv.run(dialer)
	return nil
}
```

上面是server启动时候的代码，主要做了如下几件事：

* 对server的相关变量进行初始化
* 创建本地节点
* 开启server的tcp连接服务
* 如果开启节点发现机制，那么开启节点发现机制
* 最后单独起一个协程将server的主循环运行

###### 1.2 srv.setupLocalNode()

```java
func (srv *Server) setupLocalNode() error {
	// Create the devp2p handshake.
    // 根据分配给服务端的私钥恢复出公钥
	pubkey := crypto.FromECDSAPub(&srv.PrivateKey.PublicKey)
    // 握手结构体初始化
	srv.ourHandshake = &protoHandshake{Version: baseProtocolVersion, Name: srv.Name, ID: pubkey[1:]}
    // 将server中支持的协议放入握手协议储存室中
	for _, p := range srv.Protocols {
		srv.ourHandshake.Caps = append(srv.ourHandshake.Caps, p.cap())
	}
    // 对协议进行排序
	sort.Sort(capsByNameAndVersion(srv.ourHandshake.Caps))
	// 创建本地数据存储目录
	// Create the local node.
	db, err := enode.OpenDB(srv.Config.NodeDatabase)
	if err != nil {
		return err
	}
	srv.nodedb = db
     // 给server.localnode填充相关属性
	srv.localnode = enode.NewLocalNode(db, srv.PrivateKey)
	srv.localnode.SetFallbackIP(net.IP{127, 0, 0, 1})
	srv.localnode.Set(capsByNameAndVersion(srv.ourHandshake.Caps))
	// TODO: check conflicts
	for _, p := range srv.Protocols {
		for _, e := range p.Attributes {
			srv.localnode.Set(e)
		}
	}
	switch srv.NAT.(type) {
	case nil:
		// No NAT interface, do nothing.
	case nat.ExtIP:
		// ExtIP doesn't block, set the IP right away.
		ip, _ := srv.NAT.ExternalIP()
		srv.localnode.SetStaticIP(ip)
	default:
		// Ask the router about the IP. This takes a while and blocks startup,
		// do it in the background.
		srv.loopWG.Add(1)
		go func() {
			defer srv.loopWG.Done()
			if ip, err := srv.NAT.ExternalIP(); err == nil {
				srv.localnode.SetStaticIP(ip)
			}
		}()
	}
	return nil
}
```

以上主要是p2p.server将本地节点的属性做了额外记录，方便以后处理

###### 1.3 srv.setupListening()

```java
func (srv *Server) setupListening() error {
	// Launch the TCP listener.
    // 开启tcp端口
	listener, err := net.Listen("tcp", srv.ListenAddr)
	if err != nil {
		return err
	}
	laddr := listener.Addr().(*net.TCPAddr)
	srv.ListenAddr = laddr.String()
	srv.listener = listener
	srv.localnode.Set(enr.TCP(laddr.Port))

	srv.loopWG.Add(1)
    // 开启主循环
	go srv.listenLoop()

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

// listenLoop runs in its own goroutine and accepts
// inbound connections.
func (srv *Server) listenLoop() {
	defer srv.loopWG.Done()
	srv.log.Debug("TCP listener up", "addr", srv.listener.Addr())
	//defaultMaxPendingPeers = 50  可以配置
	tokens := defaultMaxPendingPeers
	if srv.MaxPendingPeers > 0 {
		tokens = srv.MaxPendingPeers
	}
	// 先申请槽位 go语言里面struct{} 占用width为0
    // slots主要用来控制循环次数
	slots := make(chan struct{}, tokens)
	for i := 0; i < tokens; i++ {
		slots <- struct{}{}
	}

	for {
		// Wait for a handshake slot before accepting.
		<-slots

		var (
			fd  net.Conn
			err error
		)
		for {
             // 处理外部连接
			fd, err = srv.listener.Accept()
			if netutil.IsTemporaryError(err) {
				srv.log.Debug("Temporary read error", "err", err)
				continue
			} else if err != nil {
				srv.log.Debug("Read error", "err", err)
				return
			}
			break
		}
		// 如果节点开启了白名单验证，那么不在白名单列表的将直接被拒绝
		// Reject connections that do not match NetRestrict.
		if srv.NetRestrict != nil {
			if tcp, ok := fd.RemoteAddr().(*net.TCPAddr); ok && !srv.NetRestrict.Contains(tcp.IP) {
				srv.log.Debug("Rejected conn (not whitelisted in NetRestrict)", "addr", fd.RemoteAddr())
				fd.Close()
				slots <- struct{}{}
				continue
			}
		}

		var ip net.IP
		if tcp, ok := fd.RemoteAddr().(*net.TCPAddr); ok {
			ip = tcp.IP
		}
		//监控需求
		fd = newMeteredConn(fd, true, ip)
		srv.log.Trace("Accepted connection", "addr", fd.RemoteAddr())
		go func() {
			// 进行握手  后 将节点作为inboundConn类型添加为自己的peer
			srv.SetupConn(fd, inboundConn, nil)
			slots <- struct{}{}
		}()
	}
}

// SetupConn runs the handshakes and attempts to add the connection
// as a peer. It returns when the connection has been added as a peer
// or the handshakes have failed.
func (srv *Server) SetupConn(fd net.Conn, flags connFlag, dialDest *enode.Node) error {
    // 将要连接的节点包装为一个conn结构体
	c := &conn{fd: fd, transport: srv.newTransport(fd), flags: flags, cont: make(chan error)}
	err := srv.setupConn(c, flags, dialDest)
	if err != nil {
		c.close(err)
		srv.log.Trace("Setting up connection failed", "addr", fd.RemoteAddr(), "err", err)
	}
	return err
}

func (srv *Server) setupConn(c *conn, flags connFlag, dialDest *enode.Node) error {
	// Prevent leftover pending conns from entering the handshake.
	srv.lock.Lock()
	running := srv.running
	srv.lock.Unlock()
	if !running {
		return errServerStopped
	}
    // 如果要与远程节点进行沟通 则算出远程节点的公钥
	// If dialing, figure out the remote public key.
	var dialPubkey *ecdsa.PublicKey
	if dialDest != nil {
		dialPubkey = new(ecdsa.PublicKey)
		if err := dialDest.Load((*enode.Secp256k1)(dialPubkey)); err != nil {
			return errors.New("dial destination doesn't have a secp256k1 public key")
		}
	}
    // 开始进行加密握手，主要交换双方的公钥
	// Run the encryption handshake.
	remotePubkey, err := c.doEncHandshake(srv.PrivateKey, dialPubkey)
	if err != nil {
		srv.log.Trace("Failed RLPx handshake", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
		return err
	}
	if dialDest != nil {
		// For dialed connections, check that the remote public key matches.
		if dialPubkey.X.Cmp(remotePubkey.X) != 0 || dialPubkey.Y.Cmp(remotePubkey.Y) != 0 {
			return DiscUnexpectedIdentity
		}
		c.node = dialDest
	} else {
        // 将远程节点包装为一个Node
		c.node = nodeFromConn(remotePubkey, c.fd)
	}
	if conn, ok := c.fd.(*meteredConn); ok {
		conn.handshakeDone(c.node.ID())
	}
	clog := srv.log.New("id", c.node.ID(), "addr", c.fd.RemoteAddr(), "conn", c.flags)
    // 开始进行一次检查，将c传到posthandshake通道 主要检查是否为已知节点或者节点个数超出当前限制，对静态节点和trusted节点开绿灯
	err = srv.checkpoint(c, srv.posthandshake)
	if err != nil {
		clog.Trace("Rejected peer before protocol handshake", "err", err)
		return err
	}
    // 开始执行协议握手，主要将自己和对方支持的协议进行对比
	// Run the protocol handshake
	phs, err := c.doProtoHandshake(srv.ourHandshake)
	if err != nil {
		clog.Trace("Failed proto handshake", "err", err)
		return err
	}
    // 如果当前连接的节点身份和远程交换的不服 返回错误
	if id := c.node.ID(); !bytes.Equal(crypto.Keccak256(phs.ID), id[:]) {
		clog.Trace("Wrong devp2p handshake identity", "phsid", hex.EncodeToString(phs.ID))
		return DiscUnexpectedIdentity
	}
    // 记录远程节点支持的所有交易和远程节点的名称
	c.caps, c.name = phs.Caps, phs.Name
    // 又一个检查点，将c 传入addpeer通道
	err = srv.checkpoint(c, srv.addpeer)
	if err != nil {
		clog.Trace("Rejected peer", "err", err)
		return err
	}
	// If the checks completed successfully, runPeer has now been
	// launched by run.
	clog.Trace("connection set up", "inbound", dialDest == nil)
	return nil
}
```

以上是p2p服务接收外部连接的部分，主要做了以下几件事情：

* 开启tcp监听端口，固定槽位，无限监听外部连接，每收到一个连接请求，开启单独的协程处理连接请求
* 与远程节点建立连接，连接期间主要做了加密握手，加密握手成功以后进行预前检查，查看是不是超出节点最大连接数、是不是已知节点等等。
* 紧接着进行协议握手，协议握手成功后执行一次检查，将此连接插入addpeer通道，尝试将此连接作为一个peer加入本节点。

接下来先分析跟dail.go相关的逻辑，主要是一些动态连接任务，动态连接任务总数为maxPeer/3个

###### 1.4srv.run(dialer)

```java
// server的主循环
func (srv *Server) run(dialstate dialer) {
	srv.log.Info("Started P2P networking", "self", srv.localnode.Node())
	defer srv.loopWG.Done()
	defer srv.nodedb.Close()

	var (
        //存放所有已连接的peer
		peers        = make(map[enode.ID]*Peer)
        // 统计内部连接数量
		inboundCount = 0
        // 记录trusted节点 ，主要当节点数量限制上面对trustednode有绿灯
		trusted      = make(map[enode.ID]bool, len(srv.TrustedNodes))
        // 最大活跃dail任务数为16 
		taskdone     = make(chan task, maxActiveDialTasks)
        // 正在运行中的任务
		runningTasks []task
        // 队列中的任务
		queuedTasks  []task // tasks that can't run yet
	)
	//添加trusted-nodes
	// Put trusted nodes into a map to speed up checks.
	// Trusted peers are loaded on startup or added via AddTrustedPeer RPC.
	for _, n := range srv.TrustedNodes {
		trusted[n.ID()] = true
	}
	// 从运行中的task删除task的函数定义
	// removes t from runningTasks
	delTask := func(t task) {
		for i := range runningTasks {
			if runningTasks[i] == t {
				runningTasks = append(runningTasks[:i], runningTasks[i+1:]...)
				break
			}
		}
	}

	// starts until max number of active tasks is satisfied
    // 如果运行中的任务数量小于限制，且计数器小于任务数，那么将queue中的任务拿出来执行，并返回剩余的任务
	startTasks := func(ts []task) (rest []task) {
		i := 0
		//maxActiveDialTask = 16
		for ; len(runningTasks) < maxActiveDialTasks && i < len(ts); i++ {
			t := ts[i]
			srv.log.Trace("New dial task", "task", t)
			go func() { t.Do(srv); taskdone <- t }()
			runningTasks = append(runningTasks, t)
		}
		return ts[i:]
	}
    // 定时器执行逻辑
	scheduleTasks := func() {
        //  将队列更新为运行完剩余的任务
		// Start from queue first.
		queuedTasks = append(queuedTasks[:0], startTasks(queuedTasks)...)
         // 立刻查询一次运行任务是不是小于限制，若小于限制，则创建一批新的任务，立即执行一次开始任务的操作
		// Query dialer for new tasks and start as many as possible now.
		if len(runningTasks) < maxActiveDialTasks {
			//新放进来一批任务 ，每次任务都不一样
			//nt = new task
			nt := dialstate.newTasks(len(runningTasks)+len(queuedTasks), peers, time.Now())
			queuedTasks = append(queuedTasks, startTasks(nt)...)
		}
	}
// 下面是server的主要循环，处理各种通道的事件
running:
	for {
		scheduleTasks()

		select {
         // 如果srv.quit通道发来退出server的请求，那么跳出running循环，进行清理逻辑
		case <-srv.quit:
			// The server was stopped. Run the cleanup logic.
			break running
		case n := <-srv.addstatic:
			//给静态节点都添加dialtask  经过dailtask以后如果正常他们会被放入addpeer通道
			// This channel is used by AddPeer to add to the
			// ephemeral static peer list. Add it to the dialer,
			// it will keep the node connected.
			srv.log.Trace("Adding static node", "node", n)
			dialstate.addStatic(n)
		case n := <-srv.removestatic:
             // 移除与静态节点的连接
			// This channel is used by RemovePeer to send a
			// disconnect request to a peer and begin the
			// stop keeping the node connected.
			srv.log.Trace("Removing static node", "node", n)
			dialstate.removeStatic(n)
			if p, ok := peers[n.ID()]; ok {
				p.Disconnect(DiscRequested)
			}
		case n := <-srv.addtrusted:
             //添加信任节点
			// This channel is used by AddTrustedPeer to add an enode
			// to the trusted node set.
			srv.log.Trace("Adding trusted node", "node", n)
			trusted[n.ID()] = true
			// Mark any already-connected peer as trusted
			if p, ok := peers[n.ID()]; ok {
				p.rw.set(trustedConn, true)
			}
		case n := <-srv.removetrusted:
             // 移除信任节点
			// This channel is used by RemoveTrustedPeer to remove an enode
			// from the trusted node set.
			srv.log.Trace("Removing trusted node", "node", n)
			if _, ok := trusted[n.ID()]; ok {
				delete(trusted, n.ID())
			}
			// Unmark any already-connected peer as trusted
			if p, ok := peers[n.ID()]; ok {
				p.rw.set(trustedConn, false)
			}
		case op := <-srv.peerOp:
             // 定义了一些对所有peer的操作函数，在此执行
			// This channel is used by Peers and PeerCount.
			op(peers)
			srv.peerOpDone <- struct{}{}
		case t := <-taskdone:
			//一个task完成以后 通知dailstate 更新state 并从活跃任务列表移除
			// A task got done. Tell dialstate about it so it
			// can update its state and remove it from the active
			// tasks list.
			srv.log.Trace("Dial task done", "task", t)
			dialstate.taskDone(t, time.Now())
			delTask(t)
		case c := <-srv.posthandshake:
             // 经过加密连接以后，通过检查点把连接传到这里执行一次检查
			// A connection has passed the encryption handshake so
			// the remote identity is known (but hasn't been verified yet).
			if trusted[c.node.ID()] {
				// Ensure that the trusted flag is set before checking against MaxPeers.
				c.flags |= trustedConn
			}
			// TODO: track in-progress inbound node IDs (pre-Peer) to avoid dialing them.
			select {
			case c.cont <- srv.encHandshakeChecks(peers, inboundCount, c):
			case <-srv.quit:
				break running
			}
		case c := <-srv.addpeer:
             // 当peer经过所有验证时，将被传到这里执行实际的peer添加操作
			// At this point the connection is past the protocol handshake.
			// Its capabilities are known and the remote identity is verified.
			//这个阶段已经通过协议握手，他的功能
			err := srv.protoHandshakeChecks(peers, inboundCount, c)
			//如果通过协议握手检查
			if err == nil {
				// The handshakes are done and it passed all checks.
				p := newPeer(c, srv.Protocols)
				//消息事件推送
				// If message events are enabled, pass the peerFeed
				// to the peer
				if srv.EnableMsgEvents {
					p.events = &srv.peerFeed
				}
				//对name进行截断
				name := truncateName(c.name)
				srv.log.Debug("Adding p2p peer", "name", name, "addr", c.fd.RemoteAddr(), "peers", len(peers)+1)
				//开启线程运行peer
				go srv.runPeer(p)
				//将peer添加到peers map
				peers[c.node.ID()] = p
				if p.Inbound() {
					inboundCount++
				}
			}
			// The dialer logic relies on the assumption that
			// dial tasks complete after the peer has been added or
			// discarded. Unblock the task last.
			select {
			case c.cont <- err:
			case <-srv.quit:
				break running
			}
		case pd := <-srv.delpeer:
             // 删除一个peer 
			// A peer disconnected.
			d := common.PrettyDuration(mclock.Now() - pd.created)
			pd.log.Debug("Removing p2p peer", "duration", d, "peers", len(peers)-1, "req", pd.requested, "err", pd.err)
			//从peers map里面删除peer
			delete(peers, pd.ID())
			if pd.Inbound() {
				inboundCount--
			}
		}
	}

	srv.log.Trace("P2P networking is spinning down")
	//关闭udp  table
	// Terminate discovery. If there is a running lookup it will terminate soon.
	if srv.ntab != nil {
		srv.ntab.Close()
	}
	if srv.DiscV5 != nil {
		srv.DiscV5.Close()
	}
	//和所有peer断开连接
	// Disconnect all peers.
	for _, p := range peers {
		p.Disconnect(DiscQuitting)
	}
	//待理解
	// Wait for peers to shut down. Pending connections and tasks are
	// not handled here and will terminate soon-ish because srv.quit
	// is closed.
	for len(peers) > 0 {
		p := <-srv.delpeer
		p.log.Trace("<-delpeer (spindown)", "remainingTasks", len(runningTasks))
		delete(peers, p.ID())
	}
}
```

以上为server的主循环，主要做了以下几件事：

* 定时执行一批任务，调用了task.Do()方法，每个任务具体做什么后面细讲
* 处理各种通道的事件

###### 1.5 dialstate.newTasks()

在分析这部分代码之前先明确一件事，task总共有几种类型，总的task类型有三种：dailTask  discoverTask waitExpireTask。这三种任务分别执行的是连接任务、节点发现任务、等待过期任务，三种任务各自实现了task接口的Do方法。task接口定义如下：

```java
type task interface {
	Do(*Server)
}
```

下面开始分析newTask()方法

```java
func (s *dialstate) newTasks(nRunning int, peers map[enode.ID]*Peer, now time.Time) []task {
	if s.start.IsZero() {
		s.start = now
	}

	var newtasks []task
	//添加dailtask
	addDial := func(flag connFlag, n *enode.Node) bool {
		if err := s.checkDial(n, peers); err != nil {
			log.Trace("Skipping dial candidate", "id", n.ID(), "addr", &net.TCPAddr{IP: n.IP(), Port: n.TCP()}, "err", err)
			return false
		}
		s.dialing[n.ID()] = flag
		newtasks = append(newtasks, &dialTask{flags: flag, dest: n})
		return true
	}
	
	// Compute number of dynamic dials necessary at this point.
	needDynDials := s.maxDynDials //maxDynDials = MaxPeers/3
    //1 、判断所有peer里是否有动态连接的 若有则总的动态连接任务计数缩小
    // 如果已经连接的peer中动态连接类型的节点数量过多，将导致needDynDials小于0  那么下面大多数逻辑就不能执行
	for _, p := range peers {
		if p.rw.is(dynDialedConn) {
			needDynDials--
		}
	}

	//2、计算正在dail中的是动态dail的任务，若有动态连接的任务，缩小动态连接任务的计数
	for _, flag := range s.dialing {
		if flag&dynDialedConn != 0 {
			needDynDials--
		}
	}
	//3、每次newTask调用时候将过期的dail任务弹出堆
	// Expire the dial history on every invocation.
	s.hist.expire(now)
	// 4、为非连接状态的静态节点创建dailtask    项目初次启动时候会给所有静态节点添加dailTask任务
	// Create dials for static nodes if they are not connected.
	for id, t := range s.static {
		err := s.checkDial(t.dest, peers)
		switch err {
		case errNotWhitelisted, errSelf:
			log.Warn("Removing static dial candidate", "id", t.dest.ID, "addr", &net.TCPAddr{IP: t.dest.IP(), Port: t.dest.TCP()}, "err", err)
			delete(s.static, t.dest.ID())
		case nil:
			s.dialing[id] = t.flags
			newtasks = append(newtasks, t)
		}
	}
	//5、如果我们的peers为空且引导节点个数大于0且动态任务剩余计数大于0且现在时间减去开始时间大于20s 则尝试联系一个bootnode节点 一般为bootnode的第一个
	// If we don't have any peers whatsoever, try to dial a random bootnode. This
	// scenario is useful for the testnet (and private networks) where the discovery
	// table might be full of mostly bad peers, making it hard to find good ones.
	if len(peers) == 0 && len(s.bootnodes) > 0 && needDynDials > 0 && now.Sub(s.start) > fallbackInterval {
         // 暂存引导节点列表第一个
		bootnode := s.bootnodes[0]
         // 将后面节点往前面移动覆盖第一个节点
		s.bootnodes = append(s.bootnodes[:0], s.bootnodes[1:]...)
         // 将第一个节点追加到引导节点列表尾部
		s.bootnodes = append(s.bootnodes, bootnode)
		// 将bootnodez作为一个dynDialedConn类型添加一为个dailtask
		if addDial(dynDialedConn, bootnode) {
			needDynDials--
		}
	}
	//6、此时我们将还剩余的动态dail位置的一半记为randomCandidates，如果计数还大于0，那么从bucket里面读取randomCandidates个节点进行dail 
    // 相当于定期拿出bucket里面的节点进行连接
	// Use random nodes from the table for half of the necessary
	// dynamic dials.
	randomCandidates := needDynDials / 2
	if randomCandidates > 0 {
        // randomNodes切片的长度为(maxPeers/3)/2
		n := s.ntab.ReadRandomNodes(s.randomNodes)
		for i := 0; i < randomCandidates && i < n; i++ {
			if addDial(dynDialedConn, s.randomNodes[i]) {
				needDynDials--
			}
		}
	}
    // 创建随机节点查找任务，将查找到的结果填充到lookupBuf
	// Create dynamic dials from random lookup results, removing tried
	// items from the result buffer.
	i := 0
	for ; i < len(s.lookupBuf) && needDynDials > 0; i++ {
		if addDial(dynDialedConn, s.lookupBuf[i]) {
			needDynDials--
		}
	}
	s.lookupBuf = s.lookupBuf[:copy(s.lookupBuf, s.lookupBuf[i:])]
	// Launch a discovery lookup if more candidates are needed.
	if len(s.lookupBuf) < needDynDials && !s.lookupRunning {
		s.lookupRunning = true
		//给lookup添加一个发现节点的任务
		newtasks = append(newtasks, &discoverTask{})
	}

	// Launch a timer to wait for the next node to expire if all
	// candidates have been tried and no task is currently active.
	// This should prevent cases where the dialer logic is not ticked
	// because there are no pending events.
	//如果nRunning为0且newTasks长度为0且历史任务列表大于0创建等待过期的任务
	if nRunning == 0 && len(newtasks) == 0 && s.hist.Len() > 0 {
		t := &waitExpireTask{s.hist.min().exp.Sub(now)}
		newtasks = append(newtasks, t)
	}
	return newtasks
}
// 额外加一段代码方便理解
// 当dailTask和discoverTask做完以后会做相应操作
func (s *dialstate) taskDone(t task, now time.Time) {
	switch t := t.(type) {
	case *dialTask:
        // 在history中添加此结果，并在dialing列表中删除已完成的任务
		s.hist.add(t.dest.ID(), now.Add(dialHistoryExpiration))
		delete(s.dialing, t.dest.ID())
	case *discoverTask:
		s.lookupRunning = false
         // 此部分将节点发现机制发现的节点存在lookupBuf中
		s.lookupBuf = append(s.lookupBuf, t.results...)
	}
}
```

下面先讲几个任务的Do的具体实现

```java
dailTask的Do实现
func (t *dialTask) Do(srv *Server) {
	if t.dest.Incomplete() {
		if !t.resolve(srv) {
			return
		}
	}
	err := t.dial(srv, t.dest)
	if err != nil {
		log.Trace("Dial error", "task", t, "err", err)
		// Try resolving the ID of static nodes if dialing failed.
		if _, ok := err.(*dialError); ok && t.flags&staticDialedConn != 0 {
			if t.resolve(srv) {
				t.dial(srv, t.dest)
			}
		}
	}
}
discoverTask的Do实现
func (t *discoverTask) Do(srv *Server) {
	// newTasks generates a lookup task whenever dynamic dials are
	// necessary. Lookups need to take some time, otherwise the
	// event loop spins too fast.
	next := srv.lastLookup.Add(lookupInterval)
	if now := time.Now(); now.Before(next) {
		time.Sleep(next.Sub(now))
	}
	srv.lastLookup = time.Now()
	t.results = srv.ntab.LookupRandom()
}
waitExpireTask的Do实现
func (t waitExpireTask) Do(*Server) {
	time.Sleep(t.Duration)
}
```

以上主要是在server.go里面实现的代码，主要开启了tcp监听端口来接收外部连接，还定时执行三种task任务，节点发现部分下一节单独分析