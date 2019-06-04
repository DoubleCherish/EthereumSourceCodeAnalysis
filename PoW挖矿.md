#### PoW挖矿

代码基于在学习以太坊挖矿以前先来了解几个相关的数据结构作为铺垫：

```java
数据结构1：
type Miner struct {
    mux *event.TypeMux // 事件锁，已被feed.mu.lock替代
    worker *worker // 干活的人
    coinbase common.Address // 结点地址
    mining   int32 // 代表挖矿进行中的状态
    eth      Backend // Backend对象，Backend是一个自定义接口封装了所有挖矿所需方法。
    engine   consensus.Engine // 共识引擎
    canStart    int32 // 是否能够开始挖矿操作
    shouldStart int32 // 同步以后是否应该开始挖矿
}
//实际的工人
type worker struct {
	config *params.ChainConfig //链配置
	engine consensus.Engine //一致性引擎，ethash或者clique poa（这个目前只在测试网测试）

	mu sync.Mutex //锁

	// update loop
	mux    *event.TypeMux 
	events *event.TypeMuxSubscription
	wg     sync.WaitGroup

	agents map[Agent]struct{} //agent 是挖矿代理，实际执行挖矿的代理，目前以太坊默认注册cpuagent，矿池应该是自己实现了自己的agent注册到这里
	recv   chan *Result //这是一个结果通道，挖矿完成以后将结果推送到此通道

	eth     Backend //以太坊定义
	chain   *core.BlockChain
	proc    core.Validator
	chainDb ethdb.Database

	coinbase common.Address //基础帐户地址
	extra    []byte

	currentMu sync.Mutex
	current   *Work  //实际将每一个区块作为一个工作work推给agent进行挖矿

	uncleMu        sync.Mutex
	possibleUncles map[common.Hash]*types.Block //可能的数块

	txQueueMu sync.Mutex
	txQueue   map[common.Hash]*types.Transaction

	unconfirmed *unconfirmedBlocks // set of locally mined blocks pending canonicalness confirmations

	// atomic status counters
	mining int32
	atWork int32

	fullValidation bool
}
//agent接口如下，实现以下接口的 就可作为一个agent
type Agent interface {
	Work() chan<- *Work
	SetReturnCh(chan<- *Result)
	Stop()
	Start()
	GetHashRate() int64
}

```

上面记录了要开始学习挖矿的基础结构，其实还有block的header数据结构需要很熟悉，方便后续分析

在backend.go里面New一个ethereum时候，调用了如下语句：

```java
//先单独看如下两句：
	engine: CreateConsensusEngine(ctx, config, chainConfig, chainDb),
	engine := ethash.New(ctx.ResolvePath(config.EthashCacheDir), config.EthashCachesInMem, config.EthashCachesOnDisk,config.EthashDatasetDir, config.EthashDatasetsInMem, config.EthashDatasetsOnDisk)
   //从上面可以看出来geth启动时候默认的共识引擎为ethash

 //下面语句开始New一个miner了
eth.miner = miner.New(eth, eth.chainConfig, eth.EventMux(), eth.engine)
 
 # go-ethereum/miner/miner.go
func New(eth Backend, config *params.ChainConfig, mux *event.TypeMux, engine consensus.Engine) *Miner {
	//开始创建miner结构体
	miner := &Miner{
		eth:      eth,
		mux:      mux,
		engine:   engine,
		worker:   newWorker(config, engine, common.Address{}, eth, mux), //创建了一个工人
		canStart: 1,
	}
	//注册代理
	miner.Register(NewCpuAgent(eth.BlockChain(), engine))
	go miner.update()
	return miner
}
# go-ethereum/miner/worker.go
func newWorker(config *params.ChainConfig, engine consensus.Engine, coinbase common.Address, eth Backend, mux *event.TypeMux) *worker {
	worker := &worker{
		config:         config,
		engine:         engine,
		eth:            eth,
		mux:            mux,
		chainDb:        eth.ChainDb(),
		recv:           make(chan *Result, resultQueueSize), //结果通道
		chain:          eth.BlockChain(),
		proc:           eth.BlockChain().Validator(),
		possibleUncles: make(map[common.Hash]*types.Block),
		coinbase:       coinbase,
		txQueue:        make(map[common.Hash]*types.Transaction),
		agents:         make(map[Agent]struct{}),
		unconfirmed:    newUnconfirmedBlocks(eth.BlockChain(), 5),
		fullValidation: false,
	}
	//worker开始订阅相关三个事件
	worker.events = worker.mux.Subscribe(core.ChainHeadEvent{}, core.ChainSideEvent{}, core.TxPreEvent{})
	//先来分析一下update()函数
	go worker.update()

	go worker.wait()
	worker.commitNewWork()

	return worker
}

func (self *worker) update() {
	//遍历自己的事件通道
	for event := range self.events.Chan() {
		// A real event arrived, process interesting content
		switch ev := event.Data.(type) {
		//如果是新区块加入事件，那么工人开始挖下一个区块
		case core.ChainHeadEvent:
			self.commitNewWork()
		//如果是区块旁支事件（俗称的叔块）
		case core.ChainSideEvent:
			self.uncleMu.Lock()
			//在map结构里添加可能的叔块
			self.possibleUncles[ev.Block.Hash()] = ev.Block
			self.uncleMu.Unlock()
		case core.TxPreEvent:
			// Apply transaction to the pending state if we're not mining
			if atomic.LoadInt32(&self.mining) == 0 {
				self.currentMu.Lock()

				acc, _ := types.Sender(self.current.signer, ev.Tx)
				txs := map[common.Address]types.Transactions{acc: {ev.Tx}}
				txset := types.NewTransactionsByPriceAndNonce(txs)

				self.current.commitTransactions(self.mux, txset, self.chain, self.coinbase)
				self.currentMu.Unlock()
			}
		}
	}
}


```

​		介绍下ChainHeadEvent，ChainSideEvent，TxPreEvent几个事件，每个事件会触发worker不同的反应。ChainHeadEvent是指区块链中已经加入了一个新的区块作为整个链的链头，这时worker的回应是立即开始准备挖掘下一个新区块(也是够忙的)；ChainSideEvent指区块链中加入了一个新区块作为当前链头的旁支，worker会把这个区块收纳进possibleUncles[]数组，作为下一个挖掘新区块可能的Uncle之一；TxPreEvent是TxPool对象发出的，指的是一个新的交易tx被加入了TxPool，这时如果worker没有处于挖掘中，那么就去执行这个tx，并把它收纳进Work.txs数组，为下次挖掘新区块备用。

​		需要稍稍注意的是，ChainHeadEvent并不一定是外部源发出。由于worker对象有个成员变量chain(eth.BlockChain)，所以当worker自己完成挖掘一个新区块，并把它写入数据库，加进区块链里成为新的链头时，worker自己也可以调用chain发出一个ChainHeadEvent，从而被worker.update()函数监听到，进入下一次区块挖掘



```java
commitNewWork()在另外一篇文章中已经单独分析，接下来主要分析worker.wait()
func (self *worker) wait() {
	for {
		mustCommitNewWork := true
         //worker.wait会一直阻塞在这里，等待有新的区块经过seal后被推送到recv通道
		for result := range self.recv {
			atomic.AddInt32(&self.atWork, -1)

			if result == nil {
				continue
			}
			block := result.Block
			work := result.Work
			//是否是全验证模式
			if self.fullValidation {
				//将新区块插入到主链
				if _, err := self.chain.InsertChain(types.Blocks{block}); err != nil {
					log.Error("Mined invalid block", "err", err)
					continue
				}
                //发送新挖出区块事件，会通知当前的miner和protocolManager和其他订阅者
				go self.mux.Post(core.NewMinedBlockEvent{Block: block})
			} else {
				work.state.CommitTo(self.chainDb, self.config.IsEIP158(block.Number()))
				stat, err := self.chain.WriteBlock(block)
				if err != nil {
					log.Error("Failed writing block to chain", "err", err)
					continue
				}
				// update block hash since it is now available and not when the receipt/log of individual transactions were created
                //遍历当前所挖区块的所有txreceipts，给log的blockhash字段填充值
				for _, r := range work.receipts {
					for _, l := range r.Logs {
						l.BlockHash = block.Hash()
					}
				}
				for _, log := range work.state.Logs() {
					log.BlockHash = block.Hash()
				}

				// check if canon block and write transactions
				if stat == core.CanonStatTy {
					// This puts transactions in a extra db for rpc
					core.WriteTransactions(self.chainDb, block)
					// store the receipts
					core.WriteReceipts(self.chainDb, work.receipts)
					// Write map map bloom filters
					core.WriteMipmapBloom(self.chainDb, block.NumberU64(), work.receipts)
					// implicit by posting ChainHeadEvent
					mustCommitNewWork = false
				}
				//广播相关事件出去
				// broadcast before waiting for validation
				go func(block *types.Block, logs []*types.Log, receipts []*types.Receipt) {
					self.mux.Post(core.NewMinedBlockEvent{Block: block})
					self.mux.Post(core.ChainEvent{Block: block, Hash: block.Hash(), Logs: logs})

					if stat == core.CanonStatTy {
						self.mux.Post(core.ChainHeadEvent{Block: block})
						self.mux.Post(logs)
					}
					if err := core.WriteBlockReceipts(self.chainDb, block.Hash(), block.NumberU64(), receipts); err != nil {
						log.Warn("Failed writing block receipts", "err", err)
					}
				}(block, work.state.Logs(), work.receipts)
			}
            //将区块号和区块hash插入未确认表
			// Insert the block into the set of pending ones to wait for confirmations
			self.unconfirmed.Insert(block.NumberU64(), block.Hash())
			//如果再挖出一个新块必须开启下一次挖掘工作，那么执行新的挖矿工作
			if mustCommitNewWork {
				self.commitNewWork()
			}
		}
	}
}
接下来回到Miner.New下面继续看miner.Register(NewCpuAgent(eth.BlockChain(), engine))
    
func (self *Miner) Register(agent Agent) {
    //如果自己开启了挖矿
	if self.Mining() {
        //那么启动代理
		agent.Start()
	}
    //在工人处注册此代理
	self.worker.register(agent)
}
# go-ethereum/miner/agent.go
func (self *CpuAgent) Start() {
	//类似java的CAS
	if !atomic.CompareAndSwapInt32(&self.isMining, 0, 1) {
		return // agent already started
	}
	//自己开启一个携程进行工作
	go self.update()
}

func (self *CpuAgent) update() {
out:
	//死循环工作，以太坊常常做的事情，哈哈
	for {
		select {
		//遍历workCh，查看是否有work提交，前面分析commitNewWork()时候讲解到会将一个区块信息填充执行Finalize后提交到此通道
		case work := <-self.workCh:
			self.mu.Lock()
			if self.quitCurrentOp != nil {
				close(self.quitCurrentOp)
			}
			self.quitCurrentOp = make(chan struct{})
			//开启协程执行挖矿操作,核心操作
			go self.mine(work, self.quitCurrentOp)
			self.mu.Unlock()
		case <-self.stop:
			self.mu.Lock()
			if self.quitCurrentOp != nil {
				close(self.quitCurrentOp)
				self.quitCurrentOp = nil
			}
			self.mu.Unlock()
			break out
		}
	}
	............................
}

func (self *CpuAgent) mine(work *Work, stop <-chan struct{}) {
	//实际调用ethash.Seal进行挖矿
	if result, err := self.engine.Seal(self.chain, work.Block, stop); result != nil {
		log.Info("Successfully sealed new block", "number", result.Number(), "hash", result.Hash())
		//如果挖矿有结果则推送到returnCh，交给worker.wait()处理
		self.returnCh <- &Result{work, result}
	} else {
		if err != nil {
			log.Warn("Block sealing failed", "err", err)
		}
		self.returnCh <- nil
	}
}
# go-ethereum/consensus/ethhash/sealer.go
// Seal implements consensus.Engine, attempting to find a nonce that satisfies
// the block's difficulty requirements.
func (ethash *Ethash) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	//一种测试模式
	// If we're running a fake PoW, simply return a 0 nonce immediately
	if ethash.fakeMode {
		header := block.Header()
		header.Nonce, header.MixDigest = types.BlockNonce{}, common.Hash{}
		return block.WithSeal(header), nil
	}
	//一种测试模式
	// If we're running a shared PoW, delegate sealing to it
	if ethash.shared != nil {
		return ethash.shared.Seal(chain, block, stop)
	}
	// Create a runner and the multiple search threads it directs
	//中断通道
	abort := make(chan struct{})
	//结果通道
	found := make(chan *types.Block)

	ethash.lock.Lock()
	threads := ethash.threads
	//开始为区块中的nonce做准备
	if ethash.rand == nil {
		//使用"crypto/rand"下的函数生成随机数种子
		seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
		if err != nil {
			ethash.lock.Unlock()
			return nil, err
		}
		//使用随机数种子生成随机数赋值给ethash.hash
		ethash.rand = rand.New(rand.NewSource(seed.Int64()))
	}
	ethash.lock.Unlock()
	//如果挖矿线程数为0则将线程数赋值为cpu个数
	if threads == 0 {
		threads = runtime.NumCPU()
	}
	if threads < 0 {
		threads = 0 // Allows disabling local mining without extra logic around local/remote
	}
	var pend sync.WaitGroup
	//开启数个线程同时执行挖矿
	for i := 0; i < threads; i++ {
		pend.Add(1)
		go func(id int, nonce uint64) {
			defer pend.Done()
			ethash.mine(block, id, nonce, abort, found) //调用ethash进行实际挖矿
		}(i, uint64(ethash.rand.Int63())) //将上面生成的随机数赋值给nonce做初始值
	}
	//一直在此等着上面有如下几种结果之一出现
	// Wait until sealing is terminated or a nonce is found
	var result *types.Block
	select {
	case <-stop:
		// Outside abort, stop all miner threads
		close(abort)
	case result = <-found:
		// One of the threads found a block, abort all others
		close(abort)
	case <-ethash.update:
		// Thread count was changed on user request, restart
		close(abort)
		pend.Wait()
		return ethash.Seal(chain, block, stop)
	}
	// Wait for all miners to terminate and return the block
	pend.Wait()
	return result, nil
}
//实际的挖矿函数
// mine is the actual proof-of-work miner that searches for a nonce starting from
// seed that results in correct final block difficulty.
func (ethash *Ethash) mine(block *types.Block, id int, seed uint64, abort chan struct{}, found chan *types.Block) {
	// Extract some data from the header
	var (
		header = block.Header() 
		hash   = header.HashNoNonce().Bytes() //获取commitNewWork提交来的区块头无nonce的hash
		target = new(big.Int).Div(maxUint256, header.Difficulty) //target

		number  = header.Number.Uint64()
		dataset = ethash.dataset(number) //根据区块号获取数据集，数据集又是另一个话题
	)
	// Start generating random nonces until we abort or find a good one
	var (
		//尝试次数
		attempts = int64(0)
		//nonce
		nonce    = seed
	)
	logger := log.New("miner", id)
	logger.Trace("Started ethash search for new nonces", "seed", seed)
	for {
		select {
		case <-abort:
			// Mining terminated, update stats and abort
			logger.Trace("Ethash nonce search aborted", "attempts", nonce-seed)
			ethash.hashrate.Mark(attempts)
			return

		default:
			// We don't have to update hash rate on every nonce, so update after after 2^X nonces
			attempts++
			//当尝试测试达到2的15次方时候，做一次标记，并从头开始
			if (attempts % (1 << 15)) == 0 {
				ethash.hashrate.Mark(attempts)
				attempts = 0
			}
			// Compute the PoW value of this nonce
			//下面就是主要计算符合挖矿条件的函数
			digest, result := hashimotoFull(dataset, hash, nonce)
			//如果计算结果比目标值小，那么就算挖矿成功
			if new(big.Int).SetBytes(result).Cmp(target) <= 0 {
				// Correct nonce found, create a new header with it
				//拷贝区块头
				header = types.CopyHeader(header)
				//给区块头填充nonce值
				header.Nonce = types.EncodeNonce(nonce)
				//给区块mixHash字段填充值，为了验证做准备
				header.MixDigest = common.BytesToHash(digest)

				// Seal and return a block (if still needed)
				select {
				//将组装的block推送到found通道，其实最终交由worker.wait()处理
				case found <- block.WithSeal(header):
					logger.Trace("Ethash nonce found and reported", "attempts", nonce-seed, "nonce", nonce)
				case <-abort:
					logger.Trace("Ethash nonce found but discarded", "attempts", nonce-seed, "nonce", nonce)
				}
				return
			}
			//nonce在初始化以后每次都会自增一后重新尝试
			nonce++
		}
	}
}
//最后分析一下Miner.New的最后一个方法
// update keeps track of the downloader events. Please be aware that this is a one shot type of update loop.
// It's entered once and as soon as `Done` or `Failed` has been broadcasted the events are unregistered and
// the loop is exited. This to prevent a major security vuln where external parties can DOS you with blocks
// and halt your mining operation for as long as the DOS continues.
func (self *Miner) update() {
	//订阅download下的事件
	events := self.mux.Subscribe(downloader.StartEvent{}, downloader.DoneEvent{}, downloader.FailedEvent{})
out:
	for ev := range events.Chan() {
		switch ev.Data.(type) {
		//如果downloader开始事件
		case downloader.StartEvent:
			//一个downloader开始，意味着需要去别的节点主动下载一些数据，那么理论上跟本地挖矿是冲突的，所以当一个downloader开始时候  将停止自己的挖矿
			atomic.StoreInt32(&self.canStart, 0)
			if self.Mining() {
				self.Stop()
				atomic.StoreInt32(&self.shouldStart, 1)
				log.Info("Mining aborted due to sync")
			}
			//如果downloader 完成事件，失败事件  都会在此开启挖矿
		case downloader.DoneEvent, downloader.FailedEvent:
			shouldStart := atomic.LoadInt32(&self.shouldStart) == 1

			atomic.StoreInt32(&self.canStart, 1)
			atomic.StoreInt32(&self.shouldStart, 0)
			if shouldStart {
				self.Start(self.coinbase)
			}
			// unsubscribe. we're only interested in this event once
			events.Unsubscribe()
			// stop immediately and ignore all further pending events
			break out
		}
	}
}
```

简单总结一下：

挖矿简单来讲就是找到符合如下公式的一个nonce

​							rand(n,h)=M/D  (n:nonce , h:headerHashNoNonce, M:uint256Max,D:Diffculty)

​		首先挖矿结构体（Miner）组合了一个worker ，在New Miner时候会先去NewWorker，NewWorker的时候会订阅相关事件，并且开启两个主要线程 `go worker.update()` 和`go worker.wait()` ，前一个主要遍历事件做出相应动作 ，commitNewWork()将一个新的区块的header填充好，交易执行完成，奖励发送到相应矿工和挖出叔块的地址后将结果封装为一个work提交给注册的实际的“矿工”，例如CpuAgent进行“挖矿”操作，CpuAgent拿到work以后开始调用共识引擎（ethash）的Seal(对外,mine对内)进行共识计算，计算找到一个合适的nonce 时候将结果提交到一个结果通道，此时worker.wait()开始拿到结果进行实际插入到blockchain，并进行事件广播。

​	   以上就是挖矿部分的流程分析，具体的计算函数hashimotoFull()本次不做展开，待下次记录。

此文档初稿:2019.06.03 17:00 随后迭代修改
