### Downloader源码分析

##### 1、介绍

​		`downloader`是以太坊中信息同步的主要模块，每10s选择自身所连接的节点中与`totalDiffculty`最大的一个节点进行同步，或者有新节点加入时候从新节点同步数据。

##### 2、源码分析

​		节点中最常使用`downloader`模块的是`ProtocolManage`的同步线程`pm.syncer()`，其每10s强制进行一次同步循环，或者新节点触发其执行同步循环。

```java
// syncer is responsible for periodically synchronising with the network, both
// downloading hashes and blocks as well as handling the announcement handler.
func (pm *ProtocolManager) syncer() {
	// Start and ensure cleanup of sync mechanisms
	pm.fetcher.Start()
	defer pm.fetcher.Stop()
	defer pm.downloader.Terminate()
	// forceSyncCycle = 10s
	// Wait for different events to fire synchronisation operations
	forceSync := time.NewTicker(forceSyncCycle)
	defer forceSync.Stop()

	for {
		select {
		case <-pm.newPeerCh:
			// Make sure we have peers to select from, then sync
			if pm.peers.Len() < minDesiredPeerCount {
				break
			}
			go pm.synchronise(pm.peers.BestPeer())

		case <-forceSync.C:
			// Force a sync even if not enough peers are present
			go pm.synchronise(pm.peers.BestPeer())

		case <-pm.noMorePeers:
			return
		}
	}
}
```

以上是`syncer()`方法，其又调用方法`pm.synchronise(pm.peers.BestPeer())`

```java
// synchronise tries to sync up our local block chain with a remote peer.
func (pm *ProtocolManager) synchronise(peer *peer) {
	// Short circuit if no peers are available
	if peer == nil {
		return
	}
	// Make sure the peer's TD is higher than our own
	currentBlock := pm.blockchain.CurrentBlock()
	td := pm.blockchain.GetTd(currentBlock.Hash(), currentBlock.NumberU64())

	pHead, pTd := peer.Head()
	if pTd.Cmp(td) <= 0 {
		return
	}
	// Otherwise try to sync with the downloader
	mode := downloader.FullSync
	if atomic.LoadUint32(&pm.fastSync) == 1 {
		// Fast sync was explicitly requested, and explicitly granted
		mode = downloader.FastSync
	} else if currentBlock.NumberU64() == 0 && pm.blockchain.CurrentFastBlock().NumberU64() > 0 {
		// The database seems empty as the current block is the genesis. Yet the fast
		// block is ahead, so fast sync was enabled for this node at a certain point.
		// The only scenario where this can happen is if the user manually (or via a
		// bad block) rolled back a fast sync node below the sync point. In this case
		// however it's safe to reenable fast sync.
		atomic.StoreUint32(&pm.fastSync, 1)
		mode = downloader.FastSync
	}
	// 如果快速同步模式下，本地链快速区块的难度值大于远程节点，那么直接返回
	if mode == downloader.FastSync {
		// Make sure the peer's total difficulty we are synchronizing is higher.
		if pm.blockchain.GetTdByHash(pm.blockchain.CurrentFastBlock().Hash()).Cmp(pTd) >= 0 {
			return
		}
	}

	// Run the sync cycle, and disable fast sync if we've went past the pivot block
	if err := pm.downloader.Synchronise(peer.id, pHead, pTd, mode); err != nil {
		return
	}
	if atomic.LoadUint32(&pm.fastSync) == 1 {
		log.Info("Fast sync complete, auto disabling")
		atomic.StoreUint32(&pm.fastSync, 0)
	}
	atomic.StoreUint32(&pm.acceptTxs, 1) // Mark initial sync done
	if head := pm.blockchain.CurrentBlock(); head.NumberU64() > 0 {
		// We've completed a sync cycle, notify all peers of new state. This path is
		// essential in star-topology networks where a gateway node needs to notify
		// all its out-of-date peers of the availability of a new block. This failure
		// scenario will most often crop up in private and hackathon networks with
		// degenerate connectivity, but it should be healthy for the mainnet too to
		// more reliably update peers or the local TD state.
		go pm.BroadcastBlock(head, false)
	}
}
```

`pm.synchronise()`方法获取本地区块链的td值，若大于远程节点则本方法简单返回，若小于则说明远程节点数据比本地节点数据更新，则确定同步方式以后调用 `pm.downloader.Synchronise(peer.id, pHead, pTd, mode)`方法，这个方法是实际downloader模块的开始。

```java
// Synchronise tries to sync up our local block chain with a remote peer, both
// adding various sanity checks as well as wrapping it with various log entries.
func (d *Downloader) Synchronise(id string, head common.Hash, td *big.Int, mode SyncMode) error {
	err := d.synchronise(id, head, td, mode)
	..................................
}
// synchronise will select the peer and use it for synchronising. If an empty string is given
// it will use the best peer possible and synchronize if its TD is higher than our own. If any of the
// checks fail an error will be returned. This method is synchronous
func (d *Downloader) synchronise(id string, hash common.Hash, td *big.Int, mode SyncMode) error {
	// Mock out the synchronisation if testing
	if d.synchroniseMock != nil {
		return d.synchroniseMock(id, hash)
	}
	// Make sure only one goroutine is ever allowed past this point at once
	if !atomic.CompareAndSwapInt32(&d.synchronising, 0, 1) {
		return errBusy
	}
	defer atomic.StoreInt32(&d.synchronising, 0)

	// Post a user notification of the sync (only once per session)
	if atomic.CompareAndSwapInt32(&d.notified, 0, 1) {
		log.Info("Block synchronisation started")
	}
	// Reset the queue, peer set and wake channels to clean any internal leftover state
	d.queue.Reset()
	// 遍历peerSet逐个调用peer.set()
	d.peers.Reset()
	// 清空相关通道数据--------------------------------------
	for _, ch := range []chan bool{d.bodyWakeCh, d.receiptWakeCh} {
		select {
		case <-ch:
		default:
		}
	}
	for _, ch := range []chan dataPack{d.headerCh, d.bodyCh, d.receiptCh} {
		for empty := false; !empty; {
			select {
			case <-ch:
			default:
				empty = true
			}
		}
	}
	for empty := false; !empty; {
		select {
		case <-d.headerProcCh:
		default:
			empty = true
		}
	}
	// 清空相关通道数据--------------------------------------
	// Create cancel channel for aborting mid-flight and mark the master peer
	d.cancelLock.Lock()
	d.cancelCh = make(chan struct{})
	d.cancelPeer = id
	d.cancelLock.Unlock()

	defer d.Cancel() // No matter what, we can't leave the cancel channel open

	// Set the requested sync mode, unless it's forbidden
	d.mode = mode

	// Retrieve the origin peer and initiate the downloading process
	p := d.peers.Peer(id)
	if p == nil {
		return errUnknownPeer
	}
	return d.syncWithPeer(p, hash, td)
}
```

以上方法是downloader模块中的方法，实际做了同步前准备工作，主要有如下几件事：

​	1、修改同步状态，确保只有一个同步线程在运行`atomic.CompareAndSwapInt32(&d.synchronising, 0, 1)`

​	2、调用`d.queue.Reset()` 、`d.peers.Reset()` 将相关数据清空，待本次同步使用

​	3、最后调用`d.syncWithPeer(p, hash, td)` 与远程节点进行同步

```java
// syncWithPeer starts a block synchronization based on the hash chain from the
// specified peer and head hash.
func (d *Downloader) syncWithPeer(p *peerConnection, hash common.Hash, td *big.Int) (err error) {
    // 发出同步开始事件，通知相关模块停止工作（如挖矿模块）
	d.mux.Post(StartEvent{})
	defer func() {
		// reset on error
		if err != nil {
			d.mux.Post(FailedEvent{err})
		} else {
			d.mux.Post(DoneEvent{})
		}
	}()
	if p.version < 62 {
		return errTooOld
	}

	log.Debug("Synchronising with the network", "peer", p.id, "eth", p.version, "head", hash, "td", td, "mode", d.mode)
	defer func(start time.Time) {
		log.Debug("Synchronisation terminated", "elapsed", time.Since(start))
	}(time.Now())
	// 向远程节点发送请求返回对方最新区块的区块头消息
	// Look up the sync boundaries: the common ancestor and the target block
	latest, err := d.fetchHeight(p)
	if err != nil {
		return err
	}
	// 对方peer区块高度
	height := latest.Number.Uint64()
	// 寻找公共祖先
	origin, err := d.findAncestor(p, latest)
	if err != nil {
		return err
	}
	d.syncStatsLock.Lock()
	if d.syncStatsChainHeight <= origin || d.syncStatsChainOrigin > origin {
		d.syncStatsChainOrigin = origin
	}
	d.syncStatsChainHeight = height
	d.syncStatsLock.Unlock()

	// Ensure our origin point is below any fast sync pivot point
	// fsMinFullBlocks = 64
	pivot := uint64(0)
	if d.mode == FastSync {
		if height <= uint64(fsMinFullBlocks) {
			origin = 0
		} else {
			pivot = height - uint64(fsMinFullBlocks)
			if pivot <= origin {
				origin = pivot - 1
			}
		}
	}
	d.committed = 1
	if d.mode == FastSync && pivot != 0 {
		d.committed = 0
	}
	// Initiate the sync using a concurrent header and content retrieval algorithm
	d.queue.Prepare(origin+1, d.mode)
	if d.syncInitHook != nil {
		d.syncInitHook(origin, height)
	}

	fetchers := []func() error{
		func() error { return d.fetchHeaders(p, origin+1, pivot) }, // Headers are always retrieved
		func() error { return d.fetchBodies(origin + 1) },          // Bodies are retrieved during normal and fast sync
		func() error { return d.fetchReceipts(origin + 1) },        // Receipts are retrieved during fast sync
		func() error { return d.processHeaders(origin+1, pivot, td) },
	}
	if d.mode == FastSync {
		fetchers = append(fetchers, func() error { return d.processFastSyncContent(latest) })
	} else if d.mode == FullSync {
		fetchers = append(fetchers, d.processFullSyncContent)
	}
	return d.spawnSync(fetchers)
}
```

上述方法主要执行以下几个步骤：

​	1、广播同步开始事件，让相关的动作停止(如挖矿)

​	2、调用` d.findAncestor(p, latest)`查找本地节点和远程节点的共同祖先

​	3、开始逐个执行 [d.fetchHeaders(p, origin+1, pivot)，d.fetchBodies(origin + 1)，d.fetchReceipts(origin + 1)，d.processHeaders(origin+1, pivot, td)]+d.processFastSyncContent(latest) or d.processFullSyncContent 方法，方法流转图如下：

​			![downloader](C:\Users\Administrator\Desktop\Downloader\downloader.png)

​		下面逐个介绍[d.fetchHeaders(p, origin+1, pivot)，d.fetchBodies(origin + 1)，d.fetchReceipts(origin + 1)，d.processHeaders(origin+1, pivot, td)]+d.processFastSyncContent(latest) or d.processFullSyncContent 方法

###### d.fetcherHeaders

首先看下getHeaders方法如何定义

```java
getHeaders := func(from uint64) {
	request = time.Now()
	ttl = d.requestTTL()
	timeout.Reset(ttl)
	if skeleton {
		p.log.Trace("Fetching skeleton headers", "count", MaxHeaderFetch, "from", from)
		// MaxSkeletonSize = 128 MaxHeaderFetch  = 192
		go p.peer.RequestHeadersByNumber(from+uint64(MaxHeaderFetch)-1, MaxSkeletonSize, MaxHeaderFetch-1, false)
	} else {
		p.log.Trace("Fetching full headers", "count", MaxHeaderFetch, "from", from)
		go p.peer.RequestHeadersByNumber(from, MaxHeaderFetch, 0, false)
	}
}
// Start pulling the header chain skeleton until all is done
getHeaders(from)
```

getHeaders方法有两种请求区块头的方法，若skeleton为true（默认值）的时候，将先请求区块头骨架，从from+191块开始，每隔192个获取一个区块头，总共获取128区块头。若skeleton为false，那从From开始获取192和区块头

```java
for {
	select {
	case <-d.cancelCh:
		return errCancelHeaderFetch

	case packet := <-d.headerCh:
		// Make sure the active peer is giving us the skeleton headers
		if packet.PeerId() != p.id {
			log.Debug("Received skeleton from incorrect peer", "peer", packet.PeerId())
			break
		}
		headerReqTimer.UpdateSince(request)
		timeout.Stop()

		// If the skeleton's finished, pull any remaining head headers directly from the origin
		if packet.Items() == 0 && skeleton {
			skeleton = false
			getHeaders(from)
			continue
		}
		// If no more headers are inbound, notify the content fetchers and return
		if packet.Items() == 0 {
			// Don't abort header fetches while the pivot is downloading
			if atomic.LoadInt32(&d.committed) == 0 && pivot <= from {
				p.log.Debug("No headers, waiting for pivot commit")
				select {
				//fsHeaderContCheck      = 3 * time.Second
				case <-time.After(fsHeaderContCheck):
					getHeaders(from)
					continue
				case <-d.cancelCh:
					return errCancelHeaderFetch
				}
			}
			// Pivot done (or not in fast sync) and no more headers, terminate the process
			p.log.Debug("No more headers available")
			select {
			case d.headerProcCh <- nil:
				return nil
			case <-d.cancelCh:
				return errCancelHeaderFetch
			}
		}
		headers := packet.(*headerPack).headers

		// If we received a skeleton batch, resolve internals concurrently
		if skeleton {
			filled, proced, err := d.fillHeaderSkeleton(from, headers)
			if err != nil {
				p.log.Debug("Skeleton chain invalid", "err", err)
				return errInvalidChain
			}
			headers = filled[proced:]
			from += uint64(proced)
		} 
        .................................................
		// Insert all the new headers and fetch the next batch
		if len(headers) > 0 {
			p.log.Trace("Scheduling new headers", "count", len(headers), "from", from)
			select {
			case d.headerProcCh <- headers:
			case <-d.cancelCh:
				return errCancelHeaderFetch
			}
			from += uint64(len(headers))
			getHeaders(from)
		}
        ................................................
}
```

以上方法获取getHeaders的结果进行处理，主要逻辑如下：

​		1、首先如果packet.Items() == 0，则表明skeleton已经完成，将skeleton设置为false，将剩余的headers按顺序获取；
​		2、如果收到了一个skeleton，则调用d.fillHeaderSkeleton(from, headers)从其他节点下载headers进行填充；
​		3、填充完毕后，将headers写入channel headerProcCh（下面的处理headers中处理），同时把from赋值为新的from，然后进行下一批headers的获取。

```java
func (d *Downloader) processHeaders(origin uint64, pivot uint64, td *big.Int) error {
    	..............................................
	case headers := <-d.headerProcCh:
		// Terminate header processing if we synced up
		if len(headers) == 0 {
			// Notify everyone that headers are fully processed
			for _, ch := range []chan bool{d.bodyWakeCh, d.receiptWakeCh} {
				select {
				case ch <- false:
				case <-d.cancelCh:
				}
			}
			// If no headers were retrieved at all, the peer violated(违反) its TD promise that it had a
			// better chain compared to ours. The only exception is if its promised blocks were
			// already imported by other means (e.g. fetcher):
			//
			// R <remote peer>, L <local node>: Both at block 10
			// R: Mine block 11, and propagate it to L
			// L: Queue block 11 for import
			// L: Notice that R's head and TD increased compared to ours, start sync
			// L: Import of block 11 finishes
			// L: Sync begins, and finds common ancestor at 11
			// L: Request new headers up from 11 (R's TD was higher, it must have something)
			// R: Nothing to give
			if d.mode != LightSync {
				head := d.blockchain.CurrentBlock()
				if !gotHeaders && td.Cmp(d.blockchain.GetTd(head.Hash(), head.NumberU64())) > 0 {
					return errStallingPeer
				}
			}
			// If fast or light syncing, ensure promised headers are indeed delivered. This is
			// needed to detect scenarios where an attacker feeds a bad pivot and then bails out
			// of delivering the post-pivot blocks that would flag the invalid content.
			//
			// This check cannot be executed "as is" for full imports, since blocks may still be
			// queued for processing when the header download completes. However, as long as the
			// peer gave us something useful, we're already happy/progressed (above check).
			if d.mode == FastSync || d.mode == LightSync {
				head := d.lightchain.CurrentHeader()
				if td.Cmp(d.lightchain.GetTd(head.Hash(), head.Number.Uint64())) > 0 {
					return errStallingPeer
				}
			}
			// Disable any rollback and return
			rollback = nil
			return nil
		}
		// Otherwise split the chunk of headers into batches and process them
		gotHeaders = true

		for len(headers) > 0 {
			// Terminate if something failed in between processing chunks
			select {
			case <-d.cancelCh:
				return errCancelHeaderProcessing
			default:
			}
			// Select the next chunk of headers to import
			limit := maxHeadersProcess
			if limit > len(headers) {
				limit = len(headers)
			}
			chunk := headers[:limit]

			// In case of header only syncing, validate the chunk immediately
			if d.mode == FastSync || d.mode == LightSync {
				// Collect the yet unknown headers to mark them as uncertain
				unknown := make([]*types.Header, 0, len(headers))
				for _, header := range chunk {
					if !d.lightchain.HasHeader(header.Hash(), header.Number.Uint64()) {
						unknown = append(unknown, header)
					}
				}
				// If we're importing pure headers, verify based on their recentness
				frequency := fsHeaderCheckFrequency
				if chunk[len(chunk)-1].Number.Uint64()+uint64(fsHeaderForceVerify) > pivot {
					frequency = 1
				}
				if n, err := d.lightchain.InsertHeaderChain(chunk, frequency); err != nil {
					// If some headers were inserted, add them too to the rollback list
					if n > 0 {
						rollback = append(rollback, chunk[:n]...)
					}
					log.Debug("Invalid header encountered", "number", chunk[n].Number, "hash", chunk[n].Hash(), "err", err)
					return errInvalidChain
					}
				// All verifications passed, store newly found uncertain headers
				rollback = append(rollback, unknown...)
				if len(rollback) > fsHeaderSafetyNet {
					rollback = append(rollback[:0], rollback[len(rollback)-fsHeaderSafetyNet:]...)
				}
			}
			// Unless we're doing light chains, schedule the headers for associated content retrieval
			if d.mode == FullSync || d.mode == FastSync {
				// If we've reached the allowed number of pending headers, stall a bit
				for d.queue.PendingBlocks() >= maxQueuedHeaders || d.queue.PendingReceipts() >= maxQueuedHeaders {
					select {
					case <-d.cancelCh:
						return errCancelHeaderProcessing
					case <-time.After(time.Second):
					}
				}
				// Otherwise insert the headers for content retrieval
				inserts := d.queue.Schedule(chunk, origin)
				if len(inserts) != len(chunk) {
					log.Debug("Stale headers")
					return errBadPeer
				}
			}
			headers = headers[limit:]
			origin += uint64(limit)
		}
		............................................
		}
	}
}

```

​		channel headerProcCh通道的另一端在processHeaders()中，processHeaders()从通道中取出一部分headers进行处理。
​		1、如果是fast或者light sync，每1K个header处理，调用lightchain.InsertHeaderChain()写入header到leveldb数据库
​		2、然后如果当前是fast或者full sync模式后，d.queue.Schedule(chunk, origin)赋值blockTaskPool/blockTaskQueue和receiptTaskPool/receiptTaskQueue（only fast 模式下），供后续同步body和同步receipt使用；

###### d.fetchbodies

```java
// fetchBodies iteratively downloads the scheduled block bodies, taking any
// available peers, reserving a chunk(块) of blocks for each, waiting for delivery
// and also periodically checking for timeouts.
func (d *Downloader) fetchBodies(from uint64) error {
	log.Debug("Downloading block bodies", "origin", from)

	var (
		deliver = func(packet dataPack) (int, error) {
			pack := packet.(*bodyPack)
			return d.queue.DeliverBodies(pack.peerID, pack.transactions, pack.uncles)
		}
		expire   = func() map[string]int { return d.queue.ExpireBodies(d.requestTTL()) }
		fetch    = func(p *peerConnection, req *fetchRequest) error { return p.FetchBodies(req) }
		capacity = func(p *peerConnection) int { return p.BlockCapacity(d.requestRTT()) }
		setIdle  = func(p *peerConnection, accepted int) { p.SetBodiesIdle(accepted) }
	)
	err := d.fetchParts(errCancelBodyFetch, d.bodyCh, deliver, d.bodyWakeCh, expire,
		d.queue.PendingBlocks, d.queue.InFlightBlocks, d.queue.ShouldThrottleBlocks, d.queue.ReserveBodies,
		d.bodyFetchHook, fetch, d.queue.CancelBodies, capacity, d.peers.BodyIdlePeers, setIdle, "bodies")

	log.Debug("Block body download terminated", "err", err)
	return err
}
```

fetchBodies方法中主要是调用了fetchParts()
		1、首先ReserveBodies()从bodyTaskPool中取出要同步的body；
		2、调用fetch，也就是调用这里的FetchBodies从节点获取body，发送GetBlockBodiesMsg消息；
		3、对端节点处理完成后发回消息BlockBodiesMsg，写入channel bodyCh；
		4、收到channel bodyCh的数据后，调用deliver函数，将Transactions和Uncles写入resultCache。

###### d.fetchReceipts

```java
// fetchReceipts iteratively downloads the scheduled block receipts, taking any
// available peers, reserving a chunk of receipts for each, waiting for delivery
// and also periodically checking for timeouts.
func (d *Downloader) fetchReceipts(from uint64) error {
	log.Debug("Downloading transaction receipts", "origin", from)

	var (
		deliver = func(packet dataPack) (int, error) {
		pack := packet.(*receiptPack)
		return d.queue.DeliverReceipts(pack.peerID, pack.receipts)
	}
	expire   = func() map[string]int { return d.queue.ExpireReceipts(d.requestTTL()) }
	fetch    = func(p *peerConnection, req *fetchRequest) error { return p.FetchReceipts(req) }
	capacity = func(p *peerConnection) int { return p.ReceiptCapacity(d.requestRTT()) }
	setIdle  = func(p *peerConnection, accepted int) { p.SetReceiptsIdle(accepted) }
	)
err := d.fetchParts(errCancelReceiptFetch, d.receiptCh, deliver, d.receiptWakeCh, expire,
d.queue.PendingReceipts, d.queue.InFlightReceipts, d.queue.ShouldThrottleReceipts, d.queue.ReserveReceipts,d.receiptFetchHook, fetch, d.queue.CancelReceipts, capacity, d.peers.ReceiptIdlePeers, setIdle, "receipts")

	log.Debug("Transaction receipt download terminated", "err", err)
	return err
}
```

fetchReceipts方法与fetchBodies如出一辙，也是调用了fetchParts()
		1、首先ReserveBodies()从ReceiptTaskPool中取出要同步的Receipt；
		2、调用fetch，也就是调用这里的FetchReceipts从节点获取receipts，发送GetReceiptsMsg消息；
		3、对端节点处理完成后发回消息ReceiptsMsg，写入channel receiptCh；
		4、收到channel receiptCh的数据后，调用deliver函数，将Receipts写入resultCache。

```java
func (d *Downloader) processFullSyncContent() error {
	for {
		results := d.queue.Results(true)
		if len(results) == 0 {
			return nil
		}
		if d.chainInsertHook != nil {
			d.chainInsertHook(results)
		}
		if err := d.importBlockResults(results); err != nil {
			return err
		}
	}
}
```

processFullSyncContent是fullSycn模式下的同步，因为在fullSync模式下Receipts没有缓存到resultCache中，所以这一步逻辑很简单，直接从缓存中取出body数据，然后执行交易生成状态，最后写进区块链即可。

```java
func (d *Downloader) processFastSyncContent(latest *types.Header) error {
	// Start syncing state of the reported head block. This should get us most of
	// the state of the pivot block.
	stateSync := d.syncState(latest.Root)
	defer stateSync.Cancel()
	go func() {
		if err := stateSync.Wait(); err != nil && err != errCancelStateFetch {
			d.queue.Close() // wake up Results
		}
	}()
	// Figure out the ideal pivot block. Note, that this goalpost may move if the
	// sync takes long enough for the chain head to move significantly.
	pivot := uint64(0)
	if height := latest.Number.Uint64(); height > uint64(fsMinFullBlocks) {
		pivot = height - uint64(fsMinFullBlocks)
	}
	// To cater for moving pivot points, track the pivot block and subsequently
	// accumulated download results separately.
	var (
		oldPivot *fetchResult   // Locked in pivot block, might change eventually
		oldTail  []*fetchResult // Downloaded content after the pivot
	)
	for {
		// Wait for the next batch of downloaded data to be available, and if the pivot
		// block became stale, move the goalpost
		results := d.queue.Results(oldPivot == nil) // Block if we're not monitoring pivot staleness
		if len(results) == 0 {
			// If pivot sync is done, stop
			if oldPivot == nil {
				return stateSync.Cancel()
			}
			// If sync failed, stop
			select {
			case <-d.cancelCh:
				return stateSync.Cancel()
			default:
			}
		}
		if d.chainInsertHook != nil {
			d.chainInsertHook(results)
		}
		if oldPivot != nil {
			results = append(append([]*fetchResult{oldPivot}, oldTail...), results...)
		}
		// Split around the pivot block and process the two sides via fast/full sync
		if atomic.LoadInt32(&d.committed) == 0 {
			latest = results[len(results)-1].Header
			if height := latest.Number.Uint64(); height > pivot+2*uint64(fsMinFullBlocks) {
				log.Warn("Pivot became stale, moving", "old", pivot, "new", height-uint64(fsMinFullBlocks))
				pivot = height - uint64(fsMinFullBlocks)
			}
		}
		P, beforeP, afterP := splitAroundPivot(pivot, results)
		if err := d.commitFastSyncData(beforeP, stateSync); err != nil {
			return err
		}
		if P != nil {
			// If new pivot block found, cancel old state retrieval and restart
			if oldPivot != P {
				stateSync.Cancel()

				stateSync = d.syncState(P.Header.Root)
				defer stateSync.Cancel()
				go func() {
					if err := stateSync.Wait(); err != nil && err != errCancelStateFetch {
						d.queue.Close() // wake up Results
					}
				}()
				oldPivot = P
			}
			// Wait for completion, occasionally checking for pivot staleness
			select {
			case <-stateSync.done:
				if stateSync.err != nil {
					return stateSync.err
				}
				if err := d.commitPivotBlock(P); err != nil {
					return err
				}
				oldPivot = nil

			case <-time.After(time.Second):
				oldTail = afterP
				continue
			}
		}
		// Fast sync done, pivot commit done, full import
		if err := d.importBlockResults(afterP); err != nil {
			return err
		}
	}
}
```

processFasrSyncContent是fastSync模式下的同步，由于Receipts、Transactions、Uncles都在resultCache中，逻辑上要下载收据然后还要多一步下载“状态”并检验，然后再写进区块链：

​		1、下载最新区块的状态d.syncState(lastest.Root);

​		2、从缓存中拿到去处理的数据results;

​		3、这只pivot为latestHeight - 64，调用splitAroundPivot()方法以pivot为中心，将results分为三个部分：beforeP，P，afterP；

​		4、对beforeP的部分调用commitFastSyncData，将body和receipt都写入区块链；

​		5、对P的部分更新状态信息为P block的状态，把P对应的result（包含body和receipt）调用commitPivotBlock插入本地区块链中，并调用FastSyncCommitHead记录这个pivot的hash值，存在downloader中，标记为快速同步的最后一个区块hash值；

​		6、对afterP调用d.importBlockResults，将body插入区块链，而不插入receipt。因为是最后64个区块，所以此时数据库中只有header和body，没有receipt和状态，要通过fullSync模式进行最后的同步。



以上是downloader的主要逻辑部分，还有相当多的细节代码需要大家自己去细看。