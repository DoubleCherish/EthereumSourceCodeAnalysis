#### 以太坊EtHash算法

上一节记录了PoW挖矿的逻辑算法，具体的hashimotoFull说下次做记录，那么本次源码阅读记录主要分析一下hashimotoFull()算法

首先先潜移默化灌输一下以太坊数据结构Ethash

```java
// Ethash is a consensus engine based on proot-of-work implementing the ethash
// algorithm.
type Ethash struct {
    //缓存参数
	cachedir     string // Data directory to store the verification caches
	cachesinmem  int    // Number of caches to keep in memory
	cachesondisk int    // Number of caches to keep on disk
    //磁盘参数
	dagdir       string // Data directory to store full mining datasets
	dagsinmem    int    // Number of mining datasets to keep in memory
	dagsondisk   int    // Number of mining datasets to keep on disk

	caches   map[uint64]*cache   // In memory caches to avoid regenerating too often
     //预先生成的cache
	fcache   *cache              // Pre-generated cache for the estimated future epoch
	datasets map[uint64]*dataset // In memory datasets to avoid regenerating too often
     //预先生成的数据集
	fdataset *dataset            // Pre-generated dataset for the estimated future epoch

	// Mining related fields
    // 这个就是挖矿时候nonce的初始值
	rand     *rand.Rand    // Properly seeded random source for nonces
	threads  int           // Number of threads to mine on if mining
	update   chan struct{} // Notification channel to update mining parameters
	hashrate metrics.Meter // Meter tracking the average hashrate

	// The fields below are hooks for testing
	tester    bool          // Flag whether to use a smaller test dataset
	shared    *Ethash       // Shared PoW verifier to avoid cache regeneration
	fakeMode  bool          // Flag whether to disable PoW checking
	fakeFull  bool          // Flag whether to disable all consensus rules
	fakeFail  uint64        // Block number which fails PoW check even in fake mode
	fakeDelay time.Duration // Time delay to sleep for before returning from verify

	lock sync.Mutex // Ensures thread safety for the in-memory caches and mining fields
}
```

下面主要介绍HashimotoFull()

```java
// hashimotoFull aggregates data from the full dataset (using the full in-memory
// dataset) in order to produce our final value for a particular header hash and
// nonce.
func hashimotoFull(dataset []uint32, hash []byte, nonce uint64) ([]byte, []byte) {
    //定义一个查找函数
	lookup := func(index uint32) []uint32 {
		offset := index * hashWords //hashWords 为16   Number of 32 bit ints in a hash
		return dataset[offset : offset+hashWords]
	}
    //主要再次调用了hashimoto方法
	return hashimoto(hash, nonce, uint64(len(dataset))*4, lookup)
}

# go-ethereum/consensus/ethash/algorithm.go

// hashimoto aggregates data from the full dataset in order to produce our final
// value for a particular header hash and nonce.
func hashimoto(hash []byte, nonce uint64, size uint64, lookup func(index uint32) []uint32) ([]byte, []byte) {
	//计算数据集的行数
	// Calculate the number of thoretical rows (we use one buffer nonetheless)
	rows := uint32(size / mixBytes)

	// Combine header+nonce into a 64 byte seed
	//定义一个40长度的字节切片
	seed := make([]byte, 40)
	//将hash（实际就是HeaderNoNonce().hash()）拷贝到seed  在此已经占用seed的32字节
	copy(seed, hash)
	//再将nonce放入seed的后8个字节 前面说过nonce为一个int64的数字
	binary.LittleEndian.PutUint64(seed[32:], nonce)
	//进行一次keccak512  将seed指向一个新的64字节数组
	seed = crypto.Keccak512(seed)
	//取出种子头  也就是seed前4个字节
	seedHead := binary.LittleEndian.Uint32(seed)

	// Start the mix with replicated seed
	//生成一个mix 切片，长度为 128/4 = 32
	mix := make([]uint32, mixBytes/4)
	for i := 0; i < len(mix); i++ {
		//开始给mix的每一个元素赋值，其实是拿seed不同部分的前四个字节
		//mix 的前16个元素和后16个元素值相同
		mix[i] = binary.LittleEndian.Uint32(seed[i%16*4:])
	}
	// Mix in random dataset nodes
	//创建一个临时变量，长度和mix相同
	temp := make([]uint32, len(mix))
	//循环64次   loopAccesses 常量值为64
	for i := 0; i < loopAccesses; i++ {
		/**
		fnv is an algorithm inspired by the FNV hash, which in some cases is used as
		a non-associative substitute for XOR. Note that we multiply the prime with
		the full 32-bit input, in contrast with the FNV-1 spec which multiplies the
		prime with one byte (octet) in turn.
		
		func fnv(a, b uint32) uint32 {
			return a*0x01000193 ^ b
		}

		fnvHash mixes in data into mix using the ethash fnv method.
		
		func fnvHash(mix []uint32, data []uint32) {
			for i := 0; i < len(mix); i++ {
			mix[i] = mix[i]*0x01000193 ^ data[i]
		}
	}
		*/
		parent := fnv(uint32(i)^seedHead, mix[i%len(mix)]) % rows
		//hashbytes = 64    mixbytes = 128
		for j := uint32(0); j < mixBytes/hashBytes; j++ {
			copy(temp[j*hashWords:], lookup(2*parent+j))
		}
		fnvHash(mix, temp)
	}
	//此处进行了大混合
	// Compress mix
	for i := 0; i < len(mix); i += 4 {
		mix[i/4] = fnv(fnv(fnv(mix[i], mix[i+1]), mix[i+2]), mix[i+3])
	}
	//  mix赋值为mix[:8] 前8个元素  一个4字节
	mix = mix[:len(mix)/4]
	//声明一个digest 切片  长度为32
	digest := make([]byte, common.HashLength)
	//遍历mix 8个元素 混合进digest
	for i, val := range mix {
		binary.LittleEndian.PutUint32(digest[i*4:], val)
	}
	//返回digest 和 seed（64字节）+digest所有元素  做一次keccak256后返回 ，也就是result
	return digest, crypto.Keccak256(append(seed, digest...))
}
```

以上就是hashimoto算法的具体过程，算法数据集生成待下次记录