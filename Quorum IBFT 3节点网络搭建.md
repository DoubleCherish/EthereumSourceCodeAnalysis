### Quorum IBFT 3节点网络搭建

先附加一张quorum私有交易架构图



![img](https:////upload-images.jianshu.io/upload_images/8801176-87f1b148b7e3d77d.JPG?imageMogr2/auto-orient/strip%7CimageView2/2/w/941/format/webp)

对上图的解释：

1、DAPP 将 TX 发送给PartyA的节点。节点收到 TX 后将上文提到的 privateFor 字段的值设置为包含PartyA和PartyB的public key的数组：["public_key_A", "public_key_B"]。
2、节点将 TX 发送给其对应的 Transaction Manager。
3、Transaction Manager 呼叫与其关联的 Enclave，并要求 Enclave 加密这笔 TX。
4、PartyA 的 Enclave 校验获取到的PartyA私钥，如果确认通过则进行如下动作： 
i. 生成一个密钥（symmetric key）。 
ii. 用上一步生成的symmetric key来加密 TX 的内容。 
iii. 用SHA3-512来获取加密后的TX内容的hash值。 
iv. 将 i 生成的symmetric key用第一步中的public key数组的所有值加密，然后生成一个新的数组。新的数组的每个元素都是由 i 中的symmetric key用原来数组的public key加密生成：["key_encrypted_by_publickey_A", "key_encrypted_by_publickey_B"] 
v. 将 ii 生成的加密TX，iii 生成的hash值，iv 生成的加密后的数组返回给Transaction Manager。

5、PartA的Transaction Manager会把加密后的TX以及加密后的symmetric key保存到本地，并用从 Enclave 中获取的 hash 值作为索引。另外Transaction Manager会把hash值，加密后的TX，public_key_B加密的symmetric key这三项通过HTTPS发送给PartyB的Transaction Manager。PartyB的Tx Manager收到数据后，同样将加密后的TX和symmetric key保存到本地，并用收到的hash值作为索引。处理完后，PartyB的TX manager发送一个成功的回执给PartyA的TX manager。

6、PartyA的TX Manager收到成功回执后，将hash值返回给其对应的Quorum节点。节点收到hash值后，用这个hash值来替换原来TX的交易内容。（参考 Transaction Processing 章节的第一张图 ）同时，将TX的 V 值设置为 37 或者 38。37或38就是Private Transaction的标识。其他节点查询后发现 V 的值为37或38时，就会认定其为Private Transaction。

7、TX内容被替换后，TX就和Pbulic Transaction一样被节点通过P2P方式广播给整个网络。

8、这条TX被某个区块收录到区块信息中。

9、节点收到带这个TX的区块后，发现这个TX的 V 值为37或38。然后这个TX就被认定为Private Transaction，并将此TX的内容（也就是替换后的hash值）传给节点对应的Transaction Manager。

10、因为PartyC的节点不在这个Private TX的范围内，所以其TX Manager无法在本地通过这个hash值找到对应的TX内容和symmetric key。然后TX Manager就会返回其节点一个 NotARecipient 回执。PartyC的节点收到这个回执后就不会更新其本地的Private State。对于PartyB的节点，其TX Manager通过这个hash值找到了本地存储的TX内容和symmetric key，但是由于这两个东西是被加密存储的，所以TX Manager将TX内容和symmetric key发送给其对应的 Enclave 进行解密。

11、PartyB的Enclave收到TX Manger发来的数据后，用PartyB的私钥Private Key来解密symmetric key。然后用解密后的symmetric key来解密TX的内容。解密完成后将正确的TX内容返回给TX Manager。

12、TX Manager收到解密的TX后通过EVM执行TX里面的内容。执行完成后将执行结果返回给Quorum节点，并更新Quorum节点的Private State。



根据Quorum的架构，我们创建三个node和三个transaction manager的网络，每个node和每个transaction manager都需要有自己的data目录，因此我们的目录结构规划如下:

```
/opt/dev/testnet/data   --数据文件根目录
|_node1                      
|     |_dd      --node1数据目录
|     |  |_geth
|     |  |_keystore
|     |_tm      --transaction manager1数据目录
|_node2
|     |_dd      --node2数据目录
|     |  |_geth
|     |  |_keystore
|     |_tm      --transaction manager2数据目录
|_node3
      |_dd      --node3数据目录
      |  |_geth
      |  |_keystore
      |_tm      --transaction manager3数据目录
```

创建脚本:

```
mkdir -p /opt/dev/quorum/testnet/data 
cd /opt/dev/quorum/testnet/data
mkdir -p node1/dd/geth/
mkdir -p node1/dd/keystore/
mkdir -p node1/tm
mkdir -p node2/dd/geth/
mkdir -p node2/dd/keystore/
mkdir -p node2/tm
mkdir -p node3/dd/geth/
mkdir -p node3/dd/keystore/
mkdir -p node3/tm
```

端口的规划如下

```
#node端口
32001~32003       --rpc服务端口
31001~31003       --node间peer通信端口
50401~50403       --raft协议端口

#transaction manager 端口
9101~9104         --tx manager间通信端口
9181~9184         --服务端口
```

### 二、创建账户Account

不同于Hyperledger Fabric拥有MSP组件可以创建管理组织以及证书，以太坊是完全基于公链设计的，并不具备这种PKI的集中管理的机制，Quorum对此并无任何改造和增强，因此account的生成完全是可以离线操作的，而账户的本质其实就是一个椭圆曲线的私钥。本文之所以要预先准备账户是为了在之后的node console中方便的使用web3的api, 因为有些api是要求节点中配置账户信息的。

本文使用的Quorum版本是[V2.2.3](https://links.jianshu.com/go?to=https%3A%2F%2Fgithub.com%2Fjpmorganchase%2Fquorum%2Freleases)
 ),请自行下载解压出geth可执行文件，创建账户的命令如下, 提示输入密码的时候可以直接回车不进行设置:

```
\>geth --datadir=/opt/dev/quorum/testnet/data/node1/dd/ account new
\>geth --datadir=/opt/dev/quorum/testnet/data/node2/dd/ account new
\>geth --datadir=/opt/dev/quorum/testnet/data/node3/dd/ account new
```

在datadir路径keystore下会生成用户私钥文件，打开其中一个查看：

```
\>ll /opt/dev/quorum/testnet/data/node1/dd/keystore
-rw------- 1 root root  491 Apr 24 16:19 UTC--2019-04-24T08-19-29.095420057Z--9affedff10f7229c680819d5eeb12c3624f6baeb

\>more /opt/dev/quorum/testnet/data/node1/dd/keystore/UTC--2019-04-24T08-19-29.095420057Z--9affedff10f7229c680819d5eeb12c3624f6baeb
{"address":"9affedff10f7229c680819d5eeb12c3624f6baeb","crypto":{"cipher":"aes-128-ctr","ciphertext":"18e7b1d213c913524e0ba16025e3bd99bcff2e9dd572874b2ffb4d55bc4cb2dd"
,"cipherparams":{"iv":"b8f2a0e7347f47d21c8181d49f639a67"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"c0933ccaa243e91789696127f0bc9c4268aed0
5a0dc2c8da8cc053faac516b28"},"mac":"119ce5ab369c2dc5e1ee07f814ebd6d83f9eeb04a94336e8da873edb9d904ae8"},"id":"40458a80-fb2e-47cd-84ee-b8d42c37ca1b","version":3}
```

json中的address即为账户地址:9affedff10f7229c680819d5eeb12c3624f6baeb.刚才的命令生成的三个账户地址如下:

```
账户1: 9affedff10f7229c680819d5eeb12c3624f6baeb
账户2: 5c8822ab6af840f8c3e52fe9a71c43f90672728e
账户3: 915779c113cffecac6583310d80a8def09546272
```

### 三、创建nodekey

nodekey是node的唯一标识，需要配置在node数据文件路径中，以太坊nodekey生成的标准命令是使用bootnode --genkey=nodekey命令，但若使用IBFT共识的话，对nodekey是有严格要求的, validator id是根据nodekey生成的，所以如果选用IBFT共识我们就需要使用istanbul-tool来生成nodekey。istanbul-tool需要从[git](https://links.jianshu.com/go?to=https%3A%2F%2Fgithub.com%2Fgetamis%2FIstanbul-tools)
 )上clone，自行构建出istanbul命令，然后在一个临时目录/opt/dev/quorum/testnet/tmp中执行:

```
\>mkdir -p /opt/dev/quorum/testnet/tmp/
\>cd /opt/dev/quorum/testnet/tmp/

\>istanbul setup --num 3 --nodes --quorum --save --verbose

\>ll
drwxr-xr-x 2 root root 4096 Apr 25 16:22 0/
drwxr-xr-x 2 root root 4096 Apr 25 16:22 1/
drwxr-xr-x 2 root root 4096 Apr 25 16:22 2/
-rwxr-xr-x 1 root root 1524 Apr 25 16:22 genesis.json*
-rwxr-xr-x 1 root root  500 Apr 25 16:22 static-nodes.json*
```

根据我们的参数--num 3，命令将创建3个nodekey, 打开其中一个可以看到:

```
\>more 0/nodekey
c3828ef20a55925c60587f63359798249fb8c20992ef68ce9d0ff10abfd8c858
```

手动将三个nodekey文件分别拷贝到相应node的数据路径

```
cp 0/nodekey /opt/dev/quorum/testnet/data/node1/dd/geth/nodekey
cp 1/nodekey /opt/dev/quorum/testnet/data/node2/dd/geth/nodekey
cp 2/nodekey /opt/dev/quorum/testnet/data/node3/dd/geth/nodekey
```

### 四、static-nodes.json, permissioned-nodes.json文件

Quorum 联盟链的node是有准入限制的，体现在permissioned-nodes.json文件中，permissioned-nodes.json同时可以用作静态节点配置，所以在本例中static-nodes.json, permissioned-nodes.json两个文件是相同的:
 首先打开我们使用istanbul命令创建的static-nodes.json文件

```
\>vim /opt/dev/quorum/testnet/tmp/static-nodes.json
```

根据我们之前的端口规划，修改端口如下:

```
[
"enode://f3c5520a8bea82dcbf28412e61c0f225fc8c5dbd9e729529b91d3755def5583b761bf94d11c434659dd4f8ffba696a1258cb8a8ce8e5ba25c2d3f25a965375a2@127.0.0.1:31001?discport=0&raftport=50401",
"enode://926c705394776e3fe25d79f9e290444a424ffcd3855fb212af049abb80d658a59f3f5843876d587f33419e262b96d60a14c914c6076312e7e9af8c93e36f9c3b@127.0.0.1:31002?discport=0&raftport=50402",
"enode://8a6690de0099da4fbba4eb741f875b15b1adc823149d85302cddeaf5c0c77e504b78fe23e93ce199fdb1c0959954c95031d0959c861fb2ce6ecfac50a49768d0@127.0.0.1:31003?discport=0&raftport=50403"
]
```

然后将文件配置到相应的node路径中:

```
cp /opt/dev/quorum/testnet/tmp/static-nodes.json  /opt/dev/quorum/testnet/data/node1/dd/static-nodes.json
cp /opt/dev/quorum/testnet/tmp/static-nodes.json  /opt/dev/quorum/testnet/data/node1/dd/permissioned-nodes.json
cp /opt/dev/quorum/testnet/tmp/static-nodes.json  /opt/dev/quorum/testnet/data/node2/dd/static-nodes.json
cp /opt/dev/quorum/testnet/tmp/static-nodes.json  /opt/dev/quorum/testnet/data/node2/dd/permissioned-nodes.json
cp /opt/dev/quorum/testnet/tmp/static-nodes.json  /opt/dev/quorum/testnet/data/node3/dd/static-nodes.json
cp /opt/dev/quorum/testnet/tmp/static-nodes.json  /opt/dev/quorum/testnet/data/node3/dd/permissioned-nodes.json
```

### 五、创建创世文件genesis.json并初始化区块链

可以使用之前istanbul命令生成的genesis.json

```
\>vim /opt/dev/quorum/testnet/tmp/genesis.json
```

内容修改如下:

```
{
    "alloc": {
      "0x9affedff10f7229c680819d5eeb12c3624f6baeb": {
        "balance": "1000000000000000000000000000"
      },
      "0x5c8822ab6af840f8c3e52fe9a71c43f90672728e": {
        "balance": "1000000000000000000000000000"
      },
      "0x915779c113cffecac6583310d80a8def09546272": {
        "balance": "1000000000000000000000000000"
      }
    },
    "coinbase": "0x0000000000000000000000000000000000000000",
    "config": {
      "homesteadBlock": 0,
      "byzantiumBlock": 0,
      "chainId": 10,
      "eip150Block": 0,
      "eip150Hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "eip155Block": 0,
      "eip158Block": 0,
      "isQuorum": true,
      "istanbul": {
        "epoch": 30000,
        "policy": 0
      }
    },
    "extraData": "0x0000000000000000000000000000000000000000000000000000000000000000f885f83f9490ccaba53ed0c2979d4659692ca3b0ecc385fd7094a02f4bb093989222608d25c6c57a5b40526f679694f0fa966e6efa633080d1603e7daea5176de87d82b8410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0",
    "gasLimit": "0xE0000000",
    "difficulty": "0x1",
    "mixHash": "0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365",
    "nonce": "0x0",
    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "timestamp": "0x00"
}
```

解释一下修改了哪些地方，其实就是把alloc部分的account换成了我们刚才生成的account, 并修改了我们希望的预置balance余额，对于quorum来说balance没什么用处，初始化一个较大的值即可。istanbul命令已经帮我们配置了"isQuorum"以及"istanbul"的属性，不必我们再去设置:

```
{
      "isQuorum": true,
      "istanbul": {
        "epoch": 30000,
        "policy": 0
      }
}
```

另外着重说一下"extraData"这个属性：

```
{
"extraData": "0x0000000000000000000000000000000000000000000000000000000000000000f885f83f9490ccaba53ed0c2979d4659692ca3b0ecc385fd7094a02f4bb093989222608d25c6c57a5b40526f679694f0fa966e6efa633080d1603e7daea5176de87d82b8410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0"
}
```

这个属性的值是istanbul工具将合法的validator编码而成的二进制字段，我们可以使用istanbul命令来解码看一下:

```
\>istanbul extra decode --extradata 0x0000000000000000000000000000000000000000000000000000000000000000f885f83f9490ccaba53ed0c2979d4659692ca3b0ecc385fd7094a02f4bb093989222608d25c6c57a5b40526f679694f0fa966e6efa633080d1603e7daea5176de87d82b8410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0
vanity:  0x0000000000000000000000000000000000000000000000000000000000000000
validator:  0x90ccABA53ed0C2979D4659692CA3B0EcC385FD70
validator:  0xA02f4bB093989222608D25C6C57a5B40526F6796
validator:  0xF0FA966E6EfA633080d1603E7dAea5176De87d82
seal: 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

可以看到解码出来三个validator，这里需要特别注意的是，这三个validator并不是account，而是从三个nodekey生成的id，也就是说三个node在进行共识投票的时候，跟node上配置的account是无关的。很多人把这个validator理解成了account，将account id用istanbul工具编码后配置到了genesis.json的extraData字段中，这样做的话，实际的共识发起者是根据nodekey生成的validator, 区块打包共识的时候发现发起者并不在extraData编码的validators列表中，则为非法发起者，导致无法成功达成共识。

然后使用genesis.json初始化三个node节点

```
\>geth --datadir /opt/dev/quorum/testnet/data/node1/dd init /opt/dev/quorum/testnet/tmp/genesis.json
\>geth --datadir /opt/dev/quorum/testnet/data/node2/dd init /opt/dev/quorum/testnet/tmp/genesis.json
\>geth --datadir /opt/dev/quorum/testnet/data/node3/dd init /opt/dev/quorum/testnet/tmp/genesis.json
```

### 六、配置transaction manager

## 1、创建秘钥对

首先下载或自行编译,  图省事可以docker pull quorumengineering/tessera:0.9, 然后启动一个容器，从容器的/tessera/tessera-app.jar 位置拷贝到宿主机/opt/dev/quorum/testnet/tmp/tessera-app-0.9.jar，然后执行如下命令，遇到弹出输入密码时同样可以直接回车：

```
\>cd /opt/dev/quorum/testnet/tmp

\>alias tessera="java -jar /opt/dev/quorum/testnet/tmp/tessera-app-0.9.jar"

\>tessera -keygen -filename 1
\>tessera -keygen -filename 2
\>tessera -keygen -filename 3

\>ll
-rw-r--r-- 1 root root  109 Apr 25 11:38 1.key
-rw-r--r-- 1 root root   44 Apr 25 11:38 1.pub
-rw-r--r-- 1 root root  109 Apr 25 11:38 2.key
-rw-r--r-- 1 root root   44 Apr 25 11:38 2.pub
-rw-r--r-- 1 root root  109 Apr 25 11:38 3.key
-rw-r--r-- 1 root root   44 Apr 25 11:38 3.pub
```

会生成三对秘钥对:
 1.key

```
{
   "type" : "unlocked",
   "data" : {
      "bytes" : "oBQw7B/TivaynIT9SQTx5Ni1jNV1M5s/J6+1r7KlCJ8="
   }
}
```

1.pub

```
NPaOkPjlF3WFgA1WaqtANE0tqX/M8Rdr1h4SzQX0ghQ=
```

2.key

```
{
   "type" : "unlocked",
   "data" : {
      "bytes" : "/FAEF3msNOcWNkLkzUdSdNLFvFSJgddjwV2HOWTV/Rk="
   }
}
```

2.pub

```
T8olcFvm2JojQd616k1MIx/Gm2IEZPkyV4GutVvrPgM=
```

3.key

```
{
   "type" : "unlocked",
   "data" : {
      "bytes" : "ZR00hvY4nCiG8sWQFasKvwGtOBi0b2oxNriVdMN++MY="
   }
}
```

3.pub

```
Uc952L7QFuk8R5sGtjpfHb9EM+X6pTFRixVa+XgPBjc=
```

创建三个tessera.json配置文件，将下面文件中的keyData改为你自己的:
 tessera-1.json

```
    {
      "useWhiteList": false,
      "jdbc": {
        "username": "sa",
        "password": "",
        "url": "jdbc:h2:/opt/dev/quorum/testnet/data/node1/tm/db;MODE=Oracle;TRACE_LEVEL_SYSTEM_OUT=0",
        "autoCreateTables": true
      },
      "serverConfigs":[
      {
        "app":"ThirdParty",
        "enabled": true,
        "serverAddress": "http://127.0.0.1:9181",
        "communicationType" : "REST"
      },
      {
        "app":"Q2T",
        "enabled": true,
        "serverAddress": "unix:/opt/dev/quorum/testnet/data/node1/tm/tm.ipc",
        "communicationType" : "REST"
      },
      {
        "app":"P2P",
        "enabled": true,
        "serverAddress": "http://127.0.0.1:9101",
        "sslConfig": {
          "tls": "OFF",
          "generateKeyStoreIfNotExisted": true,
          "serverKeyStore": "/opt/dev/quorum/testnet/data/node1/tm/server-keystore",
          "serverKeyStorePassword": "quorum",
          "serverTrustStore": "/opt/dev/quorum/testnet/data/node1/tm/server-truststore",
          "serverTrustStorePassword": "quorum",
          "serverTrustMode": "TOFU",
          "knownClientsFile": "/opt/dev/quorum/testnet/data/node1/tm/knownClients",
          "clientKeyStore": "/opt/dev/quorum/testnet/data/node1/tm/client-keystore",
          "clientKeyStorePassword": "quorum",
          "clientTrustStore": "/opt/dev/quorum/testnet/data/node1/tm/client-truststore",
          "clientTrustStorePassword": "quorum",
          "clientTrustMode": "TOFU",
          "knownServersFile": "/opt/dev/quorum/testnet/data/node1/tm/knownServers"
        },
        "communicationType" : "REST"
      }
      ],
      "peer": [
         {
             "url": "http://127.0.0.1:9101"
         },
         {
             "url": "http://127.0.0.1:9102"
         },
         {
             "url": "http://127.0.0.1:9103"
         }
      ],
      "keys": {
        "passwords": [],
        "keyData": [
          {
            "config": {"data":{"bytes":"oBQw7B/TivaynIT9SQTx5Ni1jNV1M5s/J6+1r7KlCJ8="},"type":"unlocked"},
            "publicKey": "NPaOkPjlF3WFgA1WaqtANE0tqX/M8Rdr1h4SzQX0ghQ="
          }
        ]
      },
      "alwaysSendTo": []
    }
```

tessera-2.json

```
    {
      "useWhiteList": false,
      "jdbc": {
        "username": "sa",
        "password": "",
        "url": "jdbc:h2:/opt/dev/quorum/testnet/data/node2/tm/db;MODE=Oracle;TRACE_LEVEL_SYSTEM_OUT=0",
        "autoCreateTables": true
      },
      "serverConfigs":[
      {
        "app":"ThirdParty",
        "enabled": true,
        "serverAddress": "http://127.0.0.1:9182",
        "communicationType" : "REST"
      },
      {
        "app":"Q2T",
        "enabled": true,
        "serverAddress": "unix:/opt/dev/quorum/testnet/data/node2/tm/tm.ipc",
        "communicationType" : "REST"
      },
      {
        "app":"P2P",
        "enabled": true,
        "serverAddress": "http://127.0.0.1:9102",
        "sslConfig": {
          "tls": "OFF",
          "generateKeyStoreIfNotExisted": true,
          "serverKeyStore": "/opt/dev/quorum/testnet/data/node2/tm/server-keystore",
          "serverKeyStorePassword": "quorum",
          "serverTrustStore": "/opt/dev/quorum/testnet/data/node2/tm/server-truststore",
          "serverTrustStorePassword": "quorum",
          "serverTrustMode": "TOFU",
          "knownClientsFile": "/opt/dev/quorum/testnet/data/node2/tm/knownClients",
          "clientKeyStore": "/opt/dev/quorum/testnet/data/node2/tm/client-keystore",
          "clientKeyStorePassword": "quorum",
          "clientTrustStore": "/opt/dev/quorum/testnet/data/node2/tm/client-truststore",
          "clientTrustStorePassword": "quorum",
          "clientTrustMode": "TOFU",
          "knownServersFile": "/opt/dev/quorum/testnet/data/node2/tm/knownServers"
        },
        "communicationType" : "REST"
      }
      ],
      "peer": [
         {
             "url": "http://127.0.0.1:9101"
         },
         {
             "url": "http://127.0.0.1:9102"
         },
         {
             "url": "http://127.0.0.1:9103"
         }
      ],
      "keys": {
        "passwords": [],
        "keyData": [
          {
            "config": {"data":{"bytes":"/FAEF3msNOcWNkLkzUdSdNLFvFSJgddjwV2HOWTV/Rk="},"type":"unlocked"},
            "publicKey": "T8olcFvm2JojQd616k1MIx/Gm2IEZPkyV4GutVvrPgM="
          }
        ]
      },
      "alwaysSendTo": []
    }
```

tessera-3.json

```
    {
      "useWhiteList": false,
      "jdbc": {
        "username": "sa",
        "password": "",
        "url": "jdbc:h2:/opt/dev/quorum/testnet/data/node3/tm/db;MODE=Oracle;TRACE_LEVEL_SYSTEM_OUT=0",
        "autoCreateTables": true
      },
      "serverConfigs":[
      {
        "app":"ThirdParty",
        "enabled": true,
        "serverAddress": "http://127.0.0.1:9183",
        "communicationType" : "REST"
      },
      {
        "app":"Q2T",
        "enabled": true,
        "serverAddress": "unix:/opt/dev/quorum/testnet/data/node3/tm/tm.ipc",
        "communicationType" : "REST"
      },
      {
        "app":"P2P",
        "enabled": true,
        "serverAddress": "http://127.0.0.1:9103",
        "sslConfig": {
          "tls": "OFF",
          "generateKeyStoreIfNotExisted": true,
          "serverKeyStore": "/opt/dev/quorum/testnet/data/node3/tm/server-keystore",
          "serverKeyStorePassword": "quorum",
          "serverTrustStore": "/opt/dev/quorum/testnet/data/node3/tm/server-truststore",
          "serverTrustStorePassword": "quorum",
          "serverTrustMode": "TOFU",
          "knownClientsFile": "/opt/dev/quorum/testnet/data/node3/tm/knownClients",
          "clientKeyStore": "/opt/dev/quorum/testnet/data/node3/tm/client-keystore",
          "clientKeyStorePassword": "quorum",
          "clientTrustStore": "/opt/dev/quorum/testnet/data/node3/tm/client-truststore",
          "clientTrustStorePassword": "quorum",
          "clientTrustMode": "TOFU",
          "knownServersFile": "/opt/dev/quorum/testnet/data/node3/tm/knownServers"
        },
        "communicationType" : "REST"
      }
      ],
      "peer": [
         {
             "url": "http://127.0.0.1:9101"
         },
         {
             "url": "http://127.0.0.1:9102"
         },
         {
             "url": "http://127.0.0.1:9103"
         }
      ],
      "keys": {
        "passwords": [],
        "keyData": [
          {
            "config": {"data":{"bytes":"ZR00hvY4nCiG8sWQFasKvwGtOBi0b2oxNriVdMN++MY="},"type":"unlocked"},
            "publicKey": "Uc952L7QFuk8R5sGtjpfHb9EM+X6pTFRixVa+XgPBjc="
          }
        ]
      },
      "alwaysSendTo": []
    }
```

###　七、启动transaction manager - tessera

执行如下命令后台启动三个tessera transaction manager

```
\>nohup java -Xms128M -Xmx128M -jar /opt/dev/quorum/testnet/tmp/tessera-app-0.9.jar -configfile /opt/dev/quorum/testnet/tmp/tessera-1.json >> /opt/dev/quorum/testnet/data/node1/tm.log &
\>nohup java -Xms128M -Xmx128M -jar /opt/dev/quorum/testnet/tmp/tessera-app-0.9.jar -configfile /opt/dev/quorum/testnet/tmp/tessera-2.json >> /opt/dev/quorum/testnet/data/node2/tm.log &
\>nohup java -Xms128M -Xmx128M -jar /opt/dev/quorum/testnet/tmp/tessera-app-0.9.jar -configfile /opt/dev/quorum/testnet/tmp/tessera-3.json >> /opt/dev/quorum/testnet/data/node3/tm.log &
```

tessera transaction manager启动成功后，会在相应的路径下生成ipc文件

```
/opt/dev/quorum/testnet/data/node1/tm/tm.ipc
/opt/dev/quorum/testnet/data/node2/tm/tm.ipc
/opt/dev/quorum/testnet/data/node3/tm/tm.ipc
```

### 八、启动quorum node

因为前面账户创建时候我们没有设置密码，所以建立三个空的password.txt文件

```
touch /opt/dev/quorum/testnet/data/node1/passwords.txt
touch /opt/dev/quorum/testnet/data/node2/passwords.txt
touch /opt/dev/quorum/testnet/data/node3/passwords.txt
```

执行如下命令后台启动三个quorum node, quorum node和tessera transaction manager通过ipc进行通信

```
\>export PRIVATE_CONFIG=/opt/dev/quorum/testnet/data/node1/tm/tm.ipc
\>nohup geth --identity node1-istanbul --datadir /opt/dev/quorum/testnet/data/node1/dd --permissioned --nodiscover --verbosity 5 --networkid 10 --rpc --rpcaddr 0.0.0.0 --rpcport 32001 --rpcapi admin,db,eth,debug,miner,net,shh,txpool,personal,web3,quorum,istanbul --port 31001 --unlock 0 --password /opt/dev/quorum/testnet/data/node1/passwords.txt --emitcheckpoints --istanbul.blockperiod 1 --mine --minerthreads 1 --syncmode full >> /opt/dev/quorum/testnet/data/node1/dd.log &

\>export PRIVATE_CONFIG=/opt/dev/quorum/testnet/data/node2/tm/tm.ipc 
\>nohup geth --identity node2-istanbul --datadir /opt/dev/quorum/testnet/data/node2/dd --permissioned --nodiscover --verbosity 5 --networkid 10 --rpc --rpcaddr 0.0.0.0 --rpcport 32002 --rpcapi admin,db,eth,debug,miner,net,shh,txpool,personal,web3,quorum,istanbul --port 31002 --unlock 0 --password /opt/dev/quorum/testnet/data/node2/passwords.txt --emitcheckpoints --istanbul.blockperiod 1 --mine --minerthreads 1 --syncmode full >> /opt/dev/quorum/testnet/data/node2/dd.log &

\>export PRIVATE_CONFIG=/opt/dev/quorum/testnet/data/node3/tm/tm.ipc
\>nohup geth --identity node3-istanbul --datadir /opt/dev/quorum/testnet/data/node3/dd --permissioned --nodiscover --verbosity 5 --networkid 10 --rpc --rpcaddr 0.0.0.0 --rpcport 32003 --rpcapi admin,db,eth,debug,miner,net,shh,txpool,personal,web3,quorum,istanbul --port 31003 --unlock 0 --password /opt/dev/quorum/testnet/data/node3/passwords.txt --emitcheckpoints --istanbul.blockperiod 1 --mine --minerthreads 1 --syncmode full >> /opt/dev/quorum/testnet/data/node3/dd.log &
```

至此我们的Quorum区块链网络就已经启动成功了。

### 九、验证

我们部署一个私有合约，以此来验证我们的区块链网络

首先连接到node1的console

```
\>geth attach /opt/dev/quorum/testnet/data/node1/dd/geth.ipc
zmm: cfgPath is  PRIVATE_CONFIG
Welcome to the Geth JavaScript console!

instance: Geth/node1-istanbul/v1.8.18-stable-f681cbf3(quorum-v2.2.3)/linux-amd64/go1.12.1
coinbase: 0x90ccaba53ed0c2979d4659692ca3b0ecc385fd70
at block: 4 (Sat, 27 Apr 2019 15:56:13 CST)
 datadir: /opt/dev/quorum/testnet/data/node1/dd
 modules: admin:1.0 debug:1.0 eth:1.0 istanbul:1.0 miner:1.0 net:1.0 personal:1.0 rpc:1.0 txpool:1.0 web3:1.0

> 
```

贴入以下内容部署一个私有合约, 例子来自官方的7nodesample, 注意修改其中的"privateFor"字段为tessera秘钥对中3.pub的内容，表明由node1发起的这个合约只同node3进行私有

```
\>more 3.pub 
Uc952L7QFuk8R5sGtjpfHb9EM+X6pTFRixVa+XgPBjc=
a = eth.accounts[0]
web3.eth.defaultAccount = a;

// abi and bytecode generated from simplestorage.sol:
// > solcjs --bin --abi simplestorage.sol
var abi = [{"constant":true,"inputs":[],"name":"storedData","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"x","type":"uint256"}],"name":"set","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"get","outputs":[{"name":"retVal","type":"uint256"}],"payable":false,"type":"function"},{"inputs":[{"name":"initVal","type":"uint256"}],"payable":false,"type":"constructor"}];

var bytecode = "0x6060604052341561000f57600080fd5b604051602080610149833981016040528080519060200190919050505b806000819055505b505b610104806100456000396000f30060606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680632a1afcd914605157806360fe47b11460775780636d4ce63c146097575b600080fd5b3415605b57600080fd5b606160bd565b6040518082815260200191505060405180910390f35b3415608157600080fd5b6095600480803590602001909190505060c3565b005b341560a157600080fd5b60a760ce565b6040518082815260200191505060405180910390f35b60005481565b806000819055505b50565b6000805490505b905600a165627a7a72305820d5851baab720bba574474de3d09dbeaabc674a15f4dd93b974908476542c23f00029";

var simpleContract = web3.eth.contract(abi);
var simple = simpleContract.new(42, {from:web3.eth.accounts[0], data: bytecode, gas: 0x47b760, privateFor: ["Uc952L7QFuk8R5sGtjpfHb9EM+X6pTFRixVa+XgPBjc="]}, function(e, contract) {
    if (e) {
        console.log("err creating contract", e);
    } else {
        if (!contract.address) {
            console.log("Contract transaction send: TransactionHash: " + contract.transactionHash + " waiting to be mined...");
        } else {
            console.log("Contract mined! Address: " + contract.address);
            console.log(contract);
        }
    }
});
```

修改"privateFor"字段之后，将其贴入console:

```
instance: Geth/node1-istanbul/v1.8.18-stable-f681cbf3(quorum-v2.2.3)/linux-amd64/go1.12.1
coinbase: 0x90ccaba53ed0c2979d4659692ca3b0ecc385fd70
at block: 109 (Sat, 27 Apr 2019 16:17:03 CST)
 datadir: /opt/dev/quorum/testnet/data/node1/dd
 modules: admin:1.0 debug:1.0 eth:1.0 istanbul:1.0 miner:1.0 net:1.0 personal:1.0 rpc:1.0 txpool:1.0 web3:1.0

> a = eth.accounts[0]
:false,"type":"function"},{"constant":false,"inputs":[{"name":"x","type":"uint256"}],"name":"set","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"get","outputs":[{"name":"retVal","type":"uint256"}],"payable":false,"type"0x9affedff10f7229c680819d5eeb12c3624f6baeb"
> web3.eth.defaultAccount = a;
"0x9affedff10f7229c680819d5eeb12c3624f6baeb"
> 
> // abi and bytecode generated from simplestorage.sol:
undefined
> // > solcjs --bin --abi simplestorage.sol
undefined
> var abi = [{"constant":true,"inputs":[],"name":"storedData","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"x","type":"uint256"}],"name":"set","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"get","outputs":[{"name":"retVal","type":"uint256"}],"payable":false,"type":"function"},{"inputs":[{"name":"initVal","type":"uint256"}],"payable":false,"type":"constructor"}];
undefined
> 
> var bytecode = "0x6060604052341561000f57600080fd5b604051602080610149833981016040528080519060200190919050505b806000819055505b505b610104806100456000396000f30060606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680632a1afcd914605157806360fe47b11460775780636d4ce63c146097575b600080fd5b3415605b57600080fd5b606160bd565b6040518082815260200191505060405180910390f35b3415608157600080fd5b6095600480803590602001909190505060c3565b005b341560a157600080fd5b60a760ce565b6040518082815260200191505060405180910390f35b60005481565b806000819055505b50565b6000805490505b905600a165627a7a72305820d5851baab720bba574474de3d09dbeaabc674a15f4dd93b974908476542c23f00029";
undefined
> 
> var simpleContract = web3.eth.contract(abi);
undefined
> var simple = simpleContract.new(42, {from:web3.eth.accounts[0], data: bytecode, gas: 0x47b760, privateFor: ["Uc952L7QFuk8R5sGtjpfHb9EM+X6pTFRixVa+XgPBjc="]}, function(e, contract) {
...... if (e) {
......... console.log("err creating contract", e);
......... } else {
......... if (!contract.address) {
............ console.log("Contract transaction send: TransactionHash: " + contract.transactionHash + " waiting to be mined...");
............ } else {
............ console.log("Contract mined! Address: " + contract.address);
............ console.log(contract);
............ }
......... }
...... });
Contract transaction send: TransactionHash: 0x74efa531fa5e8c1962a0b7cd2c1f3c34e5f19890cec27a1f90438edb074bda51 waiting to be mined...
undefined
> Contract mined! Address: 0xc48ba0d7ea03ab25a5f264845b848d847d391fc4
[object Object]
> 
```

看到下方的Contract mined! Address: 0x5f71775e74bc96902c31df3205aca9a968811a42则说明IBFT工作正常，成功出块，接下来我们验证private隐私性，因为我们使用了privateFor，只允许node3持有私有数据，因此我们对node1、node2和node3分别调用智能合约，看看结果如何:
 对于node1，我们继续使用刚才的console

```
> simple.get()
42
```

结果是我们创建合约时候赋值的42，接着打开node2终端

```
\>geth attach /opt/dev/quorum/testnet/data/node2/dd/geth.ipc
zmm: cfgPath is  PRIVATE_CONFIG
Welcome to the Geth JavaScript console!

instance: Geth/node2-istanbul/v1.8.18-stable-f681cbf3(quorum-v2.2.3)/linux-amd64/go1.12.1
coinbase: 0xa02f4bb093989222608d25c6c57a5b40526f6796
at block: 445 (Sat, 27 Apr 2019 16:22:39 CST)
 datadir: /opt/dev/quorum/testnet/data/node2/dd
 modules: admin:1.0 debug:1.0 eth:1.0 istanbul:1.0 miner:1.0 net:1.0 personal:1.0 rpc:1.0 txpool:1.0 web3:1.0

> 
```

为了调用我们刚才创建的智能合约，simple.at处应该使用地址0xc48ba0d7ea03ab25a5f264845b848d847d391fc4，注意你应该把地址修改成你自己刚刚部署的contract地址，在node2的console贴入如下代码:

```
a = eth.accounts[0]
web3.eth.defaultAccount = a;

// abi and bytecode generated from simplestorage.sol:
// > solcjs --bin --abi simplestorage.sol
var abi = [{"constant":true,"inputs":[],"name":"storedData","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"x","type":"uint256"}],"name":"set","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"get","outputs":[{"name":"retVal","type":"uint256"}],"payable":false,"type":"function"},{"inputs":[{"name":"initVal","type":"uint256"}],"payable":false,"type":"constructor"}];

var simpleContract = web3.eth.contract(abi);
var simple = simpleContract.at("0xc48ba0d7ea03ab25a5f264845b848d847d391fc4")
```

结果:

```
> a = eth.accounts[0]
:false,"type":"function"},{"constant":false,"inputs":[{"name":"x","type":"uint256"}],"name":"set","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"get","outputs":[{"name":"retVal","type":"uint256"}],"payable":false,"type"0x5c8822ab6af840f8c3e52fe9a71c43f90672728e"
> web3.eth.defaultAccount = a;
"0x5c8822ab6af840f8c3e52fe9a71c43f90672728e"
> 
> // abi and bytecode generated from simplestorage.sol:
undefined
> // > solcjs --bin --abi simplestorage.sol
undefined
> var abi = [{"constant":true,"inputs":[],"name":"storedData","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"x","type":"uint256"}],"name":"set","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"get","outputs":[{"name":"retVal","type":"uint256"}],"payable":false,"type":"function"},{"inputs":[{"name":"initVal","type":"uint256"}],"payable":false,"type":"constructor"}];
undefined
> 
> var simpleContract = web3.eth.contract(abi);
undefined
> var simple = simpleContract.at("0xc48ba0d7ea03ab25a5f264845b848d847d391fc4")
undefined
```

接着我们调用合约:

```
> simple.get()
0
```

结果符合预期，node2应该看不到node1和node3的私有合约
 接下来以同样的方式打开node3的console

```
\>geth attach /opt/dev/quorum/testnet/data/node3/dd/geth.ipc
zmm: cfgPath is  PRIVATE_CONFIG
Welcome to the Geth JavaScript console!

instance: Geth/node3-istanbul/v1.8.18-stable-f681cbf3(quorum-v2.2.3)/linux-amd64/go1.12.1
coinbase: 0xf0fa966e6efa633080d1603e7daea5176de87d82
at block: 754 (Sat, 27 Apr 2019 16:27:48 CST)
 datadir: /opt/dev/quorum/testnet/data/node3/dd
 modules: admin:1.0 debug:1.0 eth:1.0 istanbul:1.0 miner:1.0 net:1.0 personal:1.0 rpc:1.0 txpool:1.0 web3:1.0

> a = eth.accounts[0]
:false,"type":"function"},{"constant":false,"inputs":[{"name":"x","type":"uint256"}],"name":"set","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"get","outputs":[{"name":"retVal","type":"uint256"}],"payable":false,"type"0x915779c113cffecac6583310d80a8def09546272"
> web3.eth.defaultAccount = a;
"0x915779c113cffecac6583310d80a8def09546272"
> 
> // abi and bytecode generated from simplestorage.sol:
undefined
> // > solcjs --bin --abi simplestorage.sol
undefined
> var abi = [{"constant":true,"inputs":[],"name":"storedData","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"x","type":"uint256"}],"name":"set","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"get","outputs":[{"name":"retVal","type":"uint256"}],"payable":false,"type":"function"},{"inputs":[{"name":"initVal","type":"uint256"}],"payable":false,"type":"constructor"}];
undefined
> 
> var simpleContract = web3.eth.contract(abi);
undefined
> var simple = simpleContract.at("0xc48ba0d7ea03ab25a5f264845b848d847d391fc4")
undefined
> simple.get()
42
> 
```

可以看到结果符合预期，node3读出了私有合约的值42。