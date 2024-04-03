# Rebuild_dbs
基于长安链的数据归档服务;归档功能是指将链上数据转移到独立存储上，归档后的数据具备可查询、可恢复到链上的特性。


## 数据归档

> 默认端口:
> http: 13119 | rpc:   13120
> 归档功能是指将链上数据转移到独立存储上，归档后的数据具备可查询、可恢复到链上的特性。

## 部署教程

> 1 编译

```bash
cd tools/cmc/
go build && make build # 编译
cp cmc bin 
make start # 启动归档服务
make stop # 停止归档服务 
```

> 2. 1 传入证书文件,海草路径,见接口 1.1

> 2. 2 生成并配置bysdk.yml
>    例子:{"chain_id_parameter": "chain1","org_id_parameter": "wx-org2.chainmaker.org","node_addr": "127.0.0.1:12302","tls_host_name": "chainmaker.org","archive_center_http_url": "http://127.0.0.1:13119","rpc_addr": "127.0.0.1:13120"}

```bash
# 调用http接口/sdkSetGroup/sdkConfig,进行配置,首次将生成配置文件,之后则修改配置文件
curl -X POST 'http://127.0.0.1:13119/sdkSetGroup/sdkInit' -d '{"chain_id_parameter": [链ID],"org_id_parameter": [组织ID],"node_addr": [节点地址],"tls_host_name": [TLS hostname],,"archive_center_http_url": [http服务地址],"rpc_addr": [rpc服务地址]}'
```

> 3 创世区块chain_genesis_hash的获取可以采用如下步骤: 见接口1.2和1.3

```bash
# 调用http接口/get_genesis_block_hash,获取base64编码的genesis_block_hash
curl -X POST 'http://127.0.0.1:13119/get_genesis_block_hash' -d '{}'
# 调用http接口/archive/getBlockhash,获取hex编码的genesis_block_hash,其中[blockhash]为创世区块base64编码的hash
curl -X POST 'http://127.0.0.1:13119/archive/getBlockhash' -d '{"chain_base_hash": [blockhash]}'
```

> 4 配置sdk.yml(补上hash)

```bash
# 调用http接口/sdkSetGroup/sdkHashConfig,进行修改配置
curl -X POST 'http://127.0.0.1:13119/sdkSetGroup/sdkHashConfig' -d '{"chain_genesis_hash": [链hex编码哈希]}'
```

得到如下配置 : 可cat bin路径下的sdk.yml查看

**sdk_config.yml 客户端连接配置(示例)**

```yaml
chain_client:
  chain_id: chain1
  org_id: wx-org2.chainmaker.org
  user_key_file_path: ./testdata/crypto-config/wx-orgby.chainmaker.org/user/admin1/admin1.tls.key
  user_crt_file_path: ./testdata/crypto-config/wx-orgby.chainmaker.org/user/admin1/admin1.tls.crt
  user_sign_key_file_path: ./testdata/crypto-config/wx-orgby.chainmaker.org/user/admin1/admin1.sign.key
  user_sign_crt_file_path: ./testdata/crypto-config/wx-orgby.chainmaker.org/user/admin1/admin1.sign.crt
  retry_limit: 20
  retry_interval: 500
  enable_tx_result_dispatcher: true
  nodes:
  - node_addr: 127.0.0.1:12302
    conn_cnt: 10
    enable_tls: true
    trust_root_paths:
    - ./testdata/crypto-config/wx-orgby.chainmaker.org/ca
    tls_host_name: chainmaker.org
  archive:
    type: archivecenter
    dest: root:123456:localhost:3306
    secret_key: xxx
  rpc_client:
    max_receive_message_size: 100
    max_send_message_size: 100
    send_tx_timeout: 60
    get_tx_timeout: 60
  pkcs11:
    enabled: false
    library: /usr/local/lib64/pkcs11/libupkcs11.so
    label: HSM
    password: "11111111"
    session_cache_size: 10
    hash: SHA256
  archive_center_config:
    chain_genesis_hash: 472dc822e15c483534cc1a1b587df8c8825f4982084b05afd50c1187d958c6c0
    archive_center_http_url: http://127.0.0.1:13119
    request_second_limit: 10
    rpc_address: 127.0.0.1:13120
    tls_enable: false
    tls:
      server_name: archiveserver1.tls.wx-org.chainmaker.org
      priv_key_file: ./testdata/archivecenter/archiveadmin1.tls.key
      cert_file: ./testdata/archivecenter/archiveadmin1.tls.crt
      trust_ca_list:
      - ./testdata/archivecenter/ca.crt
    max_send_msg_size: 200
    max_recv_msg_size: 200
```

5 **修改分布式存储配置信息**

> 默认配置如下:(如果需要,在cmc/bin/seaweedfs.yml里修改),**全局变量**
>
> ```
> ak       = "1"                     //文件服务分配的账号
> sk       = "2"                     //文件服务分配的秘钥
> endPoint = "http://127.0.0.1:8333" //上图weed S3服务的地址
> region   = "test.com"              //适用范围
> ```

测试可用/sdkSetGroup/sdkTest 验证是否正确

> 返回示例:
>
> {
>
> ​    "ak": "1",
>
> ​    "endPoint": "http://127.0.0.1:8333",
>
> ​    "region": "test.com",
>
> ​    "sk": "2"
>
> }

**注意** !!!!!!!!!!!!!!!!!!

**如果修改了配置yml文件,需要重启一下服务,make stop make start** 
**因为 服务需要初始化,会读入全局变量**

6 **修改config.yml配置信息**

如下值,设置为和链一样的大小即可一一对应

storage_template: 

​	 logdb_segment_size: 32

---

**服务返回信息说明**

- 服务返回code字段(integer)；>0 代表接口返回错误信息；接口成功返回数据则该字段不返回

- 服务返回errorMsg字段(string)；非空则代表错误信息；接口成功返回数据则该字段不返回

- 服务返回data字段(json对象)；接口成功返回的具体数据

**响应状态码**

| 状态码 | 描述           |
| ------ | -------------- |
| 200    | 请求成功       |
| 400    | 请求参数错误   |
| 401    | 未授权         |
| 404    | 用户不存在     |
| 500    | 服务器内部错误 |

## 1.1 POST SDK配置接口

POST /sdkSetGroup/sdkDownload

> Body 请求参数

```
{
    "key_file_path": [私钥海草路径],
    "crt_file_path": [证书海草路径],
    "key_sign_file_path": [签名私钥海草路径],
    "crt_sign_file_path": [签名证书海草路径],
    "trust_crt_path": [ca证书海草路径],//组织的
    "trust_key_path": [ca密钥海草路径]//组织的
}
```

> 例子:
>
> {
>
> ​    "key_file_path": "http://127.0.0.1:8333/weed-test-buck/testkey",
>
> ​    "crt_file_path": "http://127.0.0.1:8333/weed-test-buck/testkey",
>
> ​    "key_sign_file_path": "http://127.0.0.1:8333/weed-test-buck/testkey",
>
> ​    "crt_sign_file_path": "http://127.0.0.1:8333/weed-test-buck/testkey",
>
> ​    "trust_crt_path": "http://127.0.0.1:8333/weed-test-buck/testkey",
>
> ​    "trust_key_path": "http://127.0.0.1:8333/weed-test-buck/weed-test-003"
>
> }

### 请求参数

| 名称            | 位置 | 类型 | 必选 | 说明 |
| --------------- | ---- | ---- | ---- | ---- |
| 见Body 请求参数 |      |      |      |      |

### 返回结果

| 状态码 | 状态码含义                                              | 说明 | 数据模型 |
| ------ | ------------------------------------------------------- | ---- | -------- |
| 200    | [OK](https://tools.ietf.org/html/rfc7231#section-6.3.1) | 成功 | Inline   |

### data 对应的数据结构

```json
{
    "message": "Command executed successfully"
}
```

## 1.2 POST 获取链base64编码的hash

POST /get_genesis_block_hash

> Body 请求参数

```
{}
```

> 返回结果

| 状态码 | 状态码含义                                              | 说明 | 数据模型 |
| ------ | ------------------------------------------------------- | ---- | -------- |
| 200    | [OK](https://tools.ietf.org/html/rfc7231#section-6.3.1) | 成功 | Inline   |

### data 对应的数据结构

```
{
  "block_hash": "bmKqHpf8TqwwaTo5FA9GtPW0SdNAqrxIeQE7vCmFd9A=",
}
```

## 1.3 POST 根据区块hash的base64编码计算hash的hex编码

POST /archive/getBlockhash

> Body 请求参数

```
{
 "chain_base_hash":"Ry3IIuFcSDU0zBobWH34yIJfSYIISwWv1QwRh9lYxsA="
}
```

> 返回示例

### 请求参数

| 名称            | 位置 | 类型   | 必选 | 说明                 |
| --------------- | ---- | ------ | ---- | -------------------- |
| chain_base_hash | body | string | 是   | 链的base64编码的hash |

### 返回结果

| 状态码 | 状态码含义                                              | 说明 | 数据模型 |
| ------ | ------------------------------------------------------- | ---- | -------- |
| 200    | [OK](https://tools.ietf.org/html/rfc7231#section-6.3.1) | 成功 | Inline   |

### data 对应的数据结构

```
{
    "output": "472dc822e15c483534cc1a1b587df8c8825f4982084b05afd50c1187d958c6c0\n"
}
```

## 1.4 DEBUG接口

http://127.0.0.1:13119/archive/version 

{}

返回值:

{

​    "version": "用来确认是否新版本3.27"

}

---

检验从海草下载文件是否正常

> 文件生成在bin路径下 test.txt,核对大小是否和海草一致即可

http://127.0.0.1:13119/get_cert_test

{

​    "test_parameter": "http://127.0.0.1:8333/472dc822e15c483534cc1a1b587df8c8825f4982084b05afd50c1187d958c6c0-org3/00000000000000006888.fdb.END"

}

返回值:

{

​    "message": "Command executed successfully"

}

http://127.0.0.1:13119/archive/getgoruntine

{}

返回值：该服务的资源消耗，包括内存占用，协程数等

---

## 2.1 POST 获取节点归档状态-》获取恢复的高度和区块最大高度

POST /archive/getChainStatus

> Body 请求参数

```
{}
```

> 返回示例

### 返回结果

| 状态码 | 状态码含义                                              | 说明 | 数据模型 |
| ------ | ------------------------------------------------------- | ---- | -------- |
| 200    | [OK](https://tools.ietf.org/html/rfc7231#section-6.3.1) | 成功 | Inline   |

### data返回数据结构

```
{//ArchivePivot恢复的高度,MaxAllowArchiveHeight区块最大高度
  "output": "ArchivePivot: 0, MaxAllowArchiveHeight: 7049 . &store.ArchiveStatus{Type:1, FileRanges:[]*store.FileRange(nil), ArchivePivot:0x0, MaxAllowArchiveHeight:0x1b89, Process:0}\n"
}
```

## 2.2 POST 获取当前所有归档的链的信息-》已经dump的高度

POST /get_chains_infos

> Body 请求参数

### 请求参数

> {}

### 返回结果

| 状态码 | 状态码含义                                              | 说明 | 数据模型 |
| ------ | ------------------------------------------------------- | ---- | -------- |
| 200    | [OK](https://tools.ietf.org/html/rfc7231#section-6.3.1) | 成功 | Inline   |

### data 对应的数据结构

```
{//archivedHeight已经dump的高度
    "data": [
        {
            "chainId": "chain1",
            "genesisHashStr": "Ry3IIuFcSDU0zBobWH34yIJfSYIISwWv1QwRh9lYxsA=",
            "genesisHashHex": "472dc822e15c483534cc1a1b587df8c8825f4982084b05afd50c1187d958c6c0",
            "archivedHeight": 350,
            "inArchive": false,
            "compressedHeight": 0,
            "inCompress": false,
            "inCompressFileName": ""
        }
    ]
}
```

## 3.1 POST 发送归档数据请求接口

POST http://127.0.0.1:13119/archive/ybTest

> Body 请求参数

```
{
    "dump_height_parameter": "7004",
    "chain_hex_hash": "472dc822e15c483534cc1a1b587df8c8825f4982084b05afd50c1187d958c6c0",
    "org_id_parameter": "org3"
}
```

### data 对应的数据结构

```
//首次执行或执行了3.2(接收了该次dump的数据,异步)
{
    "message": "dump任务已启动，正在后台执行"
}
//如果重复执行,会提示如下(随便试)
{
    "message": "当前有dump任务在执行，请稍后再试！"
}
```

## 3.2 POST 监听归档接口

POST http://127.0.0.1:13119/archive/ybRcv

> Body 请求参数

```
{}
```

### data 对应的数据结构

```
//未准备好的情况:
c.JSON(http.StatusOK, gin.H{
			"status": "DUMP in_progress",
		}

//接收
{
    "object_ids_parameter": [
        "http://127.0.0.1:8333/472dc822e15c483534cc1a1b587df8c8825f4982084b05afd50c1187d958c6c0-org3/00000000000000000001.fdb",
        "http://127.0.0.1:8333/472dc822e15c483534cc1a1b587df8c8825f4982084b05afd50c1187d958c6c0-org3/00000000000000006888.fdb.END"
    ],
    "ress_parameter": [
        "00000000000000000001.fdb",
        "00000000000000006888.fdb.END"
    ],
    "result": "dump任务已完成Error: no block to archive\nUsage:\n  cmc archive dump [archive height] [flags]\n\nFlags:\n  -h, --help                   help for dump\n      --mode string            specify archive mode ,can be quick or normal \n      --sdk-conf-path string   specify sdk config path\n\n",
    "status": "DUMP completed"
}
```



## 4 POST 已归档数据清理接口

> - ArchiveHeightParameter: 清理目标区块高度
> - 注：
>   - archiveHeight 范围：ArchivePivot < archiveHeight < MaxAllowArchiveHeight
>   - ArchivePivot、MaxAllowArchiveHeight、Process可由GetArchiveStatus()接口获取
>   - 返回”archive range less than”错误信息时，请调大archiveHeight值，直到成功
>   - **实际的归档区块高度可能会比archiveHeight小，节点会根据当前存储状态自动选择合适的归档区块高度!!!!!!!!!!!**

POST /archive/dumpClean

> Body 请求参数

```
{
  "archive_height_parameter": "string",//清理的高度
  "chain_hex_hash": "string",
}
```

示例:

{

​    "archive_height_parameter": "6887",

​    "chain_hex_hash": "472dc822e15c483534cc1a1b587df8c8825f4982084b05afd50c1187d958c6c0"

}

### 请求参数

| 名称                     | 位置 | 类型   | 必选 | 说明                                    |
| ------------------------ | ---- | ------ | ---- | --------------------------------------- |
| archive_height_parameter | body | string | 是   | 清理的高度(覆盖形式,不支持截取片段清理) |
| chain_hex_hash           | body | string | 是   | 链的hex编码哈希                         |

### 返回结果

| 状态码 | 状态码含义                                              | 说明 | 数据模型 |
| ------ | ------------------------------------------------------- | ---- | -------- |
| 200    | [OK](https://tools.ietf.org/html/rfc7231#section-6.3.1) | 成功 | Inline   |

### data 对应的数据结构

```
{
  "dumpoutput": "chain has got archive command!",
} 
```

## 5.1 POST  恢复已归档数据接口

> ress和objects数组一一对应

POST /archive/ybrestoreTest

> Body 请求参数

```
{
    "restore_height_parameter": "6860",
    "chain_hex_hash": "472dc822e15c483534cc1a1b587df8c8825f4982084b05afd50c1187d958c6c0",
    "ress_parameter": [
        "00000000000000000001.fdb",
        "00000000000000006888.fdb.END"
    ],
    "object_ids_parameter": [
        "http://127.0.0.1:8333/472dc822e15c483534cc1a1b587df8c8825f4982084b05afd50c1187d958c6c0-org3/00000000000000000001.fdb",
        "http://127.0.0.1:8333/472dc822e15c483534cc1a1b587df8c8825f4982084b05afd50c1187d958c6c0-org3/00000000000000006888.fdb.END"
    ]
}
```

### data 对应的数据结构

```bash
{//非等待状态
    "message": "restore任务已启动，正在后台执行"
}
{//等待状态
    "message": "当前有restore任务在执行，请稍后再试！"
}
```

## 5.2 POST  监听恢复数据接口

POST /archive/ybrestoreRcv

> Body 请求参数

```
{
    "restore_height_parameter": "6860"
}
```

### 请求参数

| 名称                     | 位置 | 类型   | 必选 | 说明                   |
| ------------------------ | ---- | ------ | ---- | ---------------------- |
| restore_height_parameter | body | string | 是   | 指定到恢复的高度(倒序) |

### data 对应的数据结构

```bash
{//未完成状态1,还在执行restore指令
    "status": "in_progress-Restore"
}
{//未完成状态2,resotre指令执行完毕,链上还在merge
    "status": "in_progress-Restore fdb merge"
}
{//完成时
    "completedTime": "2024-03-28T22:05:40.098796+08:00",
    "result":"非首次恢复restore任务已完成Restoring Blocks (1/7)\n ",
    "startTime": "2024-03-26T23:45:09.364508197+08:00",
    "status": "Restore completed",
    "value": "6859"
}
```

## 6 POST  退出服务(换其它节点必须做的事)

POST /archive/cmcexit

> Body 请求参数

```
{
  "chain_hex_hash": "string",
}
```

返回值:

```bash
{
    "output": "CLean done,exit OK",
    "res": [
        "sdk.log.2024032722",
        "sdk.log.2024032722 2",
        "sdk.log.2024032722 3"
    ]
}
```

## 7 POST  切换回已经归档过的节点（新节点不用此步骤）

> 本质是从海草取之前已经归档的数据文件

POST /archive/predump

> Body 请求参数

```
{
    "chain_hex_hash": "472dc822e15c483534cc1a1b587df8c8825f4982084b05afd50c1187d958c6c0",
    "ress_parameter": [
        "00000000000000000001.fdb",
        "00000000000000006888.fdb.END"
    ],
    "object_ids_parameter": [
        "http://127.0.0.1:8333/472dc822e15c483534cc1a1b587df8c8825f4982084b05afd50c1187d958c6c0-org3/00000000000000000001.fdb",
        "http://127.0.0.1:8333/472dc822e15c483534cc1a1b587df8c8825f4982084b05afd50c1187d958c6c0-org3/00000000000000006888.fdb.END"
    ]
}
```

返回值:

```bash
{
    "message":  "Command executed successfully",
		"fileURLs": fileURLs,
		"Dirpath":  Dirpath,
		"ress":     inParameter.RessParameter,
		"isExist":  isExist,
}
```

## 代码实现

 server.go 

```
// Listen 开启http监听
func (srv *HttpSrv) Listen(apiCfg serverconf.HttpConfig) {
resultChan = make(chan string)  // 初始化 resultChan
	resultChan1 = make(chan string) // 初始化 resultChan
	resChan = make(chan []string)
	objectidsChan = make(chan []string)
	notInTask = true
	notInTask1 = true

	go func() {
		for {
			result, ok1 := <-resultChan
			result1, ok2 := <-resChan
			result2, ok3 := <-objectidsChan
			if ok1 && ok2 && ok3 {
				taskFinished = true
				taskResult = result
				resResult = result1
				objectidsResult = result2
			}
		}
	}()

	//restore
	go func() {
		for {
			result, ok1 := <-resultChan1
			if ok1 {
				taskFinished1 = true
				taskResult1 = result

			}
		}
	}()
}
```

初始化dump和restore的通道，并开2个协程用来接收和等待

```
func (srv *HttpSrv) registerRouters() {
    srv.router.POST("/get_chains_infos", srv.GetChainInfos)
    srv.router.POST("/get_genesis_block_hash", srv.GetGenesisBlockHash) //获取链的base64哈希
    srv.router.POST("/get_cert", srv.GetCert)                           //获取证书
    srv.router.POST("/get_cert_test", srv.GetCertTest)                  //下载到指定路径测试
    srv.router.POST("/upload_test", srv.UploadTest)                     //上传测试
    // 需要加一下token
    //adminGroup := srv.router.Group("/admin", srv.tokenMiddleWare())
    //archive
    archiveGroup := srv.router.Group("/archive")
    archiveGroup.POST("/getBlockhash", srv.BaseToHex)        //获取链的创世区块哈希,依据cmc查询出来的base64编码的hash
    archiveGroup.POST("/getChainStatus", srv.getChainStatus) //获取节点归档信息
    archiveGroup.POST("/dumpClean", srv.dumpClean)           //清理链上已归档区块文件(不分片),OK
    archiveGroup.POST("/cmcexit", srv.cmcexit)               //清理cmc本地缓存文件 ,OK
    archiveGroup.POST("/dump", srv.dump)                     //cmc dump
    archiveGroup.POST("/predump", srv.predump)               //cmc dump
    archiveGroup.POST("/ybTest", srv.ybTest)
    archiveGroup.POST("/ybTest1", srv.ybTest1)
    archiveGroup.POST("/getgoruntine", srv.getgoruntine)
    archiveGroup.POST("/ybRcv", srv.ybRcv)

    archiveGroup.POST("/ybrestoreTest", srv.ybrestoreTest)
    archiveGroup.POST("/ybrestoreRcv", srv.ybrestoreRcv)
    archiveGroup.POST("/version", srv.version)

    archiveGroup.POST("/restore", srv.restore) //cmc restore
    // archiveGroup.POST("/restore", srv.restoreListen)
    archiveGroup.POST("/onlyrestore", srv.onlyrestore)
    //sdkSet
    sdkSetGroup := srv.router.Group("/sdkSetGroup")
    sdkSetGroup.POST("/sdkConfig", srv.sdkConfig)         //初始化sdk.yml
    sdkSetGroup.POST("/sdkHashConfig", srv.sdkHashConfig) //初始化sdk.yml
    sdkSetGroup.POST("/sdkDownload", srv.sdkDownload)     //初始化sdk.yml
    sdkSetGroup.POST("/sdkTest", srv.sdkTest)
    //1：首次传，需要init，之后查询，这个逻辑变成-》一个接口 完整配置名称是：用户diy+链名称+节点名称+后缀
    //?传chain和node名字,找到对应的sdk.yml?
    //归档: 链归档到cmc本地(/dump),cmc本地归档到链外分布式存储(/dumpSave),清理链上和cmc本地数据(dumpClean)
    //dump和dumpSave可以合并
    //归档到本地是因为,cmc需要先处理每一条归档的数据,记录偏移量等区块信息
    //恢复: bass平台向cmc发起恢复请求,包括一些参数(需要恢复的块高,区块存在分布式存储里的数据哈希/索引),调用cmc的http接口从链外分布式存储恢复区块数据到链上
    //顺序 配置sdk -> dump->seadump->dumpClean->cmcClean seaGet->restore->cmcClean
}
```

HTTP接口暴露

**实现类**

handlers.go

```
// GetChainInfos 查询归档中心所有的链信息
func (srv *HttpSrv) GetChainInfos(ginContext *gin.Context) {
    chainStatuses := srv.ProxyProcessor.GetAllChainInfo()
    ginContext.JSONP(http.StatusOK, Response{
       Data: chainStatuses,
    })
}
```

```
func (srv *HttpSrv) GetGenesisBlockHash(c *gin.Context) {//获取链的base64哈希
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }
    cmd := exec.Command("./cmc", "query", "block-by-height", "0",
       "--sdk-conf-path", "./bysdk.yml")
    output, err := cmd.CombinedOutput()

    //解析获取
    type Vertex struct{}

    type Dag struct {
       Vertexes []Vertex `json:"vertexes"`
    }

    type Header struct {
       BlockHash      string `json:"block_hash"`
       BlockTimestamp int    `json:"block_timestamp"`
       BlockType      int    `json:"block_type"`
       BlockVersion   int    `json:"block_version"`
       ChainID        string `json:"chain_id"`
       DagHash        string `json:"dag_hash"`
       RWSetRoot      string `json:"rw_set_root"`
       TxCount        int    `json:"tx_count"`
       TxRoot         string `json:"tx_root"`
    }

    type Tx struct {
       Payload struct {
          ChainID      string `json:"chain_id"`
          ContractName string `json:"contract_name"`
          Method       string `json:"method"`
          Parameters   []struct {
             Key string `json:"key"`
          } `json:"parameters"`
       } `json:"payload"`
    }

    type Block struct {
       Dag    Dag    `json:"dag"`
       Header Header `json:"header"`
       Txs    []Tx   `json:"txs"`
    }

    type Response struct {
       Block Block `json:"block"`
    }
    var response Response
    err = json.Unmarshal(output, &response)
    if err != nil {
       fmt.Println("解析JSON数据时发生错误:", err)
       return
    }
    // 访问解析后的数据
    blockHash := response.Block.Header.BlockHash
    if err != nil {
       c.JSON(http.StatusInternalServerError, gin.H{
          "error": "Error executing GetGenesisBlockHash command",
       })
       return
    }
    c.JSON(http.StatusOK, gin.H{
       // "output":          string(output),
       "blockBase64Hash": blockHash,
    })
}
```

```
func (srv *HttpSrv) GetCert(c *gin.Context) {//获取证书
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }
    //从bin开始
    Dirpath := "./testdata/crypto-config/wx-orgby.chainmaker.org/user/admin1"
    fileURL := inParameter.TestParameter // 指定要下载的私钥 URL
    // 发送 GET 请求获取文件数据
    resp, err := http.Get(fileURL)
    if err != nil {
       fmt.Println("Failed to download file:", err)
       return
    }
    defer resp.Body.Close()

    // 创建本地文件用于保存下载的数据
    localFile, err := os.Create(Dirpath + "test.txt")
    if err != nil {
       fmt.Println("Failed to create local file:", err)
       return
    }
    defer localFile.Close()

    // 将响应数据写入本地文件
    _, err = io.Copy(localFile, resp.Body)
    if err != nil {
       fmt.Println("Failed to save file:", err)
       return
    }

    c.JSON(http.StatusOK, gin.H{
       "message": "Command executed successfully",
    })

}
```

```
func (srv *HttpSrv) GetCertTest(c *gin.Context) {//上传下载（海草）测试接口
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }
    //从bin开始
    Dirpath := "./"
    fileURL := inParameter.TestParameter // 指定要下载的文件的 URL
    // 发送 GET 请求获取文件数据
    resp, err := http.Get(fileURL)
    if err != nil {
       fmt.Println("Failed to download file:", err)
       return
    }
    defer resp.Body.Close()

    // 创建本地文件用于保存下载的数据
    localFile, err := os.Create(Dirpath + "test.txt")
    if err != nil {
       fmt.Println("Failed to create local file:", err)
       return
    }
    defer localFile.Close()

    // 将响应数据写入本地文件
    _, err = io.Copy(localFile, resp.Body)
    if err != nil {
       fmt.Println("Failed to save file:", err)
       return
    }

    c.JSON(http.StatusOK, gin.H{
       "message": "Command executed successfully",
    })

}

// UploadTest
func (srv *HttpSrv) UploadTest(c *gin.Context) {
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }

    bucketName := "weed-test-buck"
    //将图片数据上传到weed文件服务
    objectID := "testkey"
    //SeaweedFS 将会下载该文件标识对应的所有文件。
    filePath1 := inParameter.TestUploadPath
    contentType := "application/octet-stream"

    fileContent, err := ioutil.ReadFile(filePath1)
    if err != nil {
       c.JSON(http.StatusInternalServerError, gin.H{
          "error": "Error",
       })
       return
    }
    putS3Object(fileContent, bucketName, contentType, objectID)
    c.JSON(http.StatusOK, gin.H{
       "message": "Command executed successfully",
    })
}
```

```
func (srv *HttpSrv) BaseToHex(c *gin.Context) {////获取链的创世区块哈希,依据cmc查询出来的base64编码的hash
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }
    cmd := exec.Command("./cmc", "util", "base64tohex", inParameter.ChainBaseHash)
    output, err := cmd.CombinedOutput()
    //log.Println(err)
    if err != nil {
       c.JSON(http.StatusInternalServerError, gin.H{
          "error": "Error executing base64tohex command",
       })
       return
    }
    //log.Println(err)
    c.JSON(http.StatusOK, gin.H{
       "output": strings.Replace(string(output), "\n", "", -1),
    })
}
```

```
func (srv *HttpSrv) getChainStatus(c *gin.Context) {//获取节点归档信息
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }
    cmd := exec.Command("./cmc", "archive", "query", "chain-archived-status",
       "--sdk-conf-path", "./bysdk.yml")
    output, err := cmd.CombinedOutput()
    //log.Println(err)
    if err != nil {
       c.JSON(http.StatusInternalServerError, gin.H{
          "error": "Error executing base64tohex command",
       })
       return
    }
    //log.Println(err)
    c.JSON(http.StatusOK, gin.H{
       "output": strings.Replace(string(output), "\n", "", -1),
    })
}
```

```
func (srv *HttpSrv) dumpClean(c *gin.Context) { //清理链上已归档区块文件(不分片),OK
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }
    cmd := exec.Command("./cmc", "archive", "archive", inParameter.ArchiveHeightParameter,
       "--sdk-conf-path", "./bysdk.yml",
       "--timeout", "20")
    //output, err := cmd.Output()
    dumpoutput, err := cmd.CombinedOutput()
    if err != nil {
       c.JSON(http.StatusInternalServerError, gin.H{
          "error": "Error executing dumpclean command",
       })
       return
    }

    c.JSON(http.StatusOK, gin.H{
       "dumpoutput":  string(dumpoutput),
       "cleanHeight": inParameter.ArchiveHeightParameter,
    })
}
```

```
func (srv *HttpSrv) cmcexit(c *gin.Context) {//清理cmc本地缓存文件
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }
    //清理cmc
    //从bin开始
    servicePath := "../service_datas/block_data/"
    Dirpath := servicePath + inParameter.ChainHexHash + "/"
    files, err := ioutil.ReadDir(Dirpath)
    if err != nil {
       fmt.Printf("Error reading folder: %s\n", err.Error())
       return
    }

    var res []string
    for _, file := range files {
       fileName := file.Name()
       if fileName == ".DS_Store" {
          continue
       }
       res = append(res, fileName)
       filePath := filepath.Join(Dirpath, fileName)
       err := os.Remove(filePath)
       if err != nil {
          fmt.Printf("Error deleting file: %s\n", err.Error())
          continue
       }

    }
    c.JSON(http.StatusOK, gin.H{
       "output": "CLean done,exit OK",
       "res":    res,
    })
}
```

```
func (srv *HttpSrv) dump(c *gin.Context) {//只进行dump的测试接口（不上传海草）
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }
    cmd := exec.Command("./cmc", "archive", "dump", inParameter.DumpHeightParameter,
       "--sdk-conf-path", "./bysdk.yml",
       "--mode", "quick")
    output, err := cmd.CombinedOutput()
    cmd.Wait() // 等待命令的退出
    if err != nil {
       c.JSON(http.StatusInternalServerError, gin.H{
          "error": "Error executing dump command",
       })
       return
    }
    c.JSON(http.StatusOK, gin.H{
       "output": string(output),
    })
    cmd.Process.Release() // 显式释放命令的资源
}
```

```
func (srv *HttpSrv) predump(c *gin.Context) {//切换回已经归档过的节点（新节点不用此步骤）
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }

    //sea
    count := 0
    var fileURLs []string
    //从bin开始
    servicePath := "../service_datas/block_data/"
    Dirpath := servicePath + inParameter.ChainHexHash + "/"

    if len(inParameter.ObjectIdsParameter) != len(inParameter.RessParameter) {
       fmt.Println("文件名数组不和海草路径文件一一对应:", err)
       return
    }
    isExist := "首次恢复"
    for count < len(inParameter.ObjectIdsParameter) {
       // 使用Stat函数检查文件是否存在
       _, err = os.Stat(Dirpath + inParameter.RessParameter[count])
       if err == nil {
          isExist = "非首次恢复"
          count++
          continue
       }
       fileURL := inParameter.ObjectIdsParameter[count] // 指定要下载的文件的 URL
       fileURLs = append(fileURLs, fileURL)
       //fileURL := inParameter.SeaweedfsIpParameter + "/" + bucketName + "/" + objectID
       // 发送 GET 请求获取文件数据
       resp, err := http.Get(fileURL)
       if err != nil {
          fmt.Println("Failed to download file:", err)
          return
       }
       defer resp.Body.Close()

       // 创建本地文件用于保存下载的数据
       localFile, err := os.Create(Dirpath + inParameter.RessParameter[count])
       if err != nil {
          fmt.Println("Failed to create local file:", err)
          return
       }
       defer localFile.Close()

       // 将响应数据写入本地文件
       _, err = io.Copy(localFile, resp.Body)
       if err != nil {
          fmt.Println("Failed to save file:", err)
          return
       }
       count++
    }

    c.JSON(http.StatusOK, gin.H{
       // "output":   string(output),
       "message":  "Command executed successfully",
       "fileURLs": fileURLs,
       "Dirpath":  Dirpath,
       "ress":     inParameter.RessParameter,
       "isExist":  isExist,
    })

}
```

```
func (srv *HttpSrv) ybTest(c *gin.Context) {//使用变量控制异步dump
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }
    if notInTask { //启动
       notInTask = false
       taskFinished = false
       go func() {
          cmd := exec.Command("./cmc", "archive", "dump", inParameter.DumpHeightParameter,
             "--sdk-conf-path", "./bysdk.yml",
             "--mode", "quick")
          output, err := cmd.CombinedOutput()
          if err != nil {
             c.JSON(http.StatusInternalServerError, gin.H{
                "error": "Error executing dump command",
             })
             return
          }
          truncated := truncateString(string(output), 88)
          result := "dump任务已完成" + truncated
          var res []string
          var objectIDs []string

          bucketName := inParameter.ChainHexHash + "-" + inParameter.OrgIdParameter
          //bucketName := "asd"
          createBucket(bucketName)
          //从bin开始
          servicePath := "../service_datas/block_data/"
          Dirpath := servicePath + inParameter.ChainHexHash + "/"

          dataImage, err := ioutil.ReadDir(Dirpath)
          if err != nil {
             fmt.Println(err.Error())
          }
          contentType := inParameter.OrgIdParameter

          endPoint1, err := getGlobalVariable("endPoint1")
          if err != nil {
             log.Fatal(err)
          }
          // 遍历文件信息列表
          for _, fileInfo := range dataImage {
             if fileInfo.Name() == ".DS_Store" {
                continue
             }
             // 读取文件内容
             filePath1 := Dirpath + fileInfo.Name()
             fileContent, err := ioutil.ReadFile(filePath1)
             res = append(res, fileInfo.Name())
             if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{
                   "error": "Error",
                })
                return
             }

             objectID1 := endPoint1 + "/" + bucketName + "/" + fileInfo.Name()
             savedPath := fileInfo.Name()
             //i = i + 1
             objectIDs = append(objectIDs, objectID1)
             //解析转义字符
             putS3Object(fileContent, bucketName, contentType, savedPath)
             //}
          }
          time.Sleep(time.Second * 1)
          resultChan <- result
          resChan <- res
          objectidsChan <- objectIDs
       }()

       c.JSON(http.StatusOK, gin.H{
          "message": "dump任务已启动，正在后台执行",
       })
    } else { //被占用情况
       c.JSON(http.StatusOK, gin.H{
          "message": "当前有dump任务在执行，请稍后再试！",
       })
    }

}
```

```
// ybRcv
func (srv *HttpSrv) ybRcv(c *gin.Context) {//异步dump接收数据
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }
    if taskFinished {
       c.JSON(http.StatusOK, gin.H{
          "status":               "DUMP completed",
          "result":               taskResult,
          "ress_parameter":       resResult,
          "object_ids_parameter": objectidsResult,
       })
       notInTask = true
       // 手动触发垃圾回收
       runtime.GC()
       //close(resultChan)
       //close(resChan)
       //close(objectidsChan)
    } else {
       c.JSON(http.StatusOK, gin.H{
          "status": "DUMP in_progress",
       })
    }

}
```

```
func (srv *HttpSrv) ybTest1(c *gin.Context) {//加互斥锁控制异步dump
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }
    taskMutex.Lock()
    defer taskMutex.Unlock()

    if task != nil { // 如果有任务正在执行
       c.JSON(http.StatusOK, gin.H{
          "message": "当前有dump任务在执行，请稍后再试！",
       })
       return
    }

    task = &Task{
       done: make(chan struct{}),
    }

    go func(t *Task) {
       defer func() {
          taskMutex.Lock()
          defer taskMutex.Unlock()

          task = nil // 清除任务

          close(t.done) // 关闭退出通道
       }()

       cmd := exec.Command("./cmc", "archive", "dump", inParameter.DumpHeightParameter,
          "--sdk-conf-path", "./bysdk.yml",
          "--mode", "quick")
       output, err := cmd.CombinedOutput()
       if err != nil {
          c.JSON(http.StatusInternalServerError, gin.H{
             "error": "Error executing dump command",
          })
          return
       }
       truncated := truncateString(string(output), 88)
       result := "dump任务已完成" + truncated
       var res []string
       var objectIDs []string

       bucketName := inParameter.ChainHexHash + "-" + inParameter.OrgIdParameter
       //bucketName := "asd"
       createBucket(bucketName)
       //从bin开始
       servicePath := "../service_datas/block_data/"
       Dirpath := servicePath + inParameter.ChainHexHash + "/"

       dataImage, err := ioutil.ReadDir(Dirpath)
       if err != nil {
          fmt.Println(err.Error())
       }
       contentType := inParameter.OrgIdParameter

       endPoint1, err := getGlobalVariable("endPoint1")
       if err != nil {
          log.Fatal(err)
       }
       // 遍历文件信息列表
       for _, fileInfo := range dataImage {
          if fileInfo.Name() == ".DS_Store" {
             continue
          }
          // 读取文件内容
          filePath1 := Dirpath + fileInfo.Name()
          fileContent, err := ioutil.ReadFile(filePath1)
          res = append(res, fileInfo.Name())
          if err != nil {
             c.JSON(http.StatusInternalServerError, gin.H{
                "error": "Error",
             })
             return
          }

          objectID1 := endPoint1 + "/" + bucketName + "/" + fileInfo.Name()
          savedPath := fileInfo.Name()
          //i = i + 1
          objectIDs = append(objectIDs, objectID1)
          //解析转义字符
          putS3Object(fileContent, bucketName, contentType, savedPath)
          //}
       }
       time.Sleep(time.Second * 1)
       resultChan <- result
       resChan <- res
       objectidsChan <- objectIDs

       // 使用 select 语句监听退出通道，以便在接收到退出信号时退出 goroutine
       select {
       case <-t.done:
          return
       default:
          // 执行任务的逻辑代码
          // ...
       }
    }(task)

    c.JSON(http.StatusOK, gin.H{
       "message": "dump任务已启动，正在后台执行",
    })
}
```

```
func (srv *HttpSrv) getgoruntine(c *gin.Context) {//debug 查看资源消耗接口
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }
    num := runtime.NumGoroutine()
    // 获取当前内存统计信息
    var stats runtime.MemStats
    runtime.ReadMemStats(&stats)

    // 打印内存占用信息
    fmt.Printf("Allocated memory: %d bytes\n", stats.Alloc)
    fmt.Printf("Total memory allocated and not yet freed: %d bytes\n", stats.TotalAlloc)
    fmt.Printf("Heap memory allocated: %d bytes\n", stats.HeapAlloc)
    fmt.Printf("Heap memory system reserved: %d bytes\n", stats.HeapSys)
    fmt.Printf("Number of allocated objects: %d\n", stats.Mallocs)
    fmt.Printf("Number of freed objects: %d\n", stats.Frees)
    c.JSON(http.StatusOK, gin.H{
       "stats.Alloc":       stats.Alloc,
       " stats.TotalAlloc": stats.TotalAlloc,
       "stats.HeapAlloc":   stats.HeapAlloc,
       "stats.HeapSys":     stats.HeapSys,
       "stats.Mallocs":     stats.Mallocs,
       "stats.Frees":       stats.Frees,
       "num":               num,
    })

}
```

```
func (srv *HttpSrv) ybrestoreTest(c *gin.Context) {//异步恢复
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }
    h, err := strconv.Atoi(inParameter.RestoreHeightParameter)
    if err != nil {
       c.JSON(http.StatusInternalServerError, gin.H{
          "error": "高度输入错误!请输入正确的数字",
       })
       return
    }
    if h < 100 {
       c.JSON(http.StatusInternalServerError, gin.H{
          "error": "unarchive height,请选择大于100的合适高度!",
       })
       return
    }
    if notInTask1 { //启动
       notInTask1 = false
       taskFinished1 = false
       go func() {
          //sea
          count := 0
          var fileURLs []string
          //从bin开始
          servicePath := "../service_datas/block_data/"
          Dirpath := servicePath + inParameter.ChainHexHash + "/"
          if len(inParameter.ObjectIdsParameter) != len(inParameter.RessParameter) {
             c.JSON(http.StatusInternalServerError, gin.H{
                "error": "文件名数组不和海草路径文件一一对应!",
             })
             return
          }
          isExist := "首次恢复"
          for count < len(inParameter.ObjectIdsParameter) {
             // 使用Stat函数检查文件是否存在
             _, err = os.Stat(Dirpath + inParameter.RessParameter[count])
             if err == nil {
                isExist = "非首次恢复"
                count++
                continue
             }
             fileURL := inParameter.ObjectIdsParameter[count] // 指定要下载的文件的 URL
             fileURLs = append(fileURLs, fileURL)
             //fileURL := inParameter.SeaweedfsIpParameter + "/" + bucketName + "/" + objectID
             // 发送 GET 请求获取文件数据
             resp, err := http.Get(fileURL)
             if err != nil {
                fmt.Println("Failed to download file:", err)
                return
             }
             defer resp.Body.Close()

             // 创建本地文件用于保存下载的数据
             localFile, err := os.Create(Dirpath + inParameter.RessParameter[count])
             if err != nil {
                fmt.Println("Failed to create local file:", err)
                return
             }
             defer localFile.Close()

             // 将响应数据写入本地文件
             _, err = io.Copy(localFile, resp.Body)
             if err != nil {
                fmt.Println("Failed to save file:", err)
                return
             }
             count++
          }

          // cmc restore
          cmd := exec.Command("../cmc", "archive", "restore", inParameter.RestoreHeightParameter,
             "--timeout", "20",
             "--sdk-conf-path", "./bysdk.yml")

          output, err := cmd.CombinedOutput()
          result := isExist + "restore任务已完成" + string(output)
          if err != nil {
             c.JSON(http.StatusInternalServerError, gin.H{
                "error": "Error executing restore command",
             })
             return
          }
          time.Sleep(time.Second * 1)
          resultChan1 <- result
       }()

       c.JSON(http.StatusOK, gin.H{
          "message": "restore任务已启动，正在后台执行",
       })
    } else { //被占用情况
       c.JSON(http.StatusOK, gin.H{
          "message": "当前有restore任务在执行，请稍后再试！",
       })
    }

}
```

```
func (srv *HttpSrv) ybrestoreRcv(c *gin.Context) {//异步接收
    var inParameter CmcParameter
    err := c.BindJSON(&inParameter)
    if err != nil {
       c.SecureJSON(http.StatusOK, Response{
          ErrorMsg: archive_utils.MsgHttpInvalidParameter,
          Code:     archive_utils.CodeHttpInvalidParameter,
       })
       return
    }
    if taskFinished1 {
       cmd := exec.Command("./cmc", "archive", "query", "chain-archived-status",
          "--sdk-conf-path", "./bysdk.yml")
       output, err := cmd.CombinedOutput()
       //log.Println(err)
       if err != nil {
          c.JSON(http.StatusInternalServerError, gin.H{
             "error": "Error executing chain-archived-status command",
          })
          return
       }
       str := string(output)
       re := regexp.MustCompile(`ArchivePivot:\s*(\d+)`)
       match := re.FindStringSubmatch(str)
       value := ""
       if len(match) > 1 {
          value = match[1]
       } else {
          c.JSON(http.StatusInternalServerError, gin.H{
             "error": "Value not found",
          })
          return
       }
       //从bin开始
       servicePath := "../service_datas/block_data/"
       Dirpath := servicePath + inParameter.ChainHexHash + "/"
       modTime, curTime, err, ising := GetFolderModTime(Dirpath)
       if err != nil {
          log.Fatal(err)
       }
       a, _ := strconv.Atoi(value)
       b, _ := strconv.Atoi(inParameter.RestoreHeightParameter)
       if !ising && a <= b {
          c.JSON(http.StatusOK, gin.H{
             "status":        "Restore completed",
             "completedTime": curTime,
             "startTime":     modTime,
             "value":         value,
             "result":        taskResult1,
          })
          notInTask1 = true
       } else {
          c.JSON(http.StatusOK, gin.H{
             "status": "in_progress-Restore fdb merge",
          })
       }
    } else {
       c.JSON(http.StatusOK, gin.H{
          "status": "in_progress-Restore",
       })
    }

}
```
