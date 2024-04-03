/*
Copyright (C) BABEC. All rights reserved.


SPDX-License-Identifier: Apache-2.0
*/

// Package httpserver define http operation
package httpserver

import (
	"chainmaker.org/chainmaker-go/tools/cmc/src/logger"
	"chainmaker.org/chainmaker-go/tools/cmc/src/process"
	"chainmaker.org/chainmaker-go/tools/cmc/src/serverconf"
	"fmt"
	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
)

// HttpSrv http服务结构
type HttpSrv struct {
	router         *gin.Engine
	ProxyProcessor *process.ProcessorMgr
	ApiSrv         *http.Server
	logger         *logger.WrappedLogger
}

// NewHttpServer 构造新的http服务器
func NewHttpServer(proxy *process.ProcessorMgr) *HttpSrv {
	gin.SetMode(gin.ReleaseMode)
	apiLog := logger.NewLogger("APISERVICE", &serverconf.LogConfig{
		LogPath:      fmt.Sprintf("%s/apiservice.log", serverconf.GlobalServerCFG.LogCFG.LogPath),
		LogLevel:     serverconf.GlobalServerCFG.LogCFG.LogLevel,
		LogInConsole: serverconf.GlobalServerCFG.LogCFG.LogInConsole,
		ShowColor:    serverconf.GlobalServerCFG.LogCFG.ShowColor,
		MaxSize:      serverconf.GlobalServerCFG.LogCFG.MaxSize,
		MaxBackups:   serverconf.GlobalServerCFG.LogCFG.MaxBackups,
		MaxAge:       serverconf.GlobalServerCFG.LogCFG.MaxAge,
		Compress:     serverconf.GlobalServerCFG.LogCFG.Compress,
	})
	return &HttpSrv{
		router:         gin.New(),
		ProxyProcessor: proxy,
		logger:         apiLog,
	}
}

// Listen 开启http监听
func (srv *HttpSrv) Listen(apiCfg serverconf.HttpConfig) {
	if serverconf.GlobalServerCFG.HttpCFG.WhiteListConfig.Enabled {
		srv.router.Use(gin.Recovery(), whiteListMiddleWare(), rateLimitMiddleWare(), gzip.Gzip(gzip.DefaultCompression))
	} else {
		srv.router.Use(gin.Recovery(), rateLimitMiddleWare(), gzip.Gzip(gzip.DefaultCompression))
	}

	srv.registerRouters()
	srv.ApiSrv = &http.Server{
		Addr:    fmt.Sprintf(":%d", apiCfg.Port),
		Handler: srv.router,
	}
	go func() {
		if err := srv.ApiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, " http server start error , %s \n", err.Error())
		}
	}()

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
	//	archiveGroup.POST("/restore", srv.restoreListen)
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
