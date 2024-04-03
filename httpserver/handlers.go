/*
Copyright (C) BABEC. All rights reserved.


SPDX-License-Identifier: Apache-2.0
*/

// Package httpserver define http operation
package httpserver

import (
	"bytes"
	"chainmaker.org/chainmaker-go/tools/cmc/src/archive_utils"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/gin-gonic/gin"
	yaml "gopkg.in/yaml.v2"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	//shell "github.com/ipfs/go-ipfs-api"
	"io/ioutil"
	//"log"
	"net/http"
	//"os"
	"os/exec"

	//seaweedfs
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
)

// dump
var (
	resultChan      chan string //
	resChan         chan []string
	objectidsChan   chan []string
	taskFinished    bool     // 任务完成状态
	notInTask       bool     // 有任务在执行
	taskResult      string   // 任务结果
	resResult       []string // 任务结果
	objectidsResult []string // 任务结果
)

type Task struct {
	done chan struct{} // 退出通道
}

var (
	taskMutex sync.Mutex // 互斥锁，用于保护任务状态
	task      *Task      // 当前任务
)

// restore
var (
	resultChan1      chan string //
	resChan1         chan []string
	objectidsChan1   chan []string
	taskFinished1    bool     // 任务完成状态
	notInTask1       bool     // 有任务在执行
	taskResult1      string   // 任务结果
	resResult1       []string // 任务结果
	objectidsResult1 []string // 任务结果
)

// QueryParameter http的查询信息
type QueryParameter struct {
	ChainGenesisHash string `json:"chain_genesis_hash,omitempty"`
	Start            uint64 `json:"start,omitempty"`
	End              uint64 `json:"end,omitempty"`
	BlockHash        string `json:"block_hash,omitempty"`
	ByteBlockHash    []byte
	Height           uint64 `json:"height,omitempty"`
	TxId             string `json:"tx_id,omitempty"`
	WithRwSet        bool   `json:"with_rwset,omitempty"`
	TruncateLength   int    `json:"truncate_length,omitempty"`
	TruncateModel    string `json:"truncate_model,omitempty"`
}

// Response 通用http返回信息
type Response struct {
	Code     int         `json:"code,omitempty"` // 错误码,0代表成功.其余代表失败
	ErrorMsg string      `json:"errorMsg,omitempty"`
	Data     interface{} `json:"data,omitempty"`
}

// cmc 封装cmc的http参数信息
// 使用小写字母开头的私有字段标签，这可能导致在 JSON 编码和解码时无法正确处理该字段!
type CmcParameter struct {
	TestParameter          string `json:"test_parameter,omitempty"`
	TestWriteParameter     string `json:"test_write_parameter,omitempty"`
	DumpHeightParameter    string `json:"dump_height_parameter,omitempty"`    //dump高度
	ArchiveHeightParameter string `json:"archive_height_parameter,omitempty"` //archive高度
	RestoreHeightParameter string `json:"restore_height_parameter,omitempty"` //restore高度
	RebuildDbsParameter    string `json:"rebuild_dbs_parameter,omitempty"`    //数据恢复工具路径
	ChainBaseHash          string `json:"chain_base_hash,omitempty"`          //cmc查询出来的base64编码的hash
	ChainHexHash           string `json:"chain_hex_hash,omitempty"`           //链的hex hash
	CmcCleanHeight         string `json:"cmc_clean_height,omitempty"`         //cmc清理的高度

	//seaweedfs
	SeaPathParameter      string   `json:"sea_path_parameter,omitempty"`             //文件路径
	SeaSavedPathParameter string   `json:"sea_saved_path_parameter,omitempty"`       //文件保存路径
	SeaGetParameter       string   `json:"sea_get_parameter,omitempty"`              //文件标识
	SeaNameParameter      string   `json:"sea_name_parameter,omitempty"`             //文件名
	SeaTypeParameter      string   `json:"sea_type_parameter,omitempty,default=fdb"` //文件类型
	DumpCleanPath         string   `json:"dump_clean_path,omitempty"`                //区块路径
	BuckNameParameter     string   `json:"buck_name_parameter,omitempty"`            //桶标识
	ObjectIdsParameter    []string `json:"object_ids_parameter,omitempty"`           //拼接字符串数组
	RessParameter         []string `json:"ress_parameter,omitempty"`                 //文件名数组
	SeaweedfsIpParameter  string   `json:"seaweedfs_ip_parameter,omitempty"`         //分布式存储的ip  格式为：IP:端口:连接数 例如http://127.0.0.1:8333

	//sdkconfig
	UserIdParameter      string   `json:"user_id_parameter,omitempty"`       //一个用户一个sdk文件
	SdkConfigParameter   string   `json:"sdk_config_parameter,omitempty"`    //config路径
	ChainIdParameter     string   `json:"chain_id_parameter,omitempty"`      //链ID
	OrgIdParameter       string   `json:"org_id_parameter,omitempty"`        //组织ID
	CrtFilePath          string   `json:"crt_file_path,omitempty"`           //客户端用户私钥路径
	KeyFilePath          string   `json:"key_file_path,omitempty"`           //客户端用户私钥密码
	CrtEncFilePath       string   `json:"crt_enc_file_path,omitempty"`       //客户端用户证书路径
	KeyEncFilePath       string   `json:"key_enc_file_path,omitempty"`       //客户端用户加密私钥路径
	CrtSignFilePath      string   `json:"crt_sign_file_path,omitempty"`      //客户端用户加密证书路径
	KeySignFilePath      string   `json:"key_sign_file_path,omitempty"`      //客户端用户交易签名私钥路径
	NodeAddr             string   `json:"node_addr,omitempty"`               //节点地址，格式为：IP:端口:连接数 例如http://127.0.0.1:8333
	TrustRootPath        []string `json:"trust_root_path,omitempty"`         // 信任证书池路径
	TlsHostName          string   `json:"tls_host_name,omitempty"`           // TLS hostname
	ChainGenesisHash     string   `json:"chain_genesis_hash,omitempty"`      // 归档的链的块高为0的区块hash(hex编码)
	ArchiveCenterHttpUrl string   `json:"archive_center_http_url,omitempty"` // 归档http服务地址
	RpcAddr              string   `json:"rpc_addr,omitempty"`                // 归档rpc服务地址

	//test
	TestPath       string `json:"test_path,omitempty"`        // 下载的地址
	TestUploadPath string `json:"test_upload_path,omitempty"` //上传文件路径
	//trust
	TrustCrtPath string `json:"trust_crt_path,omitempty"` // 下载的地址
	TrustKeyPath string `json:"trust_key_path,omitempty"` // 下载的地址
}

var (
	caFileName = "ca_name"
)

// GetChainInfos 查询归档中心所有的链信息
func (srv *HttpSrv) GetChainInfos(ginContext *gin.Context) {
	chainStatuses := srv.ProxyProcessor.GetAllChainInfo()
	ginContext.JSONP(http.StatusOK, Response{
		Data: chainStatuses,
	})
}

// dump
func (srv *HttpSrv) dump(c *gin.Context) {
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

func (srv *HttpSrv) version(c *gin.Context) {
	var inParameter CmcParameter
	err := c.BindJSON(&inParameter)
	if err != nil {
		c.SecureJSON(http.StatusOK, Response{
			ErrorMsg: archive_utils.MsgHttpInvalidParameter,
			Code:     archive_utils.CodeHttpInvalidParameter,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"version": "用来确认是否新版本3.27",
	})
}

// predump
func (srv *HttpSrv) predump(c *gin.Context) {
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
		//	"output":   string(output),
		"message":  "Command executed successfully",
		"fileURLs": fileURLs,
		"Dirpath":  Dirpath,
		"ress":     inParameter.RessParameter,
		"isExist":  isExist,
	})

}
func (srv *HttpSrv) getgoruntine(c *gin.Context) {
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
func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length]
}

// ybtest
func (srv *HttpSrv) ybTest1(c *gin.Context) {
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

func (srv *HttpSrv) ybTest(c *gin.Context) {
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

// ybRcv
func (srv *HttpSrv) ybRcv(c *gin.Context) {
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

// restore
func (srv *HttpSrv) restore(c *gin.Context) {
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

	// cmc restore
	cmd := exec.Command("../cmc", "archive", "restore", inParameter.RestoreHeightParameter,
		"--timeout", "20",
		"--sdk-conf-path", "./bysdk.yml")

	output, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Error executing restore command",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"output":   string(output),
		"message":  "Command executed successfully",
		"fileURLs": fileURLs,
		"Dirpath":  Dirpath,
		"ress":     inParameter.RessParameter,
		"isExist":  isExist,
	})

}

func GetFolderModTime(folderPath string) (time.Time, time.Time, error, bool) {
	isIng := false
	fileInfo, err := os.Stat(folderPath)
	if err != nil {
		return time.Time{}, time.Time{}, err, true
	}
	modTime := fileInfo.ModTime()
	curTime := time.Now()
	duration := curTime.Sub(modTime)
	if duration < time.Minute {
		isIng = true
	}
	err = filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			duration := curTime.Sub(info.ModTime())
			if duration < time.Minute {
				isIng = true
			}
		}
		return nil
	})
	if err != nil {
		return time.Time{}, time.Time{}, err, true
	}
	return modTime, curTime, nil, isIng
}

func (srv *HttpSrv) onlyrestore(c *gin.Context) {
	var inParameter CmcParameter
	err := c.BindJSON(&inParameter)
	if err != nil {
		c.SecureJSON(http.StatusOK, Response{
			ErrorMsg: archive_utils.MsgHttpInvalidParameter,
			Code:     archive_utils.CodeHttpInvalidParameter,
		})
		return
	}

	cmd := exec.Command("../cmc", "archive", "restore", inParameter.RestoreHeightParameter,
		"--timeout", "20",
		"--sdk-conf-path", "./bysdk.yml")

	output, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Error executing restore command",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"output":  string(output),
		"message": "Command executed successfully",
	})

}
func (srv *HttpSrv) GetGenesisBlockHash(c *gin.Context) {
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
		//	"output":          string(output),
		"blockBase64Hash": blockHash,
	})
}

// base64 to hex
func (srv *HttpSrv) BaseToHex(c *gin.Context) {
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

// getChainStatus
func (srv *HttpSrv) getChainStatus(c *gin.Context) {
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

// 定义全局变量结构体
type Globals struct {
	Ak       string `yaml:"ak"`
	Sk       string `yaml:"sk"`
	EndPoint string `yaml:"endPoint"`
	Region   string `yaml:"region"`
	//	Test     string `yaml:"test"`
	EndPoint1 string `yaml:"endPoint1"`
}

// seaweedfs
var (
	//ak       = "1"                     //文件服务分配的账号
	//sk       = "2"                     //文件服务分配的秘钥
	//endPoint = "http://127.0.0.1:8333" //上图weed S3服务的地址
	//region   = "test.com"              //适用范围
	svc *s3.S3
)

//公司
/*
var (
	ak       = "admin"                       //文件服务分配的账号
	sk       = "diEvRU6eQez123456Dkkpo4srS"  //文件服务分配的秘钥
	endPoint = "http://192.168.100.137:30455" //上图weed S3服务的地址
	region   = "us-west-2"                   //适用范围
	svc      *s3.S3
)
*/
// 加载YAML文件并返回全局变量结构体
func loadGlobals() (*Globals, error) {
	// 读取YAML文件内容
	content, err := ioutil.ReadFile("seaweedfs.yml")
	if err != nil {
		return nil, err
	}

	// 解析YAML为结构体对象
	var globals Globals
	err = yaml.Unmarshal(content, &globals)
	if err != nil {
		return nil, err
	}

	return &globals, nil
}

// 获取指定变量的值
func getGlobalVariable(variableName string) (string, error) {
	globals, err := loadGlobals()
	if err != nil {
		return "", err
	}
	switch variableName {
	case "ak":
		return globals.Ak, nil
	case "sk":
		return globals.Sk, nil
	case "endPoint":
		return globals.EndPoint, nil
	case "endPoint1":
		return globals.EndPoint1, nil
	case "region":
		return globals.Region, nil
	default:
		return "", fmt.Errorf("unknown variable: %s", variableName)
	}
}

func init() {
	//读入全局变量
	ak, err := getGlobalVariable("ak")
	if err != nil {
		log.Fatal(err)
	}
	sk, err := getGlobalVariable("sk")
	if err != nil {
		log.Fatal(err)
	}
	endPoint, err := getGlobalVariable("endPoint")
	if err != nil {
		log.Fatal(err)
	}
	//endPoint1, err := getGlobalVariable("endPoint1")
	//if err != nil {
	//	log.Fatal(err)
	//}
	region, err := getGlobalVariable("region")
	if err != nil {
		log.Fatal(err)
	}
	cres := credentials.NewStaticCredentials(ak, sk, "")
	cfg := aws.NewConfig().WithRegion(region).WithEndpoint(endPoint).WithCredentials(cres).WithS3ForcePathStyle(true)
	sess, err := session.NewSession(cfg)
	if err != nil {
		fmt.Println(err)
	}
	svc = s3.New(sess)
}

func createBucket(bucketName string) {
	input := &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	}
	result, err := svc.CreateBucket(input)
	fmt.Println(result)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeBucketAlreadyExists:
				fmt.Println(s3.ErrCodeBucketAlreadyExists, aerr.Error())
			case s3.ErrCodeBucketAlreadyOwnedByYou:
				fmt.Println(s3.ErrCodeBucketAlreadyOwnedByYou, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}
}

func putS3Object(dataImage []byte, bucketName, contentType, objectID string) {

	inputObject := &s3.PutObjectInput{
		Bucket:      aws.String(bucketName),
		Key:         aws.String(objectID),
		ContentType: aws.String(contentType),
		Body:        bytes.NewReader(dataImage),
	}
	resp, err := svc.PutObject(inputObject)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(resp)
}

func getS3Object(bucketName, objectID string) []byte {

	inputObject := &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectID),
	}
	out, err := svc.GetObject(inputObject)
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}
	res, err := ioutil.ReadAll(out.Body)
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}
	return res
}

func deleteS3Object(bucketName, objectID string) {
	params := &s3.DeleteObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectID),
	}

	resp, err := svc.DeleteObject(params)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(resp)
}

/*
// seadumpSaveTest
func (srv *HttpSrv) seadump(c *gin.Context) {
	var inParameter CmcParameter
	err := c.BindJSON(&inParameter)
	if err != nil {
		c.SecureJSON(http.StatusOK, Response{
			ErrorMsg: archive_utils.MsgHttpInvalidParameter,
			Code:     archive_utils.CodeHttpInvalidParameter,
		})
		return
	}
	var res []string
	var objectIDs []string
	//创建桶
	bucketName := inParameter.BuckNameParameter //桶的名称也是存取这个桶下面数据的唯一标识
	createBucket(bucketName)
	//将图片数据上传到weed文件服务
	objectID := inParameter.SeaGetParameter //文件唯一标识 ,用户要记住!

	//SeaweedFS 将会下载该文件标识对应的所有文件。
	//当多个文件共享相同的文件标识时，它们被视为同一文件的不同版本或副本。

	//从bin开始
	servicePath := "../service_datas/block_data/"
	Dirpath := servicePath + inParameter.ChainHexHash + "/"

	dataImage, err := ioutil.ReadDir(Dirpath)
	if err != nil {
		fmt.Println(err.Error())
	}
	contentType := "application/octet-stream"
	var i = 1
	// 遍历文件信息列表
	for _, fileInfo := range dataImage {
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
		str := strconv.Itoa(i)
		objectID1 := objectID + str
		i = i + 1
		objectIDs = append(objectIDs, objectID1)
		putS3Object(fileContent, bucketName, contentType, objectID1)
	}
	//log.Println(err)
	c.JSON(http.StatusOK, gin.H{
		"ResourceId": bucketName + "/" + inParameter.SeaGetParameter,
		"output":     "Save done",
		"res":        res,
		"objectIDs":  objectIDs,
	})
}
*/
/*
// seadumpGetTest
func (srv *HttpSrv) seaGet(c *gin.Context) {
	var inParameter CmcParameter
	err := c.BindJSON(&inParameter)
	if err != nil {
		c.SecureJSON(http.StatusOK, Response{
			ErrorMsg: archive_utils.MsgHttpInvalidParameter,
			Code:     archive_utils.CodeHttpInvalidParameter,
		})
		return
	}

	bucketName := inParameter.BuckNameParameter //桶的名称也是存取这个桶下面数据的唯一标识
	objectID := inParameter.SeaGetParameter
	// 指定要下载的文件的 URL
	fileURL := inParameter.SeaweedfsIpParameter + "/" + bucketName + "/" + objectID

	// 发送 GET 请求获取文件数据
	resp, err := http.Get(fileURL)
	if err != nil {
		fmt.Println("Failed to download file:", err)
		return
	}
	defer resp.Body.Close()

	//从bin开始
	servicePath := "../service_datas/block_data/"
	Dirpath := servicePath + inParameter.ChainHexHash + "/"

	// 创建本地文件用于保存下载的数据
	localFile, err := os.Create(Dirpath + inParameter.SeaNameParameter + "." + inParameter.SeaTypeParameter)
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

	fmt.Println("File downloaded successfully!")
	c.JSON(http.StatusOK, gin.H{
		"output":   "Get done",
		"fileURL":  fileURL,
		"Dirpath":  Dirpath,
		"fileName": inParameter.SeaNameParameter + "." + inParameter.SeaTypeParameter,
	})
}
*/
// dumpClean
func (srv *HttpSrv) dumpClean(c *gin.Context) {
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

// cmcexit

func (srv *HttpSrv) cmcexit(c *gin.Context) {
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

func (srv *HttpSrv) sdkInit(c *gin.Context) {
	var inParameter CmcParameter
	err := c.BindJSON(&inParameter)
	if err != nil {
		c.SecureJSON(http.StatusOK, Response{
			ErrorMsg: archive_utils.MsgHttpInvalidParameter,
			Code:     archive_utils.CodeHttpInvalidParameter,
		})
		return
	}

	//判断是否已经存在
	relativePath := inParameter.UserIdParameter + "sdk.yml"
	// 获取文件的绝对路径
	absolutePath, err := filepath.Abs(relativePath)
	// 检查文件是否已经存在
	_, err = os.Stat(absolutePath)
	if err == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "文件已存在，无需生成。",
			"path":  absolutePath,
		})
		return
	}
	// 创建并打开文件
	file, err := os.Create(inParameter.UserIdParameter + "sdk.yml")
	if err != nil {
		log.Fatal("Failed to create file:", err)
	}
	defer file.Close()
	data := "chain_client:\n  # 链ID\n  chain_id: \"chain1\"\n  # 组织ID\n  org_id: \"wx-org1.chainmaker.org\"\n  # 客户端用户私钥路径\n  user_key_file_path: \"./testdata/crypto-config/wx-org1.chainmaker.org/user/admin1/admin1.tls.key\"\n  # 客户端用户私钥密码(无密码则不需要设置)\n#  user_key_pwd: \"123\"\n  # 客户端用户证书路径\n  user_crt_file_path: \"./testdata/crypto-config/wx-org1.chainmaker.org/user/admin1/admin1.tls.crt\"\n  # 客户端用户加密私钥路径(tls加密证书对应私钥，应用于国密GMTLS双证书体系；若未设置仅使用单证书）\n  user_enc_key_file_path: \"./testdata/crypto-config/wx-org1.chainmaker.org/user/admin1/admin1.tls.enc.key\"\n  # 客户端用户加密私钥密码(无密码则不需要设置)\n#  user_enc_key_pwd: \"123\"\n  # 客户端用户加密证书路径(tls加密证书，应用于国密GMTLS双证书体系；若未设置仅使用单证书）\n  user_enc_crt_file_path: \"./testdata/crypto-config/wx-org1.chainmaker.org/user/admin1/admin1.tls.enc.crt\"\n  # 客户端用户交易签名私钥路径(若未设置，将使用user_key_file_path)\n  user_sign_key_file_path: \"./testdata/crypto-config/wx-org1.chainmaker.org/user/admin1/admin1.sign.key\"\n  # 客户端用户交易签名私钥密码(无密码则不需要设置)\n#  user_sign_key_pwd: \"123\"\n  # 客户端用户交易签名证书路径(若未设置，将使用user_crt_file_path)\n  user_sign_crt_file_path: \"./testdata/crypto-config/wx-org1.chainmaker.org/user/admin1/admin1.sign.crt\"\n  # 同步交易结果模式下，轮询获取交易结果时的最大轮询次数，删除此项或设为<=0则使用默认值 10\n  retry_limit: 20\n  # 同步交易结果模式下，每次轮询交易结果时的等待时间，单位：ms 删除此项或设为<=0则使用默认值 500\n  retry_interval: 500\n  # 当前签名证书的别名。当设置此配置项时，chain client 对象将自动检查链上是否已添加此别名，如果没有则自动上链此证书别名，\n  # 并且后续所有交易都会使用别名，别名可降低交易体大小。若为空则不启用。\n#  alias: my_cert_alias\n  # txid配置项：默认支持TimestampKey，如果开启enableNormalKey则使用NormalKey\n  enable_normal_key: false\n\n  enable_tx_result_dispatcher: true\n\n  nodes:\n    - # 节点地址，格式为：IP:端口:连接数\n      node_addr: \"127.0.0.1:12301\"\n      # 节点连接数\n      conn_cnt: 10\n      # RPC连接是否启用双向TLS认证\n      enable_tls: true\n      # 信任证书池路径\n      trust_root_paths:\n        - \"./testdata/crypto-config/wx-org1.chainmaker.org/ca\"\n      # TLS hostname\n      tls_host_name: \"chainmaker.org\"\n  archive:\n    # 数据归档链外存储相关配置\n    # 如果使用了新版本的归档中心,这个地方配置为archivecenter\n    type: \"archivecenter\"  # archivecenter 归档中心, mysql mysql数据库\n    dest: \"root:123456:localhost:3306\"\n    secret_key: xxx\n  rpc_client:\n    max_receive_message_size: 100 # grpc客户端接收消息时，允许单条message大小的最大值(MB)\n    max_send_message_size: 100 # grpc客户端发送消息时，允许单条message大小的最大值(MB)\n    send_tx_timeout: 60 # grpc 客户端发送交易超时时间\n    get_tx_timeout: 60 # rpc 客户端查询交易超时时间\n  pkcs11:\n    enabled: false # pkcs11 is not used by default\n    library: /usr/local/lib64/pkcs11/libupkcs11.so # path to the .so file of pkcs11 interface\n    label: HSM # label for the slot to be used\n    password: 11111111 # password to logon the HSM(Hardware security module)\n    session_cache_size: 10 # size of HSM session cache, default to 10\n    hash: \"SHA256\" # hash algorithm used to compute SKI  \n  # # 如果启用了归档中心,可以打开下面的归档中心配置  \n  archive_center_query_first: false # 如果为true且归档中心配置打开,那么查询数据优先从归档中心查询\n  archive_center_config:\n    chain_genesis_hash: 472dc822e15c483534cc1a1b587df8c8825f4982084b05afd50c1187d958c6c0  #归档的链的块高为0的区块hash(hex编码)\n    archive_center_http_url: http://127.0.0.1:13119 # 归档中心http服务地址,\n    request_second_limit: 10 # 归档中心http请求超时时间,秒单位\n    rpc_address: 127.0.0.1:13120 #归档中心rpc服务地址\n    tls_enable: false # 不开启grpc的tls的时候,如下配置可忽略\n    tls:\n      server_name: archiveserver1.tls.wx-org.chainmaker.org # 归档中心tls服务注册的名称\n      priv_key_file: ./testdata/archivecenter/archiveadmin1.tls.key  # cmc侧做tls的私钥\n      cert_file: ./testdata/archivecenter/archiveadmin1.tls.crt  # cmc侧做tls的证书\n      trust_ca_list:\n        - ./testdata/archivecenter/ca.crt    # 归档中心服务根证书\n    max_send_msg_size: 200  # grpc 发送最大消息(MB为单位)\n    max_recv_msg_size: 200 # grpc 接收最大消息(MB为单位)"
	byteData := []byte(data)
	// 将 YAML 数据写入文件
	_, err = file.Write(byteData)
	if err != nil {
		log.Fatal("Failed to write YAML data to file:", err)
	}

	if err != nil {
		log.Fatal("Failed to get absolute path:", err)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Error executing ",
		})
		return
	}
	//log.Println(err)
	c.JSON(http.StatusOK, gin.H{
		"output":  "sdkgene done",
		"sdkPath": absolutePath,
	})
}

type Config struct {
	ChainClient struct {
		ChainID                  string              `yaml:"chain_id"`
		OrgID                    string              `yaml:"org_id"`
		UserKeyFilePath          string              `yaml:"user_key_file_path"`
		UserCrtFilePath          string              `yaml:"user_crt_file_path"`
		UserSignKeyFilePath      string              `yaml:"user_sign_key_file_path"`
		UserSignCrtFilePath      string              `yaml:"user_sign_crt_file_path"`
		RetryLimit               int                 `yaml:"retry_limit,omitempty"`
		RetryInterval            int                 `yaml:"retry_interval,omitempty"`
		EnableNormalKey          bool                `yaml:"enable_normal_key,omitempty"`
		EnableTxResultDispatcher bool                `yaml:"enable_tx_result_dispatcher,omitempty"`
		Nodes                    []Node              `yaml:"nodes"`
		Archive                  Archive             `yaml:"archive"`
		RPCClient                RPCClient           `yaml:"rpc_client"`
		PKCS11                   PKCS11              `yaml:"pkcs11"`
		ArchiveCenterQueryFirst  bool                `yaml:"archive_center_query_first,omitempty"`
		ArchiveCenterConfig      ArchiveCenterConfig `yaml:"archive_center_config,omitempty"`
	} `yaml:"chain_client"`
}

type Node struct {
	NodeAddr       string   `yaml:"node_addr"`
	ConnCnt        int      `yaml:"conn_cnt"`
	EnableTLS      bool     `yaml:"enable_tls"`
	TrustRootPaths []string `yaml:"trust_root_paths"`
	TLSHostName    string   `yaml:"tls_host_name"`
}

type Archive struct {
	Type      string `yaml:"type"`
	Dest      string `yaml:"dest"`
	SecretKey string `yaml:"secret_key"`
}

type RPCClient struct {
	MaxReceiveMessageSize int `yaml:"max_receive_message_size"`
	MaxSendMessageSize    int `yaml:"max_send_message_size"`
	SendTxTimeout         int `yaml:"send_tx_timeout"`
	GetTxTimeout          int `yaml:"get_tx_timeout"`
}

type PKCS11 struct {
	Enabled          bool   `yaml:"enabled"`
	Library          string `yaml:"library"`
	Label            string `yaml:"label"`
	Password         string `yaml:"password"`
	SessionCacheSize int    `yaml:"session_cache_size"`
	Hash             string `yaml:"hash"`
}

type ArchiveCenterConfig struct {
	ChainGenesisHash     string    `yaml:"chain_genesis_hash"`
	ArchiveCenterHTTPURL string    `yaml:"archive_center_http_url"`
	RequestSecondLimit   int       `yaml:"request_second_limit"`
	RPCAddress           string    `yaml:"rpc_address"`
	TLSEnable            bool      `yaml:"tls_enable"`
	TLS                  TLSConfig `yaml:"tls"`
	MaxSendMsgSize       int       `yaml:"max_send_msg_size"`
	MaxRecvMsgSize       int       `yaml:"max_recv_msg_size"`
}

type TLSConfig struct {
	ServerName     string   `yaml:"server_name"`
	PrivateKeyFile string   `yaml:"priv_key_file"`
	CertFile       string   `yaml:"cert_file"`
	TrustCAList    []string `yaml:"trust_ca_list"`
}

func (srv *HttpSrv) sdkConfig(c *gin.Context) {

	var inParameter CmcParameter
	err := c.BindJSON(&inParameter)
	if err != nil {
		c.SecureJSON(http.StatusOK, Response{
			ErrorMsg: archive_utils.MsgHttpInvalidParameter,
			Code:     archive_utils.CodeHttpInvalidParameter,
		})
		return
	}

	relativePath := "bysdk.yml"
	// 获取文件的绝对路径
	absolutePath, err := filepath.Abs(relativePath)
	// 检查文件是否已经存在
	_, err = os.Stat(absolutePath)
	var isExist = "配置文件已生成!"
	if err == nil {
		isExist = "配置文件已修改!"
	}
	// 创建并打开文件
	file, err := os.Create(relativePath)
	if err != nil {
		log.Fatal("Failed to create file:", err)
	}
	//defer file.Close()
	data := "chain_client:\n  chain_id: chain1\n  org_id: wx-org2.chainmaker.org\n  user_key_file_path: ./testdata/crypto-config/wx-orgby.chainmaker.org/user/admin1/admin1.tls.key\n  user_crt_file_path: ./testdata/crypto-config/wx-orgby.chainmaker.org/user/admin1/admin1.tls.crt\n  user_sign_key_file_path: ./testdata/crypto-config/wx-orgby.chainmaker.org/user/admin1/admin1.sign.key\n  user_sign_crt_file_path: ./testdata/crypto-config/wx-orgby.chainmaker.org/user/admin1/admin1.sign.crt\n  retry_limit: 20\n  retry_interval: 500\n  enable_tx_result_dispatcher: true\n  nodes:\n  - node_addr: 127.0.0.1:12302\n    conn_cnt: 10\n    enable_tls: true\n    trust_root_paths:\n    - ./testdata/crypto-config/wx-orgby.chainmaker.org/ca\n    tls_host_name: chainmaker.org\n  archive:\n    type: archivecenter\n    dest: root:123456:localhost:3306\n    secret_key: xxx\n  rpc_client:\n    max_receive_message_size: 100\n    max_send_message_size: 100\n    send_tx_timeout: 60\n    get_tx_timeout: 60\n  pkcs11:\n    enabled: false\n    library: /usr/local/lib64/pkcs11/libupkcs11.so\n    label: HSM\n    password: \"11111111\"\n    session_cache_size: 10\n    hash: SHA256\n  archive_center_config:\n    chain_genesis_hash: \n    archive_center_http_url: http://127.0.0.1:13119\n    request_second_limit: 10\n    rpc_address: 127.0.0.1:13120\n    tls_enable: false\n    tls:\n      server_name: archiveserver1.tls.wx-org.chainmaker.org\n      priv_key_file: ./testdata/archivecenter/archiveadmin1.tls.key\n      cert_file: ./testdata/archivecenter/archiveadmin1.tls.crt\n      trust_ca_list:\n      - ./testdata/archivecenter/ca.crt\n    max_send_msg_size: 200\n    max_recv_msg_size: 200\n"
	byteData := []byte(data)
	// 将 YAML 数据写入文件
	_, err = file.Write(byteData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Error executing ",
		})
		return
	}
	file.Close()

	// 读取 YAML 文件
	yamlFile, err := ioutil.ReadFile(absolutePath)
	if err != nil {
		log.Fatalf("Failed to read YAML file: %v", err)
	}

	// 解析 YAML 文件
	var config Config
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Failed to parse YAML file: %v", err)
	}

	// 修改 yml 配置
	config.ChainClient.ChainID = inParameter.ChainIdParameter
	config.ChainClient.OrgID = inParameter.OrgIdParameter
	//config.ChainClient.UserKeyFilePath = inParameter.KeyFilePath
	//config.ChainClient.UserCrtFilePath = inParameter.CrtFilePath
	//config.ChainClient.UserEncCrtFilePath = inParameter.CrtEncFilePath
	//config.ChainClient.UserEncKeyFilePath = inParameter.KeyEncFilePath
	//config.ChainClient.UserSignKeyFilePath = inParameter.KeySignFilePath
	//config.ChainClient.UserSignCrtFilePath = inParameter.CrtSignFilePath
	config.ChainClient.Nodes[0].NodeAddr = inParameter.NodeAddr
	/*
		if inParameter.TrustRootPath != nil {
			arr := []string{""}
			arr[0] = inParameter.TrustRootPath
			config.ChainClient.Nodes[0].TrustRootPaths = arr
		}*/
	//config.ChainClient.Nodes[0].TrustRootPaths = inParameter.TrustRootPath
	config.ChainClient.Nodes[0].TLSHostName = inParameter.TlsHostName
	//config.ChainClient.ArchiveCenterConfig.ChainGenesisHash = inParameter.ChainGenesisHash
	config.ChainClient.ArchiveCenterConfig.ArchiveCenterHTTPURL = inParameter.ArchiveCenterHttpUrl
	config.ChainClient.ArchiveCenterConfig.RPCAddress = inParameter.RpcAddr
	// 将修改后的配置转换为 YAML 格式
	modifiedYAML, err := yaml.Marshal(&config)
	if err != nil {
		log.Fatalf("Failed to marshal YAML: %v", err)
	}
	// 将修改后的配置写入文件
	err = ioutil.WriteFile(relativePath, modifiedYAML, 0644)
	if err != nil {
		log.Fatalf("Failed to write YAML file: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"output":  "sdkConfig done",
		"sdkPath": absolutePath,
		"isExist": isExist,
	})
}

// GetCertTest
func (srv *HttpSrv) GetCertTest(c *gin.Context) {
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

// GetCert
func (srv *HttpSrv) GetCert(c *gin.Context) {
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
func (srv *HttpSrv) sdkHashConfig(c *gin.Context) {
	var inParameter CmcParameter
	err := c.BindJSON(&inParameter)
	if err != nil {
		c.SecureJSON(http.StatusOK, Response{
			ErrorMsg: archive_utils.MsgHttpInvalidParameter,
			Code:     archive_utils.CodeHttpInvalidParameter,
		})
		return
	}
	relativePath := "bysdk.yml"
	// 获取文件的绝对路径
	absolutePath, err := filepath.Abs(relativePath)
	// 检查文件是否已经存在
	_, err = os.Stat(absolutePath)
	var isExist = "文件未生成,修改失败"
	if err == nil {
		isExist = "配置文件已修改!"
		// 读取 YAML 文件
		yamlFile, err := ioutil.ReadFile(absolutePath)
		if err != nil {
			log.Fatalf("Failed to read YAML file: %v", err)
		}

		// 解析 YAML 文件
		var config Config
		err = yaml.Unmarshal(yamlFile, &config)
		if err != nil {
			log.Fatalf("Failed to parse YAML file: %v", err)
		}

		// 修改 yml 配置
		config.ChainClient.ArchiveCenterConfig.ChainGenesisHash = inParameter.ChainGenesisHash
		// 将修改后的配置转换为 YAML 格式
		modifiedYAML, err := yaml.Marshal(&config)
		if err != nil {
			log.Fatalf("Failed to marshal YAML: %v", err)
		}
		// 将修改后的配置写入文件
		err = ioutil.WriteFile(relativePath, modifiedYAML, 0644)
		if err != nil {
			log.Fatalf("Failed to write YAML file: %v", err)
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"sdkPath": absolutePath,
		"isExist": isExist,
	})
}

// sdkDownload
func (srv *HttpSrv) sdkDownload(c *gin.Context) {
	var inParameter CmcParameter
	err := c.BindJSON(&inParameter)
	if err != nil {
		c.SecureJSON(http.StatusOK, Response{
			ErrorMsg: archive_utils.MsgHttpInvalidParameter,
			Code:     archive_utils.CodeHttpInvalidParameter,
		})
		return
	}

	fileURL := inParameter.KeyFilePath // 指定要下载的文件的 URL
	// 发送 GET 请求获取文件数据
	resp, err := http.Get(fileURL)
	if err != nil {
		fmt.Println("Failed to download file:", err)
		return
	}
	defer resp.Body.Close()
	// 创建本地文件用于保存下载的数据
	localFile, err := os.Create("./testdata/crypto-config/wx-orgby.chainmaker.org/user/admin1/admin1.tls.key")
	if err != nil {
		fmt.Println("Failed to create local file:", err)
		return
	}
	defer localFile.Close()

	// 将响应数据写入本地文件
	_, err = io.Copy(localFile, resp.Body)
	if err != nil {
		fmt.Println("Failed to save keyfile:", err)
		return
	}

	fileURL1 := inParameter.CrtFilePath // 指定要下载的文件的 URL
	// 发送 GET 请求获取文件数据
	resp1, err := http.Get(fileURL1)
	if err != nil {
		fmt.Println("Failed to download file:", err)
		return
	}
	defer resp1.Body.Close()
	// 创建本地文件用于保存下载的数据
	localFile1, err := os.Create("./testdata/crypto-config/wx-orgby.chainmaker.org/user/admin1/admin1.tls.crt")
	if err != nil {
		fmt.Println("Failed to create local file:", err)
		return
	}
	defer localFile1.Close()

	// 将响应数据写入本地文件
	_, err = io.Copy(localFile1, resp1.Body)
	if err != nil {
		fmt.Println("Failed to save crtfile:", err)
		return
	}

	fileURL2 := inParameter.KeySignFilePath // 指定要下载的文件的 URL
	// 发送 GET 请求获取文件数据
	resp2, err := http.Get(fileURL2)
	if err != nil {
		fmt.Println("Failed to download file:", err)
		return
	}
	defer resp2.Body.Close()
	// 创建本地文件用于保存下载的数据
	localFile2, err := os.Create("./testdata/crypto-config/wx-orgby.chainmaker.org/user/admin1/admin1.sign.key")
	if err != nil {
		fmt.Println("Failed to create local file:", err)
		return
	}
	defer localFile2.Close()

	// 将响应数据写入本地文件
	_, err = io.Copy(localFile2, resp2.Body)
	if err != nil {
		fmt.Println("Failed to save signfile:", err)
		return
	}

	fileURL3 := inParameter.TrustCrtPath // 指定要下载的文件的 URL
	// 发送 GET 请求获取文件数据
	resp3, err := http.Get(fileURL3)
	if err != nil {
		fmt.Println("Failed to download file:", err)
		return
	}
	defer resp3.Body.Close()
	// 创建本地文件用于保存下载的数据
	localFile3, err := os.Create("./testdata/crypto-config/wx-orgby.chainmaker.org/ca/ca.crt")
	if err != nil {
		fmt.Println("Failed to create local file:", err)
		return
	}
	defer localFile3.Close()

	// 将响应数据写入本地文件
	_, err = io.Copy(localFile3, resp3.Body)
	if err != nil {
		fmt.Println("Failed to save signfile:", err)
		return
	}

	fileURL4 := inParameter.CrtSignFilePath // 指定要下载的文件的 URL
	// 发送 GET 请求获取文件数据
	resp4, err := http.Get(fileURL4)
	if err != nil {
		fmt.Println("Failed to download file:", err)
		return
	}
	defer resp4.Body.Close()
	// 创建本地文件用于保存下载的数据
	localFile4, err := os.Create("./testdata/crypto-config/wx-orgby.chainmaker.org/user/admin1/admin1.sign.crt")
	if err != nil {
		fmt.Println("Failed to create local file:", err)
		return
	}
	defer localFile4.Close()

	// 将响应数据写入本地文件
	_, err = io.Copy(localFile4, resp4.Body)
	if err != nil {
		fmt.Println("Failed to save crtsignfile:", err)
		return
	}

	fileURL5 := inParameter.TrustKeyPath // 指定要下载的文件的 URL
	// 发送 GET 请求获取文件数据
	resp5, err := http.Get(fileURL5)
	if err != nil {
		fmt.Println("Failed to download file:", err)
		return
	}
	defer resp5.Body.Close()
	// 创建本地文件用于保存下载的数据
	localFile5, err := os.Create("./testdata/crypto-config/wx-orgby.chainmaker.org/ca/ca.key")
	if err != nil {
		fmt.Println("Failed to create local file:", err)
		return
	}
	defer localFile5.Close()

	// 将响应数据写入本地文件
	_, err = io.Copy(localFile5, resp5.Body)
	if err != nil {
		fmt.Println("Failed to save trustkeyfile:", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Command executed successfully",
	})

}

// sdkTest
func (srv *HttpSrv) sdkTest(c *gin.Context) {
	var inParameter CmcParameter
	err := c.BindJSON(&inParameter)
	if err != nil {
		c.SecureJSON(http.StatusOK, Response{
			ErrorMsg: archive_utils.MsgHttpInvalidParameter,
			Code:     archive_utils.CodeHttpInvalidParameter,
		})
		return
	}

	// 获取全局变量的值
	ak, err := getGlobalVariable("ak")
	if err != nil {
		log.Fatal(err)
	}
	sk, err := getGlobalVariable("sk")
	if err != nil {
		log.Fatal(err)
	}
	endPoint, err := getGlobalVariable("endPoint")
	if err != nil {
		log.Fatal(err)
	}
	region, err := getGlobalVariable("region")
	if err != nil {
		log.Fatal(err)
	}
	c.JSON(http.StatusOK, gin.H{
		"ak":       ak,
		"sk":       sk,
		"endPoint": endPoint,
		"region":   region,
	})

}

func (srv *HttpSrv) ybrestoreTest(c *gin.Context) {
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

func (srv *HttpSrv) ybrestoreRcv(c *gin.Context) {
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
