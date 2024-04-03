/*
Copyright (C) BABEC. All rights reserved.


SPDX-License-Identifier: Apache-2.0
*/
//2024/2/26
// Package httpserver define http operation
package httpserver

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"chainmaker.org/chainmaker-go/tools/cmc/src/serverconf"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

const (
	defaultTokenBucketSize = 1000
	defaultTokenPerSecond  = 1000
	// TokenHeader http管理类接口token
	TokenHeader             = "x-token"
	rateLimitHttpTypeGlobal = 0
)

// whiteListMiddleWare 白名单拦截器
func whiteListMiddleWare() gin.HandlerFunc {
	if !serverconf.GlobalServerCFG.HttpCFG.WhiteListConfig.Enabled {
		return func(ctx *gin.Context) {
			ctx.Next()
		}
	}
	whiteAddressMap := make(map[string]struct{})
	for i := 0; i < len(serverconf.GlobalServerCFG.HttpCFG.WhiteListConfig.Address); i++ {
		tempAddress := serverconf.GlobalServerCFG.HttpCFG.WhiteListConfig.Address[i]
		whiteAddressMap[strings.TrimSpace(tempAddress)] = struct{}{}
	}
	return func(ctx *gin.Context) {
		ip := getClientIp(ctx)
		_, ok := whiteAddressMap[ip]
		if !ok {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		ctx.Next()
	}
}

func getClientIp(ctx *gin.Context) string {
	sendIpPort := ctx.Request.RemoteAddr
	fmt.Println("ip is : ", sendIpPort)
	seps := strings.Split(sendIpPort, ":")
	if len(seps) != 2 {
		return ""
	}
	return strings.TrimSpace(seps[0])
}

// rateLimitMiddleWare 限流器
func rateLimitMiddleWare() gin.HandlerFunc {
	if !serverconf.GlobalServerCFG.HttpCFG.RateLimitConfig.Enabled {
		return func(ctx *gin.Context) {
			ctx.Next()
		}
	}
	tokenBucketSize := serverconf.GlobalServerCFG.HttpCFG.RateLimitConfig.TokenBucketSize
	tokenPerSecond := serverconf.GlobalServerCFG.HttpCFG.RateLimitConfig.TokenPerSecond
	rateLimitType := serverconf.GlobalServerCFG.HttpCFG.RateLimitConfig.Type
	bucketMap := sync.Map{}
	return func(ctx *gin.Context) {
		ipAddr := getClientIp(ctx)
		bucket := getRateLimitBucket(&bucketMap, rateLimitType,
			tokenBucketSize, tokenPerSecond, ipAddr)
		if bucket != nil && !bucket.Allow() {
			ctx.AbortWithStatus(http.StatusTooManyRequests)
			return
		}
		ctx.Next()
	}
}

// getRateLimitBucket 根据ip计算令牌筒
func getRateLimitBucket(bucketMap *sync.Map, rateLimitType, tokenBucketSize,
	tokenPerSecond int, peerIpAddr string) *rate.Limiter {
	var (
		bucket interface{}
		ok     bool
	)

	if rateLimitType == rateLimitHttpTypeGlobal {
		if bucket, ok = bucketMap.Load(rateLimitHttpTypeGlobal); ok {
			return bucket.(*rate.Limiter)
		}
	} else {
		if bucket, ok = bucketMap.Load(peerIpAddr); ok {
			return bucket.(*rate.Limiter)
		}
	}

	if tokenBucketSize >= 0 && tokenPerSecond >= 0 {
		if tokenBucketSize == 0 {
			tokenBucketSize = defaultTokenBucketSize
		}
		if tokenPerSecond == 0 {
			tokenPerSecond = defaultTokenPerSecond
		}
		bucket = rate.NewLimiter(rate.Limit(tokenPerSecond), tokenBucketSize)
	} else {
		return nil
	}
	if rateLimitType == rateLimitHttpTypeGlobal {
		bucket, _ = bucketMap.LoadOrStore(rateLimitHttpTypeGlobal, bucket)
	} else {
		bucketMap.LoadOrStore(peerIpAddr, bucket)
	}
	return bucket.(*rate.Limiter)
}

// tokenMiddleWare 返回token验证中间件
func (srv *HttpSrv) tokenMiddleWare() gin.HandlerFunc {
	httpToken := srv.ProxyProcessor.GetHttpToken()
	return func(ctx *gin.Context) {
		token := ctx.GetHeader(TokenHeader)
		if strings.TrimSpace(token) != httpToken {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		ctx.Next()
	}
}
