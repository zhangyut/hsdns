{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}
module Main where

import Network.Socket (
  getAddrInfo,
  AddrInfo(..),
  defaultProtocol,
  SocketType(..), 
  addrFamily,
  getAddrInfo,
  Socket,
  SockAddr,
  withSocketsDo,
  socket,
  bind,
  close)

import Network.Socket.ByteString (sendTo, recvFrom)

import Data.Binary (Binary(..), decode, encode)
import Data.ByteString.Lazy (ByteString, toStrict, fromStrict)
import Control.Concurrent (threadDelay)
import Control.Monad (forever)
import GHC.Generics (Generic)
import Data.Word (Word16)
import qualified Data.Map as M
import Control.Concurrent.STM
import Control.Concurrent.Async (async, race_, wait)
import Net
import Types
import Data.IP

-- 示例中间件定义
-- 中间件1：请求日志记录
logMiddleware :: DNSMiddleware
logMiddleware = DNSMiddleware 10 $ \pkt -> do
  case decode pkt of
    Right (DNSMessage header (question:_) _ _ _) -> do
      let transactionId = show (headerId header)
          queryName = questionName question
      putStrLn $ "[Request] ID:"
      return pkt
    
    Left err -> do
      putStrLn $ "Decode error: " ++ err
      return pkt
    
    _ -> do
      putStrLn "Invalid DNS message structure"
      return pkt
-- 修正响应生成逻辑
responseMiddleware :: TVar (M.Map String ByteString) -> DNSMiddleware
responseMiddleware cacheVar = DNSMiddleware 30 $ \pkt -> do
  case decode pkt of
    msg@(DNSMessage header [question] _ _ _) -> do
      let response = DNSMessage
            { header = header { headerFlags = 0x8000 }  -- 设置QR位
            , questions = [question]
            , answers = [DNSRecord (questionName question) A IN 300 (ARecord (toIPv4 [127,0,0,1]))]
            , authorities = []
            , additionals = []
            }
      return $ encode response
    _ -> return pkt

-- 主程序
main :: IO ()
main = do
  -- 使用非标准端口避免权限问题
  let testPort = 1053
    
  -- 启动服务器
  putStrLn "Starting DNS server..."
  cache <- newTVarIO M.empty
  serverAsync <- async $ 
    runServer "127.0.0.1" testPort [
      logMiddleware,
      responseMiddleware cache
    ]
  
  threadDelay 1000000  -- 等待服务器启动
  
  -- 保持服务器运行
  wait serverAsync

