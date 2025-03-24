{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}
module Main where

import Network.Socket (Socket,SockAddr)
import Data.Binary (Binary(..), decode, encode)
import Data.ByteString.Lazy (ByteString)
import Control.Concurrent (threadDelay)
import Control.Monad (forever)
import GHC.Generics (Generic)
import Data.Word (Word16)
import qualified Data.Map as M
import Control.Concurrent.STM
import Net
import qualified Types as T

-- 定义简单的DNS消息结构
data DNSMessage = DNSMessage {
  transactionId :: Word16,
  isResponse :: Bool,
  query :: String,
  answer :: Maybe String
} deriving (Show, Eq, Generic, Binary)

-- 示例中间件定义
-- 中间件1：请求日志记录
logMiddleware :: DNSMiddleware
logMiddleware = DNSMiddleware 10 $ \pkt -> do
  case decode pkt of
    msg@(DNSMessage tid False q _) -> do
      putStrLn $ "[Request] TransactionID:" ++ show tid ++ " Query:" ++ q
    _ -> return ()
  return pkt

-- 中间件2：响应生成器
responseMiddleware :: DNSMiddleware
responseMiddleware = DNSMiddleware 30 $ \pkt -> do
  case decode pkt of
    msg@(DNSMessage tid False q _) -> do
      let response = DNSMessage tid True q (Just "127.0.0.1")
      putStrLn $ "[Response] Generated answer for:" ++ q
      return $ encode response
    _ -> return pkt

-- 中间件3：模拟缓存
cacheMiddleware :: TVar (M.Map String String) -> DNSMiddleware
cacheMiddleware cacheVar = DNSMiddleware 20 $ \pkt -> do
  case decode pkt of
    msg@(DNSMessage tid False q _) -> do
      cache <- readTVarIO cacheVar
      case M.lookup q cache of
        Just cached -> do
          putStrLn $ "[Cache] Hit for:" ++ q
          let response = DNSMessage tid True q (Just cached)
          return $ encode response
        Nothing -> do
          putStrLn $ "[Cache] Miss for:" ++ q
          return pkt
    _ -> return pkt

-- 测试客户端（在同一程序中模拟）
testClient :: String -> Int -> IO ()
testClient host port = withSocketsDo $ do
  addr <- head <$> getAddrInfo Nothing (Just host) (Just $ show port)
  sock <- socket (addrFamily addr) Datagram defaultProtocol
  
  let sendQuery q = do
        let msg = DNSMessage 1234 False q Nothing
        sendTo sock (encode msg) (addrAddress addr)
        putStrLn $ "\n[Client] Sent query:" ++ q
        
        (response, _) <- recvFrom sock 4096
        case decode response of
          DNSMessage _ True q' (Just a) -> putStrLn $ "[Client] Received answer:" ++ a
          _ -> putStrLn "[Client] Invalid response"
  
  -- 发送测试请求
  sendQuery "example.com"
  threadDelay 1000000
  sendQuery "example.com"  -- 测试缓存命中
  sendQuery "test.org"

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
      cacheMiddleware cache,
      responseMiddleware
    ]
  
  threadDelay 1000000  -- 等待服务器启动
  
  -- 运行测试客户端
  testClient "127.0.0.1" testPort
  
  -- 保持服务器运行
  wait serverAsync

