{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}
module Net where

import Network.Socket hiding (recvFrom, sendTo)
import Network.Socket.ByteString (recvFrom, sendTo)
import Data.Binary (decode,encode)
import qualified Data.ByteString.Lazy as Lazy
import Control.Monad (forever)
import GHC.Generics (Generic)
import Data.Word (Word16)
import qualified Data.Map as M
import Control.Concurrent.STM
import Control.Concurrent.Async 
import Control.Monad
import Data.List (sortOn)

import Types

type DNSPacket = Lazy.ByteString

data DNSMiddleware = DNSMiddleware {
  middlewarePriority :: Int,
  middlewareHandler :: DNSPacket -> IO DNSPacket
}

data FrameworkState = FrameworkState {
  middlewares :: TVar [DNSMiddleware],
  requestQueue :: TQueue (Socket, SockAddr, DNSPacket)
}

newFrameworkState :: IO FrameworkState
newFrameworkState = do
  m <- newTVarIO []
  q <- newTQueueIO
  return $ FrameworkState m q

addMiddleware :: FrameworkState -> DNSMiddleware -> IO ()
addMiddleware state middleware = atomically $ do
  modifyTVar' (middlewares state) (insertByPriority middleware)
  where
    insertByPriority m [] = [m]
    insertByPriority m (x:xs)
      | middlewarePriority m < middlewarePriority x = m : x : xs
      | otherwise = x : insertByPriority m xs

receiver :: Socket -> TQueue (Socket, SockAddr, DNSPacket) -> IO ()
receiver sock queue = forever $ do
  (strictPkt, addr) <- Network.Socket.ByteString.recvFrom sock 4096
  let lazyPkt = Lazy.fromStrict strictPkt
  atomically $ writeTQueue queue (sock, addr, lazyPkt)

processingPipeline :: FrameworkState -> IO ()
processingPipeline state = forever $ do
  (sock, addr, pkt) <- atomically $ readTQueue (requestQueue state)
  async $ do
    ms <- atomically $ readTVar (middlewares state)
    processed <- applyMiddlewares ms pkt
    sendResponse sock addr processed

applyMiddlewares :: [DNSMiddleware] -> DNSPacket -> IO DNSPacket
applyMiddlewares ms pkt = foldM applyMiddleware pkt (sortOn middlewarePriority ms)
  where
    applyMiddleware pkt' m = middlewareHandler m pkt'

sendResponse :: Socket -> SockAddr -> DNSPacket -> IO ()
sendResponse sock addr pkt = do
  let encodedStrict = Lazy.toStrict (encode pkt)
  _ <- Network.Socket.ByteString.sendTo sock encodedStrict addr
  return ()

runServer :: String -> Int -> [DNSMiddleware] -> IO ()
runServer host port initialMiddlewares = withSocketsDo $ do
  addr <- head <$> getAddrInfo Nothing (Just host) (Just $ show port)
  sock <- socket (addrFamily addr) Datagram defaultProtocol
  bind sock (addrAddress addr)

  state <- newFrameworkState
  mapM_ (addMiddleware state) initialMiddlewares

  race_ (receiver sock (requestQueue state))
        (replicateConcurrently 16 (processingPipeline state))

