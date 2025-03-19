{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}
module Net where

import Network.DNS.Framework
import Data.Binary (Binary(..),decode,encode)
import Data.ByteString.lazy (ByteString)
import Control.Concurrent (threadDelay)
import Control.Monad (forever)
import GHC.Generics (Generic)
import Data.Word (Word16)
import qualified Data.Map as M
import Control.Concurrent.STM
import Types

type DNSPacket = ByteString

data DNSMiddleware = DNSMiddleware {
  middlewarePriority :: Int,
  middlewareHandle :: DNSPacket -> IO DNSPacket
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
