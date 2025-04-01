{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
module Types where

import Data.Word (Word8, Word16, Word32)
import Data.ByteString (ByteString)
import Data.IP (IPv4, IPv6)
import Data.Bits (shiftR, (.&.))
import qualified Data.ByteString.Char8 as BS
import Data.Binary (Binary(..), putWord8, getWord8)
import Data.Binary.Put (putWord16be)
import Data.Binary.Get (getWord16be)
import GHC.Generics (Generic)
import Data.IP (toIPv4w, toIPv6w)
import Data.Bits (shiftR, (.&.))
import Data.IP (IPv4, IPv6, toIPv4w, toIPv6w)
import Control.Monad (replicateM)

toOctets :: IP -> [Word8]
toOctets (IPv4 addr) = let (a, b, c, d) = toIPv4w addr in [fromIntegral a, fromIntegral b, fromIntegral c, fromIntegral d]
toOctets _ = error "Not an IPv4 address"

toWord16s :: IP -> [Word16]
toWord16s (IPv6 addr) = let (a, b, c, d, e, f, g, h) = toIPv6w addr in [a, b, c, d, e, f, g, h]
toWord16s _ = error "Not an IPv6 address"

instance Binary IPv4 where
    put ip = mapM_ putWord8 (toOctets (IPv4 ip))
    get = toIPv4 <$> (replicateM 4 getWord8 >>= \ws -> return (fromIntegral <$> ws))

instance Binary IPv6 where
    put ip = mapM_ putWord16be (toWord16s (IPv6 ip))
    get = toIPv6 <$> (replicateM 8 getWord16be >>= \ws -> return (fromIntegral <$> ws))



data DNSType
    = A
    | NS
    | CNAME
    | SOA
    | PTR
    | MX
    | TXT
    | AAAA
    | Other Word16
    deriving (Show, Eq, Generic)

instance Binary DNSType where
    put A = putWord8 1
    put NS = putWord8 2
    put CNAME = putWord8 5
    put SOA = putWord8 6
    put PTR = putWord8 12
    put MX = putWord8 15
    put TXT = putWord8 16
    put AAAA = putWord8 28
    put (Other code) = putWord16be code

    get = do
        tag <- getWord8
        case tag of
            1 -> return A
            2 -> return NS
            5 -> return CNAME
            6 -> return SOA
            12 -> return PTR
            15 -> return MX
            16 -> return TXT
            28 -> return AAAA
            _ -> Other <$> getWord16be

data DNSClass
    = IN
    | CS
    | CH
    | HS
    | OtherClass Word16
    deriving (Show, Eq, Generic)

instance Binary DNSClass where
    put IN = putWord16be 1
    put CS = putWord16be 2
    put CH = putWord16be 3
    put HS = putWord16be 4
    put (OtherClass code) = putWord16be code

    get = do
        tag <- getWord16be
        case tag of
            1 -> return IN
            2 -> return CS
            3 -> return CH
            4 -> return HS
            _ -> OtherClass <$> getWord16be

data DNSRecord = DNSRecord 
    { recordName :: ByteString
    , recordType :: DNSType
    , recordClass :: DNSClass
    , recordTTL :: Word32
    , recordData :: DNSRData
    } deriving (Show, Eq, Generic)

instance Binary DNSRecord where
    put (DNSRecord name typ cls ttl rdata) = do
        put name
        put typ
        put cls
        put ttl
        put rdata
    get = DNSRecord <$> get <*> get <*> get <*> get <*> get

data DNSRData
    = ARecord IPv4
    | AAAARecord IPv6
    | CNAMERecord ByteString
    | NSRecord ByteString
    | MXRecord Word16 ByteString
    | TXTRecord ByteString
    | SOARecord SOAData
    | PTRRecord ByteString
    | UnknownRecord ByteString
    deriving (Show, Eq, Generic)

instance Binary DNSRData where
    put (ARecord ipv4) = putWord8 1 >> put ipv4
    put (AAAARecord ipv6) = putWord8 2 >> put ipv6
    put (CNAMERecord bs) = putWord8 3 >> put bs
    put (NSRecord bs) = putWord8 4 >> put bs
    put (MXRecord priority bs) = putWord8 5 >> put priority >> put bs
    put (TXTRecord bs) = putWord8 6 >> put bs
    put (SOARecord soa) = putWord8 7 >> put soa
    put (PTRRecord bs) = putWord8 8 >> put bs
    put (UnknownRecord bs) = putWord8 9 >> put bs

    get = do
        tag <- getWord8
        case tag of
            1 -> ARecord <$> get
            2 -> AAAARecord <$> get
            3 -> CNAMERecord <$> get
            4 -> NSRecord <$> get
            5 -> MXRecord <$> get <*> get
            6 -> TXTRecord <$> get
            7 -> SOARecord <$> get
            8 -> PTRRecord <$> get
            _ -> UnknownRecord <$> get

data SOAData = SOAData
    { soaMName :: ByteString
    , soaRName :: ByteString
    , soaSerial :: Word32
    , soaRefresh :: Word32
    , soaRetry :: Word32
    , soaExpire :: Word32
    , soaMinimum :: Word32
    } deriving (Show, Eq, Generic)

instance Binary SOAData where
    put (SOAData mName rName serial refresh retry expire minimum) = do
        put mName
        put rName
        put serial
        put refresh
        put retry
        put expire
        put minimum
    get = SOAData <$> get <*> get <*> get <*> get <*> get <*> get <*> get

data DNSHeader = DNSHeader
    { headerId :: Word16
    , headerFlags :: Word16
    , headerQDCount :: Word16
    , headerANCount :: Word16
    , headerNSCount :: Word16
    , headerARCount :: Word16
    } deriving (Show, Eq, Generic)

data DNSQuestion = DNSQuestion
    { questionName :: ByteString
    , questionType :: DNSType
    , questionClass :: DNSClass
    } deriving (Show, Eq, Generic)

data DNSMessage = DNSMessage
    { header :: DNSHeader
    , questions :: [DNSQuestion]
    , answers :: [DNSRecord]
    , authorities :: [DNSRecord]
    , additionals :: [DNSRecord]
    } deriving (Show, Eq, Generic)
instance Binary DNSMessage
instance Binary DNSHeader
instance Binary DNSQuestion
