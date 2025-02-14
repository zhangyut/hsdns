{-# LANGUAGE OverloadedStrings #-}
module Types where

import Data.Word (Word8, Word16, Word32)
import Data.ByteString (ByteString)
import Data.IP
import Data.IPv6
import qualified Data.ByteString.Char8 as BS

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
    deriving (Show, Eq)

data DNSClass
    = IN
    | CS
    | CH
    | HS
    | OtherClass Word16
    deriving (Show, Eq)

data DNSRecord = DNSRecord 
    { recordName :: ByteString
    , recordType :: DNSType
    , recordClass :: DNSClass
    , recordTTL :: Word32
    , recordData :: DNSRData
    } deriving (Show, Eq)

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
    deriving (Show, Eq)

data SOAData = SOAData
    { soaMName :: ByteString
    , soaRName :: ByteString
    , soaSerial :: Word32
    , soaRefresh :: Word32
    , soaRetry :: Word32
    , soaExpire :: Word32
    , soaMinimum :: Word32
    } deriving (Show, Eq)

data DNSHeader = DNSHeader
    { headerId :: Word16
    , headerFlags :: Word16
    , headerQDCount :: Word16
    , headerANCount :: Word16
    , headerNSCount :: Word16
    , headerARCount :: Word16
    } deriving (Show, Eq)

data DNSQuestion = DNSQuestion
    { questionName :: ByteString
    , questionType :: DNSType
    , questionClass :: DNSClass
    } deriving (Show, Eq)

data DNSMessage = DNSMessage
    { header :: DNSHeader
    , questions :: [DNSQuestion]
    , answers :: [DNSRecord]
    , authorities :: [DNSRecord]
    , additionals :: [DNSRecord]
    } deriving (Show, Eq)

