{-# LANGUAGE OverloadedStrings #-}
module Serialization where

import Types
import Data.Binary (Binary, get, put, Word16, Word8)
import Data.Binary.Get (Get, getWord16be, getWord32be, getByteString)
import Data.Binary.Put (Put, putWord16be, putWord32be, putByteString)
import Data.ByteString
import Data.IP

import Data.Bits (shiftR,shiftL, (.&.))
import Data.ByteString (ByteString, cons)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS1
import Data.IP (IPv4, IPv6, toIPv4, toIPv6)
import Data.Binary.Get (
  Get, getWord8, getWord16be, getWord32be,
  getByteString, bytesRead, skip)
import Control.Monad (replicateM)

getDomainName :: Get ByteString
getDomainName = do
  len <- getWord8
  if len == 0
    then return ""
    else do
      label <- getByteString (fromIntegral len)
      rest <- getDomainName
      return $ label `BS.append` "." `BS.append` rest

getDNSType :: Get DNSType
getDNSType = do 
    typ <- getWord16be
    return $ case typ of
        1 -> A
        2 -> NS
        5 -> CNAME
        6 -> SOA
        12 -> PTR
        15 -> MX
        16 -> TXT
        28 -> AAAA
        _ -> Other typ

putDNSType :: DNSType -> Put
putDNSType typ = case typ of
    A -> putWord16be 1
    NS -> putWord16be 2
    CNAME -> putWord16be 5
    SOA -> putWord16be 6
    PTR -> putWord16be 12
    MX -> putWord16be 15
    TXT -> putWord16be 16
    AAAA -> putWord16be 28
    Other typ -> putWord16be typ

getDNSClass :: Get DNSClass
getDNSClass = do
    cls <- getWord16be
    return $ case cls of
        1 -> IN 
        2 -> CS
        3 -> CH
        4 -> HS
        _ -> OtherClass cls

getDNSRData :: DNSType -> Word16 -> Get DNSRData
getDNSRData typ rdlen = case typ of
    A -> parseARecord
    AAAA -> parseAAAARecord
    CNAME -> parseCNAMERecord
    NS -> parseNSRecord
    MX -> parseMXRecord
    TXT -> parseTXTRecord
    SOA -> parseSOARecord
    PTR -> parsePTRRecord
    _ -> parseUnknownRecord
    where
        parseARecord = do
            bytes <- getByteString 4
            return $ ARecord (toIPv4 $ Prelude.map fromIntegral (BS.unpack bytes))
        parseAAAARecord = do
            bytes <- getByteString 16
            return $ AAAARecord (toIPv6b $ Prelude.map fromIntegral (BS.unpack bytes))
        parseCNAMERecord = CNAMERecord <$> getDomainName
        parseNSRecord = NSRecord <$> getDomainName
        parsePTRRecord = PTRRecord <$> getDomainName
        parseMXRecord = do
          preference <- getWord16be
          server <- getDomainName
          return $ MXRecord preference server
        parseTXTRecord = do
          txt <- getByteString (fromIntegral rdlen)
          return $ TXTRecord txt
        parseSOARecord = do
          mname <- getDomainName
          rname <- getDomainName
          serial <- getWord32be
          refresh <- getWord32be
          retry <- getWord32be
          expire <- getWord32be
          minimum <- getWord32be
          return $ SOARecord (SOAData mname rname serial refresh retry expire minimum)
        parseUnknownRecord = UnknownRecord <$> getByteString (fromIntegral rdlen)

getDNSRecord :: Get DNSRecord
getDNSRecord = do 
    name <- getDomainName
    typ <- getDNSType
    cls <- getDNSClass
    ttl <- getWord32be
    rdlen <- getWord16be
    rdata <- getDNSRData typ rdlen
    return $ DNSRecord name typ cls ttl rdata

getDNSQuestion :: Get DNSQuestion
getDNSQuestion = do
    name <- getDomainName
    typ <- getDNSType
    cls <- getDNSClass
    return $ DNSQuestion name typ cls

getDNSHeader :: Get DNSHeader
getDNSHeader = do
    qid <- getWord16be
    flags <- getWord16be
    qdcount <- getWord16be
    ancount <- getWord16be
    nscount <- getWord16be
    arcount <- getWord16be
    return $ DNSHeader qid flags qdcount ancount nscount arcount

getDNSMessage :: Get DNSMessage
getDNSMessage = do
    header <- getDNSHeader
    questions <- replicateM (fromIntegral $ headerQDCount header) getDNSQuestion
    answers <- replicateM (fromIntegral $ headerANCount header) getDNSRecord
    authorities <- replicateM (fromIntegral $ headerNSCount header) getDNSRecord
    additionals <- replicateM (fromIntegral $ headerARCount header) getDNSRecord
    return $ DNSMessage header questions answers authorities additionals
