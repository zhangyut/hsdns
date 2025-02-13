{-# LANGUAGE OverloadedStrings #-}
module Serialization where

import Types
import Data.Binary (Binary, get, put)
import Data.Binary.Get (Get, getWord16be, getWord32be, getByteString)
import Data.Binary.Put (Put, putWord16be, putWord32be, putByteString)

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

getDNSRecord :: Get DNSRecord
getDNSRecord = do 
    name <- getDomainName
    typ <- getDNSType
    cls <- getDNSClass
    ttl <- getWord32be
    rdlen <- getWord16be
    rdata <- getDNSRData typ rdlen
    return $ DNSRecord name typ cls ttl rdata

putDNSRecord :: DNSRecord -> Put
putDNSRecord (DNSRecord name typ cls ttl rdata) = do 
    putDomainName name
    putDNSType typ 
    putDNSClass cla 
    putWrod32be ttl 
    putDNSRData rdata 

getDomainName :: GetByteString
getDomainName = do
    len <- getWord8
    if len == 0
        then return ""
        else do
            label <- getByteString (fromIntegral len)
            rest <- getDomainName
            return $ label `BS.append` "." `BS.append` rest

putDomainName :: ByteString -> Put
putDomainName domain = mapM_ putLabel (BS.split '.' domain)
    where
        putLabel label = do
            putWord8 (fromIntegral $ BS.length label)
            putByteString label
        putWord8 = put . fromIntegral

