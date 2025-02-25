module Main where

import qualified Data.ByteString.Lazy.Char8 as BS1
import qualified Data.ByteString.Lazy as BS
import Serialization
import Data.Binary 
import Data.Binary.Get
import Types
import Test.HUnit
import Data.Binary.Get (runGet)
import qualified Data.ByteString.Char8 as BS2
import qualified Data.ByteString as BS3
import Data.Word (Word16, Word32)
import Data.IP

parseAllType :: BS1.ByteString -> IO()
parseAllType input = case runGetOrFail getDNSType input of
        Left (_,_,err) -> putStrLn $ "解析失败: " ++ err
        Right (remaining,_,typ) -> do 
          putStrLn $ "1解析成功:" ++ show typ
          parseAllType remaining

-- 定义测试用例
tests :: Test
tests = TestList
    [ testA
    , testAAAA
    , testCNAME
    , testMX
    , testSOA
    , testTXT
    , testUnknown
    ]

-- 辅助函数：运行解析器并比较结果
runParser typ rdlen bytes expected = TestCase $
    case runGetOrFail (getDNSRData typ rdlen) bytes of
        Left (_,_,err) -> assertFailure ("Parse failed: " ++ err)
        Right (_,_,actual) -> assertEqual "Parsed result mismatch" expected actual

-- 测试A记录解析
testA :: Test
testA = runParser A 4 (BS.pack [0x7F, 0x00, 0x00, 0x01]) expected
    where
        expected = ARecord (toIPv4 [127,0,0,1])

-- 测试AAAA记录解析
testAAAA :: Test
testAAAA = runParser AAAA 16 (BS.pack [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]) expected
    where
        --expected = AAAARecord (toIPv6w (0x0,0x0,0x0,0x1))
        expected = AAAARecord $ (read "00:00:00:00:00:00:00:01" :: IPv6)

-- 测试CNAME记录解析
testCNAME :: Test
testCNAME = runParser CNAME 11 (BS.pack [7, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 3, 0x63, 0x6F, 0x6D, 0]) expected
    where
        expected = CNAMERecord $ BS2.pack "example.com."

-- 测试MX记录解析
testMX :: Test
testMX = runParser MX (2 + 11) (BS.concat [BS.pack [0x12, 0x34], mxDomain]) expected
    where
        mxDomain = BS.pack [7, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 3, 0x6F, 0x72, 0x67, 0]
        expected = MXRecord 0x1234 $ BS2.pack "example.org."

-- 测试SOA记录解析
testSOA :: Test
testSOA = runParser SOA (2 * 12 + 5 * 4) (BS.concat [mname, rname, serial, refresh, retry, expire, minimum]) expected
    where
        mname = BS.pack [6, 0x6D, 0x6E, 0x61, 0x6D, 0x65, 0x65, 7, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0]
        rname = BS.pack [6, 0x72, 0x6E, 0x61, 0x6D, 0x65, 0x65, 7, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0]
        serial = BS.pack [0x00, 0x00, 0x00, 0x01]
        refresh = BS.pack [0x00, 0x00, 0x00, 0x02]
        retry = BS.pack [0x00, 0x00, 0x00, 0x03]
        expire = BS.pack [0x00, 0x00, 0x00, 0x04]
        minimum = BS.pack [0x00, 0x00, 0x00, 0x05]
        expected = SOARecord (SOAData (BS2.pack "mnamee.example.") (BS2.pack "rnamee.example.") 1 2 3 4 5)

-- 测试TXT记录解析
testTXT :: Test
testTXT = runParser TXT 5 (BS.pack [0x48, 0x65, 0x6C, 0x6C, 0x6F]) expected
    where
        expected = TXTRecord (BS3.pack [0x48, 0x65, 0x6C, 0x6C, 0x6F])

-- 测试未知记录类型解析
testUnknown :: Test
testUnknown = runParser (Other 999) 3 (BS.pack [0xAA, 0xBB, 0xCC]) expected
    where
        expected = UnknownRecord (BS3.pack [0xAA, 0xBB, 0xCC])


main :: IO ()
main = do
    -- test getDNSType 
    let input = "\x00\x01\x00\x02\x00\x03\x00\x05\x00\x06"
    parseAllType (BS1.pack input)

    -- test getDomainName
    let domain = BS.pack [7,101,120,97,109,112,108,101,3,99,111,109,0]
    let result = runGet getDomainName domain
    print result

    counts  <- runTestTT tests
    print counts
          
