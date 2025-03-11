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
import qualified Test.Tasty as TT
import qualified Test.Tasty.HUnit as TTH

testGetDNSClass :: BS.ByteString -> DNSClass -> Test
testGetDNSClass input expected = TestCase $
  assertEqual ("应解析为 " ++ show expected) expected (runGet getDNSClass input)

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
testAAAA = runParser AAAA 16 (BS.pack [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01]) expected
    where
        expected = AAAARecord (toIPv6w (0x0,0x0,0x0,0x1))

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

testGetDNSType :: BS.ByteString -> DNSType -> Test
testGetDNSType input expected = TestCase $
  assertEqual ("输入" ++ show input ++ " 应解析为 " ++ show expected)
    expected
    (runGet getDNSType input)

-- 测试空域名
testEmptyDomain :: Test
testEmptyDomain = 
  runGet getDomainName (BS.pack [0x00]) ~?= BS3.empty


-- 测试 www
testSingleLabel :: Test
testSingleLabel = 
  let 
    input = BS.pack [0x03, 0x77, 0x77, 0x77, 0x00]
    expected = BS3.pack [0x77, 0x77, 0x77, 0x2E]
  in
    runGet getDomainName input ~?= expected

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
    , testGetDNSClass (BS.pack [0x00, 0x01]) IN
    , testGetDNSClass (BS.pack [0x00, 0x02]) CS 
    , testGetDNSClass (BS.pack [0x00, 0x03]) CH
    , testGetDNSClass (BS.pack [0x00, 0x04]) HS
    , testGetDNSClass (BS.pack [0x00, 0x05]) (OtherClass 5)
    , testGetDNSClass (BS.pack [0xFF, 0xFF]) (OtherClass 0xFFFF)
    , testGetDNSType (BS.pack [0x00, 0x01]) A
    , testGetDNSType (BS.pack [0x00, 0x02]) NS
    , testGetDNSType (BS.pack [0x00, 0x05]) CNAME
    , testGetDNSType (BS.pack [0x00, 0x06]) SOA
    , testGetDNSType (BS.pack [0x00, 0x0C]) PTR
    , testGetDNSType (BS.pack [0x00, 0x0F]) MX
    , testGetDNSType (BS.pack [0x00, 0x10]) TXT
    , testGetDNSType (BS.pack [0x00, 0x1C]) AAAA
    , testGetDNSType (BS.pack [0x00, 0x00]) (Other 0)
    , testGetDNSType (BS.pack [0x00, 0x03]) (Other 3)
    , testGetDNSType (BS.pack [0x03, 0xE7]) (Other 999)
    , testGetDNSType (BS.pack [0xFF, 0xFF]) (Other 0xFFFF)
    , testEmptyDomain
    , testSingleLabel
    ]

testSuite :: TT.TestTree
testSuite = TT.testGroup "DNSRecord Parser"
  [ testARecord
--  , testCNAMERecord
--  , testMXRecord
--  , testTXTRecord
--  , testEmptyName
--  , testInvalidLength
  ]

domainEncode :: String -> ByteString
domainEncode "example.com" = BS1.pack [7,0x65,0x78,0x61,0x6D,0x70,0x6C,0x65,3,0x63,0x6F,0x6D,0x00]
domainEncode _ = error "Unimplemented domain encoder"

testARecord :: TT.TestTree
testARecord = TTH.testCase "Parse A record" $ do
  let input = domainEncode "example.com"
      <> BS3.pack [0x00, 0x01]
      <> BS3.pack [0x00, 0x01]
      <> BS3.pack [0x00, 0x00, 0x0E, 0x10]
      <> BS3.pack [0x00, 0x04]
      <> BS3.pack [0xC0, 0x00, 0x02, 0x01]

  let expected = DNSRecord {
      recordName = domainEncode "example.com"
      , recordType = A
      , recordClass = IN
      , recordTTL = 3600
      , recordData = ARecord (toIPv4 [127,0,0,1])
  }
  parsed <- runGet getDNSRecord input
  parsed @?= expected

main :: IO ()
main = do
    -- test getDomainName
    let domain = BS.pack [7,101,120,97,109,112,108,101,3,99,111,109,0]
    let result = runGet getDomainName domain
    print result

    counts  <- runTestTT tests
    print counts
          
