module Main where

import qualified Data.ByteString.Lazy.Char8 as BS
import Serialization
import Data.Binary 
import Data.Binary.Get
import Types
  {-
        5 -> CNAME
        6 -> SOA
        12 -> PTR
        15 -> MX
        16 -> TXT
        28 -> AAAA
        _ -> Other typ
        -}

parseAllType :: BS.ByteString -> IO()
parseAllType input = case runGetOrFail getDNSType input of
        Left (_,_,err) -> putStrLn $ "解析失败: " ++ err
        Right (remaining,_,typ) -> do 
          putStrLn $ "1解析成功:" ++ show typ
          parseAllType remaining

main :: IO ()
main = do
    let input = "\x00\x01\x00\x02\x00\x03\x00\x05\x00\x06"
    parseAllType (BS.pack input)
          
