module Main where

import qualified Data.ByteString.Lazy.Char8 as BS
import qualified Data.ByteString.Lazy as BS1
import Serialization
import Data.Binary 
import Data.Binary.Get
import Types

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
    let domain = BS1.pack [7,101,120,97,109,112,108,101,3,99,111,109,0]
    let result = runGet getDomainName domain
    print result
          
