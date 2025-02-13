module Main where

import qualified Data.ByteString.Char8 as BS
import Serialization
import Types

main :: IO ()
main = do
    let input = "\x00\x01"
    case runGetOrFail getDNSType (BS.pack input) of
        Left err -> putStrLn $ "解析失败: " ++ err
        Right (_,_,typ) -> putStrLn $ "解析成功: " ++ show tpy
