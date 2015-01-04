{-# LANGUAGE OverloadedStrings, FlexibleContexts #-}

import Control.Applicative ((<$>), (<*>), (<$), (<*), some)
import Control.Concurrent
import Control.Exception hiding (try)
import Control.Monad
import Data.Bits
import Data.Char
import Data.IP
import Data.List
import Data.Maybe
import Data.Yaml.YamlLight
import Network.Socket
import Safe
import System.Console.GetOpt
import System.Directory
import System.Environment
import System.FilePath.Posix
import Text.Appar.String
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8

data Record = Record { community :: String
                     , rawData   :: B.ByteString
                     , yaml      :: YamlLight
                     } deriving (Show, Eq)

data Database = Database { asns      :: [(Int, Record)]
                         , ip6ranges :: [(AddrRange IPv6, Record)]
                         , ip4ranges :: [(AddrRange IPv4, Record)]
                         , domains   :: [(String, Record)]
                         } deriving (Show)

data Query = ASNQuery Int
           | IP6Query (AddrRange IPv6)
           | IP4Query (AddrRange IPv4)
           | DomainQuery String
           deriving (Show)

readYamlFile :: FilePath -> IO (Maybe Record)
readYamlFile p = catch read' handler
  where read' = do
                  d <- B.readFile p
                  d' <- parseYamlBytes d
                  return $ Just $ Record (takeBaseName p) d d'
        handler :: SomeException -> IO (Maybe Record)
        handler _ = return Nothing

readAllFiles :: FilePath -> IO [Record]
readAllFiles p = do
        d <- liftM (map $ (</>) p) $ getDirectoryContents p
        liftM catMaybes $ sequence $ map readYamlFile d

buildDatabase :: [Record] -> Database
buildDatabase rs = Database asn ip6ranges ip4ranges domains
  where
    asn = filterMap' ["asn"] (\x -> unStr x >>= readMay . B8.unpack) rs
    ip6ranges = concat . map (\(x,y) -> zip x (cycle [y])) $ filterMap' ["networks", "ipv6"] (liftM (catMaybes . map (\x -> unStr x >>= readMay . B8.unpack)) . unSeq) rs
    ip4ranges = concat . map (\(x,y) -> zip x (cycle [y])) $ filterMap' ["networks", "ipv4"] (liftM (catMaybes . map (\x -> unStr x >>= readMay . B8.unpack)) . unSeq) rs
    domains = concat . map (\(x,y) -> zip x (cycle [y])) $ filterMap' ["domains"] (liftM (map B8.unpack . catMaybes . map unStr) . unSeq) rs

filterMap' f g = filterMap (lookupYLDeep f . yaml) g

lookupYLDeep :: [B.ByteString] -> YamlLight -> Maybe YamlLight
lookupYLDeep tokens x = foldl (>>=) (return x) $ map (lookupYL . YStr) tokens

filterMap :: (a -> Maybe YamlLight) -> (YamlLight -> Maybe d) -> [a] -> [(d, a)]
filterMap f g = catMaybes . map f' 
  where
    f' x = f x >>= g >>= \x' -> Just (x', x)

printRecord :: Record -> String
printRecord r = "# " ++ (community r) ++ "\n" ++ yaml
  where
    yaml = B8.unpack $ rawData r

queryDatabase :: Database -> Query -> [Record]
queryDatabase db (ASNQuery q) = map snd . filter ((==) q . fst) . asns $ db
queryDatabase db (IP6Query q) = map snd . filter (flip (>:>) q . fst) . ip6ranges $ db
queryDatabase db (IP4Query q) = map snd . filter (flip (>:>) q . fst) . ip4ranges $ db
queryDatabase db (DomainQuery q) = map snd . filter ((==) q . fst) . domains $ db

positiveNatural :: Parser Int
positiveNatural = 
    foldl' (\a i -> a * 10 + digitToInt i) 0 <$> some digit

parseASN :: Parser Query
parseASN = string "AS" >> ASNQuery <$> positiveNatural

parseDomain :: Parser Query
parseDomain = DomainQuery <$> many (alphaNum <|> char '-')

parseIP6 = IP6Query <$> ip6range
parseIP4 = IP4Query <$> ip4range

parseQuery :: Parser Query
parseQuery = choice $ map try [parseASN, parseIP6, parseIP4, parseDomain]

queryDatabase' :: Database -> String -> Maybe [Record]
queryDatabase' db q = parse parseQuery q >>= return . nub . (queryDatabase db)

printResults :: [Record] -> String
printResults [] = "No match found."
printResults xs = concat $ map printRecord xs

query :: Database -> String -> String
query db s = case queryDatabase' db s of
                 Nothing -> "Invalid query."
                 Just r  -> printResults r

options :: [OptDescr (Options -> IO Options)]
options =
  [ Option ['p'] ["port"]     
    (ReqArg (\arg opt -> return opt { optPort = fromIntegral $ read arg }) "PORT")
    "Port to listen on"
  , Option ['d'] ["database"]
    (ReqArg (\arg opt -> return opt { optDatabasePath = arg }) "PATH")
    "Path to icvpn-meta"
  ]

data Options = Options { optDatabasePath :: FilePath
                       , optPort         :: PortNumber
                       }

startOptions = Options { optDatabasePath = ".", optPort = 43 }

main :: IO ()
main = do
    args <- getArgs
    args' <- case getOpt Permute options args of
      (o,n,[]  ) -> return (o,n)
      (_,_,errs) -> ioError (userError (concat errs ++ usageInfo header options))

    opts <- foldl (>>=) (return startOptions) (fst args')

    sock <- socket AF_INET6 Stream 0
    setSocketOption sock ReuseAddr 1
    bindSocket sock (SockAddrInet6 (optPort opts) 0 iN6ADDR_ANY 0)
    -- allow a maximum of 8 outstanding connections
    listen sock 8

    mainLoop opts sock

    where
      header = "Usage: freifunk-whois -p PORT -d /foo/bar/icvpn-meta"
 
mainLoop :: Options -> Socket -> IO ()
mainLoop opts sock = forever $ do
    conn <- accept sock
    forkIO $ runConn (optDatabasePath opts) conn
 
runConn :: FilePath -> (Socket, SockAddr) -> IO ()
runConn fp (sock, _) = do
    db <- liftM buildDatabase $ readAllFiles fp
    s <- recv sock 256
    send sock $ query db s
    sClose sock
