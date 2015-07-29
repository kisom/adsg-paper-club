{-

Low budget Merkle Tree implementation for a talk.

-}
module Merkle where

import qualified Crypto.Hash.SHA256 as SHA256
import Data.ByteString.Char8 (ByteString, append, pack)

data Tree = Leaf String | Node ByteString Tree Tree 
            deriving (Show, Read)


-- Given h1, h2, produce the hash of both of them.
hashHashes :: ByteString -> ByteString -> ByteString
hashHashes h1 h2 = SHA256.hash $ append h1 h2

-- Return all the leaves in the tree.
getLeaves :: Tree -> [String]
getLeaves (Leaf s) = [s]
getLeaves (Node _ l r) = getLeaves l ++ getLeaves r

-- Produce a digest of the tree.
digest :: Tree ->  ByteString
digest (Leaf s)     = SHA256.hash $ pack s
digest (Node _ l r) =
  hashHashes (digest l) (digest r)

-- Convenience function for building a node from two strings.
joinLeaves :: String -> String -> Tree
joinLeaves a b =
  Node (digest tempNode) (Leaf a) (Leaf b)
  where tempNode = Node (pack "") (Leaf a) (Leaf b)

-- Produce a new node that contains the digest of both its trees.
joinNodes :: Tree -> Tree -> Tree
joinNodes l@(Node h1 l1 r1) r@(Node h2 l2 r2) =
  Node (digest tempNode) l r
  where tempNode = Node (pack "") l r
joinNodes (Leaf a) (Leaf b) = joinLeaves a b

-- Inefficient, ends up recomputing many of the digests.
-- Ensure that all the digests match up.
verifyTree :: Tree -> Bool
verifyTree (Leaf _) = True
verifyTree node@(Node h l r) =
  verifyTree l && verifyTree r && h == digest node 

------------------------------------------------

-- trees are generated with
--   joinNodes (joinLeaves "Hello" "World") (joinLeaves "goodbye" "moon")
-- goodTree is untampered with
-- badTreeN have been tampered with
goodTree :: Tree
goodTree = read "Node \"\\200\\222\\NAKwrqs;\\128\\180\\134\\216\\165\\SUBl\\SI\\150\\&0\\163#\\ACKq\\232\\226\\137\\254O#\\203\\217\\177-\" (Node \"}\\205(DU\\FS\\149\\178\\DEL\\130M\\173\\179>\\229B\\ETX\\224\\EM\\DC3c.\\162\\DEL\\200]q\\174z\\184\\209\\163\" (Leaf \"Hello\") (Leaf \"World\")) (Node \"\\202Z\\158\\RSh\\233\\191\\253\\197>z\\131\\STX\\181\\191\\210\\158\\135\\228\\DC4[\\n\\217\\160\\203\\228-\\166\\207WI\\232\" (Leaf \"goodbye\") (Leaf \"moon\"))"

-- badTree1: leaf tampered with (moon -> monn)
badTree1 :: Tree
badTree1 = read "Node \"\\200\\222\\NAKwrqs;\\128\\180\\134\\216\\165\\SUBl\\SI\\150\\&0\\163#\\ACKq\\232\\226\\137\\254O#\\203\\217\\177-\" (Node \"}\\205(DU\\FS\\149\\178\\DEL\\130M\\173\\179>\\229B\\ETX\\224\\EM\\DC3c.\\162\\DEL\\200]q\\174z\\184\\209\\163\" (Leaf \"Hello\") (Leaf \"World\")) (Node \"\\202Z\\158\\RSh\\233\\191\\253\\197>z\\131\\STX\\181\\191\\210\\158\\135\\228\\DC4[\\n\\217\\160\\203\\228-\\166\\207WI\\232\" (Leaf \"goodbye\") (Leaf \"monn\"))"

-- badTree2: middle node tampered with (202 -> 234)
badTree2 :: Tree
badTree2 = read "Node \"\\200\\222\\NAKwrqs;\\128\\180\\134\\216\\165\\SUBl\\SI\\150\\&0\\163#\\ACKq\\232\\226\\137\\254O#\\203\\217\\177-\" (Node \"}\\205(DU\\FS\\149\\178\\DEL\\130M\\173\\179>\\229B\\ETX\\224\\EM\\DC3c.\\162\\DEL\\200]q\\174z\\184\\209\\163\" (Leaf \"Hello\") (Leaf \"World\")) (Node \"\\234Z\\158\\RSh\\233\\191\\253\\197>z\\131\\STX\\181\\191\\210\\158\\135\\228\\DC4[\\n\\217\\160\\203\\228-\\166\\207WI\\232\" (Leaf \"goodbye\") (Leaf \"moon\"))"
 
-- badTree3: root node tampered with (200 -> 202)
badTree3 :: Tree
badTree3 = read "Node \"\\202\\222\\NAKwrqs;\\128\\180\\134\\216\\165\\SUBl\\SI\\150\\&0\\163#\\ACKq\\232\\226\\137\\254O#\\203\\217\\177-\" (Node \"}\\205(DU\\FS\\149\\178\\DEL\\130M\\173\\179>\\229B\\ETX\\224\\EM\\DC3c.\\162\\DEL\\200]q\\174z\\184\\209\\163\" (Leaf \"Hello\") (Leaf \"World\")) (Node \"\\202Z\\158\\RSh\\233\\191\\253\\197>z\\131\\STX\\181\\191\\210\\158\\135\\228\\DC4[\\n\\217\\160\\203\\228-\\166\\207WI\\232\" (Leaf \"goodbye\") (Leaf \"moon\"))"

assert :: Bool -> Bool
assert False = error "Assertion failed."
assert _ = True

badTrees :: [Tree]
badTrees = [badTree1, badTree2, badTree3]

testVerifyBad = Prelude.map (\t -> assert (not (verifyTree t))) badTrees
testVerify = (all id $ testVerifyBad) && (verifyTree goodTree)
