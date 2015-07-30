{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances #-}

{-
This is an implementation of hash lists [1] as an example of an
authenticated data structure. It does not use lambda auth.

[1] https://en.wikipedia.org/wiki/Hash_list
-}

module HashList (
  HashBlock, getHash, getValue
 ,HashList, newHashList, pushBlock, verifyHashList
 ,getBlock, getValues
) where

import qualified Crypto.Hash.SHA256 as SHA256
import Data.ByteString.Char8 (ByteString, append, concat, pack)

-- digestGeneric uses the Show form of a type to hash it.
digestGeneric :: (Show a) => a -> ByteString
digestGeneric x = SHA256.hash . pack $ show x

-- A HashBlock stores data alongside a hash.
data HashBlock a = Block ByteString a deriving (Show, Read)

-- getHash returns the hash from a block.
getHash :: HashBlock a -> ByteString
getHash (Block h _) = h

-- getValue returns the value from a block.
getValue :: HashBlock a -> a
getValue (Block _ v) = v

-- newBlock creates a block from a value.
newBlock :: (Show a) => a -> HashBlock a
newBlock v = Block (digestGeneric v) v

-- hashBlocks computes the hash of all the hashes in a list of blocks.
hashBlocks :: [HashBlock a] -> ByteString
hashBlocks blocks = SHA256.hash $ Data.ByteString.Char8.concat hs
  where hs = map getHash blocks

-- A HashList stores a root hash, which is the hash of all the hashes
-- in the hash list's blocks, and a list of hash blocks.
data HashList a = HashList {rootHash :: ByteString
                           ,blockList :: [HashBlock a]}
                  deriving (Show, Read)

-- initHashList creates a new hash list from a value.
initHashList :: (Show a) => a -> HashList a
initHashList v = HashList root block
  where block = [(Block (digestGeneric v) v)]
        root  = hashBlocks block

-- newHashList creates a new hash list from a list of values. In
-- effect, it converts an unauthenticated list to an authenticated
-- list.
newHashList :: (Show a) => [a] -> HashList a
newHashList values = HashList (hashBlocks blocks) blocks
  where blocks = map newBlock values

-- pushBlock adds a new block to the hash list.
pushBlock :: (Show a) => HashList a -> a -> HashList a
pushBlock hlst@(HashList _ blocks) v =
  HashList (hashBlocks blocks') blocks'
  where blocks' = blocks ++ [(Block (digestGeneric v) v)]

-- verifyBlock verifies the hash on a single block.
verifyBlock :: (Show a) => HashBlock a -> Bool
verifyBlock (Block h v) = h == digestGeneric v

-- verifyHashList verifies the blocks in the hash list, and verifies
-- that the root hash is valid.
verifyHashList :: (Show a) => HashList a -> Bool
verifyHashList (HashList root blocks) =
  root == hashBlocks blocks && (all id $ map verifyBlock blocks)

-- getBlock returns the value of the block at a given index.
getBlock :: HashList a -> Int -> a
getBlock (HashList _ blocks) idx = getValue $ blocks !! idx

-- getValues returns a list of the values in the hash list. In effect,
-- it converts the authenticated list to an unauthenticated list.
getValues :: HashList a -> [a]
getValues (HashList _ blocks) = map getValue blocks

-- getRoot returns the root hash of the hash list.
getRoot :: (Show a) => HashList a -> ByteString
getRoot (HashList root _) = root

instance (Show a) => Eq (HashList a) where
  a == b = ((verifyHashList a) && (verifyHashList b)) &&
           getRoot a == getRoot b
