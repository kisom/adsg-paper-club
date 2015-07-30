{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances #-}

{-

This is an implementation in Haskell of basic generic authenticated
types, used as a demonstration of some of the ideas in the paper
"Authenticated Data Structures, Generically". It has many shortcomings,
namely that lacking compiler support for doing this makes it hard to
actually build an authenticated type.

-}

module AuthTypes (
    Proof
  , Authenticated
  , AuthT
  , Party
  , auth, unauth
) where

import qualified Crypto.Hash.SHA256 as SHA256
import Data.ByteString.Char8 (ByteString, append, concat, pack)

-- A proof contains either a value or a bytestring.
data Proof a = ProofValue a | ProofHash ByteString
               deriving (Show, Read)
-- I'm not entirely sure that's what the authors intended,
-- but I don't quite understand the use of the OCaml channels
-- that are used for proof streams.

-- digestGeneric uses the Show form of a type to hash it.
digestGeneric :: (Show a) => a -> ByteString
digestGeneric x = SHA256.hash . pack $ show x

-- An Authenticated type can be digested and can produce a shallow
-- projection from its contents.
class (Show a) => Authenticated a where
  digest  :: a -> ByteString
  shallow :: a -> Proof a

-- Realisations of the Authenticated type for strings, integers,
-- and lists of strings.
instance Authenticated String where
  digest  x = SHA256.hash $ pack x
  shallow x = ProofValue x

instance Authenticated Int where
  digest  = digestGeneric
  shallow = ProofValue

instance Authenticated [String] where
  digest  = digestGeneric
  shallow = ProofValue

-- A Prover stores an authenticated type as <v, h>, while
-- a verifier stores only the digest.
data AuthT a = Prover a ByteString | Verifier ByteString
               deriving (Show, Read)
-- The cryptohash package provides digests as ByteStrings.

-- The party is either a P(rover) or V(erifier).
data Party = P | V

-- auth creates a new authenticated type. Note this type signature in Go
-- would be 'func auth (x interface{}) AuthT', where AuthT would be an
-- interface.
--
-- We have to provide different functions for the prover (who stores
-- the pair (V, H)) and the verifier (who stores H).
auth :: (Authenticated a) => Party -> a -> AuthT a
auth P x = Prover x (digest x)
auth V x = Verifier (digest x)

-- unauth is the interesting part. This is the part that's not
-- right, as I still need to work out the implementation of a
-- proof stream.
unauth :: (Authenticated a) => [Proof a] -> AuthT a
                            -> ([Proof a], Maybe a)
unauth p (Prover v _) = (shallow v : p, Just v)

-- If there is no proof stream, nothing can be verified.
unauth [] (Verifier h) = ([], Nothing)
unauth [(ProofValue v)] (Verifier h) = case (digest v) == h of
  True  -> ([], Just v)
  False -> ([ProofValue v], Nothing)
unauth ((ProofValue v) : p) (Verifier h) =
  case unauth [(ProofValue v)] (Verifier h) of
    ([], Just x) -> (p, Just x)
    _            -> (p, Nothing)


-- Let's try to build a hash list.

data HashBlock a = Block ByteString a deriving (Show, Read)

getHash :: HashBlock a -> ByteString
getHash (Block h _) = h

getValue :: HashBlock a -> a
getValue (Block _ v) = v

hashBlocks :: [HashBlock a] -> ByteString
hashBlocks blocks = SHA256.hash $ Data.ByteString.Char8.concat hs
  where hs = map getHash blocks

data HashList a = HashList {rootHash :: ByteString
                           ,blockList :: [HashBlock a]}
                  deriving (Show, Read)

newHashList :: (Show a) => a -> HashList a
newHashList v = HashList root block
  where block = [(Block (digestGeneric v) v)]
        root  = hashBlocks block

pushBlock :: (Show a) => HashList a -> a -> HashList a
pushBlock hlst@(HashList _ blocks) v =
  HashList (hashBlocks blocks') blocks'
  where blocks' = blocks ++ [(Block (digestGeneric v) v)]

verifyBlock :: (Show a) => HashBlock a -> Bool
verifyBlock (Block h v) = h == digestGeneric v

verifyHashList :: (Show a) => HashList a -> Bool
verifyHashList (HashList root blocks) =
  root == hashBlocks blocks && (all id $ map verifyBlock blocks)

getBlock :: HashList a -> Int -> a
getBlock (HashList _ blocks) idx = getValue $ blocks !! idx
