Papers club talk on Authenticated Data Structures, Generically (more or
less). It ends up being more a talk on ADS in general, as the implementation
in the paper involves a compiler hack.

Presentations:

* Authenticated Data Structures, Generically.pdf :: the presentation
  as a shiny PDF
* adsg.org :: the org-mode version of the presentation

Source:

There is some terrible Haskell code in the `adsg` directory. The
`AuthTypes` module provides a rough hack of some of the ideas from
the paper, while `Merkle` is a rough sketch of a Merkle tree.

Illustrations:

* Why.png is an elaborate and highly complex visualisation of a
  scenario where authenticated data structures are useful.
* merkle.png is the Merkle tree diagram from the paper.
