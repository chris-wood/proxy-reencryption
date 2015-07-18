TODO
----

* create node class composed of an identity
* nodes request secret keys from a source, and propagate this information to other nodes

General Design
==============

1. master key generator (the application)
2. nodes have principal objects, which have identities
3. nodes request secret keys from the MKG and re-encrypt names