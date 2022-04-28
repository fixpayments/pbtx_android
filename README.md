# pbtx_android
PBTX client library for Android devices

This Kotlin library will provide a set of primitives that allow building PBTX client applicatios for Android devices.

## Steps of Installation

Update Settings.gradle like following

```
include ':app' 
include ':pbtxKeyProvider'
```

Update build.gradle of app directory

```
dependencies {

      ..     
      implementation project(':pbtxKeyProvider')
      ..
      
}

```

## Usage

Create a public key 

``
var publicKey : Pbtx.PublicKey  =  PbtxClient.createKey("alias")
``


List of Existing keys from keystore

``
var KeyList = PbtxClient.listKeys()
``

Delete Key with name of the alias.

``
PbtxClient.deleteKey("alias")
``

Sign Data array with private key of keystore with alias name

``
var signData : byte[] = PbtxClient.signData(byte[] data, String alias)
``

## 1. Low-level key management

Private keys are stored in Android Keystore provider. 

1.1. `byte[] PbtxClient.createKey(String alias)` generates a new `secp256r1` keypair and returns the public key as `pbtx.PublicKey` protobuf message.

1.2. `PbtxClient.listKeys()` lists existing keys and provides them as an array of (byte[], String) tuples, containing `pbtx.PublicKey` messages and corresponding aliases.

1.3. `PbtxClient.deleteKey(String alias)` deletes a key from keystore.

## 2. Low-level signatures

2.1. `byte[] PbtxClient.signData(byte[] data, String alias)` signs the input data with a key specified in the alias, and returns the 66-byte raw signature as described in PBTX protocol.

## 3. PBTX transaction generator

The PBTX transaction generator provides the following functionality:

* store the information about one or several PBTX accounts that are managed by private keys in keyStore. Each account is identified by a (network_id, actor) pair.

* keep track of current `seqnum` and `prev_hash` for each account.

* keep a history of transactions for each account up to a certain limit.


3.1 `PbtxClient.registerAccount(BigInteger network_id, BigInteger actor, Pbtx.PublicKey, BigInteger seqnum, BigInteger prev_hash)` adds a new account to persistent storage and initializes it with initial values. It verifies if the public key is known.

3.2. `PbtxClient.getHead(BigInteger network_id, BigInteger actor)` returns the `seqnum` and `prev_hash` values from last signed transaction in the storage.

3.3. `PbtxClient.getTransactions(BigInteger network_id, BigInteger actor, BigInteger seqnum_start, BigInteger seqnum_end)` retrieves signed transactions from the storage.

3.4. `PbtxClient.getSyncHead(BigInteger network_id, BigInteger actor)` returns the `seqnum` and `prev_hash` of the latest transaction that was synched with the network.

3.5. `PbtxClient.setSyncHead(BigInteger network_id, BigInteger actor, BigInteger seqnum, BigInteger prev_hash)` the network confirms that the result of `getHead` is consistent with the network. 

3.5 `PbtxClient.syncTransactions(BigInteger network_id, BigInteger actor, Transaction[] transactions)` if the result of `getHead` is not consistent with the network, the network supplies an array of transactions that are stemming from the sequence returned by `getSyncHead` method. If transactions in the local storage are conflicting with what is learned from the network, the library stores their copies in the log of failed transactions.

3.6. `PbtxClient.getFailedTransactions(BigInteger network_id, BigInteger actor, ...)` retrieves the list of failed transactions (TODO: define the selection criteria).

3.3. `PbtxClient.getHistory(BigInteger network_id, BigInteger actor, ...)` retrieves the history of transactions based on specified criteria (number of entries or maximum transaction age).

3.4.`PbtxClient.signTransaction(BigInteger network_id, BigInteger actor, BigInteger transaction_type, byte[] transaction_content)` and returns a `pbtx.Transaction` protobuf message as an object.



Copyright and License
=====================

Copyright 2022 Fix Payments Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License.  You may
obtain a copy of the License at
[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.  See the License for the specific language governing
permissions and limitations under the License.

