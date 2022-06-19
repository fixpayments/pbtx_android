# pbtx_android

PBTX client library for Android devices

This Kotlin library will provide a set of primitives that allow building PBTX client applicatios for
Android devices.

## Steps of Installation

- Use existing release or create a new one using jitpack
- Add the following to the root build.gradle of your project

```
allprojects {
	repositories {
	    ...
		maven { url 'https://jitpack.io' }
	}
}
```

- Add the dependency in your application

```
dependencies {
    ....
    implementation 'com.github.fixpayments:pbtx_android:<version_tag>'
}
```

## Usage

Create a public key

``
var publicKey : Pbtx.PublicKey = PbtxClient.createKey("alias")
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

1.1. `byte[] PbtxClient.createKey(String alias)` generates a new `secp256r1` keypair and returns the
public key as `pbtx.PublicKey` protobuf message.

1.2. `PbtxClient.listKeys()` lists existing keys and provides them as an array of (byte[], String)
tuples, containing `pbtx.PublicKey` messages and corresponding aliases.

1.3. `PbtxClient.deleteKey(String alias)` deletes a key from keystore.

## 2. Low-level signatures

2.1. `byte[] PbtxClient.signData(byte[] data, String alias)` signs the input data with a key
specified in the alias, and returns the 66-byte raw signature as described in PBTX protocol.

## 3. PBTX transaction manager

The PBTX transaction generator provides the following functionality:

* store the information about one or several PBTX accounts that are managed by private keys in
  keyStore. Each account is identified by a (network_id, actor) pair.

* keep track of current `seqnum` and `prev_hash` for each account.

* keep a history of transactions for each account up to a certain limit.

There are two storage databases for storing the transactions: the ones that the client signed
locally do not have the timestamp, and they were not yet confirmed by the network. And the ones that
are known to the network are supplied with the network timestamp in `TransactionHistoryEntry`
protobuf message.

#### 3.1. Implemented methods

3.1.1. `PbtxClient.initRegistration(): KeyModel` generates a new public/private key pair, saves it
in Android Keystore with an alias, saves a RegistrationRecord in the local db for future usage, and
returns a KeyModel object consisting of the generated `public key` and the `alias` used for the
private key in Android Keystore. For on-boarding new accounts, call this method once and use the
returned key alias when signing challenge data.

3.1.2. `PbtxClient.registerAccount(networkId: Long, permission: Permission, seqNumber: Int = 0, prevHash: Long = 0)`
adds a new account to persistent storage and initializes it with initial values. It verifies if one
of the public keys in the permission is known. Currently only the first key in the Permission object
is verified/used.

3.1.3. `PbtxClient.getLocalSyncHead(networkId: Long, actor: Long): Pair<Int, Long>` returns the
local stored `seqnum` and `prev_hash` of the account.

3.1.4. `PbtxClient.updateLocalSyncHead(networkId: Long, actor: Long, seqNumber: Int, prevHash: Long)`
updates the local values of `seqNum` and `prevHash`. Use it to either sync these local properties
with the blockchain, or to update them when a new signed transaction is created and stored locally.

3.1.5.`PbtxClient.signTransaction(networkId: Long, actor: Long, transactionType: Int, transactionContent: ByteArray): Transaction`
returns a signed `pbtx.Transaction` protobuf message. It contains the `TransactionBody` built from
the input params, and the authority signature obtained by signing the `TransactionBody` with the
private key owned locally by the account.

#### 3.2. Methods to implement

3.2.1. `PbtxClient.updPermission(BigInteger network_id, Pbtx.Permission)` updates the permission
object associated with an actor. The library checks if one of public keys is known.

3.2.2. `PbtxClient.getHead(BigInteger network_id, BigInteger actor)` returns the `seqnum`
and `prev_hash` values from last signed transaction in the storage.

3.2.3. `PbtxClient.getHeadTransactions(BigInteger network_id, BigInteger actor)` retrieves all
transactions that were locally signed, but were not yet confirmed by the network.

3.2.4 `PbtxClient.syncTransactions(BigInteger network_id, BigInteger actor, TransactionHistoryEntry[] transactions)`
if the result of `getSyncHead` is behind the latest transactions in the network, the network
supplies an array of `TransactionHistoryEntry` messages that are stemming from the sequence returned
by `getSyncHead` method. If transactions in the local storage are conflicting with what is learned
from the network, the library stores their copies in the log of failed transactions.

3.2.5. `PbtxClient.getFailedTransactions(BigInteger network_id, BigInteger actor, ...)` retrieves
the list of failed transactions (TODO: define the selection criteria).

3.2.6. `PbtxClient.addThirdPartyTransactions(BigInteger network_id, BigInteger actor, TransactionHistoryEntry[] transactions)`
adds third-party transactions to the actor's history. They are signed by other actors, but they are
relevant to this actor (for example, incoming payments or notifications). The library does not
verify them, but only stores them for `getHistory()` output.

3.2.7. `PbtxClient.getHistory(BigInteger network_id, BigInteger actor, ...)` retrieves the history
of transactions based on specified criteria (number of entries or maximum transaction age). It
returns a sequence of `TransactionHistoryEntry` messages. For those transactions which were not
confirmed by the network, `backend_timestamp` indicates the time when the user has signed the
transaction, and `backend_trxid` is empty.


Copyright and License
=====================

Copyright 2022 Fix Payments Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
compliance with the License. You may obtain a copy of the License at
[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.

