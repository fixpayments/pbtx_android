# pbtx_android
PBTX client library for Android devices

This Kotlin library will provide a set of primitives that allow building PBTX client applicatios for Android devices.

## 1. Low-level key management

Private keys are stored in Android Keystore provider. 

1.1. Generate a new `secp256r1` keypair and return the public key as `pbtx.PublicKey` protobuf message.

1.2. List existing keys and provide them as `pbtx.PublicKey` messages.

1.3. Delete a key from keystore (takes `pbtx.PublicKey` as argument)

## 2. Low-level signatures

2.1. Take an input byte array and `pbtx.PublicKey` as arguments, and return a signature as a byte array in the format described in PBTX protocol.

## 3. PBTX transaction generator

The PBTX transaction generator provides the following functionality:

* store the information about one or several PBTX accounts that are managed by private keys in keyStore. Each account is identified by a (network_id, actor) pair.

* keep track of current `seqnum` and `prev_hash` for each account.

* keep a history of transactions for each account up to a certain limit.


3.1. Register a PBTX account: takes `network_id`, `actor`, `seqnum`, `prev_hash` as arguments and stores them in persistent storage.

3.2. Update history: takes a list of `pbtx.Transaction` messages and merges them with the history.

3.3. Retrieve the history: returns the latest transactios, based on maximum number of entries and maximum transaction age.

3.4. Sign transaction: takes `network_id`, `actor`, `transaction_type`, `transaction_content` and returns a `pbtx.Transaction` protobuf message.



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

