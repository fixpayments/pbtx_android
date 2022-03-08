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

**Step to perform unit test**

1) Clone the GitHub project on your system using git URL : https://github.com/shravanvavadiya/pbtx_android.git
2) Go to the folder where .git folder is located in the project.
3) Open terminal in your computer.
4) Checkout branch ‘develop’.
5) Open project in android studio and connect your mobile device with the computer.
6) Build gradle by writing  command given below (You must be at folder path where .gradle folder is located in the project)
gradlew build
7) Execute below commands to perform unit testing.
adb shell am instrument -w -m	-e debug false -e class 'ekis.pbtxjavaandroidkeystoresignatureprovider.EkisAndroidKeyStoreSignatureProviderInstrumentedTest#generateKeyStoreTest' ekis.pbtxjavaandroidkeystoresignatureprovider.test/androidx.test.runner.AndroidJUnitRunner
8) If you want to print logs use below commands in other terminal.
adb logcat | FINDSTR System.out (For windows OS)
adb logcat|grep System.out (For other OS)


