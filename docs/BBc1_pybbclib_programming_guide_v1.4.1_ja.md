Programming guide for py-bbclib version 1.4
====

py-bbclibはBBc-1のトランザクションのデータ構造を定義するモジュールであり、BBc-1の中で最も重要な役割をもつ。このドキュメントでは、py-bbclibの利用方法についてまとめ、後半では事例集を載せる。

なお、このリポジトリはbbc1リポジトリからも参照されるが、BBc-1のアプリケーション開発のための解説はbbc1リポジトリ内の[docs/BBc1_programming_guide_v1.3_ja.md](https://github.com/beyond-blockchain/bbc1/tree/develop/docs)を参照されたい。




# トランザクションのライフサイクル
BBc-1におけるトランザクションは以下のようなライフサイクルを持つ。

* BBcTransactionクラスのオブジェクトを作る
* BBcTransactionオブジェクトをシリアライズ（バイナリ化）して、データベースやストレージに保存したり、他のユーザに送付する
* 受け取ったシリアライズされたをデシリアライズして、BBcTransactionオブジェクトに復元し、署名を検証する
* BBcTransactionオブジェクトに含まれる情報（BBcAssetなど）を利用する

シリアライズやデシリアライズについては、[BBc1_data_format_ja.md](./BBc1_data_format_ja.md)に解説している。本ドキュメントでは、BBcTransactionクラスのオブジェクトの生成や署名検証の方法について解説する。



# BBcTransactionオブジェクトの構築

BBc-1のトランザクション（すなわちBBcTransactionオブジェクト）は、アセットデータおよび他のトランザクションへのポインタを保持し、デジタル署名によって保護される。

BBcTransactionオブジェクトを生成するためには、まずIDの長さの設定と、鍵ペアオブジェクト(KeyPairクラスのオブジェクト)の生成を行う。

### IDの長さの設定

BBcTransactionオブジェクトに含まれる[各種ID](./BBc1_IDs_ja.md)は、デフォルトではすべて256bit (=32byte)の長さを持つ。トランザクションのデータサイズを圧縮したい場合、IDの値が衝突しないと確信できるなら、長さを短縮しても実用上問題ない。v1.4以降では、IDの種別ごとに長さをバイト単位で設定することが可能である。

IDの長さに関する情報は、bbc1/bbclib.pyの中で保持している。下記のようにすることで、IDの長さを変更できる。一度変更すると、次に変更する前でその設定が引き継がれる。

```python
from bbclib import configure_id_length

id_length = {
  "transaction_id": 24,
  "asset_group_id": 6,
  "user_id": 8,
  "asset_id": 16,
  "nonce": 9
}
configure_id_length(id_len_conf)
```

上記の例では、transaction_idの長さを24バイト、asset_group_idの長さを6バイト、user_idの長さを6バイト、asset_idの長さを16バイト、BBcAssetに含まれる乱数値Nonceの長さを9バイトに設定している。

また、全て同じ長さに設定したい場合はconfigure_id_length_all()というメソッドを使うこともできる。下記は、すべてのID（およびNonce）の長さを16バイトに設定する例である。

```python
from bbclib import configure_id_length_all

configure_id_length_all(16)
```



### 鍵ペアオブジェクトの生成

トランザクションに署名したりBBcSignatureに公開鍵を格納するために、BBcTransactionオブジェクト鍵ペアを登録する必要がある。その鍵ペアは、新規に生成する場合と、既存の鍵ペアを利用する場合の2通りがある。

新規に鍵ペアを生成する方法は以下の通りである。

```python
from bbclib import KeyPair

keyPair = KeyPair()
keyPair.generate()
```

この結果、keyPairの中に秘密鍵と公開鍵が生成される。BBcTransactionにはこのkeyPairを渡せば良い。

また、このkeyPairの中の秘密鍵と公開鍵は、PEM形式、DER形式、またはナイーブなバイナリ形式（公開鍵はこの形でBBcSignatureに格納される)でエクスポートすることができる。

```python
privateKey_pem = keyPair.get_private_key_in_pem()
publicKey_pem = keyPair.get_public_key_in_pem()

privateKey_der = keyPair.get_private_key_in_der()
privateKey_der = keyPair.get_private_key_in_der()

privateKey_naive = keyPair.private_key
publicKey_naive = keyPair.public_key
```

エクスポートされた鍵をファイルやデータベースに保存しておき、それを以下のようにしてインポートすることで同じ鍵ペアをいつでも再生できる。

```python
from bbclib import KeyPair

keyPair = KeyPair()
keyPair.generate()
privateKey_pem = keyPair.get_private_key_in_pem()
// privateKey_pemをファイルに保存

...

// ファイルからprivateKey_pemを読み込む
keyPair2 = KeyPair()
keyPair2.mk_keyobj_from_private_key_pem(privateKey_pem)
```

keyPair2は、もとのkeyPairと同じ内容である。なお、鍵ペアオブジェクトの再生には、秘密鍵だけを与えればよい（公開鍵は秘密鍵から計算できるため）。上記の例は、PEM形式の鍵から再生する方法だが、この他にも、DER形式の鍵から再生するためのmk_keyobj_from_private_key()と、ナイーブなバイナリ形式から再生するためのmk_keyobj_from_private_key()も用意されている。

```python
keyPair2.mk_keyobj_from_private_key(privateKey_der)
keyPair2.mk_keyobj_from_private_key(privateKey_naive)
```

また、PEM形式の公開鍵証明書と秘密鍵のペアをインポートして鍵ペアオブジェクトを再生することもできる。下記では、公開鍵証明書(publicKey_cert_x509)と秘密鍵(privateKey_pem)を用いている。このimport_publickey_cert_pem()関数は、証明書の正しさも検証し、不正であればresult = Falseを返す。

```python
keyPair3 = KeyPair()
result = keyPair3.import_publickey_cert_pem(publicKey_cert_x509, privateKey_pem)
```



### BBcTransactionオブジェクトの生成

BBcTransactionオブジェクトのは、以下のようにして生成する。

```python
from bbclib import BBcTransaction, BBcRelation, BBcWitness, BBcAsset, KeyPair

keyPair_1 = KeyPair()
keyPair_1.genarate()
transaction1 = BBcTransaction()
```

生成されたBBcTransactionオブジェクトは、他のパーツ群（BBcEvent、BBcReference、BBcRelation、BBcAsset、BBcCrossRef、BBcSignature）の器となるオブジェクトである。データ構造は[BBc-1_transaction_data_ja.md](./BBc-1_transaction_data_ja.md)を参照されたい。上記のようにして「素のトランザクション」を生成した時点ではヘッダ情報（タイムスタンプなど）しか含まれていない。そのあと、様々なパーツを追加していく必要がある。

以下に例を示す。

```python
asset_group_1 = bbclib.get_new_id("asset_group_id for testing")
user_1 = bbclib.get_new_id("user x")

asset1 = BBcAsset()
asset1.add(user_id=user_1, asset_body=b'some information')

relation1 = BBcRelation()
relation1.add(asset_group_id=asset_group_1, asset=asset1)  # 1

witness1 = BBcWitness()
witness1.add_witness(user_1)   # 2

transaction1.add(relation=relation1, witness=witness1)  #3
```

BBcAssetは、BBcRelation（またはBBcEvent）の中に含まれるオブジェクトであるため、上の例の#1で、BBcRelationオブジェクトの中にBBcAssetオブジェクトを格納している。そして上の例の#2で、BBcTransactionオブジェクトにBBcRelationオブジェクトとBBcWitnessオブジェクトを格納している。

ここまでで、BBcTransactionオブジェクトの本体が完成したことになる。最後にuser_1の署名を付与すれば全体が完成する。

```python
sig = transaction1.sign(private_key=keyPair_1.private_key, public_key=keyPair_1.public_key) #4
transaction1.witness.add_signature(user_id=user_1, signature=sig)  #5
```

まず、上の例の#3でBBcSignatureオブジェクトを生成する。#4の戻り値sigはすでに、transactionへの署名やそれを検証するための公開鍵の情報を含んだものになっている。そして、#5で、そのBBcSignatureオブジェクトをuser_1と紐づけてBBcTransactionオブジェクトに格納している。つまりこれによって、「#3で生成した署名がuser_1による署名であること」を主張することになる。

なお、上記のような一連のコードを簡単に生成するためのユーティリティメソッドが[bbc1/libs/bbclib_utils.py](bbc1/libs/bbclib_utils.py)に定義されている。それを使えば、上記の例は次のように書くことができる。

```python
import bbclib

keyPair_1 = KeyPair()
keyPair_1.genarate()
asset_group_1 = bbclib.get_new_id("asset_group_id for testing")
user_1 = bbclib.get_new_id("user x")

transaction1 = bbclib.make_transaction(relation_num=1, witness=True)  #6
bbclib.add_relation_asset(transaction1, relation_idx=0,
                          asset_group_id=asset_group_1,
                          user_id=user_1, asset_body=b'some information')  #7
transaction1.witness.add_witness(user_1)  #8


sig = transaction1.sign(keypair=keyPair_1)  #9
transaction1.witness.add_signature(user_1, sig)
```

上記の#6は、BBcTransactionオブジェクトを作ると同時に、BBcRelationオブジェクト1つとBBcWitnessオブジェクトも生成してBBcTransactionオブジェクトに格納するユーティリティである。また、#7は、BBcTransactionオブジェクト内のBBcRelationオブジェクトに、BBcAssetオブジェクトを生成・格納するためのユーティリティである。このユーティリティメソッドの第1引数で対象となるBBcTransactionオブジェクトを、第2引数でその中の何番目のBBcRelationオブジェクトかを指定している。#8は#2と同じ処理である。#9はユーティリティではないが、秘密鍵と公開鍵を個別に指定せずとも、鍵ペアオブジェクトをそのまま渡すことができることを示している。署名以外のすべての情報がBBcTransactionオブジェクトに格納された後に、#9の署名生成を行わなければならないことに注意されたい。

以上でBBcTransactionオブジェクトが完成した。この後、このオブジェクトをシリアライズすれば、それを保存したり他へ送信することができるようになる。



### BBcTransactionオブジェクト生成（ポインタを含める場合）

前節の例は、他のトランザクションと何の関係も持たない単独のトランザクションを生成する例だった。本節ではBBcPointerを含めることで、他のトランザクションとの関係性を持たせる例を紹介する。なお、関係を持たせるトランザクションは前節で生成したtransaction1とする。

```python
from bbclib import BBcTransaction, BBcRelation, BBcPointer, BBcWitness, BBcAsset, KeyPair

asset_group_1 = bbclib.get_new_id("asset_group_id for testing")
user_1 = bbclib.get_new_id("user x")

asset2 = BBcAsset()
asset2.add(user_id=user_1, asset_body=b'some information')

pointer2 = BBcPointer()
transaction_id_1 = transaction1.transaction_id   # 1
asset_id_1 = transaction1.relation[0].asset.asset_id  #2
pointer2.add(transaction_id=transaction_id_1, asset_id=asset_id_1)  # 3

relation2 = BBcRelation()
relation2.add(asset_group_id=asset_group_1, asset=asset2, pointer=pointer2)  # 4

witness2 = BBcWitness()
witness2.add_witness(user_1)

transaction2 = BBcTransaction()
transaction2.add(relation=relation2, witness=witness2)
sig = transaction1.sign(private_key=keyPair_1.private_key, public_key=keyPair_1.public_key)
transaction1.witness.add_signature(user_id=user_1, signature=sig)
```

前節との違いは、#1〜#4の部分だけである。BBcTransactionオブジェクトを構築する手順はどのようなトランザクションを作るときも同じであり、含めたいパーツを作り、それをaddメソッドで追加すればよい。

上記の例の#1、#2は関係するトランザクションやアセットの識別子を取得し、#3でそれをBBcPointerオブジェクトに格納している。なお、関係するassetが自明であれば、asset_idの方はNoneを指定しても構わない（トランザクションの中にアセットが一つしかない場合など）。

BBcPointerオブジェクトはBBcRelationオブジェクトの中に含まれるため、上記#4にて、pointer2もいっしょにBBcRelationオブジェクトの中に加えている。



# シリアライズ/デシリアライズ

BBcTransactionオブジェクトは、そのままの形では保存や他者への送信ができないため、バイナリデータ化つまりシリアライズする必要がある。データ構造については、[BBc-1_transaction_data_ja.md](./BBc-1_transaction_data_ja.md)に解説している。下記の例は、transaction1というBBcTransactionオブジェクトをシリアライズする例である。

```python
import bbclib

txdata = bbclib.serialize(transaction1)
txdata_compressed = bbclib.serialize(transaction1, format_type=BBcFormat.FORMAT_ZLIB)
```

txdataはバイナリデータである。また、txdata_compressedはシリアライズする際にデータを圧縮したものであるが、実質的な中身（もとのBBcTrsansactionオブジェクト）は同じである。

バイナリデータを受け取ったときは、これをデシリアライズすることで、もとのBBcTransactionオブジェクトに復元することができる。

```python
import bbclib

txobj, fmt_type = bbclib.deserialize(txdata)
```

txdataがバイナリデータで、txobjがBBcTransactionオブジェクトである。ここで、bbclib.deserialize()は2つの戻り値を取ることに注意されたい。2つ目の戻り値fmt_typeは、txdataのワイヤーフォーマットの種別を示している（ワイヤーフォーマットについての[詳細はこちら](./BBc1_data_format_ja.md)）



# トランザクションの署名検証

取得したトランザクションはデシリアライズした後、改ざんが無いことを確認するために、トランザクションに付与された署名（BBcSignatureオブジェクト）の検証を行う。署名検証は、BBcSignatureオブジェクトに用意されているverify()メソッドを用いれば良い。

下記の例は、BBcSignatureオブジェクトに公開鍵が含まれている場合（version 1.4 より前）である。なお、トランザクションには3つのBBcSignatureオブジェクトが含まれているものとする。

```python
import bbclib

txobj, fmt_type = bbclib.deserialize(txdata)
digest = txobj.transaction_id

for i in range(len(txobj.signatures)):
	result = txobj.signatures[i].verify(digest)
  if not result:
    print("Verify failed...")
```

また、version 1.4からは、BBcSignatureオブジェクトに公開鍵を含めず、検証時に与えることが可能である。以下その例を示す。なお、検証に用いる公開鍵はkeyPairオブジェクトに格納されているものとする。

```python
import bbclib

txobj, fmt_type = bbclib.deserialize(txdata)
digest = txobj.transaction_id

result = txobj.signatures[0].verify(digest, pubkey=keyPair.public_key)
if not result:
  print("Verify failed...")
```



# トランザクション内の情報へのアクセス

BBcTransactionオブジェクトは先にも述べたように、他のパーツ群（BBcEvent、BBcReference、BBcRelation、BBcAsset、BBcCrossRef、BBcSignature）の器となるオブジェクトである。これらのオブジェクトが配列に格納されているので、トランザクション内の情報にアクセスするには、オブジェクト種別ごとの配列に対して要素を指定する。

例えば、BBcRelationオブジェクトを2つ含んでいて、そのそれぞれの中にさらにBBcPointerを1つずつ含んでいるとすれば、次のように情報にアクセスできる。

```python
relation_1 = txobj.relations[0]
asset_1 = relation_1.asset
asset_body_1 = asset_1.asset_body   # アセット情報が格納されているはず
pointer_1 = relation_1.pointers[0]
ptr_transactionId_1 = pointer_1.transaction_id
ptr_assetId_1 = pointer_1.asset_id

relation_2 = txobj.relations[1]
asset_2 = relation_2.asset
asset_body_2 = asset_2.asset_body   # アセット情報が格納されているはず
pointer_2 = relation_2.pointers[0]
ptr_transactionId_2 = pointer_2.transaction_id
ptr_assetId_2 = pointer_2.asset_id
```



# トランザクション作成事例

以下、BBcTransactionオブジェクトの作成事例を紹介する。なお、すべての事例についてimportや鍵ペアの生成・読み込み、asset_group_idやuser_idの設定は下記のようなコードで実施されているものとする。

```python
import bbclib
from bbclib import BBcTransaction, BBcEvent, BBcReference, BBcRelation, BBcWitness, BBcAsset, KeyPair

asset_group_1 = bbclib.get_new_id("asset_group_id for testing #1")
asset_group_2 = bbclib.get_new_id("asset_group_id for testing #2")

user_1 = bbclib.get_new_id("user 1")
user_2 = bbclib.get_new_id("user 2")

keyPair_user_1 = KeyPair()
keyPair_user_1.generate()
keyPair_user_2 = KeyPair()
keyPair_user_2.generate()
```



### BBcRelation1つ、BBcPointerなし、署名2ユーザ分

```
       +-------------------------+
       |         header          |
       +-------------------------+
       |                         |
       |        relations        |
       |     (BBcRelation x 1)   |
       |                         |
       +-------------------------+
       |                         |
       |         witness         |
       |                         |
       +-------------------------+
       |                         |
       |       signatures        |
       |    (BBcSignature x 2)   |
       |                         |
       +-------------------------+
```

```python
transaction1 = bbclib.make_transaction(relation_num=1, witness=True)

bbclib.add_relation_asset(transaction1, relation_idx=0,
                          asset_group_id=asset_group_1,
                          user_id=user_1, asset_body=b'some information')

transaction1.witness.add_witness(user_1)
transaction1.witness.add_witness(user_2)

sig1 = transaction1.sign(keypair=keyPair_1)
sig2 = transaction1.sign(keypair=keyPair_2)

transaction1.witness.add_signature(user_1, sig1)
transaction1.witness.add_signature(user_2, sig2)
```



### BBcRelation2つ、BBcPointer各2つ、署名2ユーザ分

```
       +-------------------------+
       |         header          |
       +-------------------------+
       |                         |
       |        relations        |
       |     (BBcRelation x 2)   |  <-- BBcPointer x 2 in each BBcRelation object
       |                         |
       +-------------------------+
       |                         |
       |         witness         |
       |                         |
       +-------------------------+
       |                         |
       |       signatures        |
       |    (BBcSignature x 2)   |
       |                         |
       +-------------------------+
```



下記では、transaction_id_1〜4、asset_id_1〜2が事前に生成されているものとする。

```python
transaction5 = bbclib.make_transaction(relation_num=2, witness=True)

bbclib.add_relation_asset(transaction5, relation_idx=0,
                          asset_group_id=asset_group_1,
                          user_id=user_1, asset_body=b'some information 1')
bbclib.add_relation_pointer(transaction5, relation_idx=0,
                           ref_transaction_id=transaction_id_1,
                           ref_asset_id=asset_id_1)
bbclib.add_relation_pointer(transaction5, relation_idx=1,
                           ref_transaction_id=transaction_id_2,
                           ref_asset_id=asset_id_2)

bbclib.add_relation_asset(transaction5, relation_idx=1,
                          asset_group_id=asset_group_2,
                          user_id=user_1, asset_body=b'some information 2')
bbclib.add_relation_pointer(transaction5, relation_idx=0,
                           ref_transaction_id=transaction_id_3,
                           ref_asset_id=None)
bbclib.add_relation_pointer(transaction5, relation_idx=1,
                           ref_transaction_id=transaction_id_4,
                           ref_asset_id=None)

transaction5.witness.add_witness(user_1)
transaction5.witness.add_witness(user_2)

sig1 = transaction5.sign(keypair=keyPair_1)
sig2 = transaction5.sign(keypair=keyPair_2)

transaction5.witness.add_signature(user_1, sig1)
transaction5.witness.add_signature(user_2, sig2)
```



### BBcEvent1つ (approver 1ユーザ)、BBcReferenceなし、署名1ユーザ分

```
       +-------------------------+
       |         header          |
       +-------------------------+
       |                         |
       |          events         |
       |       (BBcEvent x 1)    |
       |                         |
       +-------------------------+
       |                         |
       |         witness         |
       |                         |
       +-------------------------+
       |                         |
       |       signatures        |
       |    (BBcSignature x 1)   |
       |                         |
       +-------------------------+
```

```python
transaction1 = bbclib.make_transaction(event_num=1, witness=True)

bbclib.add_event_asset(transaction1, event_idx=0,
                       asset_group_id=asset_group_1,
                       user_id=user_1, asset_body=b'some information')

transaction1.witness.add_witness(user_1)

sig1 = transaction1.sign(keypair=keyPair_1)

transaction1.witness.add_signature(user_1, sig1)
```



### BBcEvent1つ (approver 1ユーザ)、BBcReference1つ、署名1ユーザ分

この例では、UTXOの入力としてBBcEventが一つ、出力としてBBcReferenceが一つのトランザクションを考える。BBcReferenceの参照先におけるBBcEventでapproverがuser_1一人だった場合を想定している。

```
       +-------------------------+
       |         header          |
       +-------------------------+
       |                         |
       |          events         |
       |       (BBcEvent x 1)    |
       |                         |
       +-------------------------+
       |                         |
       |       references        |
       |    (BBcReference x 1)   |  <-- Referring to a transaction with a single approver 
       |                         |
       +-------------------------+
       |                         |
       |       signatures        |
       |    (BBcSignature x 1)   |
       |                         |
       +-------------------------+
```



参照しているトランザクションがtransaction1で、その中の1番目のBBcEventをUTXOの入力だと想定する。

```python
transaction2 = bbclib.make_transaction(event_num=1, reference_num=1, witness=False)

bbclib.add_event_asset(transaction1, event_idx=0,
                       asset_group_id=asset_group_1,
                       user_id=user_1, asset_body=b'some information X')
bbclib.add_reference_to_transaction(transaction2, 
                                    asset_group_id=asset_group_1,
                                    ref_transaction_obj=transaction1,
                                    event_index_in_ref=0)

sig1 = transaction1.sign(keypair=keyPair_1)
transaction1.reference.add_signature(user_1, sig1)
```

