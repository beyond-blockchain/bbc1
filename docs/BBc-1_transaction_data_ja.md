BBc-1 Transaction data structure
====

このドキュメントでは、BBc-1のトランザクションのデータ構造について説明する。参照するバージョンは、BBc-1 v1.2とする。

# データフォーマット概要

<a id="fig1"/>

BBc-1のトランザクションは、transaction object (BBcTransaction)、packed binary data、serialized dataの3つの形態をとる。なお、アプリケーションプログラマが実際に気にすべきはtransaction objectのみであり、serialized dataはデータベースに格納するなど、外部システムに出力されるときのバイナリフォーマットである。また、packed binary dataは内部処理でのみ利用する中間形態である。データフォーマットの関係性は[この資料](https://github.com/beyond-blockchain/bbc1/blob/develop/docs/BBc1_data_format_ja.md)にも示しているが、以下の通りである。

```asciiarmor
+--------------------+           +------------------+            +------------------+
|                    |   pack    |                  |  Serialize |                  |
|                    | +-------> |                  |  +-------> |                  |
| Transaction object |           |  Packed binary   |            |  Serialized data |
| (BBcTransaction)   |           |  data            |            |                  |
|                    |  unpack   |                  | Deserialize|                  |
|                    | <-------+ |                  |  <-------+ |                  |
+--------------------+           +------------------+            +------------------+
```

<center>図1 フォーマット変換</center>

Serialized dataには2バイトのヘッダが付加されるが、このヘッダ値はPacked binary dataをどのようにしてシリアライズしているかを表す。BBc-1 v1.2時点では2種類のシリアライズ方法をサポートしており、ヘッダ値との対応は以下の通りである。

| ヘッダ値 | シリアライズ方法                   |
| -------- | :--------------------------------- |
| 0x0000   | Packed binary dataをそのまま用いる |
| 0x0010   | Packed binary dataをzlibで圧縮する |

シリアライズの方法によらず、Packed binary dataはtransaction objectから一意に作成されなければならない。

## Packed binary data formatの全体像

<a id="fig2"/>

Packed binary dataは、Length-Value形式を基本とする。ネットワークプロトコルなどではType-Length-Valueの形式を取ることが多いが、BBc-1ではデータ種別（Type）の格納順序を固定するため、Typeを明示する必要がない。このPacked binary dataは次のような構成になっている。

```asciiarmor
       +-------------------------+
       |         header          |
       +-------------------------+
       |                         |
       |         events          |
       |    (list of events)     |
       |                         |
       +-------------------------+
       |                         |
       |       references        |
       |  (list of references)   |
       |                         |
       +-------------------------+
       |                         |
       |        relations        |
       |   (list of relations)   |
       |                         |
       +-------------------------+
       |                         |
       |         witness         |
       |                         |
       +-------------------------+
       |                         |
       |        cross_ref        |
       |                         |
       +-------------------------+
       |                         |
       |       signatures        |
       |  (list of signatures)   |
       |                         |
       +-------------------------+
```

<center>図2 Packed binary data構造</center>

図2のように、Packed binary dataは複数のパーツから構成される。events、references、relations、signaturesは、それぞれBBcEvent、BBcReference、BBcRelation、BBcSignatureオブジェクト複数を含むリスト構造をバイナリ化(pack)したものである。



#BBcTransactionに含まれるオブジェクト群

以降では、[図2](#fig2)の各パーツに対応するオブジェクトとそのpack方法について説明する。

## BBcTransaction

定義ファイル：[bbc1/core/libs/bbclib_transaction.py](https://github.com/beyond-blockchain/bbc1/blob/develop/bbc1/core/libs/bbclib_transaction.py)

BBcTranactionオブジェクトは、トランザクション全体の器として機能を提供する。このBBcTransactionオブジェクトは[図2](#fig2)に示した各種オブジェクトを格納するリストなどを持ち、オブジェクトに対してpackを行うと格納している各種オブジェクトのpack関数を順次呼び出して[図2](#fig2)のデータ構造を作成する。

またこのオブジェクトは、自分自身のダイジェスト計算機能も提供しており、ダイジェスト値がトランザクションIDとなる。電子署名の計算はトランザクションIDはに対して行われる。なお、ダイジェストの計算方法は特殊であるため、詳細を[後述](#digest)する。

### クラス定義

```python
class BBcTransaction:
    def __init__(self, version=1, unpack=None, id_length=DEFAULT_ID_LEN):
        self.id_length = id_length
        self.version = version
        self.timestamp = int(time.time())
        self.events = []
        self.references = []
        self.relations = []
        self.witness = None
        self.cross_ref = None
        self.signatures = []
        self.userid_sigidx_mapping = dict()
        self.transaction_id = None
        self.transaction_base_digest = None
        self.transaction_data = None
        self.asset_group_ids = dict()
        if unpack is not None:
            self.unpack(unpack)
```

* packされる変数

| 変数名     | 説明                                                         |
| ---------- | ------------------------------------------------------------ |
| id_length  | transaction_id、asset_group_id、asset_id、user_idはデフォルトでは32バイトであるが、id_lengthを指定することで、長さを短くできる。単位はバイトで指定し、指定バイト分だけidバイナリ列の下位部分を取り出してidとする。 |
| version    | Transaction objectのフォーマットバージョンを表す。2018年12月の最新は1である。 |
| timestamp  | オブジェクト作成時刻のUNIXタイムを格納する。秒単位、ミリ秒単位、ナノ秒単位のいずれかを用いる。どれを用いるかはアプリケーション次第である。 |
| events     | BBcEventオブジェクトをリストで保持する。BBcEventオブジェクト内部にBBcAssetオブジェクトを含む。 |
| references | BBcReferenceオブジェクトをリストで保持する                   |
| relations  | BBcRelationオブジェクトをリストで保持する。BBcRelationオブジェクト内部にBBcAssetオブジェクトを含む。 |
| witness    | BBcWitnessオブジェクト                                       |
| cross_ref  | BBcCrossRefオブジェクト                                      |
| signatures | BBcSignatureオブジェクトをリストで保持する                   |

* packされない変数

| 変数名                  | 説明                                                         |
| ----------------------- | ------------------------------------------------------------ |
| userid_sigidx_mapping   | signaturesリストのどの電子署名（BBcSignature）が、どのuser_idのものに対応するかのマッピング情報を保持する。BBcWitnessやBBcReferenceから利用される。 |
| transaction_id          | このtransaction objectの識別子。署名にも用いられる。         |
| transaction_base_digest | transaction_idを算出する際の中間情報（[後述](#digest)）      |
| transaction_data        | unpackされたこのtransaction objectのバイナリデータを保持する |
| asset_group_ids         | このtransaction objectの中のBBcEventやBBcRelationで定義されているasset_group_id群を保持するリスト。アプリケーションから参照しやすくするためのユーティリティなので、実装は必須ではない。 |

### Packed binary data

<a id="fig3"/>

```
    0               1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            version (4)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           timestamp (8)                       |
   +                                                               +
   |      [unixtime in seconds, milliseconds or nanoseconds]       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         id_length (2)         |         num_events (2)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                           events                          ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      num_referencess (2)      |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|                               +
   |                                                               |
   ~~~                         references                        ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       num_relations (2)       |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|                               +
   |                                                               |
   ~~~                         relations                         ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   num_witness (2)  [0 or 1]   |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|                               +
   |                                                               |
   ~~~                          witness                          ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   num_crossref (2)  [0 or 1]  |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|                               +
   |                                                               |
   ~~~                        cross_ref                          ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         num_signatures (2)    |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|                               +
   |                                                               |
   ~~~                        signatures                         ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

<center>図3 トランザクション全体のPacked data format</center>

Packed data内の数値の表現形式はすべて**little endian**とする。またカッコ内の数値はフィールドの長さをバイト数で表したものである（以下すべてのpacked dataの図で同様とする）。

冒頭のversion、timestamp、id_lengthは図2のheaderに対応し、以下events、references、relations、witness、cross_ref、signaturesが続く。なお、これら各部の先頭には、中に何個のオブジェクトが含まれているかを表す数値（例えば、num_eventsは、event部の中に含まれるBBcEventオブジェクトの数）が置かれる。この数値が0の場合は、データが省略される。例えば、num_crossref=0の場合、witness、cross_ref、signature付近のデータは以下のようになる。

```asciiarmor
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   num_witness (2)  [0 or 1]   |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|                               +
   |                                                               |
   ~~~                          witness                          ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     num_crossref (2)  [0]     |      num_signatures (2)       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                        signatures                         ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

<center>図4 num_crossrefが0の場合の例</center>

### ダイジェストの計算

<a id="digest"/>

transaction objectのダイジェストは以下のような手順で計算する。またこの手順を図5にも示す。

1. header、events、references、relations、witnessまでのpacked dataに対してSHA256ダイジェストを計算し、それをtransaction_base_digestとする。
2. transaction_base_digestとpackされたcross_refを結合したバイナリ列に対してSHA256ダイジェストを計算し、それをtransaction_idとする。

2段階に別れている理由は、他ドメインとの間で履歴交差を行う際に、トランザクション全体を他ドメインに提示することなく存在証明を行えるようにするためである。

```asciiarmor
+----------------------+XX
|        header        | X
+----------------------+ X
|        events        | X
+----------------------+ X
|       references     | +--------> transaction_base_digest
+----------------------+ X                    X
|       relations      | X                    X
+----------------------+ X                    +-------> transaction_id
|       witness        | X                    X
+----------------------+XX                    X
|       cross_ref      XXXXXXXXXXXXXXXXXXXXXXXX
+----------------------+
|       signatures     |
+----------------------+
```

<center>図5 ダイジェスト計算手順</center>

## 共通フォーマット

### オブジェクトリスト

events、references、relations、witness、cross_ref、signaturesはそれぞれ0個以上のオブジェクトのリストをpackしたものになる。各部に含まれるオブジェクトの個数は、[図3](#fig3)に示したように、num_eventsなどの数値で指定される。オブジェクトをpackしたものはそれぞれバイト長が異なる可能性があるため、オブジェクトごとにサイズを指定する（Length-Value形式）。つまり、各部は下図のような構成となる。

```asciiarmor
    0               1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       length of data (4)                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                 packed data of an object                  ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       length of data (4)                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                 packed data of an object                  ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       length of data (4)                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                                                           ~~~
```

<center>図6 オブジェクトリストのpacked dataの構成</center>

### ID structure

識別子の長さは、BBcTransactionのid_lengthで変更可能である。そのため、識別子をpackする際には、下図のように必ずそのバイト長を示す必要がある（やはりLength-Value形式である）。

```asciiarmor
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    length of identifier (2)   |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|                               +
   |                                                               |
   ~~~                          identifier                       ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

<center>図7 識別子のpacked dataの構成</center>



## BBcEvent

定義ファイル：[bbc1/core/libs/bbclib_event.py](https://github.com/beyond-blockchain/bbc1/blob/develop/bbc1/core/libs/bbclib_event.py)

BBcEventオブジェクトは、UTXO形式の出力データに対応し、内部にアセット情報（BBcAsset）を含む。

### クラス定義

```python
class BBcEvent:
    def __init__(self, asset_group_id=None, id_length=DEFAULT_ID_LEN):
        self.id_length = id_length
        if asset_group_id is not None and id_length < 32:
            self.asset_group_id = asset_group_id[:id_length]
        else:
            self.asset_group_id = asset_group_id
        self.reference_indices = []
        self.mandatory_approvers = []
        self.option_approver_num_numerator = 0
        self.option_approver_num_denominator = 0
        self.option_approvers = []
        self.asset = None
```

- packされる変数

| 変数名                          | 説明                                                         |
| ------------------------------- | ------------------------------------------------------------ |
| asset_group_id                  | このオブジェクトが保持するBBcAssetオブジェクトのアセット種別を表す識別子 |
| reference_indices               | 上位のtransaction objectがBBcReferenceオブジェクトを伴う場合に、このBBcEventオブジェクトがどのBBcReferenceオブジェクトに対応するものかをリスト(events)の要素番号で指定する。 |
| mandatory_approvers             | このオブジェクトに登録されているBBcAssetを操作する（所有権移転など）際に、必ず承認を取得すべきuser_idのリストを保持する。 |
| option_approver_num_numerator   | このオブジェクトに登録されているBBcAssetを操作する（所有権移転など）際に、いくつのuser_idからの承認が必要かを指定する。（分子の値） |
| option_approver_num_denominator | このオブジェクトに登録されているBBcAssetを操作する（所有権移転など）際に、承認をもらうべきuser_idの候補数を指定する。（分母の値）。つまり、分母の数の候補のうち、分子の数だけ署名が揃わなければならないことを表す。 |
| option_approvers                | このオブジェクトに登録されているBBcAssetを操作する（所有権移転など）際に、承認をもらうべきuser_idのリストを保持する。 |
| asset                           | BBcAssetオブジェクト                                         |

- packされない変数

| 変数名    | 説明                                           |
| --------- | ---------------------------------------------- |
| id_length | 上位のBBcTransactionオブジェクトの値を引き継ぐ |

### Packed binary data

<a id="fig8"/>

[図3](#fig3)の"events"の部分のpacked dataの全体構成は図6のとおりであり、packed data of an objectは、BBcEventオブジェクトがpackされたものである。オブジェクトのpacked dataの構成は以下の通りである。

```asciiarmor
    0               1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                 asset_group_id (ID structure)             ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   num_reference_indcies (2)   |      index value (2)          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
   |         index value (2)       |            ....             ~~~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
   ~~~                       ... (index values)                  ~~~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
   |   num_mandatory_approvers (2) |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
   ~~~                 user_id (ID structure)                    ~~~
   |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                               |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
   |                  user_id (ID structure)                     ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                      ... user_ids                         ~~~
   |                    (list of ID structures)                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      opt_num_numerator(2)     |    opt_num_denominator(2)     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                      ... user_ids                         ~~~
   |              (num of users is opt_num_denominator)            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      length of asset (4)                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                           asset                           ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

<center>図8 BBcEventのpacked data</center>

num_reference_indciesはreference_indicesの要素数を表し、その後にその数の数値の列（index value）が並ぶ。num_mandatory_approversもmandatory_approversの要素数を表し、指定された数だけその後にuser_id列が格納される。option_approversについては、opt_num_denominator （option_approver_num_denominator）に指定された数だけ、その後にuser_id列が格納される（格納方法はmandatory_approversと同じ）。

最後に、BBcAssetのpacked dataのバイト長とそのpacked dataが格納される。



## BBcReference

定義ファイル：[bbc1/core/libs/bbclib_reference.py](https://github.com/beyond-blockchain/bbc1/blob/develop/bbc1/core/libs/bbclib_reference.py)

BBcEventオブジェクトは、UTXO形式の入力データに対応する。

### クラス定義

```python
class BBcReference:
    def __init__(self, asset_group_id, transaction, ref_transaction=None, event_
index_in_ref=0, id_length=DEFAULT_ID_LEN):
        self.id_length = id_length
        if asset_group_id is not None:
            self.asset_group_id = asset_group_id[:self.id_length]
        else:
            self.asset_group_id = asset_group_id
        self.transaction_id = None
        self.transaction = transaction
        self.ref_transaction = ref_transaction
        self.event_index_in_ref = event_index_in_ref
        self.sig_indices = []
        self.mandatory_approvers = None
        self.option_approvers = None
        self.option_sig_ids = []
        if ref_transaction is None:
            return
        self.prepare_reference(ref_transaction=ref_transaction)
```

- packされる変数

| 変数名             | 説明                                                         |
| ------------------ | ------------------------------------------------------------ |
| asset_group_id     | このオブジェクトが参照するBBcEventオブジェクトが指定するアセット種別を表す識別子 |
| transaction_id     | 参照する過去のトランザクションの識別子                       |
| event_index_in_ref | tranaction_idで参照するトランザクションの中どのBBcEventオブジェクトを参照するかを、eventsの配列要素番号で指定する。 |
| sig_indices        | 上位のBBcTransactionオブジェクトのどのBBcSignatureが参照しているBBcEventのapproverの署名であるかを、signaturesの配列要素番号で指定する。 |

- packされない変数

| 変数名           | 説明                                                         |
| ---------------- | ------------------------------------------------------------ |
| id_length        | 上位のBBcTransactionオブジェクトの値を引き継ぐ               |
| transaction      | 上位のBBcTransactionオブジェクトへの参照（eventsやsignaturesにアクセスするため） |
| ref_transaction  | 参照するBBcTransactionオブジェクト                           |
| option_approvers | 承認を受ける候補のuser_id群                                  |
| option_sig_ids   | option_approversの署名が上位のBBcTransactionオブジェクトのsignatures配列のどの要素に対応するかを示す |

### Packed binary data

[図3](#fig3)の"references"の部分のpacked dataの全体構成は図6のとおりであり、packed data of an objectは、BBcReferenceオブジェクトがpackされたものである。オブジェクトのpacked dataの構成は以下の通りである。

```asciiarmor
    0               1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                 asset_group_id (ID structure)             ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                 transaction_id (ID structure)             ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      event_index_in_ref (2)   |      num_sig_indices (2)      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
   |         index value (2)       |            ....             ~~~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
   ~~~                       ... (index values)                  ~~~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
```

<center>図9 BBcReferenceのpacked data</center>

num_sig_indicesはsig_indicesの要素数を表し、その後にその数の数値の列（index value）が並ぶ。



## BBcRelation

定義ファイル：[bbc1/core/libs/bbclib_relation.py](https://github.com/beyond-blockchain/bbc1/blob/develop/bbc1/core/libs/bbclib_relation.py)

BBcRelationオブジェクトは、アカウント形式（ステート形式）の情報を記述し、内部にアセット情報（BBcAsset）およびポインタ情報（BBcPointer）を含む。

### クラス定義

```python
class BBcRelation:
    def __init__(self, asset_group_id=None, id_length=DEFAULT_ID_LEN):
        self.id_length = id_length
        if asset_group_id is not None and id_length < 32:
            self.asset_group_id = asset_group_id[:id_length]
        else:
            self.asset_group_id = asset_group_id
        self.pointers = list()
        self.asset = None
```

- packされる変数

| 変数名         | 説明                                                         |
| -------------- | ------------------------------------------------------------ |
| asset_group_id | このオブジェクトが保持するBBcAssetオブジェクトのアセット種別を表す識別子 |
| pointers       | 上位のtransaction objectがBBcReferenceオブジェクトを伴う場合に、このBBcEventオブジェクトがどのBBcReferenceオブジェクトに対応するものかをリスト(events)の要素番号で指定する。 |
| asset          | このオブジェクトに登録されているBBcAssetを操作する（所有権移転など）際に、必ず承認を取得すべきuser_idのリストを保持する。 |

- packされない変数

| 変数名    | 説明                                           |
| --------- | ---------------------------------------------- |
| id_length | 上位のBBcTransactionオブジェクトの値を引き継ぐ |

### Packed binary data

<a id="fig10"/>

[図3](#fig3)の"relations"の部分のpacked dataの全体構成は図6のとおりであり、packed data of an objectは、BBcRelationオブジェクトがpackされたものである。オブジェクトのpacked dataの構成は以下の通りである。

```asciiarmor
    0               1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                 asset_group_id (ID structure)             ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        num_pointers (2)       |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
   |                                                               |
   ~~~              packed data array of pointers                ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      length of asset (4)                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                           asset                           ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

<center>図10 BBcEventのpacked data</center>

num_pointersはBBcPointerオブジェクト群の数を表し、それらのpacked data群をpointersの部分に格納する。最後に、BBcAssetのpacked dataのバイト長とそのpacked dataが格納される。



## BBcAsset

定義ファイル：[bbc1/core/libs/bbclib_asset.py](https://github.com/beyond-blockchain/bbc1/blob/develop/bbc1/core/libs/bbclib_asset.py)

BBcAssetオブジェクトは、アセット情報の本体を保持する。保持できるアセット情報は、文字列、バイナリ、dictオブジェクトと、外部ファイルのSHA256ダイジェストである（ファイル名をこのオブジェクトのasset_idにすることを想定している）。

### クラス定義

```python
class BBcAsset:
    def __init__(self, user_id=None, asset_file=None, asset_body=None, id_length=DEFAULT_ID_LEN):
        self.id_length = id_length
        self.asset_id = None
        if user_id is not None and id_length < 32:
            self.user_id = user_id[:id_length]
        else:
            self.user_id = user_id
        self.nonce = bbclib_utils.get_random_value()
        self.asset_file_size = 0
        self.asset_file = None
        self.asset_file_digest = None
        self.asset_body_size = 0
        self.asset_body = None
        if user_id is not None:
            self.add(user_id, asset_file, asset_body)
```

- packされる変数

| 変数名            | 説明                                                         |
| ----------------- | ------------------------------------------------------------ |
| asset_id          | BBcAssetオブジェクトの識別子（アセットの識別子）             |
| user_id           | このアセットの所有者の識別子                                 |
| nonce             | ランダムな値 (オブジェクト作成時に生成される)                |
| asset_file_size   | 外部ファイルのファイルサイズ（バイト）                       |
| asset_file_digest | 外部ファイルのSHA256ダイジェスト                             |
| asset_body_size   | このオブジェクト（asset_body）に格納する情報のサイズ（バイト） |
| asset_body        | アセット情報本体（文字列、バイナリまたはdictオブジェクト(pythonのみ)） |

- packされない変数

| 変数名    | 説明                                           |
| --------- | ---------------------------------------------- |
| id_length | 上位のBBcTransactionオブジェクトの値を引き継ぐ |

### Packed binary data

[図8](#fig8)と[図10](#fig10)の"asset"の部分に、BBcAssetオブジェクトをpackしたものを格納する。その内容は以下の通りである。

```asciiarmor
    0               1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                 asset_group_id (ID structure)             ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                    user_id (ID structure)                 ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                      nonce (ID structure)                 ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      asset_file_size (4)                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                  asset_file_digest (32)                   ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        asset_body_size (2)    |      asset_body_type (2)      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
   |                                                               |
   ~~~                         asset_body                        ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

<center>図11 BBcAssetのpacked data</center>

外部ファイルが存在しない場合は、asset_file_size=0としてasset_file_digestの部分を省略する。asset_body_sizeはasset_body部分のバイト長である（バイト単位）。asset_body_typeは0または1の値を取り、下記の通りasset_bodyの中身の種類を表す。

| asset_body_type値 | 説明                           |
| ----------------- | ------------------------------ |
| 0                 | 文字列またはバイナリデータ     |
| 1                 | pythonのdictionaryオブジェクト |



## BBcPointer

定義ファイル：[bbc1/core/libs/bbclib_pointer.py](https://github.com/beyond-blockchain/bbc1/blob/develop/bbc1/core/libs/bbclib_pointer.py)

BBcPointerオブジェクトは、過去のトランザクションを参照する（関係性を表す）ために用いる。

### クラス定義

```python
class BBcPointer:
    def __init__(self, transaction_id=None, asset_id=None, id_length=DEFAULT_ID_LEN):
        self.id_length = id_length
        if transaction_id is not None and id_length < 32:
            self.transaction_id = transaction_id[:id_length]
        else:
            self.transaction_id = transaction_id
        if asset_id is not None and id_length < 32:
            self.asset_id = asset_id[:id_length]
        else:
            self.asset_id = asset_id
```

- packされる変数

| 変数名         | 説明                                                         |
| -------------- | ------------------------------------------------------------ |
| transaction_id | 参照する過去のトランザクションの識別子                       |
| asset_id       | transaction_idで参照しているBBcTransactionオブジェクトの中の対象となるBBcAssetオブジェクトのasset_id。アプリケーション次第では省略可能（何を参照しているかをtransaction_idだけで判断できるなら）。 |

- packされない変数

| 変数名    | 説明                                           |
| --------- | ---------------------------------------------- |
| id_length | 上位のBBcTransactionオブジェクトの値を引き継ぐ |

### Packed binary data

[図10](#fig10)の"packed data array of pointers"の部分に、BBcPointerオブジェクトをpackしたものを連ねて格納する。それぞれのオブジェクトのpacked dataの内容は以下の通りである。

```asciiarmor
    0               1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                 transaction_id (ID structure)             ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    asset_id_existence (2)     |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
   ~~~                   asset_id (ID structure)                 ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

<center>図12 BBcPointerのpacked data</center>

asset_idを省略する場合は、asset_id_existence=0とし、省略しない場合はasset_id_existence=1とする。



## BBcWitness

定義ファイル：[bbc1/core/libs/bbclib_witness.py](https://github.com/beyond-blockchain/bbc1/blob/develop/bbc1/core/libs/bbclib_witness.py)

BBcWitnessオブジェクトは、どのユーザの署名がどこに格納されているか（上位のtransaction objectのsignaturesの何番目の要素か）を保存する。BBcReferenceを用いている場合など、必要なければこのオブジェクトは省略可能である。

### クラス定義

```python
class BBcWitness:
    def __init__(self, id_length=DEFAULT_ID_LEN):
        self.id_length = id_length
        self.transaction = None
        self.user_ids = list()
        self.sig_indices = list()
```

- packされる変数

| 変数名      | 説明                                                         |
| ----------- | ------------------------------------------------------------ |
| user_ids    | ユーザ識別子のリスト                                         |
| sig_indices | user_idsにリストされているユーザの署名が、上位のBBcTransactionオブジェクトのsignatresリストのどの要素に対応するかを示す。(つまりuser_idsリストとsig_indicesリストの要素数はおなじになる) |

- packされない変数

| 変数名      | 説明                                           |
| ----------- | ---------------------------------------------- |
| id_length   | 上位のBBcTransactionオブジェクトの値を引き継ぐ |
| transaction | 上位のBBcTransactionオブジェクトへの参照       |

### Packed binary data

[図3](#fig3)の"witness"の部分のpacked dataの全体構成は図6のとおりであり、packed data of an objectは、BBcWitnessオブジェクトがpackされたものである。witnessはリストではなく単独のオブジェクトであるため、たかだかオブジェクトを一つしか含まない。オブジェクトのpacked dataの構成は以下の通りである。

```asciiarmor
    0               1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      num_sig_indices (2)      |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
   ~~~                        user_ids                           ~~~
   |                   (list of ID structures)                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         index value (2)       |            ....             ~~~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
   ~~~                       ... (index values)                  ~~~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
```

<center>図13 BBcPointerのpacked data</center>

user_idsとsig_indicesはともに同じ要素数のリストなので、packed dataの冒頭のnum_sig_indicesで両方の要素数を表している。user_idsのリストに続き、要素番号列（sig_indices）が格納される。



## BBcCrossRef

定義ファイル：[bbc1/core/libs/bbclib_crossref.py](https://github.com/beyond-blockchain/bbc1/blob/develop/bbc1/core/libs/bbclib_crossref.py)

BBcCrossRefオブジェクトは、他のドメインで発生したトランザクションの存在を証明する（履歴交差）ために用いる。このオブジェクトは省略可能である。

### クラス定義

```python
class BBcCrossRef:
    def __init__(self, domain_id=None, transaction_id=None, unpack=None):
        self.domain_id = domain_id
        self.transaction_id = transaction_id
        if unpack is not None:
            self.unpack(unpack)
```

- packされる変数

| 変数名         | 説明                                                         |
| -------------- | ------------------------------------------------------------ |
| domain_id      | トランザクションが登録されたドメインの識別子                 |
| transaction_id | domain_idの識別子を持つドメインに登録されたトランザクションの識別子。 |

### Packed binary data

[図3](#fig3)の"cross_ref"の部分のpacked dataの全体構成は図6のとおりであり、packed data of an objectは、BBcCrossRefオブジェクトがpackされたものである。witnessはリストではなく単独のオブジェクトであるため、たかだかオブジェクトを一つしか含まない。オブジェクトのpacked dataの構成は以下の通りである。

```asciiarmor
    0               1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~         domain_id (ID structure, id_length=32 only)       ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~      transaction_id (ID structure, id_length=32 only)     ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


```

<center>図14 BBcPointerのpacked data</center>

他のドメインと整合を取るため、domain_idとtransaction_idのid_lengthは最大長の32バイト固定とする。短いid_lengthを使っている場合は、下位バイトだけを取得すれば良い。



## BBcSignature

定義ファイル：[bbc1/core/libs/bbclib_signature.py](https://github.com/beyond-blockchain/bbc1/blob/develop/bbc1/core/libs/bbclib_signature.py)

BBcSignatureオブジェクトは、トランザクションへの署名と検証用の公開鍵を格納する。署名は上位BBcTransactionオブジェクトのtransaction_idを秘密鍵で暗号化することによって行われる。

### クラス定義

```python
class BBcSignature:
    def __init__(self, key_type=DEFAULT_CURVETYPE, unpack=None):
        self.key_type = key_type
        self.signature = None
        self.pubkey = None
        self.keypair = None
        self.not_initialized = True
        if unpack is not None:
            self.not_initialized = False
            self.unpack(unpack)

```

- packされる変数

| 変数名    | 説明                                                         |
| --------- | ------------------------------------------------------------ |
| key_type  | 楕円曲線のタイプ                                             |
| signature | 署名のバイナリ                                               |
| pubkey    | 公開鍵のnaiiveバイナリ（256bit系の鍵なら33バイトまたは65バイトの長さを持つ） |

- packされない変数

| 変数名          | 説明                                                         |
| --------------- | ------------------------------------------------------------ |
| not_initialized | 署名がすでに格納されているかどうかを表すフラグ(Trueなら格納済み) |
| keypair         | 鍵ペアオブジェクト。検証に、このオブジェクト内の秘密鍵を用いる。 |

### Packed binary data

[図3](#fig3)の"signatures"の部分のpacked dataの全体構成は図6のとおりであり、packed data of an objectは、BBcSignatureオブジェクトがpackされたものである。オブジェクトのpacked dataの構成は以下の通りである。

```asciiarmor
    0               1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          key_type (4)                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         key_length (4)    [unit is "bit"]     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                      public key binary                    ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       signature_length (4)   [unit is "bit"]  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~~~                      public key binary                    ~~~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


```

<center>図15 BBcPointerのpacked data</center>

key_type=0の場合は、key_length以降すべてのデータを省略する。なお、key_typeの種類はbbclib_keypair.pyで定義されており、2018年12月現在、対応するkey_typeは以下の通りである。

| key_type             | 説明                                                         |
| -------------------- | ------------------------------------------------------------ |
| NOT_INITIALIZED (=0) | まだBBcSignatureオブジェクトに署名や鍵が格納されていない。SIGN_REQUESTなどで他ノードに署名がまだ付与されていないトランザクションを送るときなどに用いる。 |
| ECDSA_SECP256k1 (=1) | ECC SECP256k1                                                |
| ECDSA_P256v1 (=2)    | ECC Prime-256v1                                              |

また、key_lengthおよびsignature_lengthは**ビット単位**であることに注意する。



# 他言語への移植

bbclib、つまりトランザクションデータそのものの操作機能を他のプログラミング言語に移植する場合も、[図1](#fig1)およびその後に示したとおりｍ，packed binary dataとBBcTranactionオブジェクトの変換が行えれば良い。2018年12月現在、[Go言語版](https://github.com/beyond-blockchain/bbclib-go)が存在する。