Programming guide for BBc-1 version 1.0
====
BBc-1のアプリケーションを開発するためのAPIの利用方法について解説する。

BBc-1アプリケーションは、bbc1/core/ディレクトリにあるbbc\_app.pyとbbclib.pyが提供する機能を利用する。クライアントアプリケーションはcore nodeにTCPで接続し、トランザクションの登録や検索などをcore nodeに指示する。まずはcore nodeに接続する方法を解説する。core nodeから応答メッセージを受け取る方法には、同期型と非同期型の方法があるが、以下ではまず同期型を前提に説明する。また細かいエラー処理は省略している。

# メッセージの構造
クライアントとcore node間でやり取りされるメッセージは、全てdictionary型であり、基本的な情報として以下のキーを持つ。メッセージ送信時にメッセージ構造をプログラマが意識する必要はないが、受信時にはキーを指定したアクセスが必要になる。
```
msg = {
    KeyType.command: コマンドタイプ(bbclib.MsgType),
    KeyType.domain_id: ドメインID(256bitのバイナリ),
    KeyType.source_user_id: 送信元ユーザID,
    KeyType.query_id: 問い合わせID(2バイトのバイナリ),
    KeyType.status: エラーコード(bbc_error.pyで定義),  # core nodeからの応答メッセージのみ
}
```
コマンドの種別に応じて、さらに様々なキーが追加される。なお、全てのキーはmessage\_key\_types.pyの中のKeyTypeクラスで定義されている。


# 接続〜トランザクション生成〜登録〜検索
## 準備
まずは、core nodeをdomainに参加させる必要がある。最も簡単な方法は、bbc\_domain\_config.pyを利用する方法である。すでにdomainに参加済みであればこの手順は不要である。

## core nodeへの接続
core nodeへの接続までのコード例を以下に示す。

```
from bbc1.core import bbclib
from bbc1.core import bbc_app


user_id = bbclib.get_new_id("user_id for testing")
domain_id = bbclib.get_new_id("domain_id for testing")
keypair = bbclib.KeyPair()
keypair.generate()
path_to_node_key_file = "path/to/file"

client = bbc_app.BBcAppClient(port=9000, multiq=False, loglevel='all')  # default port is 9000
client.set_domain_id(domain_id)
client.set_user_id(user_id)
client.set_keypair(keypair)
client.set_node_key(path_to_node_key_file)

client.register_to_core()
```
user\_idとdomain\_idはいずれも256bitのバイト列である。ここでは適当なバイト列を文字列から生成している。BBcAppClient()によって、core nodeに接続するクライアントオブジェクトが生成される。なおこの時点ですでにTCPコネクションが張られる。set\_domain\_id)()およびset_user\_id()はclient(クライアントオブジェクト)にセットするだけで、これらのメソッドだけではcore nodeには伝わらない。最後のregister\_to\_core()によって、domain\_idを持つdomainに対してuser\_idを登録し、メッセージ授受が可能になる。なお、register\_to\_core()を読んだ時点でcore nodeが指定domainに参加していない場合は、登録に失敗するが失敗メッセージは返答されないので注意が必要である。

keypairはトランザクションに署名する際に利用する。set_keypair()でクライアントオブジェクトに登録しているのは、非同期型メッセージ処理を行う際にコールバックの中で署名を付与する場合があるためである(後述のSIGN\_REQUESTで利用する)。

core nodeとクライアント間のメッセージングの内、システム管理用のメッセージについては、権限を持ったクライアントだけに使用を限定するために、メッセージに署名を付加する必要がある。署名計算用の秘密鍵はbbc\_core.pyが自動生成し、ワーキングディレクトリにnode\_key.pemというファイルとして保存される。上記のpath/to/fileにはそのファイルへのパスを記載する（またはファイル自体を何処かにコピーして、そのパスを記載しても良い）。なお、bbc\_core.pyのコンフィグ（config.json）で"use\_node\_key"をfalseにする、または```bbc\_core.py --no\_nodekey```で起動することで、このnode\_keyを利用しないように設定することも可能である。



## トランザクションの生成
トランザクションは、アセットデータおよび他のトランザクションへのポインタを保持し、デジタル署名によって保護される。そのデータ構造を作るためには、bbclib.pyを利用する。
```
asset_group_id = bbclib.get_new_id("asset_group_id for testing")

keypair = bbclib.Keypair()
keypair.generate()

txobj = bbclib.make_transaction(relation_num=1, witness=True)
bbclib.add_relation_asset(txobj, relation_idx=0, asset_group_id=asset_group_id,
                          user_id=user_id, asset_body=b'test asset data', asset_file=b'file content')
txobj.witness.add_witness(user_id)
sig = txobj.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1, private_key=keypair.private_key, public_key=keypair.public_key)

txobj.witness.add_signature(user_id=user_id, signature=sig)

print(txobj)
```
asset\_group\_idも他のidと同様に256bitのバイト列である。keypairは秘密鍵と公開鍵のペアを保存するオブジェクトである。一般的なアプリケーションでは鍵を外部ファイルに保存しておき、それを読み込んでKeyPairオブジェクトを作成するが上記の例では、その場で鍵ペアを生成している。

make\_transaction()はトランザクションデータ構造を生成するためのユーティリティであり、relation\_numやevent\_num等で、トランザクション内にどの項目を何個埋め込むかを指定できる。上記の例では、Relationを1つとWitnessをトランザクションに含めることになる。add\_relation\_asset()は生成されたトランザクションオブジェクトにAssetを登録するためのユーティリティである。relation\_idxで何番目のRelationに情報を格納するかを指定している。ここでは、トランザクションデータ構造の中に直接埋め込まれる情報(b'test asset data')とアセットファイルとして分離して管理される情報(b'file content')が登録される。

witness.add\_witness(user\_id)は、user\_id用の署名領域をトランザクション内に確保する。その後、witness.add\_signature()によって、実際の署名オブジェクトをトランザクションに格納する。署名オブジェクトはトランザクションオブジェクト(txobj)のsign()に鍵を指定すれば得られる。

BBcTransactionクラスには__str__メソッドが定義されているので、print文などで文字列としてアクセスすれば、トランザクションデータの内容を取得できる。

### トランザクションのデータフォーマット
トランザクションのデータフォーマットは、デフォルト設定では独自のバイナリフォーマットである。無駄が少ないためデータサイズは小さくなるが、バイナリ操作を必要とするためjavascript
などの言語では利用しにくい。そのため、データフォーマットとして、bson (binary JSON)
およびbzip2で圧縮したbsonフォーマットもサポートする。トランザクションデータの先頭2バイトがフォーマットタイプを表しており、取りうる値はbbclib.pyのBBcFormatクラスに宣言されている。
なお、圧縮されたbsonフォーマットは解凍後はbsonフォーマットと全く同じものになるため、bbclib.pyの内部では全く同じ処理が行われている（シリアライズの最後のデータ出力じにcompress、デシリアライズの最初のデータ入力時にdecompressするのみである）

データフォーマットが変わると、同じ内容でもtransaction\_idが変わってしまうため、署名結果も変わってしまう。したがって、同一domain内ではデータフォーマットを統一すべきである。

デフォルトのフォーマット以外を利用する際は、各種オブジェクトを生成する際に、format_typeパラメータを指定する必要がある。
```
asset_group_id = bbclib.get_new_id("asset_group_id for testing")

keypair = bbclib.Keypair()
keypair.generate()

txobj = bbclib.make_transaction(relation_num=1, witness=True, format_type=bbclib.BBcFormat.FORMAT_BSON_COMPRESS_BZ2)
bbclib.add_relation_asset(txobj, relation_idx=0, asset_group_id=asset_group_id,
                          user_id=user_id, asset_body=b'test asset data', asset_file=b'file content')
txobj.witness.add_witness(user_id)
sig = txobj.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1, private_key=keypair.private_key, public_key=keypair.public_key)

txobj.witness.add_signature(user_id=user_id, signature=sig)

print(txobj)
```
上記の例では、make\_transaction()のところで、```format_type=bbclib.BBcFormat.FORMAT_BSON_COMPRESS_BZ2```を指定している。
BBcAssetなどのオブジェクトを直接生成する場合は、それぞれのオブジェクト生成時に同じように```format_type=```を指定する必要がある（不整合が起こるとエラーでinsertできなくなる）。

## トランザクションの登録
生成したトランザクションは以下のようにしてcore nodeに登録する。
```
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_error import *

client.insert_transaction(txobj)
response_data = client.callback.synchronize()
if response_data[KeyType.status] < ESUCCESS:
    print("ERROR: ", response_data[KeyType.reason].decode())
    assert False
```
insert\_transaction()でトランザクションをcore nodeに送り込む。成否について返答メッセージが送られてくるため、callback.synchronize()で応答メッセージを待ち受ける（同期型）。応答メッセージはdictionary型であり、response\_dataに格納れる。なお、失敗するケースとしては、そもそもcore nodeがドメインに参加していないパターンが考えられる。


## トランザクションの検索
core nodeに保存されているトランザクションを検索、取得するメソッドは2つある。そのトランザクションのtransaction\_idが判明している場合と、asset\_group\_idやasset\_idなどが判明している場合で利用できるメソッドが異なる。

### transaction\_idが判明している場合
```
txobj.digest()
txid = txobj.transaction_id
astid = txobj.relations[0].asset.asset_id

client.search_transaction(txid)
response_data = client.callback.synchronize()
if response_data[KeyType.status] < ESUCCESS:
    print("ERROR: ", response_data[KeyType.reason].decode())
    assert False
if response_data[KeyType.transaction_id] != txid:
    print("ERROR: something wrong")
    assert False
tx_data = response_data[KeyType.transaction_data]
asset_files = response_data[KeyType.all_asset_files]
txobj_obtained = bbclib.BBcTransaction(deserialize=tx_data)

print(txobj_obtained)
print("# Content of the asset file:", asset_files[astid])
```
トランザクションオブジェクトは一度digestメソッドでダイジェスト計算を実施すると、自分自身のtransaction_idや含まれているアセットのasset_idも計算される(本来このような使い方はしないはずであるが、説明用のテストサンプルとして記述している)。
search_transaction()はtransaction_idが判明している場合に、トランザクションデータを取得するメソッドである。改ざんされていなければ、返答メッセージのdictionaryの中のKeyType.transaction_dataというキーに対応するvalueとして得られる。また、KeyType.all_asset_filesというキーに対応するvalueとしてアセットファイルを格納したdictionaryが得られる。
得られたtx_dataはバイナリデータ列なので、BBcTransactionオブジェクトのデシリアライズする必要がある。BBcTransactionを初期化する際にdeserialize引数を指定すれば、同時にデシリアライズできる。


### transaction\_idが判明していない場合
asset\_group\_idやasset\_id、user\_idで検索できる。(以下は、asset\_group\_idとasset\_idの例）
```
client.search_transaction_with_condition(asset_group_id=asset_group_id, count=10)  # the default value of "count" is 1
response_data = client.callback.synchronize()
if response_data[KeyType.status] < ESUCCESS:
    print("ERROR: ", response_data[KeyType.reason].decode())
    assert False
txdata_array = response_data[KeyType.transactions]
asset_files = response_data[KeyType.all_asset_files]
txobj_obtained = bbclib.BBcTransaction(deserialize=txdata_array[0])
print(txobj_obtained)
print("# Content of the asset file:", asset_files[astid])

client.search_transaction_with_condition(asset_id=astid, count=10)  # the default value of "count" is 1
response_data = client.callback.synchronize()
if response_data[KeyType.status] < ESUCCESS:
    print("ERROR: ", response_data[KeyType.reason].decode())
    assert False
txdata_array = response_data[KeyType.transactions]
asset_files = response_data[KeyType.all_asset_files]
txobj_obtained = bbclib.BBcTransaction(deserialize=txdata_array[0])
print(txobj_obtained)
print("# Content of the asset file:", asset_files[astid])
```
前半はasset\_group\_idを指定した検索、後半はasset\_idを指定した検索で、いずれもsearch\_transaction\_with\_condition()によって行う。複数のトランザクションが見つかる可能性があるため、返答する最大のトランザクション数をcountで指定する。複数の項目(asset\_group\_id、asset\_id、user\_id)を指定することもできる。複数指定した場合は条件はANDで絞り込まれる。search\_transaction\_with\_condition()で検索した場合、結果は複数のトランザクションを含む可能性があるため、前述のsearch\_transaction()の場合と異なりKeyType.transactionsがキーとなる。この例では、検索に合致するトランザクションが1つしかないことがわかっているので、txdata\_array\[0\]のように決め打ちで指定している。


### トランザクションまたはアセットが改ざんされた場合(改ざんからの復旧)
ここでの改ざんは、署名検証に失敗する改ざんである。core nodeはトランザクションをsearchする度に署名を検証する。署名検証に失敗した場合、その旨をクライアントに通知する。
```
client.search_transaction_with_condition(asset_group_id=asset_group_id)
response_data = client.callback.synchronize()
```
上記で、検索結果がdictionary型のresponse_dataに格納されるが、トランザクション情報は以下のkeyに対するvalueに格納される。

|key|中身|データタイプ
|:------|:-----|:------|
|KeyType.transactions|改ざんされていない正常なトランザクション|list型|
|KeyType.all\_asset\_files|改ざんされていない正常なアセットファイル|dictionary型|
|KeyType.compromised\_transactions|改ざんされたトランザクション|list型|
|KeyType.compromised\_asset\_files|改ざんされたアセットファイル|dictionary型|

つまり、search\_transaction()およびsearch\_transaction\_with\_condition()の戻り値を得たときは、KeyType.compromised\_transactionsおよびKeyType.compromised\_asset\_filesの存在を確認しなければならない。

トランザクションは複数のcore nodeやDBで保持するように設定することができる（bbc\_domain\_config.pyを用いて設定可能）。あるDB上でトランザクションが万一改ざんされた場合でも、他のDBの同一トランザクションが正常であれば、不正なトランザクションを正常なトランザクションで上書きすれば、実質的には改ざんを防ぐことができる。

BBc-1では、改ざんが行われた事実そのものにも情報があると考え、改ざんデータの復旧のトリガはクライアントから与えるよう設計した。つまり、上述のように、KeyType.compromised\_transactionsおよびKeyType.compromised\_asset\_filesのvalueが存在する場合、次に示すメソッドを呼んで、core nodeに対して改ざんからの復旧を指示する。
```
client.request_to_repair_transaction(txid)
client.request_to_repair_asset(asset_group_id, asset_id)
```
トランザクションとアセットファイルはそれぞれ別々に復旧させる必要がある。上記のtxidは復旧したいトランザクションのtransaction\_idであり、asset\_group\_idとasset\_idも復旧したいアセットファイルに関するものである。なお、request\_to\_repair\_transaction()とrequest\_to\_repair\_asset()には一切の応答メッセージはないため、再度searchメソッドを呼んで復旧が完了したかを確認する必要がある。


## トランザクション登録完了通知
アプリケーションによっては、他のクライアントがトランザクションを登録したことをトリガにして、処理を行う場合がある。BBc-1では、asset\_group\_id単位でトランザクション登録完了通知を受け取ることができる。なお、この通知は、core nodeから非同期に発生するメッセージであるため、コールバックメソッドを登録しておく必要がある（コールバックについての詳細は後述する）
```
def proc_notify_inserted(self, dat):
    list_of_asset_group_ids = dat[KeyType.asset_group_ids]
    txid = dat[KeyType.transaction_id]
    print("Inserted transaction %s with asset_groups %s" % (txid.hex(), [asgid.hex() for asgid in list_of_asset_group_ids])


client.callback.proc_notify_inserted = proc_notify_inserted

client.request_insert_completion_notification(asset_group_id)
```
request\_insert\_completion\_notificationメソッドで、監視したいasset\_group\_idを指定すると、それ以降そのasset\_group\_idをもつトランザクション（より具体的にはトランザクション内のBBcEventおよびBBcRelationにそのasset\_group\_idを含むもの）が登録される度に、KeyType.commandがKeyType.NOTIFY\_INSERTEDであるようなメッセージ（登録完了通知）を受け取ることができる。通知を解除したい場合は、```client.cancel_insert_completion_notification(asset_group_id)```を呼べば良い。

1つのトランザクションには複数のBBcEventやBBcRelationオブジェクトを含むことが出来、しかもそれらはそれぞれ別々のasset\_group\_idを持つ可能性があるため、1つのトランザクションの登録は、複数のasset\_group\_idについてNOTIFY\_INSERTEDメッセージを発生させる可能性がある。そのため、コールバック関数proc\_notify\_inserted()にあるように、KeyType.list\_of\_asset\_group\_idsでasset\_group\_idのlistが、KeyType.transaction\_idとともに通知される。

```client.callback.proc_notify_inserted = proc_notify_inserted```でコールバックメソッドを上書きしているが、後述するように、コールバッククラスを継承する方法もある。


# core nodeからのメッセージ受信

core nodeから応答メッセージを受け取る方法には、同期型と非同期型の方法がある。受信するメッセージ種別ごとに処理メソッドがbbc_app.pyの中のCallbackクラスに定義されている。

同期型アプリケーションを作成したい場合は、Callbackクラスのデフォルト実装をそのまま用いれば、メッセージ待受キューに受信メッセージが到着するまで待つので、到着後にキューからメッセージを取得して処理すれば良い。非同期型で応答メッセージを処理する場合は、そのクラスを継承して、メッセージ処理メソッドをオーバーライドすれば良い。以下に2種類の同期型の実装方法と、非同期型の実装方法を示す。

## 同期型(先着順)の実装
コールバッククラスのオブジェクトは、メッセージキューを持つ。単一のキューを持たせる方法は最も単純な実装方法であり、前節までに紹介した方法である。トランザクション検索の最も単純な例を再掲する。

```
client.search_transaction(txid)
response_data = client.callback.synchronize()
```
callback.synchronize()は、コールバックオブジェクトの単一キュー(self.queue)にメッセージが到達するまで待ち、メッセージがと達すると、その内容を戻り値として返すメソッドである。

キューが単一であるため、core nodeで時間のかかる処理と簡単な処理を投入した場合や、前述の登録完了通知や後述のユーザ間メッセージなど非同期に発生するメッセージがあると、意図しない順番でメッセージを取得してしまうため、注意が必要である。簡易なアプリケーションやテスト目的以外での利用は推奨しない。

## 同期型(問い合わせIDごとの複数キュー)の実装
上記の問題を解決するために、BBc−1ではquery\_id（問い合わせID）が各メッセージに付与される。何らかの応答が見込まれるメッセージ（REQUEST/RESPONSE型）に対して、メッセージ送信時にquery\_idが付与され、その度にそのquery\_id用の待受キューが作成される。メッセージを受信してクライアントプログラムがそれを処理すれば自動的にキュー自体が破棄される。この方式と非同期型を組み合わるのがベストプラクティスだと考えられる。

これを利用するためには、BBcAppClientクラスの初期化時に```multiq=True```を設定し、```client.callback.synchronize()```の代わりに```client.callback.sync_by_queryid()```を用いれば良い。

```
from bbc1.core import bbclib
from bbc1.core import bbc_app


user_id = bbclib.get_new_id("user_id for testing")
domain_id = bbclib.get_new_id("domain_id for testing")

client = bbc_app.BBcAppClient(port=9000, multiq=True, loglevel='all')  # default multiq value is True
client.set_domain_id(domain_id)
client.set_user_id(user_id)

client.register_to_core()

(中略)

query_id = client.search_transaction(txid)
response_data = client.callback.sync_by_queryid(query_id)
```
これまで触れてこなかったが、search\_transactionやinsertなどのメソッドは問い合わせID(2バイトのバイト列)を返す。前節までのsynchronize()では問い合わせIDを利用していなかったので、戻り値を取っていなかった。
callback.sync\_by\_queryid(query\_id)によって問い合わせIDを指定したメッセージ待受が可能になる。

## 非同期型の実装

core nodeから受信したメッセージは、メッセージ内のKeyType.commandというキーのvalueに応じてコールバックメソッドが呼び出される。デフォルトでは、受信したメッセージをキューに格納する処理が実装されているため、前述のような同期型メッセージングが可能になっている。

非同期に受信メッセージを処理する場合は、非同期処理にしたいメソッドのみオーバーライドするようなコールバッククラスを定義すれば良い（トランザクション登録完了通知の例ではクラスを継承せずにメソッド単体を再定義していた）。

```
class MessageProcessor(bbc_app.Callback):
    def __init__(self):
        super(MessageProcessor, self).__init__(self)

    def proc_user_message(self, dat):
        user_message = dat[KeyType.message]
        print("Received user message: %s" % user_message)


client = bbc_app.BBcAppClient(port=9000, loglevel='all')  # the default of multiq is true
client.set_domain_id(domain_id)
client.set_user_id(user_id)
callback_obj = MessageProcessor()
client.set_callback(callback_obj)

client.register_to_core()
```

set\_callback()で、オリジナルのコールバックオブジェクト(callback\_obj)を登録している。このオリジナルのコールバッククラスは、proc\_user\_messageメソッド(後述するクライアント間メッセージを処理するメソッド)のみをオーバーライドしている（それ以外はデフォルトのまま）。これによってクライアント間のメッセージだけを非同期処理できるようになる。


# クライアント間のメッセージング
前述したようにクライアントはそれぞれuser\_idを持ち、core nodeにregister\_to\_core()で登録している。このように登録されたクライアント同士はuser\_idを指定することで任意のメッセージを送り合うことができる。他ユーザからのメッセージを受信するコールバックメソッドは、proc\_user\_message()である。

## ユニキャストメッセージ
```
class MessageProcessor(bbc_app.Callback):
    def __init__(self):
        super(MessageProcessor, self).__init__(self)

    def proc_user_message(self, dat):
        user_message = dat[KeyType.message]
        print("Received user message: %s" % user_message)


user_id1 = bbclib.get_new_id("user_id1 for testing")
user_id2 = bbclib.get_new_id("user_id2 for testing")
domain_id = bbclib.get_new_id("domain_id for testing")

client = bbc_app.BBcAppClient(port=9000, loglevel='all')  # the default of multiq is true
client.set_domain_id(domain_id)
client.set_user_id(user_id1)   # or user_id2
callback_obj = MessageProcessor()
client.set_callback(callback_obj)

client.register_to_core()

message_to_send1 = {"message": "This is a test message"}
client.send_message(message_to_send1, user_id1)
message_to_send2 = "Test message No.2"
client.send_message(message_to_send2, user_id2)

import time
time.sleep(2)
```
前半部分は前節で例示したコールバックと同じものである。このコードは少なくとも2つのクライアントが必要で、それぞれuser\_id1とuser\_id2というユーザIDを持っていることを前提としている。
このコードではメッセージは2つ送信され、1つはuser\_id1のクライアントへ、もう一つはuser\_id2のクライアントへ送信される。受信したメッセージはproc\_user\_message()の中のprint文が実行される。なお、存在しないuser\_id宛にメッセージを送付しても、何も処理されずに破棄される。
なお、送付できるメッセージは、文字列、バイナリ、dictionary、list、tupleである。

## マルチキャストメッセージ
マルチキャストとは、1つのメッセージを複数のクライアントに送信することである。マルチキャストメッセージの受信を望むクライアントは、core nodeに対して、マルチキャストアドレスで待ち受けていることを通知すれば良い。なお宛先の指定方法はユニキャストの時と同様にuser\_idで指定する。IPマルチキャストと異なり、アドレス体系にマルチキャストとユニキャストの区別はなく、複数のクライアントがそのuser\_idをマルチキャストアドレスとみなしているか(つまりcore ondeに通知しているか)どうかだけで決まる。
```
multicast_receiver_id = bbclib.get_new_id("multicast for testing")

client = bbc_app.BBcAppClient(port=9000, multiq=False, loglevel='all')  # default port is 9000
client.set_domain_id(domain_id)
client.set_user_id(multicast_receiver_id)

client.register_to_core(on_multiple_nodes=True)
```
通常のユニキャストとの違いは、register\_to\_core()の引数に*on\_multiple\_nodes=True*を付加するだけである。メッセージの送信の仕方はユニキャストと全く同じで、send\_message()メソッドを用いる。


## エニーキャストメッセージ
エニーキャストは、複数の宛先クライアントのうちのどれか1つにメッセージを配送する方法である。BBc-1では、マルチキャストアドレスとしてcore nodeに登録されている宛先user\_idに対して、送信側がAnycastフラグを立ててメッセージを送信することで、エニーキャストになる。
```
anycast_receiver_id = bbclib.get_new_id("anycast for testing")
msg = "this is a test anycast message"

clisnt.send_message(msg, anycast_receiver_id, is_anycast=True)
```
事前に複数のクライアントが同一のanycast\_receiver\_idを前節で示したマルチキャストアドレスの登録(```register_to_core(on_multiple_nodes=True)```)を実施済みであることが前提である。通常のメッセージ送信との違いはsend\_message()メソッドに```is_anycast=True```を付加するだけである。


## マルチuser\_id、マルチキャストの混合利用
アプリケーションによっては、複数のuser\_idを同時に利用したい場合（さらにマルチキャストやエニーキャストを組み合わせたい場合）がある。bbc_app.pyに定義されているBBcAppClientクラスのオブジェクトはset\_user\_id()メソッドでuser\_idを登録できるが、これはメッセージ送信時に送信元user\_idを自動付加することが主目的である。つまり、メッセージを送信する直前に該当するuser\_idをset\_user\_id()でセットすれば、複数のuser\_idを扱うことができる。
```
user_id1 = bbclib.get_new_id("user_id1 for testing")
user_id2 = bbclib.get_new_id("user_id2 for testing")
multicast_receiver_id = bbclib.get_new_id("multicast for testing")

client = bbc_app.BBcAppClient(port=9000, multiq=False, loglevel='all')  # default port is 9000
client.set_domain_id(domain_id)

client.set_user_id(multicast_receiver_id)
client.register_to_core(on_multiple_nodes=True)

client.set_user_id(user_id1)
client.register_to_core()
client.set_user_id(user_id2)
client.register_to_core()

msg1 = "test message from user2"
client.send_message(msg, multicast_receiver_id)

client.set_user_id(user_id1)
msg2 = "test message from user1"
client.send_message(msg, user_id2)

```
msg1は、送信元がuser\_id2を送信元として、multicast\_receiver\_id宛にマルチキャストメッセージとして送っている。
msg2は、送信元がuser\_id1を送信元として、user\_id2宛にユニキャストメッセージを送っている(結局、自分自身がメッセージを受信することになるが、上記の例では受信のコードは省略した)。

## マルチコネクション
1つのアプリケーションを役割ごとに複数のプロセスに分割して動作させたい場合、同一user\_idをそれぞれのプロセスで利用することになる。それら全てのプロセスが同じcore nodeに接続に接続すれば、前述のマルチキャストを使わずとも、そのuser\_id宛のメッセージを全てのプロセスで受信できる(逆に言えば、複数のプロセスが異なるcore nodeに接続する場合は、マルチキャストの設定が必要になる)。
```
user_id1 = bbclib.get_new_id("user_id1 for testing")

client = bbc_app.BBcAppClient(port=9000, multiq=False, loglevel='all')  # default port is 9000
client.set_domain_id(domain_id)
client.set_user_id(user_id1)
client.register_to_core()
```
別々のプロセスで上記のコードを動作させ、同一のcore nodeに接続すると、core nodeは2つのプロセス宛にuser\_id1宛のメッセージが配送される。


# SIGN\_REQUEST
BBc-1の主要な機能の1つとして、SIGN\_REQUESTがある。これは、他のユーザにトランザクションへの署名を求める手順/メッセージングである。どのクライアントに署名を求めるかを指定してメッセージを送信するgather\_signaturesメソッドを利用する。

## BBcRelationを用いる場合（自分でどのクライアントに署名を求めるかを指定する場合）
* トランザクションを作成するクライアント側
```
from bbc1.core.bbc_error import *

user_id = bbclib.get_new_id("user_id for testing")
approver_user_id1 = bbclib.get_new_id("approver_user_id1 for testing")
approver_user_id2 = bbclib.get_new_id("approver_user_id2 for testing")

# *** make transaction ****
txobj = *****
asset_files[asset_id] = file_content
# *******

query_id = client.gather_signatures(txobj, asset_files=asset_files, destinations=[approver_user_id1, approver_user_id2])
for i in range(2):  # because 2 users will return signatures
    if i < 1:
        recv_msg = client.callback.sync_by_queryid(query_id, no_delete_q=False)
    else:
        recv_msg = client.callback.sync_by_queryid(query_id)
    if recv_msg[KeyType.status] < ESUCCESS:
        # error
        print("Error:", recv_msg[KeyType.reason])
        do_something
        continue
    result = recv_msg[KeyType.result]
    txobj.witness.add_signature(user_id=result[1], signature=result[2])
```
gather\_signatureメソッドに、対象となるトランザクションオブジェクトとそれに紐づくアセットファイルのdictionaryと、宛先ユーザのリストを指定すれば、SIGN\_REQUESTが送信される（なお、さらにanycast=Trueという引数を付加すれば、メッセージはエニーキャストとして送信される）。

query\_idを取得して、sync_by_queryidメソッドで待ち受けているが、返答は2つのクライアントから返されるので、1つ目の返答メッセージを受信しても2つ目のメッセージを受けるために専用キューを残して置かなければならないので、no_delete_q=Falseを引数に与えている。受信した署名はKeyType.resultのvalueにリストとして格納されている。result\[0\]は署名の格納場所を表すインデックス、result\[1\]は署名主のuser\_id、result\[2\]は署名本体である。トランザクションに署名を加えるのはadd\_signatureメソッドを使い、引数にはuser\_idと署名本体を渡せば良い。

署名が拒絶された場合には、KeyType.statusにエラーコードが、KeyType.reasonに拒絶理由が格納されている。

* 署名を要求されるクライアント側
```
class MessageProcessor(bbc_app.Callback):
    def __init__(self):
        super(MessageProcessor, self).__init__(self)

    def proc_cmd_sign_request(self, dat):
        dst_user_id = dat[KeyType.source_user_id]
        query_id = dat[KeyType.query_id]
        transaction_id = dat[KeyType.transaction_id]
        if KeyType.transaction_data not in dat:
            print("Invalid message")
            self.client.sendback_denial_of_sign(dst=dst_user_id, transaction_id=transaction_id, reason_text="Invalid request", query_id=query_id)
            return
        txobj_received = bbclib.BBcTransaction()
        txobj_received.deserialize(dat[KeyType.transaction_data])
        # do something
        ...
        sig = txobj_received.sign(keypair=self.client.keypair)
        self.client.sendback_signature(dest_user_id=dst_user_id, transaction_id=txobj.transaction_id, signature=sig, query_id=query_id)

client = bbc_app.BBcAppClient(port=9000, loglevel='all')  # the default of multiq is true
client.set_domain_id(domain_id)
client.set_user_id(user_id)
client.set_keypair(keypair)
callback_obj = MessageProcessor()
client.set_callback(callback_obj)
client.register_to_core()
```
SIGN\_REQUESTは、いつ受信するかが事前にはわからないので、非同期型で待ち受けるのが基本である。したがって、非同期型の実装の節で説明したように、コールバッククラスを継承してSIGN\_REQUESTを処理するproc\_cmd\_sign\_requestメソッドをオーバーライドすればよい。コールバッククラスを継承したクラスのオブジェクトをset\_callback(callback\_obj)メソッドで登録するときにclientオブジェクトが内部で登録される。そのため、メッセージをsendback\_signatureやsendback\_denial\_of\_signメソッドで返答する場合は、self.clientオブジェクトを用いれば良い。

署名は、受信したトランザクションに対してsignメソッドを呼べば良い。その際に用いる秘密鍵は、self.client.keypairに保存されている(client.set_keypair(keypair)で登録されているため)。

署名せずに拒否する場合は、self.client.sendback\_denial\_of\_signメソッドを用いる。返答メッセージには、拒絶理由を含めることができる(前述の通り、受信側のKeyType.reasonにその拒絶理由が格納される)。

## BBcReferenceを用いる場合（署名を求めるべきクライアントを以前のトランザクションから取得する場合）
UTXOタイプのトランザクションを使っている場合、BBcEventオブジェクトとBBcReferenceオブジェクトがトランザクションの中に埋め込まれている。BBcEventオブジェクトは、アセット(BBcAsset)を含み「次にそのアセットを利用するときに、誰に署名を求めなければならないか(approver)」を指定する。それを受けて次のトランザクションでそのアセットを利用する(例えばトークンを支払うなど)際には、BBcReferenceオブジェクトに「どのトランザクションのBBcEventオブジェクトに書かれた指示(approver)に従うか」を記述し、そのapproverに署名を求める。
* トランザクションを作成するクライアント側
```
# get the previous transaction that the new transaction refers to
prev_txobj = ******

txobj = bbclib.make_transaction(event_num=1)
bbclib.add_event_asset(txobj, event_idx=0, asset_group_id=asset_group_id,
                       user_id=user, asset_body=b'123456')
txobj.events[0].add(reference_index=0, mandatory_approver=user_id)

reference = bbclib.add_reference_to_transaction(txobj, asset_group_id, prev_txobj, 0)
query_id = client.gather_signatures(txobj, reference_obj=reference)
```
prev\_txobjは、参照する過去のトランザクションである(つまりBBcEventの中でapproversを指定しているもの)。add\_event\_assetメソッドはBBcEventオブジェクトをトランザクションに追加するためのユーティリティである(さらに、次のアセット利用に向けてadd(reference\_index=0, mandatory\_approver=user\_id)でapproverを設定している。

そして、本節の本題である。まずは参照するトランザクションからBBcReferenceオブジェクトを作成し、トランザクションに追加する。上記の例では、add\_reference\_to\_transactionメソッドでそれを行っており、txobjに組み込み、さらに組み込んだそのBBcReferenceオブジェクトを戻り値として取得している。前節ではSIGN\_REQUESTを送信するgather\_signaturesメソッドの引数に宛先ユーザリストを指定したが、ここではBBcReferenceオブジェクトを指定する。BBcReferenceオブジェクトには、署名を求めるべきapproverの情報が参照する過去のトランザクションから抜き出されて格納されているため、gather\_signaturesメソッドはそれを見てSIGN\_REQUESTの宛先を決めている。

なお、署名を受信した後の処理は、前述の例と同じなので省略した。

* 署名を要求されるクライアント側
```
class MessageProcessor(bbc_app.Callback):
    def __init__(self):
        super(MessageProcessor, self).__init__(self)

    def proc_cmd_sign_request(self, dat):
        dst_user_id = dat[KeyType.source_user_id]
        query_id = dat[KeyType.query_id]
        transaction_id = dat[KeyType.transaction_id]
        if KeyType.transaction_data not in dat:
            print("Invalid message")
            self.client.sendback_denial_of_sign(dst=dst_user_id, transaction_id=transaction_id, reason_text="Invalid request", query_id=query_id)
            return
        if KeyType.transactions not in dat:
            print("Invalid message (no reference transaction)")
            self.client.sendback_denial_of_sign(dst=dst_user_id, transaction_id=transaction_id, reason_text="Invalid request(no reference transaction)", query_id=query_id)
            return
        txobj_received = bbclib.BBcTransaction(deserialize=dat[KeyType.transaction_data])

        objs = dict()
        for txid, txdata in dat[KeyType.transactions].items():
            objs[txid] = bbclib.BBcTransaction(deseriarize=txdata)

        for i, reference in enumerate(txobj_received.references):
            event = objs[reference.transaction_id].events[reference.event_index_in_ref]
            if self.client.user_id in event.mandatory_approvers:
                # do something to decide whether to approve or not
                if (you approve the transaction):
                    sig = txobj_received.sign(keypair=self.client.keypair)
                    self.client.sendback_signature(dest_user_id=dst_user_id, transaction_id=transaction_id, ref_index=i, signature=sig, query_id=query_id)
                    return
                else:
                    self.client.sendback_denial_of_sign(dst=dst_user_id, transaction_id=transaction_id, reason_text="Reject", query_id=query_id)
            return
```
前述の例と異なる部分のみ例示した。具体的にはコールバックのproc\_cmd\_sign\_requestメソッドだけが異なる。SIGN\_REQUEST送信側がBBcReferenceを元にしている場合、そのメッセージにはKeyType.transactionsが含まれる。これは参照している過去のトランザクションそのものが含まれており、受信側でわざわざ検索する必要がない。受信者は自分がどのBBcEventのapproverになっているかを調べて、実際にそのトランザクションを承認するかどうかを判断し、承認するなら署名を計算してsendback\_signatureメソッドを呼べば良い。

なおこの例では、mandatory\_approversの場合のみ示している。


# トランザクションの履歴検索
トランザクションは、過去のトランザクションを参照することで、あるアセットがどのような変遷をただるかを記録する事ができる。つまり、一連のトランザクションからアセットの履歴を取得できる。さらに1つのトランザクションは同時に複数のアセット(複数種類のアセットグループも可能)を含むことができ、それぞれについての履歴を含むことができる。

具体的には、トランザクションの中のBBcRelationオブジェクト(さらにその中のBBcPointerオブジェクト)、およびBBcReferenceオブジェクトが過去のトランザクションへのポインタ(transaction\_id)を含んでいる。したがって、これらのtransaction\_idを順次検索して、トランザクションの中身を確認していけばアセットの履歴を知ることができる。このように過去のtransaction\_idを辿りながら検索していくためのユーティリティとしてtraverse\_transactionsメソッドがある。
```
query_id = client.traverse_transactions(transaction_id, direction=1, hop_count=3)
response_data = client.callback.sync_by_queryid(query_id)
if KeyType.all_asset_files in response_data:
    asset_files = response_data[KeyType.all_asset_files]
if KeyType.transaction_tree in response_data:
    for i, txtree in enumerate(response_data[KeyType.transaction_tree]):
        for txdat in txtree:
            txobj = bbclib.BBcTransaction(deserialize=txdat)
            asset_body = txobj.events[0].asset.asset_body
            print("[%d] asset=%s" % (i, asset_body))
```
traverse\_transactionsメソッドには、起点となるトランザクションのtransaction\_idと、履歴を辿る方向(1なら過去のトランザクションに向かって検索、1以外なら未来のトランザクションに向かって検索)
、および取得する最大ホップ数(何世代離れたところまで取るか)である。その応答として得られるメッセージの中のKeyType.transaction\_treeがトランザクションの履歴である。KeyType
.transaction\_treeのvalueの中身はリストになっており、リストのリスト構造は以下のとおりである。
```
  tree_of_tx = [ [txdata1_1, txdata1_2, txdata1_3,,,,], [txdata2_1, txdata2_1, txdata2_1,,,,], [txdata3_1, txdata3_1, txdata3_1,,,,],,,,, ]
```
1番目のリスト\[txdata1\_1, txdata1\_2, txdata1\_3,,,,\]は1ホップ前後のトランザクション群であり、2番目のリストはそのさらに1ホップ離れたトランザクション群である。traverse\_transactionsメソッドにhop\_countを指定しているのは、取得する情報が多くなりすぎてcore nodeに負荷をかけすぎないようにするためである。なお、KeyType.transaction\_treeに含まれるトランザクション数が規定値(bbc\_core.pyに指定されているTX_TRAVERSAL_MAX=30)よりも多くなると、オーバーする部分およびそれが発生したホップ数のリスト全体を削除して返答される。さらに辿りたい場合は、transaction\_idを指定し直して再度traverse\_transactionsメソッドを呼べば良い。

# 履歴交差(BBcCrossRefオブジェクト)
履歴交差とは、全く無関係なドメインのトランザクションのtransaction\_idをトランザクションに含めることである。関係のないドメイン間でtransaction\_idを持ち合うことで、「辻褄を合わせた完全な改ざん」が非常に困難になる。履歴交差がない場合は、ドメイン内に保存されている全てのトランザクションを差し替えられると、改ざんが行われたかどうかの事実すらわからなくなるが、外部ドメインにtransaction\_idを通知しておけば、それをチェックすることで確実にそのtransaction\_idが存在していたことを証明できる。逆に言えば、そのtransaction\_idが存在しなくなっているということは、トランザクション全体が差し替えられたといえる。

## BBcCrossRefオブジェクトのトランザクションへの付加
この履歴交差は、他者のトランザクションを保持しなければならないため、ドメイン間での相互協力が不可欠である。履歴交差情報は具体的には、BBcCrossRefオブジェクトとしてdomain0でやり取りされる。そしていずれかのトランザクションにそのBBcCrossRefオブジェクトが取り込まれて登録される。BBcCrossRefオブジェクトはアプリケーションには何の影響も与えないため、含めても含めなくてもよいが、他のドメインで発生したtransaction\_idを数多くトランザクションに含めれば、それだけ他のトランザクションで自ドメインのtransaction\_idを含めてもらいやすくなる(core nodeがその制御を行う)。BBcCrossRefオブジェクトの含め方は以下のとおりである。
```
txobj = bbclib.make_transaction(relation_num=, witness=True)
bbclib.add_relation_asset(txobj, relation_idx=0, asset_group_id=asset_group_id,
                          user_id=user_id, asset_body=b'test asset data', asset_file=b'file content')
txobj.witness.add_witness(user_id)

client.include_cross_ref(txobj)

sig = txobj.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1, private_key=keypair.private_key, public_key=keypair.public_key)
txobj.witness.add_signature(user_id=user_id, signature=sig)

print(txobj)
```
include\_cross\_refメソッドを呼ぶことで、BBcCrossRefオブジェクトが付加される。付加すべきBBcCrossRefオブジェクトはcore nodeとclient間で自動的にやり取りされている。このinclude\_cross\_ref()を呼び出した時点では、付加すべきBBcCrossRefオブジェクトが割り当てられていないこともあるため、もし割当がなければこのメソッドを呼んでも何も起こらない。
なお、外部ドメインに通知されるのは、自ドメインのdomain\_idとtransaction\_idだけであるため、機密情報が外部に漏れることはない。またBBcCrossRefオブジェクトとして他ドメインに通知されるか、またどのドメインに通知されるかはcore nodeによって確率的に選択され、通知アルゴリズムは発展途上である。

## 他ドメインへの存在確認
他のドメインのトランザクションにtranaction\_idが保存されているかどうか、またそれが改ざんされていないかどうかを確認することで、自ドメインのトランザクションが不正なものと差し替えられていないことを確認できる。
```
client.request_cross_ref_holders_list()
response_data = client.callback.synchronize()

for txid_to_verify in dat[KeyType.transaction_id_list]:
    client.request_verify_by_cross_ref(txid_to_verify)
    response_data2 = client.callback.synchronize()
    if KeyType.cross_ref_verification_info in dat
        transaction_base_digest, cross_ref_data, sigdata, tx_format = dat[KeyType.cross_ref_verification_info]
        result = bbclib.verify_using_cross_ref(dm, txid_to_verify, transaction_base_digest, cross_ref_data, sigdata, format_type=tx_format)
        if result:
            print("transaction_id %s had registered in another domain")
        else:
            print("Something wrong in another domain....")
```
まずは、どのtransaction\_idが他ドメインに登録されているかを知るために、request\_cross\_ref\_holders\_listメソッドを呼び、BBcCrossRefオブジェクトに入れてもらっているtransaction\_idのリストを取得する。上記の例では、cross\_ref\_verification\_infoメソッドで問い合わせる。どのドメイン当てなのかはクライアントが意識する必要はなく、core nodeが適宜外部ドメインに問い合わせる。bbclib.verify_using_cross_refメソッドは、得られた応答メッセージを検証するユーティリティである。例のようにKeyType.cross_ref_verification_infoの内容を与えれば良い。結果はTrue/Falseであり、TrueであればそのBBcCrossRefオブジェクトは正しいものである(Falseなら、外部ドメインで何らかの改ざんが行われている)。つまり結果がTrueとなったtransaction\_idは、確実に外部ドメインに保存されており、過去にそのtransaction\_idを持つトランザクションが登録されたことを示している。

