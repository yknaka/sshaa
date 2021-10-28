# sshaa

Linuxサーバの一つであるUbuntu OSにおいてsshアクセスが記録されるauth.logを読み込み、不正ログインを分析する。
sshによるログイン試行のうち、ログイン失敗が記録されたものについて、IPアドレスの所属国と出現回数を分析し、視覚化する。

# Outputs
## Graph
Top 5 Countries of IPs Where SSH Login Attempts Failed
![Figure](./sshanalysis_result_ignore5.png)

Top 10 IPs Where SSH Login Attempts Failed
![Figure](./sshanalysis_result_group_by_ip.png)

## CSV
```
,country,count
113.88.13.132,CN,14883
61.177.172.13,CN,1625
221.181.185.153,KR,1264
222.187.232.205,CN,1235
221.181.185.198,AU,1212
221.181.185.159,KR,1187
221.131.165.56,CN,1072
221.181.185.135,KR,1043
221.181.185.220,CN,1037
222.187.239.109,China,966
```

# install
pip install -U sshaa

# uninstall
pip uninstall -y sshaa


# Options
## addr
auth.logファイルの場所を指定。初期値は/var/log/auth.log

## show_top
解析結果のグラフ表示の際、アクセス元上位何カ国を表示するか指定。初期値は5カ国。

## ignore_less
同一IPからのアクセスが指定回数以下の場合カウントから除外する。初期値は50回。

## expire_whois
WHOIS で取得した値を保持する期間。期限が過ぎた参照値は取得し直す。デフォルト値は30日。

## whois_url
IPアドレスからアクセス元の国名を取得する際に参照するAPIのアドレス。"whois_url=auto"を指定するとプリセットリストから正しく取得できるものを巡回する。
正しく取得できない原因としてはWhois APIのアクセス数制限等が考えられる。

Whoisの取得先を直接指定する場合、正しく取得できる条件は、現状下記1パターンのみ。

1. アクセス先のURLにWHOISを行うIPアドレスを入力でき、json形式でレスポンスを取得できる

https://*****.com/1.2.3.4/json など

この場合、IPアドレスの入力箇所を'xxx'として

```
whois_url="https://*****.com/xxx/json
```

と入力する


## ip_dict
WHOIS APIで判明した国名を保存し、次回以降キャッシュを利用することで高速化をはかる。デフォルトはキャッシュONでファイル名は"ip_whois_history.pkl"

キャッシュを利用しない場合は"ip_dict=None"と入力する

## group_by_ip
分析内容を変更するフラグ。このフラグが存在する場合、国別の集計を行わなわず、アクセス元IPアドレスと所属国および攻撃数を表示する。

## show_country_name
国名の表示方法を変更するフラグ。このフラグが存在する場合、国名がフルネームで表示される。

## show_ja_country_name
国名の表示方法を変更するフラグ。このフラグが存在する場合、国名が日本語フルネームで表示される。

## export_graph_name
分析内容（デフォルトではsshでのログイン試行のうち、ログインに失敗したパターンにおけるアクセス元IPアドレスの所属国分析）を示すグラフのファイル名を変更する。デフォルトは"sshanalysis_result.png"

## export_csv_name
グラフの示す数値がリスト形式で出力される。本設定で出力されるCSVファイル名を指定できる。デフォルトは"sshanalysis_result.csv"

## export_all_ip:
ログファイル内に存在するすべてのIPアドレスと出現回数のリストを出力するフラグ。出力先は"export_iplist_name"で指定する。

## export_iplist_name
"export_all_ip"オプションを指定した場合、ログファイル内のすべてのIPアドレスと出現回数のリストをCSV形式で保存する。本設定で出力されるCSVファイル名を指定できる。
デフォルトは"sshanalysis_ip_countlist.csv"

## dont_show_gui_graph
グラフを画面表示しないフラグ。グラフのファイル出力はフラグによらず行われる。


# Example
sshaa addr='./auth.log' show_top=6 ignore_less=100 whois_url="http://ipwhois.app/json/xxx" ip_dict="dict.pkl" export_graph_name="result.png" export_all_ip

# Appendix
##Countries.csv
Quoted by [National Diet Library](https://iss.ndl.go.jp/help/help_ja/help_country_codes.html)(Oct. 28, 2021)