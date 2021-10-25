# yknsshanalysis

Linuxサーバの一つであるUbuntu OSにおいてsshアクセスが記録されるauth.logを読み込み、不正ログインを分析する。
sshによるログイン試行のうち、ログイン失敗が記録されたものについて、IPアドレスの所属国と出現回数を分析し、視覚化する。
出力はCSVリストおよび円グラフ。

# install
pip install -U yknsshanalysis

# uninstall
pip uninstall -y yknsshanalysis


# オプション
addr:
auth.logファイルの場所を指定。初期値は/var/log/auth.log

show_top:
解析結果のグラフ表示の際、アクセス元上位何カ国を表示するか指定。初期値は5カ国。

ignore_less:
同一IPからのアクセスが指定回数以下の場合カウントから除外する。初期値は50回。

expire_whois:
WHOIS で取得した値を保持する期間。期限が過ぎた参照値は取得し直す。デフォルト値は30日。

whois_url:
IPアドレスからアクセス元の国名を取得する際に参照するAPIのアドレス。"whois_url=auto"を指定するとリストから正しく取得できるものを巡回する。

ip_dict:
WHOIS APIで判明した国名を保存し、次回以降キャッシュを利用することで高速化をはかる。デフォルトはキャッシュONでファイル名は"ip_whois_history.pkl"

キャッシュを利用しない場合は"ip_dict=None"と入力する

group_by_ip:
分析内容を変更するフラグ。このフラグが存在する場合、国別の集計を行わなわず、アクセス元IPアドレスと所属国および攻撃数を表示する。

export_graph_name:
分析内容（デフォルトではsshでのログイン試行のうち、ログインに失敗したパターンにおけるアクセス元IPアドレスの所属国分析）を示すグラフのファイル名を変更する。デフォルトは"sshanalysis_result.png"

export_csv_name:
グラフの示す数値がリスト形式で出力される。本設定で出力されるCSVファイル名を指定できる。デフォルトは"sshanalysis_result.csv"

export_all_ip:
ログファイル内に存在するすべてのIPアドレスと出現回数のリストを出力するフラグ。出力先は"export_iplist_name"で指定する。

export_iplist_name:
"export_all_ip"オプションを指定した場合、ログファイル内のすべてのIPアドレスと出現回数のリストをCSV形式で保存する。本設定で出力されるCSVファイル名を指定できる。
デフォルトは"sshanalysis_ip_countlist.csv"

# Example
yknsshanalysis addr='./auth.log' show_top=6 ignore_less=100 whois_url="http://ipwhois.app/json/xxx" ip_dict="dict.pkl" export_graph_name="result.png" export_all_ip
