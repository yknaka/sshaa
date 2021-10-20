# yknsshanalysis

auth.logを解析し、ログイン試行を解析する。
# install
pip install yknsshanalysis

# 使い方
yknsshanalysis

# オプション
addr:
auth.logファイルの場所を指定。初期値は/var/log/auth.log
show_top:
解析結果のグラフ表示の際、アクセス元上位何カ国を表示するか指定。初期値は5カ国。
ignore_less:
同一IPからのアクセスが指定回数以下の場合カウントから除外する。初期値は50回。
whois_url:
IPアドレスからアクセス元の国名を取得する際に参照するAPIのアドレス。検索するIPア>

# Example
yknsshanalysis addr='./auth.log' show_top=6 ignore_less=100 whois_url="http://ipwhois.app/json/xxx"
