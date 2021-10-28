# coding: UTF-8
import sys
import pandas as pd
import requests
import time
import circlify
import matplotlib.pyplot as plt
import pickle
import consoleoptions as get_option

whois_list = ["http://ipinfo.io/xxx", "http://ipwhois.app/json/xxx", "https://ipapi.co/xxx/json"]


def main(args=sys.argv):
  # オプションの初期値を設定
  optionDict = {}
  optionDict["log"] = "/var/log/auth.log"
  optionDict["show_top"] = 5
  optionDict["ignore_less"] = 50
  optionDict["whois_url"] = "http://ipwhois.app/json/xxx"
  optionDict["ip_dict"] = "ip_whois_history.pkl"
  optionDict["expire_whois"] = 30 * 24 * 3600  # 有効期限のデフォルト値は30日
  export_name = {"graph": "sshanalysis_result.png",
                 "graph_csv": "sshanalysis_result.csv",
                 "count_csv": "sshanalysis_ip_countlist.csv"}
  # オプションの代入処理
  if type(args) is str:
    args = [args]
  optionDict = get_option.get_dict(args, optionDict)
  get_option.to_int(optionDict, "show_top")
  get_option.to_int(optionDict, "ignore_less")
  get_option.to_int(optionDict, "expire_whois")
  if optionDict["whois_url"].lower() == "auto":
    optionDict["whois_url"] = whois_list
  else:
    optionDict["whois_url"] = [optionDict["whois_url"]]
  if "export_graph_name" in optionDict:
    export_name["graph"] = optionDict["export_graph_name"]
  if "export_csv_name" in optionDict:
    export_name["graph_csv"] = optionDict["export_csv_name"]
  if "export_iplist_name" in optionDict:
    export_name["count_csv"] = optionDict["export_iplist_name"]
  # 旧版との互換性
  if "addr" in optionDict:
    optionDict["log"] = optionDict["addr"]
  group_by_ip = "group_by_ip" in optionDict

  # メイン処理
  print("reading auth.log file...")
  try:
    df = pd.read_table(optionDict["log"], header=None)
  except Exception as e:
    print("Some thing error has occurred during reading logfile.")
    print("Please check your file.")
    print(e)
    sys.exit(0)
  print("analyzing log")
  df_log = df[df[0].str.contains("Failed|Invalid user")]
  # Extract unauthorized access->count same IPs
  df_ipfreq = create_ip_count_df_fast(df_log)
  # Ignore unauthorized access from the same IP if it is below a certain level
  if group_by_ip:
    df_iphifreq = df_ipfreq.sort_values(by="count", ascending=False).head(optionDict["show_top"])
  else:
    df_iphifreq = df_ipfreq[df_ipfreq["count"] > optionDict["ignore_less"]]
  # Load whois history
  if optionDict["ip_dict"] == "None":
    print("...whois cache has been ignored.")
    dic_ip_history = None
  else:
    print("...loading whois history")
    dic_ip_history = loadLibrary(optionDict["ip_dict"])
  print("operating whois")
  df_ct_ip_freq, dic_ip_history = do_whois(df_iphifreq, dic_ip_history, optionDict)
  if dic_ip_history is not None:
    print("...exporting whois history")
    saveLibrary(optionDict["ip_dict"], dic_ip_history)
  print(df_ct_ip_freq.head(optionDict["show_top"]))
  print("grouping countries")
  if group_by_ip:
    dfs_list = list_by_ip(df_ct_ip_freq)
  else:
    dfs_list = list_by_country(df_ct_ip_freq)
  export_csv(df_ipfreq, df_ct_ip_freq, optionDict, export_name)
  show_graph(dfs_list, optionDict, export_name)


# for Ubuntu auth.log
def create_ip_count_df_fast(df_log):
  ip_list = []
  for index, row in df_log.iterrows():
    s = row[0]
    stw = 'from '
    edw = ' port '
    idx = s.find(stw)
    idx2 = s.find(edw, idx + len(stw))
    ip = s[idx + len(stw):idx2]
    ip_list.append(ip)
  return pd.DataFrame({'count': pd.DataFrame(ip_list, columns=['ip']).ip.value_counts()})


# for Ubuntu auth.log
def create_ip_count_df(df_log):
  ip_arr = []
  for index, row in df_log.iterrows():
    s = row[0]
    # Failed password for xxx,Failed password for invalid user xxx,Invalid user xxx
    stw = 'Invalid user '
    edw = 'from '
    idx = s.find(stw)
    failPasswd = True
    if idx != -1:
      idx2 = s.find(edw, idx + len(stw))
      failPasswd = False
    else:
      stw = 'Failed password for invalid user '
      idx = s.find(stw)
      if idx != -1:
        idx2 = s.find(edw, idx + len(stw))
      else:
        stw = 'Failed password for '
        idx = s.find(stw)
        if idx != -1:
          idx2 = s.find(edw, idx + len(stw))
        else:
          continue
    user = s[idx + len(stw):idx2]
    idx = idx2
    stw = edw
    edw = ' port '
    idx2 = s.find(edw, idx + len(stw))
    ip = s[idx + len(stw):idx2]
    idx = idx2
    stw = edw
    edw = ' '
    idx2 = s.find(edw, idx + len(stw))
    if idx2 == -1:
      idx2 = len(s)
    port = s[idx + len(stw):idx2]
    ip_arr.append([ip, user, port, failPasswd])
  sr_ipcnt = pd.DataFrame(ip_arr, columns=['ip', 'user', 'port', 'pwd_atk']).ip.value_counts()
  return pd.DataFrame({'count': sr_ipcnt})


def saveLibrary(libaddr, my_dict):
  try:
    with open(libaddr, "wb") as tf:
      pickle.dump(my_dict, tf)
  except Exception as e:
    print(e)


def loadLibrary(libaddr):
  try:
    with open(libaddr, "rb") as tf:
      new_dict = pickle.load(tf)
    return new_dict
  except FileNotFoundError:
    print("*****No such file... Preparing a new dictionary.")
    return {}
  except Exception as e:
    print("*****", e, " Preparing a new dictionary")
    return {}


headers = {"content-type": "application/json"}


def whoisCountry(whois_url, ip_address, defaultValue):
  url = whois_url.replace('xxx', ip_address)
  response = requests.get(url, headers=headers)
  data = response.json()
  if "country" in data:
    return data["country"]
  else:
    return defaultValue


def do_whois(df_ip_and_frequency, dic_ip_history, optionDict):
  dic_country = {}
  is_ip_history_enabled = dic_ip_history is not None
  nowtime = time.time()
  if is_ip_history_enabled:
    for ip_address, v in df_ip_and_frequency.iterrows():
      country = None
      if ip_address in dic_ip_history:
        data = dic_ip_history[ip_address]
        if nowtime - data["register"] <= optionDict["expire_whois"]:
          country = data["name"]
        else:
          print("expired:", nowtime - data["register"], "[sec]", " removing IP:", ip_address, " country:", data["name"])
          del dic_ip_history[ip_address]
      if country is None:
        for url in optionDict["whois_url"]:
          country = whoisCountry(url, ip_address, "N/A")
          if country != "N/A":
            break
        dic_ip_history[ip_address] = {"name": country, "register": time.time()}
      dic_country[ip_address] = country
  else:
    for ip_address, v in df_ip_and_frequency.iterrows():
      dic_country[ip_address] = whoisCountry(optionDict["whois_url"], "N/A")
  df_ip_country_frequency = pd.DataFrame({"country": dic_country})
  df_ip_country_frequency['count'] = df_ip_and_frequency['count']
  return df_ip_country_frequency, dic_ip_history


def list_by_country(df_ip_country_frequency):
  df_country_frequency = df_ip_country_frequency.groupby("country").sum()
  country_frequency_list = []
  # key = country, value= total attack count
  for i, v in df_country_frequency.iterrows():
    d = {'key': i, 'value': v.iloc[0]}
    country_frequency_list.append(d)
  country_frequency_list = sorted(country_frequency_list, key=lambda x: -x['value'])
  return country_frequency_list


def list_by_ip(df_ip_country_frequency):
  country_frequency_list = []
  # key = IP(country), value= total attack count
  for ip, v in df_ip_country_frequency.iterrows():
    d = {'key': ip + "\n(" + v.iloc[0] + ")", 'value': v.iloc[1]}
    country_frequency_list.append(d)
  country_frequency_list = sorted(country_frequency_list, key=lambda x: -x['value'])
  return country_frequency_list


def show_graph(country_frequency_list, optionDict, export_name):
  count = 0
  top_country = []
  top_attack = []
  for d in country_frequency_list:
    top_country.append(d.get('key'))
    top_attack.append(d.get('value'))
    count += 1
    if count >= optionDict["show_top"]:
      break
  # circleのサイズの設定方法がわからないので力技
  top_country.reverse()
  df = pd.DataFrame(country_frequency_list)
  circles = circlify.circlify(
      top_attack,
      show_enclosure=False,
      target_enclosure=circlify.Circle(x=0, y=0, r=1.0)
  )

  fig, ax = plt.subplots(figsize=(10, 10))
  ax.set_title('sshanalysis')
  ax.axis('off')

  lim = max(
      max(
          abs(circle.x) + circle.r,
          abs(circle.y) + circle.r,
      )
      for circle in circles
  )
  plt.xlim(-lim, lim)
  plt.ylim(-lim, lim)
  labels = top_country
  for circle, label in zip(circles, labels):
    x, y, r = circle
    ax.add_patch(plt.Circle((x, y), r, alpha=0.2, linewidth=2))
    plt.annotate(
        label + "\n" + str(df[df["key"] == label].value.iloc[0]),
        (x, y),
        va='center',
        ha='center'
    )
  plt.savefig(export_name["graph"])
  plt.show()


def export_csv(df_ipfreq, df_ip_country_frequency, optionDict, export_name):
  if "export_all_ip" in optionDict:
    df_ipfreq.sort_values(by="count", ascending=False).to_csv(export_name["count_csv"])
  df_ip_country_frequency.sort_values(by="count", ascending=False).to_csv(export_name["graph_csv"])


if __name__ == '__main__':
  main()
