# coding: UTF-8
import sys
import os
import time
import datetime
from ipaddress import ip_network
import socket
import pandas as pd
import requests
import circlify
import matplotlib.pyplot as plt
from matplotlib import rcParams
import pickle
import consoleoptions as get_option
whois_list = ["http://ipwhois.app/json/{ip}", "https://ipapi.co/{ip}/json", "http://ipinfo.io/{ip}"]


def main(args=sys.argv):
  df_ccode = pd.read_table("./Countries.csv", delimiter=",")
  # default option value
  optionDict = {
      "log": "/var/log/auth.log",
      "show_top": 5,
      "ignore_less": 50,
      "whois_url": "http://ipwhois.app/json/{ip}",
      "ip_dict": "ip_whois_history.pkl",
      "show_country_name_as": "COUNTRY NAME",
      "expire_whois": 30 * 24 * 3600,  # 30 days
      "alert_ip": "alert_ip",
      "alert_ip_ignore": "alert_ip_ignore",
  }
  export_name = {"alert_ip_csv": "alert_result.csv",
                 "alert_aa_stat_ip": "alert_attack_analysis_stat_by_ip.csv",
                 "alert_aa_stat": "alert_attack_analysis_stat.csv",
                 "aa_stat_ip": "attack_analysis_stat_by_ip.csv",
                 "aa_stat": "attack_analysis_stat.csv",
                 "graph": "sshanalysis_result.png",
                 "graph_csv": "sshanalysis_result.csv",
                 "count_csv": "sshanalysis_ip_countlist.csv"}
  # map option value from sys.argv
  if type(args) is str:
    args = [args]
  optionDict = get_option.get_dict(args, optionDict)
  get_option.to_int(optionDict, "show_top")
  get_option.to_int(optionDict, "ignore_less")
  get_option.to_int(optionDict, "expire_whois")
  if "option_file" in optionDict:
    optionDict = get_option.load_from_file(optionDict["option_file"], optionDict)
  if optionDict["whois_url"].lower() == "auto":
    optionDict["whois_url"] = whois_list
  else:
    if not isinstance(optionDict["whois_url"], list):
      optionDict["whois_url"] = [optionDict["whois_url"]]
  set_export("export_alert_report_name", "alert_ip_csv", optionDict, export_name)
  set_export("export_alert_aa_stat_name", "alert_aa_stat", optionDict, export_name)
  set_export("export_alert_aa_stat_by_ip_name", "alert_aa_stat_ip", optionDict, export_name)
  set_export("export_aa_stat_name", "aa_stat", optionDict, export_name)
  set_export("export_aa_stat_by_ip_name", "aa_stat_ip", optionDict, export_name)
  set_export("export_graph_name", "graph", optionDict, export_name)
  set_export("export_csv_name", "graph_csv", optionDict, export_name)
  set_export("export_iplist_name", "count_csv", optionDict, export_name)
  # old version compatibility
  if "addr" in optionDict:
    optionDict["log"] = optionDict["addr"]
  group_by_ip = "group_by_ip" in optionDict

  # main process
  print("reading auth.log file...")
  try:
    df = pd.read_table(optionDict["log"], header=None)
    lastmodified = datetime.datetime.fromtimestamp(os.path.getmtime(optionDict["log"]))
  except Exception as e:
    print("Some thing error has occurred during reading logfile.")
    print("Please check your file.")
    print(e)
    sys.exit(0)
  print("loading alert ip")
  list_alert_ip, list_ignore_ip = load_alert_ip(optionDict["alert_ip"], optionDict["alert_ip_ignore"])
  print("  *** alert IP pattern :", str(len(list_alert_ip)), "***")
  print("  *** ignore IP pattern :", str(len(list_ignore_ip)), "***")
  print("analyzing log")
  df_log = df[df[0].str.contains("Failed|Invalid user")]
  # Extract unauthorized access->count same IPs
  if 'aa' in optionDict:
    df_ipfreq, df_log_aa = create_ip_count_df(df_log, lastmodified)
  else:
    df_ipfreq = create_ip_count_df_fast(df_log)
  # Ignore unauthorized access from the same IP when it is below a certain level
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
  df_ct_ip_freq, dic_ip_history, df_alert_iphifreq = do_whois(df_iphifreq, dic_ip_history, df_ccode, list_alert_ip, list_ignore_ip, optionDict)
  if dic_ip_history is not None:
    print("...exporting whois history")
    saveLibrary(optionDict["ip_dict"], dic_ip_history)
  df_ct_ip_freq = convert_country_name(df_ct_ip_freq, df_ccode, optionDict)
  if len(df_alert_iphifreq) != 0:
    print("*** ", "\033[05;31m", "Malcious Access was Detected From Alerting IP List!!", "\033[0m", " ***")
    if 'aa' in optionDict:
      dic_al_aa_by_ip, dic_al_aa_whole = aa_analysis(df_alert_iphifreq, df_log_aa)
    print(df_alert_iphifreq.head(optionDict["show_top"]))
    print('...alert list exported')
  if 'aa' in optionDict:
    print("analyzing attacks detail")
    dic_aa_by_ip, dic_aa_whole = aa_analysis(df_ipfreq, df_log_aa)
  print("***result***")
  print(df_ct_ip_freq.head(optionDict["show_top"]))
  print("************")
  print("grouping countries")
  if group_by_ip:
    dfs_list = list_by_ip(df_ct_ip_freq)
  else:
    dfs_list = list_by_country(df_ct_ip_freq)
  # export
  if len(df_alert_iphifreq) != 0:
    if 'aa' in optionDict:
      export_aa_dic2csv(dic_al_aa_by_ip, export_name["alert_aa_stat_ip"])
      export_aa_dic2csv(dic_al_aa_whole, export_name["alert_aa_stat"])
    df_alert_iphifreq.to_csv(export_name["alert_ip_csv"], index_label=df_alert_iphifreq.columns.name)
  if 'aa' in optionDict:
    export_aa_dic2csv(dic_aa_by_ip, export_name["aa_stat_ip"])
    export_aa_dic2csv(dic_aa_whole, export_name["aa_stat"])
  else:
    print("")
  if "export_all_ip" in optionDict:
    df_ipfreq.sort_values(by="count", ascending=False).to_csv(export_name["count_csv"], index_label=df_ipfreq.columns.name)
  df_ct_ip_freq.sort_values(by="count", ascending=False).to_csv(export_name["graph_csv"], index_label=df_ct_ip_freq.columns.name)
  # make graph
  show_graph(dfs_list, df_ccode, optionDict, export_name)

# list alert ip


def load_alert_ip(pattern_file_path, ignore_file_path):
  list_alip = []
  if os.path.exists(pattern_file_path):
    with open(pattern_file_path) as f:
      for line in f:
        list_alip.append(convertip(line.strip()))
  list_igip = []
  if os.path.exists(ignore_file_path):
    with open(ignore_file_path) as f:
      for line in f:
        list_igip.append(convertip(line.strip()))
  return list_alip, list_igip


# for Ubuntu and Devian auth.log/secure
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


# for Ubuntu and Devian auth.log/secure
def create_ip_count_df(df_log, lastmodified=datetime.datetime.now()):
  ip_arr = []
  for index, row in df_log.iterrows():
    s = row[0]
    # time取得
    idx = s.find(': ')
    if idx != -1:
      s_ = s[0:idx]
      s_split = s_.split()
      time_str = ''.join([str(lastmodified.year), ",", s_split[0], ",", s_split[1], ",", s_split[2]])
      time = datetime.datetime.strptime(time_str, "%Y,%b,%d,%H:%M:%S")
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
    user = s[idx + len(stw):idx2].strip()
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
    ip_arr.append([ip, user, port, failPasswd, time])
  df_log_aa = pd.DataFrame(ip_arr, columns=['ip', 'user', 'port', 'pwd_atk', 'time'])
  sr_ipcnt = df_log_aa.ip.value_counts()
  return pd.DataFrame({'count': sr_ipcnt}), df_log_aa


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


def whoisCountry(whois_url, ip_address):
  url = whois_url.replace('{ip}', ip_address)
  response = requests.get(url, headers=headers)
  data = response.json()
  if "country_code" in data:
    data["country"] = data["country_code"].upper()
  elif "country" in data:
    data["country"]
  return data


def do_whois(df_ip_and_frequency, dic_ip_history, df_ccode, list_alert_ip, list_ignore_ip, optionDict):
  df_alert_ip_and_frequency = pd.DataFrame(columns=df_ip_and_frequency.columns)
  df_alert_ip_and_frequency.columns.name = "IP Address"
  dic_whois = {}
  is_ip_history_enabled = dic_ip_history is not None
  bool_ipfilter_exists = len(list_alert_ip) != 0 and len(list_ignore_ip) != 0
  nowtime = time.time()
  if is_ip_history_enabled:
    for ip_address, v in df_ip_and_frequency.iterrows():
      country = None
      org = None
      if bool_ipfilter_exists:
        if check_alerting_ip(ip_address, list_alert_ip, list_ignore_ip):
          df_alert_ip_and_frequency = df_alert_ip_and_frequency.append(pd.Series(v, name=ip_address))
      if ip_address in dic_ip_history:
        data = dic_ip_history[ip_address]
        if nowtime - data["register"] <= optionDict["expire_whois"]:
          if ("name" in data and "org" in data):
            country = data["name"]
            org = data["org"]
          else:
            del dic_ip_history[ip_address]
        else:
          print("expired:", nowtime - data["register"], "[sec]", " removing IP:", ip_address, " country:", data["name"])
          del dic_ip_history[ip_address]
      if country is None:
        for url in optionDict["whois_url"]:
          data = whoisCountry(url, ip_address)
          if "country" in data:
            country = data["country"]
          if "org" in data:
            org = data["org"]
          else:
            org = "N/A"
          if country != "N/A":
            break
        if len(country) != 2:
          ser = df_ccode[df_ccode['COUNTRY NAME'] == country.upper()]
          if ser.empty:
            print("No Matching Country Found:", country)
          else:
            country = ser["CODE"].iloc[-1]
        dic_ip_history[ip_address] = {"name": country, "org": org, "register": time.time()}
      dic_whois[ip_address] = {"country": country, "org": org}
  else:
    for ip_address, v in df_ip_and_frequency.iterrows():
      data = whoisCountry(optionDict["whois_url"])
      dic_whois[ip_address] = {"country": data["country"], "org": data["org"]}
  df_ip_country_frequency = pd.DataFrame.from_dict(dic_whois, orient="index")
  df_ip_country_frequency['count'] = df_ip_and_frequency['count']
  df_ip_country_frequency.columns.name = "IP Address"
  return df_ip_country_frequency, dic_ip_history, df_alert_ip_and_frequency


def check_alerting_ip(ip_address, list_alert, list_ignore):
  ip_instance = ip_network(ip_address)
  for igip in list_ignore:
    if ip_instance.subnet_of(igip):
      return False
  for alip in list_alert:
    if ip_instance.subnet_of(alip):
      return True
  return False

# attack analysis


def aa_analysis(df_ip_count, df_log_aa):
  dic_aa_by_ip = {}
  dic_aa_whole = {}
  for ip_address, v in df_ip_count.iterrows():
    df = df_log_aa[df_log_aa.ip == ip_address]
    dic = {}
    dic['user'] = df.user.value_counts().to_dict()
    dic['port'] = df.port.value_counts().to_dict()
    dic['pwd_atk'] = df.pwd_atk.value_counts().to_dict()
    dic_aa_by_ip[ip_address] = dic
  dic_aa_whole['ip_address'] = df_ip_count.to_dict()['count']
  dic_aa_whole['user'] = df_log_aa.groupby('user').size().to_dict()
  dic_aa_whole['port'] = df_log_aa.groupby('port').size().to_dict()
  dic_aa_whole['pwd_atk'] = df_log_aa.groupby('pwd_atk').size().to_dict()
  for k, v in dic_aa_whole.items():
    dic_aa_whole[k] = sorted(v.items(), key=lambda x: x[1], reverse=True)
  return dic_aa_by_ip, dic_aa_whole


def convert_country_name(df_ip_country_frequency, df_ccode, optionDict):
  if "show_country_name_as" in optionDict:
    key = optionDict["show_country_name_as"]
  else:
    return df_ip_country_frequency
  # create code dictionary
  dic_conv = {}
  for i, v in df_ccode.iterrows():
    dic_conv[v['CODE']] = v[key]
  df_ip_country_frequency.replace(dic_conv, inplace=True)
  return df_ip_country_frequency


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


def show_graph(country_frequency_list, df_ccode, optionDict, export_name):
  count = 0
  top_country = []
  top_attack = []
  for d in country_frequency_list:
    top_country.append(d.get('key'))
    top_attack.append(d.get('value'))
    count += 1
    if count >= optionDict["show_top"]:
      break
  top_country.reverse()
  df = pd.DataFrame(country_frequency_list)
  circles = circlify.circlify(
      top_attack,
      show_enclosure=False,
      target_enclosure=circlify.Circle(x=0, y=0, r=1.0)
  )

  fig, ax = plt.subplots(figsize=(10, 10))
  title = 'ssh-attacks from malicious IPs'
  ax.set_title(title)
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
  # set Japanese font if show_ja_country_name frag is active
  if "show_country_name_as" in optionDict and optionDict['show_country_name_as'] == "ja":
    rcParams['font.family'] = 'sans-serif'
    rcParams['font.sans-serif'] = ['Hiragino Maru Gothic Pro', 'Yu Gothic', 'Meiryo', 'Takao', 'IPAexGothic', 'IPAPGothic', 'VL PGothic', 'Noto Sans CJK JP']
  labels = top_country
  bool_mask_label = "mask_ip" in optionDict
  for circle, label in zip(circles, labels):
    x, y, r = circle
    ax.add_patch(plt.Circle((x, y), r, alpha=0.2, linewidth=2))
    plt.annotate(
        ("***.***.***.***" if bool_mask_label else label) + "\n" + str(df[df["key"] == label].value.iloc[0]),
        (x, y),
        va='center',
        ha='center'
    )
  plt.savefig(export_name["graph"])
  if "dont_show_graph" not in optionDict:
    plt.show()


def set_export(optionName, list_name, optionDict, export_list):
  if optionName in optionDict:
    export_list[list_name] = optionDict[optionName]


# export recursive dictionary


def export_aa_dic2csv(dic, export_path):
  with open(export_path, mode='w') as f:
    export_dic(dic, "", f)

# export dictionary recursively


def export_dic(dic, indent, f):
  for k, v in dic.items():
    f.write("".join([indent, str(k)]))
    if type(v) is list:
      f.write("\n")
      export_list(v, indent + "  ", f)
    elif type(v) is dict:
      f.write("\n")
      export_dic(v, indent + "  ", f)
    else:
      f.write("".join([":", str(v), "\n"]))

# export tuple recursively


def export_tuple(tup, indent, f):
  f.write(indent)
  vl = []
  for v in tup:
    vl.append(str(v))
  f.write(":".join(vl))
  f.write("\n")

# export list recursively


def export_list(lis, indent, f):
  for v in lis:
    if type(v) is tuple:
      export_tuple(v, indent + "  ", f)
    else:
      f.write("".join([indent, v, "\n"]))


def convertip(value):
  if value == "localhost":
    return ip_network('127.0.0.1')
  elif value.startswith('self'):
    myip = socket.gethostbyname(socket.gethostname())
    value = value.replace('self', myip)
    return ip_network(value)
  elif value.count('.') >= 3:
    return ip_network(value)
  else:
    raise ValueError('Unsupported IP address Type')


if __name__ == '__main__':
  main()
