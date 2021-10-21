import sys
import pandas as pd
import requests
import json
import time
import circlify
import matplotlib.pyplot as plt
import pickle
dic_ip_hisotry=None
whois_list=["http://ipinfo.io/xxx","http://ipwhois.app/json/xxx","https://ipapi.co/xxx/json"]
def _trim(string):
    if len(string) == 0:
        return ''
    elif string[0] == '\'' or string[0] == '\"':
        return string[1:-1]
    else :
        return string


def main(args):
    local_addr="/var/log/auth.log"
    show_top=5
    ignore_trial_less_than=50
    whois_url=["http://ipwhois.app/json/xxx"]
    ip_dict="ip_whois_history.pkl"
    export_name={"graph":"sshanalysis_result.png"}
    expire_whois=30*24*3600 #有効期限のデフォルト値は30日
    if type(args) is str:
        args=[args]
    for arg in args:
        arg_ = arg.lower()
        if arg_.startswith('addr='):
            local_addr=_trim(arg[5:])
        elif arg_.startswith('show_top='):
            show_top=int(_trim(arg[9:]))
        elif arg_.startswith('ignore_less='):
            ignore_trial_less_than=int(_trim(arg[12:]))
        elif arg_.startswith('whois_url='):
            url_tmp=_trim(arg[10:])
            if url_tmp.lower()=="auto":
                whois_url=whois_list
            else:
                whois_url=[url_tmp]
        elif arg_.startswith('ip_dict='):
            ip_dict=_trim(arg[8:])
            if ip_dict == "None":
                ip_dict=None
        elif arg_.startswith('export_graph_name='):
            export_name["graph"]=_trim(arg[18:])
        elif arg_.startswith('expire_whois='):
            expire_whois=int(_trim(arg[13:]))
    print("reading auth.log file...")
    df=pd.read_table(local_addr, header=None)
    print("analyzing log")
    df2=df[df[0].str.contains("Failed|Invalid user")]
    df_ipfreq=analyzeAuth_fast(df2)
    # 絞り込み
    df_ipfreq_=df_ipfreq[df_ipfreq["count"]>ignore_trial_less_than]
    if ip_dict is None:
        dic_ip_history=None
    else:
        print("loading whois history")
        dic_ip_history=loadLibrary(ip_dict)
    print("calling whois")
    df_ctfreq_,dic_ip_history=do_whois(whois_url,df_ipfreq_,dic_ip_history,expire_whois)
    if dic_ip_history is not None:
        print("exporting whois history")
        saveLibrary(ip_dict,dic_ip_history)
    print("grouping countries")
    dfs_list=country_grouping(df_ctfreq_)
    show_graph(show_top,dfs_list,export_name)


def analyzeAuth_fast(df):
    ip_list=[]
    for index, row in df.iterrows():
        s=row[0]
        stw='from '
        edw=' port '
        idx=s.find(stw)
        idx2=s.find(edw,idx+len(stw))
        ip=s[idx+len(stw):idx2]
        ip_list.append(ip)
    return pd.DataFrame({'count':pd.DataFrame(ip_list,columns=['ip']).ip.value_counts()})

def analyzeAuth(df):
    ip_arr=[]
    count=0
    for index, row in df.iterrows():
        s=row[0]
        # Failed password for xxx,Failed password for invalid user xxx,Invalid user xxx
        stw='Invalid user '
        edw='from '
        idx=s.find(stw)
        failPasswd=True
        if idx!=-1:
            idx2=s.find(edw,idx+len(stw))
            failPasswd=False
        else:
            stw='Failed password for invalid user '
            idx=s.find(stw)
            if idx!=-1:
                idx2=s.find(edw,idx+len(stw))
            else:
                stw='Failed password for '
                idx=s.find(stw)
                if idx!=-1:
                    idx2=s.find(edw,idx+len(stw))
                else:
                    continue
        user=s[idx+len(stw):idx2]
    #    print(user)
        idx=idx2
        stw=edw
        edw=' port '
        idx2=s.find(edw,idx+len(stw))
        ip=s[idx+len(stw):idx2]
    #    print(ip)
        idx=idx2
        stw=edw
        edw=' '
        idx2=s.find(edw,idx+len(stw))
        if idx2==-1:
            idx2=len(s)
        port=s[idx+len(stw):idx2]
    #    print(port)
        ip_arr.append([ip,user,port,failPasswd])
    #    count+=1
    #    if count>1000:
    #        break
    sr_ipcnt=pd.DataFrame(ip_arr,columns=['ip','user','port','pwd_atk']).ip.value_counts()
    return pd.DataFrame({'count':sr_ipcnt})


def saveLibrary(libaddr,my_dict):
    try:
        with open(libaddr, "wb") as tf:
            pickle.dump(my_dict,tf)
    except Exception as e:
        print(e)
def loadLibrary(libaddr):
    try:
        with open(libaddr, "rb") as tf:
            new_dict = pickle.load(tf)
        return new_dict
    except Exception as e:
        print(e)
        return {}


headers = {"content-type": "application/json"}
def whoisCountry(whois_url,ip_address,defaultValue):
    url=whois_url.replace('xxx',ip_address)
    response=requests.get(url, headers=headers)
    data = response.json()
    if "country" in data:
        return data["country"]
    else:
        return defaultValue
def do_whois(whois_url,df,dic_ip_history,expire_whois):
    dic_country={}
    is_ip_history_enabled=dic_ip_history is not None
    nowtime=time.time()
    if is_ip_history_enabled:
        for ip_address, v in df.iterrows():
            country=None
            if ip_address in dic_ip_history:
                data=dic_ip_history[ip_address]
                if nowtime-data["register"]<=expire_whois:
                    country=data["name"]
                else:
                    print("expired:",nowtime-data["register"],"[sec]"," removing IP:",ip_address," country:",data["name"])
                    del dic_ip_history[ip_address]
            if country is None:
                for url in whois_url:
                    country=whoisCountry(url,ip_address,"N/A")
                    if country!="N/A":
                        break;
                dic_ip_history[ip_address]={"name":country,"register":time.time()}
            dic_country[ip_address]=country
    else:
        for ip_address, v in df.iterrows():
            dic_country[ip_address]=whoisCountry(whois_url,"N/A")
    df_country=pd.DataFrame({"country":dic_country})
    df_country['count']=df['count']
    return df_country, dic_ip_history


def country_grouping(df):
    dfs=df.groupby("country").sum()
    dfs_list=[]
    for i,v in dfs.iterrows():
        d={'country':i,'attack':v.iloc[0]}
        dfs_list.append(d)
    dfs_list=sorted(dfs_list, key=lambda x: -x['attack'])
    return dfs_list


def show_graph(show_top,dfs_list,export_name):
    count=0
    top_country=[]
    top_attack=[]
    for d in dfs_list:
        top_country.append(d.get('country'))
        top_attack.append(d.get('attack'))
        count+=1
        if count>=show_top:
            break
    #circleのサイズの設定方法がわからないので力技
    top_country.reverse()
    df=pd.DataFrame(dfs_list)
    circles = circlify.circlify(
        top_attack,
        show_enclosure=False, 
        target_enclosure=circlify.Circle(x=0, y=0, r=1.0)
    )

    fig, ax = plt.subplots(figsize=(10,10))
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
              label+"\n"+str(df[df["country"]==label].attack.iloc[0]), 
              (x,y ) ,
              va='center',
              ha='center'
         )
    plt.savefig(export_name["graph"])
    plt.show()


main(sys.argv)
