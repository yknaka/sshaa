import sys
import pandas as pd
import requests
import json
import time
import circlify
import matplotlib.pyplot as plt

def main(args):
    local_addr="/var/log/auth.log"
    show_top=5
    ignore_trial_less_than=50
    whois_url="http://ipwhois.app/json/xxx"
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
            whois_url=int(_trim(arg[10:]))
    df=pd.read_table(local_addr, header=None)
    df2=df[df[0].str.contains("Failed|Invalid user")]
    df_ipfreq=analyzeAuth_fast(df2)
    # 絞り込み
    df_ipfreq_=df_ipfreq[df_ipfreq["count"]>ignore_trial_less_than]
    df_ctfreq_=do_whois(whois_url,df_ipfreq_)
    dfs_list=country_grouping(df_ctfreq_)
    show_graph(show_top,dfs_list)

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

def do_whois(whois_url,df):
    headers = {"content-type": "application/json"}
    dic_country={}
    #st=time.time()
    for i, v in df.iterrows():
        url=whois_url.replace('xxx',i)
        response=requests.get(url, headers=headers)
        data = response.json()
        dic_country[i]=data["country"]
    #print("finish time:"+str(time.time()-st))
    df_country=pd.DataFrame({"country":dic_country})
    df_country['count']=df['count']
    return df_country

def country_grouping(df):
    dfs=df.groupby("country").sum()
    dfs_list=[]
    for i,v in dfs.iterrows():
        d={'country':i,'attack':v.iloc[0]}
        dfs_list.append(d)
    dfs_list=sorted(dfs_list, key=lambda x: -x['attack'])
    return dfs_list

def show_graph(show_top,dfs_list):
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
    plt.savefig("sshanalysis_result.png")
    plt.show()

def _trim(string):
    if len(string) == 0:
        return ''
    elif string[0] == '\'' or string[0] == '\"':
        return string[1:-1]
    else :
        return string
main(sys.argv)
