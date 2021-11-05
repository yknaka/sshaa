# sshaa

This program reads 'auth.log', which records ssh accesses in Ubuntu and Devian OS, ones of the Linux servers, and analyzes unauthorized accesses.
This program also analyzes and visualizes the country of the IP address and the number of times the IP address appears in the ssh login attempts where login failures are recorded.

# Outputs
## Graph
Top 5 Countries of IPs Where SSH Login Attempts Failed
![Figure](https://github.com/yknaka/sshaa/blob/main/sshanalysis_result_group_by_country.png)

Top 10 IPs Where SSH Login Attempts Failed
![Figure](https://github.com/yknaka/sshaa/blob/main/sshanalysis_result_group_by_ip.png)

## CSV report
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
## log(またはaddr)
Specify the location of 'auth.log'.

The default value is "/var/log/auth.log".

## show_top
Specify how many countries are diplayed in the graph.

The default value is 5.

## ignore_less
Specify the threshold value to exclude from the count when the number of accesses from the same IP is less than the number.

The default value is 50.

## expire_whois
How long (in seconds) to keep the value retrieved by WHOIS. When the expiration date has passed, the reference value will be retrieved again.

The default value is 2592000 (30 days).

## whois_url
Specify the URL of the API to refer to when retrieving the country name of the access source from the IP.

If "whois_url=auto" is descripted, this program will cycle through the preset list to find the one that can be retrieved correctly.

The reason for not being able to obtain the correct information maybe the limitation of the access attempts of WHOIS API services.

When directly specifying the WHOIS API URL, there is currently only one condition under which the WHOIS can be obtained correctly.

1. You can get the IP address for WHOIS and get the response in json format.

For Example:

https://*****.com/1.2.3.4/json

In this case, enter the IP address you want to do WHOIS as '{IP}'

such as

```
whois_url="https://*****.com/{ip}/json"
```


## ip_dict
This program usually save the country names found by the WHOIS API and use the cache to speed up the process next time.

The default is cache ON and the file name is "ip_whois_history.pkl".

When you want NOT to use cache,

Use this option.

```
  ip_dict=None
```

## group_by_ip
Flag to change the analysis.

When this flag is present, the source IP address, country, and number of attacks will be displayed instead of being aggregated by country.

# aa
Flag to analyze what kind of attack was done.

# aa_result_name
Specify the output name of the attack analysis result(above 'aa').

The defualt value is 'aa_analysis.csv'.

## show_country_name
Specify how to display the country names.

If this flag is present, the country name will be displayed in the manner specified by 'show_country_name_as'.

## show_country_name_as
Flag to change the way the country name is displayed.

The display name will be selected from the columns that match the column names in 'Countries.csv'.

The defualt value is 'COUNTRY NAME'.

## export_graph_name
Change the file name of the analysis result graph. 

The default value is "sshanalysis_result.png".

## export_csv_name
The values shown in the graph are output in CSV format.

You can specify the name of the list file to be output with this setting.

The default is "sshanalysis_result.csv".

## export_all_ip:
Flag to output the list of all IP addresses and the number of occurrences in the log file. 

The output destination is specified by "export_iplist_name".

## export_iplist_name
If the "export_all_ip" option is specified, the list of all IP addresses and the number of occurrences in the log file will be saved in CSV format.

You can specify the name of the CSV file to be output with this setting.

The default value is "sshanalysis_ip_countlist.csv".

## dont_show_gui_graph
Flag for not displaying the result graph on the screen.

File output of graphs is performed regardless of the flag.

## mask_ip
Display IP addresses as\*\*\*.\*\*\*.\*\*\*.

# Example
``` console
  sshaa log='./auth.log' show_top=6 ignore_less=100 whois_url="http://ipwhois.app/json/{ip}" ip_dict="dict.pkl" export_graph_name="result.png" export_all_ip
```

``` Python3
  python3 src/sshaa.py log='./auth.log' show_top=6 ignore_less=100 whois_url="http://ipwhois.app/json/{ip}" ip_dict="dict.pkl" export_graph_name="result.png" export_all_ip
```

# Appendix
## Countries.csv

Quoted by [National Diet Library](https://iss.ndl.go.jp/help/help_ja/help_country_codes.html)(Oct. 28, 2021)
