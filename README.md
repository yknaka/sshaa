# sshaa

This program reads 'auth.log', which records ssh accesses in Ubuntu and Devian OS, ones of the Linux servers, and analyzes unauthorized accesses.
This program also analyzes and visualizes the country of the IP address and the number of times the IP address appears in the ssh login attempts where login failures are recorded.

# Outputs
## Graph
Top 5 Countries of IPs Where SSH Login Attempts Failed
![Figure](https://github.com/yknaka/sshaa/blob/main/sample_result_group_by_country.png)

Top 10 IPs Where SSH Login Attempts Failed
![Figure](https://github.com/yknaka/sshaa/blob/main/sample_result_group_by_ip.png)

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
## Source Settings
### option_file
Set options by JSON file.

If it is specified at the same time as other options, 'option_file' takes precedence.

### log
Specify the location of 'auth.log'(Devian or Ubuntu ssh-daemon log file) or 'secure'(CentOS ssh-daemon log file).

The default value is "/var/log/auth.log".

## Analysis Settings
### ignore_less
Specify the threshold value to exclude from the count when the number of accesses from the same IP is less than the number.

The default value is 50.

### expire_whois
How long (in seconds) to keep the value retrieved by WHOIS. When the expiration date has passed, the reference value will be retrieved again.

The default value is 2592000 (30 days).

### whois_url
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

### ip_dict
This program usually save the country names found by the WHOIS API and use the cache to speed up the process next time.

The default is cache ON and the file name is "ip_whois_history.pkl".

When you want NOT to use cache,

Use this option.

```
  ip_dict=None
```

### group_by_ip
Flag to change the analysis.

When this flag is present, the source IP address, country, and number of attacks will be displayed instead of being aggregated by country.


### aa
Flag to analyze what kind of attack was done.

If this option is active, the log will be analyzed for the login name, port number, and whether or not the password was entered (True or False), which can be obtained from the ssh log.

The analysis results will be output to the file specified by 'export_aa_stat_name' or 'export_aa_stat_by_ip_name'.

### export_all_ip:
Flag to output the list of all IP addresses and the number of occurrences in the log file. 

The output destination is specified by "export_iplist_name".

### show_top
Specify how many countries are diplayed in the graph.

The default value is 5.

### alert_ip
When the IP address of the unauthorized access exists in the list specified here, a result file will be output and a warning will be displayed in the console.

It can be used for the purpose of detecting unauthorized access from trusted networks by forged IPs and springboard IPs.

Addresses can be specified in a range by IP address and subnet mask. 

To register multiple addresses, start a new line. 

If you enter 'self' in the list, the local IP address of the PC that executed the command will be assigned.

For Example:
```
  less alert_ip
```

```
  192.168.0.0/24
  192.168.1.0/255.255.255.0
```

### alert_ip_ignore
Specify the exclusion condition for the list registered in 'alert_ip'.

It can be used for the purpose of detecting unauthorized access from trusted networks by forged IPs and springboard IPs.

Addresses can be specified in a range by IP address and subnet mask. 

To register multiple addresses, start a new line. 

If you enter 'self' in the list, the local IP address of the PC that executed the command will be assigned.

For Example:
```
  less alert_ip_ignore
```

```
  self
  localhost
```

### dont_show_graph
Flag for not displaying the result graph on the screen.

File output of graphs is performed regardless of the flag.

## View Settings
### show_country_name
Specify how to display the country names.

If this flag is present, the country name will be displayed in the manner specified by 'show_country_name_as'.

### show_country_name_as
Flag to change the way the country name is displayed.

The display name will be selected from the columns that match the column names in 'Countries.csv'.

The defualt value is 'COUNTRY NAME'.

### mask_ip
Display IP addresses as\*\*\*.\*\*\*.\*\*\*.

## Export
### export_graph_name
Change the file name of the analysis result graph. 

The default value is "sshanalysis_result.png".

### export_csv_name
The values shown in the graph are output in CSV format.

You can specify the name of the list file to be output with this setting.

The default is "sshanalysis_result.csv".

### export_iplist_name
If the "export_all_ip" option is specified, the list of all IP addresses and the number of occurrences in the log file will be saved in CSV format.

You can specify the name of the CSV file to be output with this setting.

The default value is "sshanalysis_ip_countlist.csv".

### export_aa_stat_name
Specifies the output destination of the attack analysis performed by option 'aa'.

The default value is "attack_analysis_stat.csv".

Outputs the analysis results of access source IP, login attempt user name, port number, and password input (True or False) from the access log.

### export_aa_stat_by_ip_name
Specifies the output destination of the attack analysis performed by option 'aa'.

The default value is "attack_analysis_stat_by_ip.csv".

Outputs the analysis results of the user name, port number, and whether or not password are entered (True or False) for each IP from the access log.

### export_alert_report_name
Specify the output destination of IP addresses and access attempts that exist in the range registered in 'alert_ip'.

If there is no IP in the registered list range, the file will not be output.

The default name is "alert_result.csv".


### export_alert_aa_stat_name
Specifies the output destination of the attack content analysis performed by option 'aa' for IP addresses and access attempts that exist in the range registered in 'alert_ip'.

The output items are the same as 'export_aa_stat_name'.

If there are no IPs in the registration list range, or if the option 'aa' is not specified, the file will not be output.

The default name is "alert_attack_analysis_stat.csv".

### export_alert_aa_stat_by_ip_name
Specifies the output destination of the attack content analysis performed by option 'aa' for IP addresses and access attempts that exist in the range registered in 'alert_ip'.

The output items are the same as 'export_aa_stat_by_ip_name'.

If there are no IPs in the registration list range, or if the option 'aa' is not specified, the file will not be output.

The default name is "alert_attack_analysis_stat_by_ip.csv".

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
