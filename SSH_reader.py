import re
import sys
import tarfile 
import datetime
import logging
import random
import argparse
from collections import defaultdict
from statistics import mean, stdev

log_dict_pattern = re.compile(r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<user>\w+)\s+sshd\[(?P<code>\d+)\]:\s+(?P<message>.*)")
ipv4_matcher = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
user_matcher1 = re.compile(r'(?<=Failed password for\s)(?!invalid)\S+|(?<=invalid user\s{1})\S+(?=\sfrom)')
user_matcher2 = re.compile(r'(?<=Failed password for\s)(?!invalid)\S+|(?<=invalid user\s{2})\S+(?=\sfrom)')
patterns = {
        'successful_login': r'^.*authentication success.*$',
        'failed_login': r'^.*authentication failure.*$',
        'connection_closed': r'^.*Connection closed.*$',
        'invalid_password': r'^.*Failed password.*$',
        'invalid_user': r'^.*Invalid user.*$',
        'break_in_attempt': r'^.*POSSIBLE BREAK-IN ATTEMPT!.*$'
    }
def print_dict(log):
   print(
f"""
Time: {log["time"]}
Code: {log['code']}
User: {log['user']}
Message: {log['message']}
""")
#zadanie 1 
def split_into_content(single_log:str):
  fragments=single_log.split(" ")
  if len(fragments[1])==0:
    fragments.remove("")
  time=datetime.datetime.strptime(f"{fragments[0]}/{fragments[1]} {fragments[2]}","%b/%d %H:%M:%S")
  current_year = datetime.datetime.now().year
  formatted_log = {
  "time" : time.replace(year=current_year),
  "user" : fragments[3],
  "code" : fragments[4][-7:-3],
  "message" : " ".join(fragments[5:])
  }
  return formatted_log

#zadanie 2
#a
def parse_log_entry(log:str,loglevel=None):
    match = re.match(log_dict_pattern, log)
    if match:
        data = match.groupdict()
        year = "2024"
        timestamp_str = f"{year}-{data['month']}-{data['day']} {data['time']}"
        timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%b-%d %H:%M:%S")
        user = data['user']
        message = data['message']
        code = int(data['code'])
        dict={
            "raw_content": log,
            "time": timestamp,
            "user": user,
            "code": code,
            "message": message
        }
        if loglevel is not None:
          print_log_level(dict)
        return dict
    return None
   
#b
def get_ipv4s_from_log(log_line:str):
  res=re.findall(ipv4_matcher,log_line)
  if len(res)==0:
    return []
  return res[0]

#c
def get_user_from_log(log_line:str):
  res=re.findall(user_matcher1,log_line)
  if len(res)==0:
    res=re.findall(user_matcher2,log_line)
  if len(res)==0:
    return None
  return res

#d
def get_message_type(log_line:str):
  for key, pattern in patterns.items():
        if re.match(pattern, log_line,re.IGNORECASE):
            return key
  return "other"

#zadanie 3
def print_log_level(log_line: dict):
  message_type = get_message_type(log_line["message"])
  logging.debug(f"Debug: {len(log_line['message'].encode('utf-8'))} Bytes")
  if message_type == 'successful_login' or message_type == 'connection_closed':
    logging.info(f"Info: {message_type}")
  elif message_type == 'failed_login':
      logging.warning(f"Warning: {message_type}")
  elif message_type == 'invalid_password' or message_type == 'invalid_user':
      logging.error(f"Error: {message_type}")  
  elif message_type == 'break_in_attempt':
      logging.critical(f"Critical : {message_type}")        

#zadanie 4 a
def get_n_random_logs(logs_dict, n, username):
  user_logs = [log["message"] for log in logs_dict if get_user_from_log(log["message"]) is not None and get_user_from_log(log["message"])[0] == username ]
  user_random_logs = []
  if user_logs:
    for i in range(n):
      user_random_logs.append(random.choice(user_logs))
    print_n_random_logs(user_random_logs)   
    
def print_n_random_logs(list):
  for elem in list:
    print(f"{elem}".replace("\n",""))

#zadanie 4 b 1
def  print_mean_and_stand_dev_time(time_mean, standard_deviation):
  print(f"Mean: {time_mean} Standard deviation: {standard_deviation}")

def get_global_mean_and_stan_deviation_time(user, logs_dict):
  first_time = logs_dict[0]["time"]
  last_time = logs_dict[0]["time"]
  times = []
  index = 0
  size = len(logs_dict)
  for i in range (size-1):
    if logs_dict[i]["code"] != logs_dict[index]["code"]:
      last_time = logs_dict[i-1]["time"]
      times.append((last_time - first_time).total_seconds())
      index = i
      first_time = logs_dict[i]["time"]

  if len(times) == 0:
    time_mean = 0
  else:  
    time_mean = mean(times)
  if len(times) > 1:
    standard_deviation = stdev(times)
  else: 
    standard_deviation = 0  
  if time_mean != 0:
    print(f"User: {user}")
    print_mean_and_stand_dev_time(time_mean, standard_deviation)

 
#zadanie 4 b 2
def get_users_mean_and_stdev(logs_dict):
  users_dict = defaultdict(list)
  for log in logs_dict:
    if get_user_from_log(log["message"]) is not None:  
      users_dict[get_user_from_log(log["message"])[0]].append(log)
 
  for user, user_logs in users_dict.items():
     print(f"User: {user}")
     get_global_mean_and_stan_deviation_time(user_logs)

def print_user_statistics(mean_times, stdev_times):
    print("User Statistics:")
    for user, mean_time in mean_times.items():
        stdev_time = stdev_times[user]
        print(f"User: {user} - Mean: {mean_time}, Standard deviation: {stdev_time}")

def calculate_mean_times_for_users(user_times):
    mean_times = {}
    for user, times in user_times.items():
        mean_time = mean(times)
        mean_times[user] = mean_time
    return mean_times

def calculate_stdev_times_for_users(user_times):
    stdev_times = {}
    for user, times in user_times.items():
        stdev_time = stdev(times)
        stdev_times[user] = stdev_time
    return stdev_times

def get_users_mean_and_stdev(logs_dict):
  users_dict = defaultdict(list)
  for log in logs_dict:
    if get_user_from_log(log["message"]) is not None:  
      users_dict[get_user_from_log(log["message"])[0]].append(log)
 
  for user, user_logs in users_dict.items():
     get_global_mean_and_stan_deviation_time(user,user_logs)

#zadanie 4 c
def get_most_and_least_frequent_users(logs_dict):
    users = [get_user_from_log(log["message"])[0] for log in logs_dict if get_user_from_log(log["message"]) is not None]
    most_common = max(set(users), key=users.count)
    least_common = min(set(users), key=users.count)  
    print(f"Most common : {most_common}\nLeast common: {least_common}" )

def get_dict(loglevel):
  with tarfile.open(f'{sys.argv[1]}', "r:gz") as tar:  
    tar.extractall()
  file_name=sys.argv[1].split(".")[0][0:]
  total_bytes = 0
  logs=[]
  with open(f"{file_name}.log","r") as file:
    for line in file.readlines():
      total_bytes += len(line.encode('utf-8'))
      val= split_into_content(line)
      logs.append(val)
      if loglevel is not None:
        print_log_level(val)
  return logs

#zadanie 6
def detect_brute_force(logs, max_interval, single_user):
  attacks = {}
  failed_passwords = [log for log in logs if get_message_type(log["message"]) == 'invalid_password']

  for i in range(len(failed_passwords) - 1):
    current_log = failed_passwords[i]
    next_log = failed_passwords[i + 1]
    next_time = next_log["time"]

    current_ip = get_ipv4s_from_log(current_log["message"])
    next_ip = get_ipv4s_from_log(next_log["message"])
    if current_ip and next_ip and current_ip == next_ip:
      if current_ip in attacks:
        if(next_time - attacks[current_ip]["last_attack"]).seconds <= max_interval:
          attacks[current_ip]["attempts"] += 1
          attacks[current_ip]["last_attack"] = next_time
        if not single_user and get_user_from_log(current_log["message"]) != get_user_from_log(next_log["message"]) and current_ip == next_ip:
          if get_user_from_log(current_log["message"]) not in attacks[current_ip]["user"]:
            attacks[current_ip]["user"].append(get_user_from_log(current_log["message"]))
          attacks[current_ip]["last_attack"] = next_time
      else:
        attacks[current_ip] = {
          "timestamp": current_log["time"],
          "last_attack": next_time,
          "ip": current_ip,
          "attempts": 2,
          "user": [get_user_from_log(current_log["message"])]
        }
  print_bruteforce_attacks(list(attacks.values()))

def print_bruteforce_attacks(attacks):
  for attack in attacks:
    if attack["attempts"] > 3:
      print(f"Brute force attack detected at {attack['timestamp']} from IP {attack['ip']} with {attack['attempts']} attempts at user {', '.join(x for [x] in attack['user'])}")

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('logfile', help='The location of the log file')
  parser.add_argument('--loglevel', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default = None, help='Set the minimum log level')
  subparsers = parser.add_subparsers(dest='command')

  subparsers.add_parser('2a', help='Print dictionaries')
  subparsers.add_parser('2b', help='Print all IPv4 addresses found in the logs')
  subparsers.add_parser('2c', help='Print all usernames found in the logs')
  subparsers.add_parser('2d', help='Print all message types found in the logs')

  subparser_n_logs = subparsers.add_parser('4a', help='Print n random logs for a given user')
  subparser_n_logs.add_argument('n', type=int, help='The number of logs to print')
  subparser_n_logs.add_argument('username', help='The username to print logs for')

  subparsers.add_parser('4b1', help='Print mean time and standard deviation between logs globally')
  subparsers.add_parser('4b2', help='Print mean time and standard deviation between logs for all users separately')
  subparsers.add_parser('4c', help='Print most and least frequent users in the logs')

  subparser_brute=subparsers.add_parser('6', help='Print brute force attacks in the logs')
  subparser_brute.add_argument('max_interval', type=int, help='The maximum time interval between failed login attempts')
  subparser_brute.add_argument('--single_user', action='store_true', help='Check if the attacks are from the same user')

  args = parser.parse_args()
  if args.loglevel is not None:
    logging.basicConfig(encoding="utf-8", level=args.loglevel)
  logs=[]
  if args.command == '2a':
    with tarfile.open(f'{sys.argv[1]}', "r:gz") as tar:  
      tar.extractall()
    file_name=sys.argv[1].split(".")[0][0:]
    with open(f"{file_name}.log","r") as file:
      for line in file.readlines():
         logs.append(parse_log_entry(line,args.loglevel))
    for log in logs:
       print_dict(log)
  else: 
     logs = get_dict(args.loglevel)
  if args.command == '2b':
    for log in logs:
      print(get_ipv4s_from_log(log["message"]))
  elif args.command == '2c':
    for log in logs:
      if get_user_from_log(log["message"]) is not None:
        print(get_user_from_log(log["message"]))
  elif args.command == '2d':
    for log in logs:
      print(get_message_type(log["message"]))
  elif args.command == '4a':
    get_n_random_logs(logs, int(args.n), args.username)
  elif args.command == '4b1':
    get_global_mean_and_stan_deviation_time(logs)
  elif args.command == '4b2':
    get_users_mean_and_stdev(logs)
  elif args.command == '4c':
    get_most_and_least_frequent_users(logs)
  elif args.command == '6':
    detect_brute_force(logs, args.max_interval, args.single_user)

if __name__ == "__main__":
  main()
