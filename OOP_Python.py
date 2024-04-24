from SSH_reader import parse_log_entry, split_into_content, get_message_type,ipv4_matcher,log_dict_pattern
from ipaddress import IPv4Address
import sys
import re
from abc import ABC, abstractmethod
import re
import datetime
global file 
time_pattern = re.compile(r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")
class SSHLogEntry(ABC):
    def __init__(self, content:str):
        value_dict=parse_log_entry(content)
        self.time=value_dict["time"]
        self.hostname=value_dict["user"]
        self.raw_content=value_dict["raw_content"]
        self.pid = value_dict["code"]
        self.message=value_dict["message"]
    
    def __str__(self):
        return f'Time: {self.time}, Hostname: {self.hostname}, PID: {self.pid}, IPv4: {self.get_ipv4_address()}, Message: {self.message}'

    def get_ipv4_address(self):
        match = re.search(ipv4_matcher, self.raw_content)
        if match:
            ip_address = match.group()
            ip_address = '.'.join([str(int(segment)) for segment in ip_address.split('.')])
            return IPv4Address(ip_address)
        return None
    
    @abstractmethod
    def validate(self):
        second_parse=split_into_content(self.raw_content)
        if second_parse["time"]!=self.time:
            return False
        if second_parse["user"]!=self.hostname:
            return False
        if second_parse["code"]!=self.pid:
            return False
        if second_parse["message"]!=self.message:
            return False
        return True
    
    @property
    def has_ip(self):
        return self.get_ipv4_address() is not None
    
    def __repr__(self):
        return f'SSHLogEntry(time={self.time}, hostname={self.hostname}, raw_content={self.raw_content}, pid={self.pid})'

    def __eq__(self, other):
        if isinstance(other, SSHLogEntry):
            return self.time == other.time and self.hostname == other.hostname and self.raw_content == other.raw_content and self.pid == other.pid
        return False

    def __lt__(self, other):
        if isinstance(other, SSHLogEntry):
            return self.time < other.time
        return NotImplemented

    def __gt__(self, other):
        if isinstance(other, SSHLogEntry):
            return self.time > other.time
        return NotImplemented

class PasswordRejected(SSHLogEntry):
    def __init__(self, content):
        super().__init__(content)
        self.message_type = get_message_type(self.message)
    
    def validate(self):
        if re.match(r'^.*Failed password.*$', self.message) is not None:
            return True
        return False

class PasswordAccepted(SSHLogEntry):
    def __init__(self, content):
        super().__init__(content)
        self.message_type = get_message_type(self.message)
    
    def validate(self):
        super().validate()
        if re.match(r'^.*Accepted password.*$', self.message) is not None:
            return True
        return False

class Error(SSHLogEntry):
    def __init__(self, content):
        super().__init__(content)
        self.message_type = get_message_type(self.message)
    
    def validate(self):
        super().validate()
        if re.match(r'^.*error*$', self.message) is not None:
            return True
        return False

class OtherInfo(SSHLogEntry):
    def __init__(self, content):
        super().__init__(content)
        self.info = self.raw_content 
    
    def validate(self):
        return True
    
class SSHLogJournal:
    
    def __init__(self):
        self.i=0
        self.logs = {}

    def __len__(self):
        return len(self.logs)

    def __iter__(self):
        return iter(self.logs)

    def __contains__(self, item):
        return item in self.logs

    def append(self, content):
        if re.match(r'^.*Failed password.*$', content) is not None:
            log_entry = PasswordRejected(content)
        if re.match(r'^.*Accepted password.*$', content) is not None:
            log_entry = PasswordAccepted(content)
        if re.match(r'^.*error*$', content) is not None:
            log_entry = Error(content)
        else:
            log_entry = OtherInfo(content)
        self.logs[self.i]=(log_entry)
        self.i+=1

    def get_logs_by_criteria(self, criteria):
        filtered_logs = []
        for log in self.logs:
            if criteria(self.logs[log]):
                filtered_logs.append(self.logs[log])
        return filtered_logs
    
    def __getitem__(self, parameter):
        if isinstance(parameter, slice):
            return list(self.logs.values())[parameter.start:parameter.stop:parameter.step]
        elif isinstance(parameter, int):
            return self.logs[parameter]
        elif isinstance(parameter, str):
            match = re.search(ipv4_matcher, parameter)
            if match:
                for log in self.logs:
                    if self.logs[log].get_ipv4_address() == IPv4Address(parameter):
                        return self.logs[log]
            else:
                match = re.match(time_pattern, parameter)
                if match:
                    data = match.groupdict()
                    timestamp_str = f"2024-{data['month']}-{data['day']} {data['time']}"
                    timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%b-%d %H:%M:%S")
                    for log in self.logs:
                        if self.logs[log].time == timestamp:
                            return self.logs[log]
        else:
            raise TypeError("Invalid index type. Expected int or slice.")
    #by IP and Date
           
class SSHUser:
    def __init__(self, username, last_login_date):
        self.username = username
        self.last_login_date = last_login_date
    
    def validate(self):
        def validate_username(username):
            pattern = r'^[a-z_][a-z0-9_-]{0,31}$'
            return re.match(pattern, username) is not None
        
        if validate_username(self.username):
            print(f"Username {self.username} is valid.")
        else:
            print(f"Username {self.username} is invalid.")
def main():
    file = sys.argv[1]
    user1 = SSHUser("letvuser","2024-12-12")
    user2 = SSHUser("ctssh","2024-12-12")
    user3 = SSHUser("root","2024-12-12")
    accept = PasswordAccepted('Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2')
    reject = PasswordRejected('Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2')

    users = [user1,accept, user2, reject, user3]

    for user in users:
        user.validate()

    journal = SSHLogJournal()

    with open("SSH.log", "r") as file:
        for line in file.readlines():
            journal.append(line)
    logs = journal.get_logs_by_criteria(lambda log: log.get_ipv4_address()==IPv4Address("212.47.254.145"))
    print(journal["212.47.254.145"])
    print(journal['Dec 10 06:55:48'])
    print(journal[0])
    for log in journal[0:3]:
        print(log)
    print(journal[1]==journal[1])
    print(journal.logs[0]==journal.logs[1])
    print(journal.logs[0]<journal.logs[1])
    print(journal.logs[0]>journal.logs[1])
    for log in logs:
        print(log)
if __name__ == "__main__":
    main()