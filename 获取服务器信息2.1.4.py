import json
import data
import socket
import struct
import tkinter as tk
from PIL import Image
from random import randint
from copy import deepcopy
from time import time, sleep
from queue import Queue, Empty
from os.path import expandvars
from tkinter import ttk, filedialog
from _thread import start_new_thread
from base64 import b64decode, b64encode
from func_timeout import func_set_timeout
from pyperclip import copy as copy_to_clipboard


class Infoer(tk.Toplevel):
    def __init__(self, master: tk.Tk, server_info: dict):
        super().__init__(master)
        self.info: dict = server_info
        self.init_variable()
        self.init_window()
        self.get_server_icon()
        icon_tk = tk.PhotoImage(file="icon.png")
        self.icon.configure(image=icon_tk)
        self.mainloop()

    def init_variable(self):
        self.color_map_hex = {
            "black": "#000000",
            "dark_blue": "#0000AA",
            "dark_green": "#00AA00",
            "dark_aqua": "#00AAAA",
            "dark_red": "#AA0000",
            "dark_purple": "#AA00AA",
            "gold": "#FFAA00",
            "gray": "#AAAAAA",
            "dark_gray": "#555555",
            "blue": "#5555FF",
            "green": "#55FF55",
            "aqua": "#55FFFF",
            "red": "#FF5555",
            "light_purple": "#FF55FF",
            "yellow": "#FFFF55",
            "white": "#FFFFFF",
        }
        self.motd_font = ("微软雅黑", 18)

    def init_window(self):
        with open(expandvars(r"%TEMP%\infoWin_icon.ico"), "wb+") as f:
            f.write(data.infoWin_icon)
        self.wm_iconbitmap(expandvars(r"%TEMP%\infoWin_icon.ico"))
        self.wm_title("服务器信息")
        self.create_controls()
        self.config_controls()
        self.pack_controls()

    def get_server_icon(self):
        image_data = self.info.get("favicon")
        if image_data is None:
            image_data = data.default_server_icon

        with open("icon.png", "wb") as f:
            f.write(b64decode(image_data))

        image = Image.open("icon.png")
        image = image.resize((128, 128))
        image.save("icon.png")

    def copy_mod(self, _):
        choose = self.mod_list.curselection()
        if choose != tuple():
            mod = self.mods[choose[0]]
            copy_to_clipboard(mod["mod"])

    def show_mods(self):
        self.mods = self.info["modinfo"]
        self.mod_window = tk.Toplevel(self)
        self.mod_window.wm_iconbitmap(expandvars(r"%TEMP%\infoWin_icon.ico"))
        self.mod_window.wm_title("Mod列表")
        self.tip = ttk.Label(self.mod_window, text="Mod列表 (双击项目复制Mod名称)")
        self.mod_list = tk.Listbox(self.mod_window, height=20, width=50)
        self.scrool_mod_bar = ttk.Scrollbar(
            self.mod_window, orient="vertical", command=self.mod_list.yview
        )
        self.mod_list.configure(yscrollcommand=self.scrool_mod_bar.set)
        self.mod_list.bind("<Double-Button-1>", self.copy_mod)

        for mod in self.mods:
            self.mod_list.insert(tk.END, f"模组名称: {mod['mod']}, 版本: {mod['version']}")

        self.tip.pack_configure()
        self.mod_list.pack_configure(side="left", fill="both", expand=True)
        self.scrool_mod_bar.pack_configure(side="right", fill="y")
        self.mod_window.mainloop()

    def create_controls(self):
        self.icon = tk.Label(self)

        self.motd = tk.Text(
            self,
            height=2,
            width=50,
            font=self.motd_font,
            relief=tk.FLAT,
            bg="#f0f0f0",
        )

        self.infos_f = tk.Frame(self, highlightthickness=2, highlightcolor="red")
        self.host_port = ttk.Label(
            self.infos_f, text=f"服务器IP: {self.info['host']}:{self.info['port']}"
        )
        self.version = ttk.Label(self.infos_f, text=f"版本: {self.info['version']}")

        self.players = ttk.Label(
            self.infos_f,
            text=f"玩家数量: {self.info['players']['online']}/{self.info['players']['max']}",
        )
        if self.info["players"].get("sample"):
            self.player_listf = tk.Frame(
                self.infos_f, highlightthickness=2, highlightcolor="green"
            )
            self.player_listt = ttk.Label(self.player_listf, text="玩家列表")
            self.player_list = tk.Listbox(self.player_listf, height=10, width=20)
        self.ping = ttk.Label(self.infos_f, text=f"延迟: {self.info['ping']} ms")

        self.ip = f"{self.info['host']}:{self.info['port']}"
        self.copy_ipb = ttk.Button(
            self.infos_f, text="复制IP", command=lambda: copy_to_clipboard(self.ip)
        )
        if self.info["is_forge"]:
            self.show_modsb = ttk.Button(
                self.infos_f,
                text=f"查看Mod({len(self.info['modinfo'])}个)",
                command=self.show_mods,
            )

    def config_controls(self):
        if self.info["description"]["mode"] == "normal":
            self.motd = tk.Label(
                self, font=self.motd_font, text=self.info["description"]["text"]
            )
        elif self.info["description"]["mode"] == "colorful":
            for child in self.info["description"]["extra"]:
                try:
                    assert isinstance(child, dict)
                except AssertionError:
                    print(self.info["description"]["extra"])
                now_tag = hex(randint(0, 114514))[2:]
                now_font = self.motd_font

                if isinstance(child, str):
                    self.motd.insert(tk.END, child)
                    continue
                if child.get("color"):
                    color = child["color"]
                    if color in list(self.color_map_hex.keys()):
                        color = self.color_map_hex[color]
                    self.motd.tag_configure(now_tag, foreground=color)
                if child.get("underline"):
                    self.motd.tag_configure(now_tag, underline=True)
                if child.get("bold"):
                    now_font = now_font + ("bold",)
                if child.get("italic"):
                    now_font = now_font + ("italic",)
                if child.get("strikethrough"):
                    now_font = now_font + ("overstrike",)

                self.motd.tag_configure(now_tag, font=now_font, justify="center")

                self.motd.insert(tk.END, child["text"], now_tag)
            txt = self.motd.get("1.0", tk.END)
            self.motd.configure(height=txt.count("\n"), state=tk.DISABLED)

        if self.info["players"].get("sample"):
            for player in self.info["players"]["sample"]:
                self.player_list.insert(tk.END, player)

    def pack_controls(self):
        self.icon.pack_configure()
        self.motd.pack_configure(expand=True, fill="x")

        self.infos_f.pack_configure(expand=True, fill="x")
        if self.info["players"].get("sample"):
            self.player_listf.pack_configure(side="left", expand=True, fill="x")
            self.player_listt.pack_configure()
            self.player_list.pack_configure(expand=True, fill="x")
        self.host_port.pack_configure()
        self.version.pack_configure()
        self.players.pack_configure()
        self.ping.pack_configure()
        self.copy_ipb.pack_configure()
        if self.info["is_forge"]:
            self.show_modsb.pack_configure()


class GUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.init_variable()
        self.init_window()

    def init_variable(self):
        self.server_hosts = ["127.0.0.1"]
        [
            "s2.wemc.cc",
            "cn-yw-plc-1.openfrp.top",
            "kr-se-cncn-1.openfrp.top",
            "cn-hz-bgp-1.openfrp.top",
            "jp-osk-bgp-1.openfrp.top",
            "cn-fz-plc-1.openfrp.top",
            "cn-bj-bgp-2.openfrp.top",
            "cn-qz-plc-1.openfrp.top",
            "cn-sz-bgp-1.openfrp.top",
            "cn-he-plc-1.openfrp.top",
            "us-sjc-bgp-1.openfrp.top",
            "cn-bj-bgp-4.openfrp.top",
            "cn-hk-bgp-4.openfrp.top",
            "cn-hk-bgp-5.openfrp.top",
            "cn-hk-bgp-6.openfrp.top",
            "cl-sde-bgp-1.openfrp.top",
            "cn-sz-plc-1.openfrp.top",
            "cn-bj-plc-1.openfrp.top",
            "cn-wh-plc-1.openfrp.top",
            "us-sjc-bgp-2.openfrp.top",
            "cn-bj-plc-2.openfrp.top",
            "cn-sc-plc-2.openfrp.top",
            "cn-cq-plc-1.openfrp.top",
            "cn-sy-dx-2.openfrp.top",
            "cn-he-plc-2.openfrp.top",
            "cn-nd-plc-1.openfrp.top",
            "kr-nc-bgp-1.openfrp.top",
            "ru-mow-bgp-1.openfrp.top",
        ]
        self.color_map = {
            "0": "black",
            "1": "dark_blue",
            "2": "dark_green",
            "3": "dark_aqua",
            "4": "dark_red",
            "5": "dark_purple",
            "6": "gold",
            "7": "gray",
            "8": "dark_gray",
            "9": "blue",
            "a": "green",
            "b": "aqua",
            "c": "red",
            "d": "light_purple",
            "e": "yellow",
            "f": "white",
        }
        self.color_map_hex = {
            "black": "#000000",
            "dark_blue": "#0000AA",
            "dark_green": "#00AA00",
            "dark_aqua": "#00AAAA",
            "dark_red": "#AA0000",
            "dark_purple": "#AA00AA",
            "gold": "#FFAA00",
            "gray": "#AAAAAA",
            "dark_gray": "#555555",
            "blue": "#5555FF",
            "green": "#55FF55",
            "aqua": "#55FFFF",
            "red": "#FF5555",
            "light_purple": "#FF55FF",
            "yellow": "#FFFF55",
            "white": "#FFFFFF",
        }
        self.default_scan_theards = 256  # 默认扫描线程数
        self.timeout = 0.9  # 连接超时时间
        self.protocol_version = 65  # 协议版本
        self.bar_lenght = 500  # 进度条长度
        self.outputs = []  # 扫描结果输出
        self.last_pro_info = (time(), 0)
        self.avg_speed = []  # 平均速度列表
        self.motd_font = ("微软雅黑", 18)

    def init_window(self):
        with open(expandvars(r"%TEMP%\99icon114514.ico"), "wb+") as f:
            f.write(data.program_icon)
        self.wm_iconbitmap(expandvars(r"%TEMP%\99icon114514.ico"))
        self.wm_title("MC服务器扫描器")
        self.create_controls()
        self.config_controls()
        self.pack_controls()

    def create_controls(self):
        self.host_inputf = tk.Frame(self)
        self.host_inputt = ttk.Label(self.host_inputf, text="IP输入: ")
        self.host_input = ttk.Combobox(self.host_inputf, width=50)

        self.scan_theard_inputf = tk.Frame(self)
        self.scan_theard_inputt = ttk.Label(self.scan_theard_inputf, text="线程数: ")
        self.scan_theard_input = ttk.Entry(self.scan_theard_inputf, width=20)

        self.start_scanb = ttk.Button(self, text="开始扫描")

        self.log_and_output_f = tk.Frame(
            self, highlightcolor="#114514", highlightthickness=2
        )
        self.log_frame = tk.Frame(
            self.log_and_output_f, highlightcolor="#A0A0A0", highlightthickness=2
        )
        self.log_text = ttk.Label(self.log_frame, text="日志")
        self.log_control = tk.Listbox(self.log_frame, width=30)

        self.output_frame = tk.Frame(
            self.log_and_output_f, highlightcolor="#808080", highlightthickness=2
        )
        self.output_text = ttk.Label(self.output_frame, text="服务器扫描结果")
        self.output_control = tk.Listbox(self.output_frame, height=15, activestyle=None)
        self.output_bar = ttk.Scrollbar(self.output_frame, orient=tk.VERTICAL)

        self.save_load_frame = tk.Frame(self.output_frame)
        self.save_outputb = ttk.Button(self.save_load_frame, text="保存", width=5)
        self.load_outputb = ttk.Button(self.save_load_frame, text="导入", width=5)

        self.infoer = tk.Frame(self)
        self.progress_text = ttk.Label(self.infoer, text="已扫描端口数量: 0/0 (0%)")
        self.speed_shower = tk.Label(self.infoer, text="扫描速度: 0/s")

        self.scan_frame = tk.Frame(self.infoer)
        self.scan_text = ttk.Label(self.scan_frame, text="总体扫描进度: ")
        self.scan_bar = ttk.Progressbar(self.scan_frame, length=self.bar_lenght)

    def config_controls(self):
        self.host_input["value"] = tuple(self.server_hosts)
        self.host_input.insert(tk.INSERT, self.server_hosts[0])
        self.scan_theard_input.insert(tk.INSERT, str(self.default_scan_theards))
        self.start_scanb.configure(command=self._start_scan)
        self.output_control.bind("<Double-Button-1>", self.show_infoer)
        self.output_control.configure(yscrollcommand=self.output_bar.set)
        self.output_bar.configure(command=self.output_control.yview)

        self.save_outputb.configure(command=self.save_outputs)
        self.load_outputb.configure(command=self.load_outputs)

        self.progress = tk.IntVar(self)
        self.scan_bar.configure(variable=self.progress)

    def pack_controls(self):
        self.host_inputf.pack_configure()
        self.host_inputt.pack_configure(side="left")
        self.host_input.pack_configure(side="right")

        self.scan_theard_inputf.pack_configure()
        self.scan_theard_inputt.pack_configure(side="left")
        self.scan_theard_input.pack_configure(side="right")

        self.start_scanb.pack_configure()

        self.log_and_output_f.pack_configure(fill="both", expand=True)

        self.log_frame.pack_configure(side="left", fill="y")
        self.log_text.pack_configure()
        self.log_control.pack_configure(fill="both", expand=True)

        self.output_frame.pack_configure(side="right", fill="both", expand=True)
        self.output_text.pack_configure()
        self.output_bar.pack_configure(side="right", fill="y")
        self.output_control.pack_configure(fill="both", expand=True)

        self.save_load_frame.pack_configure(fill="x")
        self.save_outputb.pack_configure(side="left")
        self.load_outputb.pack_configure(side="right")

        self.infoer.pack_configure(fill="x", side="bottom")

        self.speed_shower.pack_configure()
        self.progress_text.pack_configure()

        self.scan_frame.pack_configure(fill="x", expand=True)
        self.scan_text.pack_configure(side="left")
        self.scan_bar.pack_configure(side="right", fill="x", expand=True)

    def _start_scan(self):
        start_new_thread(self.start_scan, ())

    def start_scan(self):
        self.log("扫描开始")
        self.save_outputb.configure(state=tk.DISABLED)
        self.load_outputb.configure(state=tk.DISABLED)
        self.start_scanb.configure(state=tk.DISABLED)
        self.outputs.clear()
        self.output_control.delete(0, tk.END)
        self.log_control.delete(0, tk.END)

        try:
            scan_theard_num = int(self.scan_theard_input.get())
        except ValueError:
            scan_theard_num = self.default_scan_theards
            self.scan_theard_input.delete(0, tk.END)
            self.scan_theard_input.insert(tk.INSERT, str(scan_theard_num))

        scan_host = self.host_input.get()
        if scan_host.startswith("frp-") and scan_host.endswith(".top"):
            self.log("检测到樱花穿透节点, 停止扫描")

        port_start = 10240
        port_end = 65535
        self.scan_size = port_end - port_start
        self.all_progress = 0
        self.work_thread = 0
        self.work_strack = Queue()
        self.scan_over = False
        self.last_pro_info = (time(), 0)

        self.log("生成端口列表....")
        for i in range(port_start, port_end + 1):
            self.work_strack.put(i)

        self.log(f"启动扫描线程....(数量: {scan_theard_num})")
        for i in range(scan_theard_num):
            start_new_thread(self.scan_thread, (scan_host,))
            sleep(self.timeout / scan_theard_num / 3)
            self.update_progress()
        self.log("扫描线程启动完毕")
        self.start_scanb.configure(text="停止扫描", state=tk.NORMAL)
        self.start_scanb.configure(command=self.abort_scan)

        while (not self.work_thread < max(1, scan_theard_num - 40)) and (
            not self.scan_over
        ):
            self.update_progress()
            sleep(0.05)
        else:
            self.log("扫描结束")

        self.start_scanb.configure(text="开始扫描", state=tk.NORMAL)
        self.start_scanb.configure(command=self._start_scan)
        self.save_outputb.configure(state=tk.NORMAL)
        self.load_outputb.configure(state=tk.NORMAL)
        self.scan_over = True

    def abort_scan(self):
        self.log("扫描中止")
        self.scan_over = True

    def scan_thread(self, scan_host):
        self.work_thread += 1
        while not self.scan_over:
            try:
                now_port = self.work_strack.get(block=False)
            except Empty:
                break
            try:
                self.scan_a_port(scan_host, now_port)
            except TimeoutError:
                self.log(f"端口: {now_port}-> 意外未处理的超时")
            self.all_progress += 1
        self.work_thread -= 1

    @func_set_timeout(5)  # 设置超时时间为5秒
    def scan_a_port(self, host: str, port: int):
        """扫描单个端口"""
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
        except TimeoutError:
            return

        try:
            sock.sendall(self.make_handshake_packet(host, port))
            ping = time()
            sock.sendall(self.make_state_packet())

            data = self.read_packet(sock)
            ping = round((time() - ping) * 1000, 1)
            response = self.decode_json_bytes(data)
            parsed = self.parse_info_json(response)
            parsed["ping"] = ping
            parsed["host"] = host
            parsed["port"] = port
            self.outputs.append(parsed)
            self.add_to_output_control(parsed)
        except IndexError:
            self.log(f"端口: {port}-> 数据包长度错误")
        except struct.error:
            self.log(f"端口: {port}-> 数据打包(解包)错误")
        except TimeoutError:
            self.log(f"端口: {port}-> 运行时连接超时")
        except EOFError:
            self.log(f"端口: {port}-> 未接收到足够数据")
        except (json.decoder.JSONDecodeError, KeyError):
            self.log(f"端口: {port}-> JSON解码错误")
        except UnicodeDecodeError:
            self.log(f"端口: {port}-> Unicode解码错误")
        except ConnectionResetError:
            self.log(f"端口: {port}-> 连接被关闭")
        """except Exception as e:
            print(e.args)
            self.log(f"端口: {port}-> ", *e.args)"""

    def update_progress(self):
        self.progress_text.configure(
            text=f"已扫描端口数量: {self.all_progress}/{self.scan_size} ({round(self.all_progress/self.scan_size*100, 2)}%)"
        )

        speed = self.all_progress - self.last_pro_info[1]
        speed /= max(time() - self.last_pro_info[0], 0.002)
        speed = int(speed)
        self.avg_speed.append(speed)
        if len(self.avg_speed) > 100:
            self.avg_speed.pop(0)
        self.speed_shower.configure(
            text=f"扫描速度: {round(sum(self.avg_speed) / len(self.avg_speed), 2)}/s"
        )

        self.scan_bar.step(
            (self.all_progress - self.last_pro_info[1]) / self.scan_size * 100
        )

        self.last_pro_info = (time(), self.all_progress)

    def add_to_output_control(self, parsed: dict):
        self.output_text.configure(text=f"服务器扫描结果({len(self.outputs)}个)")
        tilite = self.get_text_tilite(parsed)
        self.output_control.insert(
            tk.END,
            f"{parsed['port']}-> 版本: {parsed['version']}, 人数: {parsed['players']['online']}, 标题: {tilite}",
        )

    def get_text_tilite(self, parsed: dict):
        tilite = ""
        if parsed["description"]["mode"] == "normal":
            tilite = parsed["description"]["text"]
        else:
            for extra in parsed["description"]["extra"]:
                if isinstance(extra, dict):
                    tilite += extra.get("text", "")
                elif isinstance(extra, str):
                    tilite += extra
                else:
                    print("Tilite Parsed Error:", extra)
        return tilite

    def log(self, *args):
        self.log_control.insert(tk.END, " ".join(args))
        self.log_control.see(tk.END)

    def text_format(self, text: str):
        """格式化文本"""
        let = text.split("§")
        extra = []
        for ext in let:
            if len(ext) > 2:
                state = {"text": ext[1:]}
                code = ext[0]
                if code == "l":
                    state["bold"] = True
                elif code == "m":
                    state["italic"] = True
                elif code == "n":
                    state["underline"] = True
                elif code == "o":
                    state["strikethrough"] = True
                elif code == "k":
                    state["obfuscated"] = True
                elif code == "r":
                    pass
                elif code in list(self.color_map.keys()):
                    state["color"] = self.color_map[code]
                extra.append(state)
            else:
                pass
        return extra

    def parse_info_json(self, data: dict):
        """解析信息包"""
        infos = {}
        infos["details"] = b64encode(str(data).encode("utf-8")).decode("utf-8")
        ########版本信息########
        infos["version"] = data["version"]["name"]
        infos["protocol"] = data["version"]["protocol"]

        ########标题信息########
        description = {}
        if "extra" in data["description"]:  # JSON彩色文本表达
            description["mode"] = "colorful"
            description["extra"] = deepcopy(data["description"]["extra"])

        elif isinstance(data["description"], str):  # 1.20.4
            description["mode"] = "normal"
            description["text"] = data["description"]

        else:
            description["mode"] = "normal"

            if data["description"].get("text") != None:  # Upper version
                description["text"] = deepcopy(data["description"]["text"])
            elif data["description"].get("translate") != None:  # 1.12.2
                description["text"] = deepcopy(data["description"]["translate"])
            else:
                print("PARSE ERROR!!!!!!!!!!!!!!!")
                print(data["description"])

            if "§" in description["text"]:  # 转化为JSON文本表达
                description["mode"] = "colorful"
                description["extra"] = self.text_format(description["text"])
                del description["text"]
        infos["description"] = deepcopy(description)

        ########玩家信息########
        infos["players"] = deepcopy(data["players"])
        if infos["players"].get("sample"):
            infos["players"]["sample"].clear()
            for player in data["players"]["sample"]:
                name = deepcopy(player["name"])
                if name == "Anonymous Player":
                    name = "匿名"
                infos["players"]["sample"].append(name)

        ########服务器图标########
        infos["favicon"] = deepcopy(data.get("favicon"))
        if infos["favicon"] is None:
            del infos["favicon"]
        else:
            infos["favicon"] = infos["favicon"][22:]

        ########Forge########
        infos["is_forge"] = True
        if data.get("forgeData"):  # 新版Forge信息 1.16.5
            infos["modinfo"] = []
            for mod in data["forgeData"]["mods"]:
                infos["modinfo"].append(
                    deepcopy({"mod": mod["modId"], "version": mod["modmarker"]})
                )
                if infos["modinfo"][-1]["version"] == "OHNOES😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱":
                    infos["modinfo"][-1]["version"] = "未知"

        elif data.get("modinfo"):  # 旧版Forge信息 1.12.2
            infos["modinfo"] = []
            for mod in data["modinfo"]["modList"]:
                infos["modinfo"].append(
                    deepcopy({"mod": mod["modid"], "version": mod["version"]})
                )
                if infos["modinfo"][-1]["version"] == "OHNOES😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱":
                    infos["modinfo"][-1]["version"] = "未知"
        else:
            infos["is_forge"] = False

        ########可选杂项########
        if data.get("enforcesSecureChat"):
            infos["enforcesSecureChat"] = deepcopy(data["enforcesSecureChat"])
        if data.get("preventsChatReports"):
            infos["preventsChatReports"] = deepcopy(data["preventsChatReports"])

        return infos

    def show_infoer(self, _):
        index = self.output_control.curselection()
        if index == tuple():
            return
        server_info: dict = self.outputs[index[0]]
        Infoer(self, server_info)

    def save_outputs(self):
        """保存扫描结果"""
        fp = filedialog.asksaveasfilename(
            title="保存扫描结果",
            filetypes=[("Json Files", "*.json"), ("All Files", ".")],
            confirmoverwrite=True,
            initialfile="扫描结果.json",
            defaultextension=".json",
        )
        if not fp:
            return
        try:
            with open(fp, "w", encoding="utf-8") as f:
                json.dump(self.outputs, f, ensure_ascii=False, indent=4)
        except OSError:
            pass

    def load_outputs(self):
        fp = filedialog.askopenfilename(
            title="打开扫描结果", filetypes=[("Json Files", "*.json"), ("All Files", ".")]
        )
        if not fp:
            return

        def temp():
            try:
                self.log("读取文件中....")
                with open(fp, encoding="utf-8") as f:
                    self.outputs = json.load(f)
                    self.log("读取完毕")
                    self.output_control.delete(0, tk.END)
                    for output in self.outputs:
                        self.add_to_output_control(output)
            except OSError:
                self.log("文件打开失败")

        start_new_thread(temp, ())

    ########Packet########
    def decode_json_bytes(self, data: bytes) -> dict:
        """解码字节流"""
        data = data[3:].decode("utf-8", errors="ignore")
        json_data = json.loads(data)
        if json_data is None:
            raise json.decoder.JSONDecodeError
        return json_data

    def make_handshake_packet(self, host: str, port: int) -> bytes:
        """创建一个握手包"""
        # 第一个字节是数据包ID
        # 下一个字节是协议版本
        # 下一个字节是主机字符串长度和字符串
        # 下两个字节是端口
        # 下一个字节是状态
        data = (
            b"\x00"
            + self.protocol_version.to_bytes(1, "little", signed=True)
            + struct.pack(">b", len(host))
            + host.encode("utf-8")
            + struct.pack(">h", port - 32768)
            + b"\x01"
        )
        return self.make_packet(data)

    def make_state_packet(self) -> bytes:
        """请求服务器信息包"""
        return self.make_packet(b"\x00")

    def make_packet(self, data: bytes) -> bytes:
        """制作一个包"""
        return struct.pack(">I", len(data)) + data

    def read_packet(self, c: socket.socket) -> bytes:
        """读取包"""
        # 读取数据包长度
        length = self.decode_varint(c.recv(2))
        # 获取足够长的数据
        return self.recvall(length, c)

    def recvall(self, length: int, c: socket.socket):
        data = b""
        while len(data) < length:
            more = c.recv(length - len(data))
            if not more:
                raise EOFError
            data += more
        return data

    def decode_varint(self, data) -> int:
        """解析计算机在通信协议中用varint表示数值的方法"""
        number = 0
        shift = 0
        for raw_byte in data:
            val_byte = raw_byte & 0x7F
            number |= val_byte << shift
            if raw_byte & 0x80 == 0:
                break
            shift += 7
        return number

    ########Packet########


if __name__ == "__main__":
    gui = GUI()
    gui.mainloop()
