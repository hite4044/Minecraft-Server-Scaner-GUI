import json
from base64 import b64encode
from copy import deepcopy

color_map = {
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


class fff:
    @staticmethod
    def text_format(text: str):
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
                elif code in list(color_map.keys):
                    state["color"] = color_map[code]
                extra.append(state)
            else:
                pass
        return extra

    @staticmethod
    def parse_info_json(data: dict):
        """解析信息包"""
        infos = {}
        infos["details"] = deepcopy(data)
        ########版本信息########
        infos["version"] = data["version"]["name"]
        infos["protocol"] = data["version"]["protocol"]

        ########标题信息########
        description = {}
        if "extra" in data["description"]:  # JSON彩色文本表达
            description["mode"] = "colorful"
            description["data"] = deepcopy(data["description"]["extra"])

        elif isinstance(data["description"], str):  # 1.20.4
            description["mode"] = "normal"
            description["data"] = data["description"]

        else:
            description["mode"] = "normal"

            if data["description"].get("text") != None:  # Upper version
                description["data"] = deepcopy(data["description"]["text"])
            elif data["description"].get("translate") != None:  # 1.12.2
                description["data"] = deepcopy(data["description"]["translate"])
            else:
                print("PARSE ERROR!!!!!!!!!!!!!!!")
                print(data["description"])

            if "§" in description["data"]:  # 转化为JSON文本表达
                description["mode"] = "colorful"
                description["data"] = fff.text_format(description["data"])
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

        infos["favicon"] = deepcopy(data.get("favicon"))
        if infos["favicon"] is None:
            infos["favicon"] = 1

        ########Forge########
        infos["is_forge"] = True
        if data.get("forgeData") != None:  # 新版Forge信息 1.16.5
            infos["modinfo"] = []
            for mod in data["forgeData"]["mods"]:
                infos["modinfo"].append(
                    deepcopy({"mod": mod["modId"], "version": mod["modmarker"]})
                )

            infos["mods"] = deepcopy(data["forgeData"]["mods"])
        elif data.get("modinfo") != None:  # 旧版Forge信息 1.12.2
            infos["modinfo"] = []
            for mod in data["modinfo"]["modList"]:
                infos["modinfo"].append(
                    deepcopy({"mod": mod["modid"], "version": mod["version"]})
                )
        else:
            infos["is_forge"] = False

        ########可选杂项########
        if data.get("enforcesSecureChat"):
            infos["enforcesSecureChat"] = deepcopy(data["enforcesSecureChat"])
        if data.get("preventsChatReports"):
            infos["preventsChatReports"] = deepcopy(data["preventsChatReports"])

        print(infos["players"])
        return infos

"""
with open(r"实用程序\获取服务器信息\2.0\test.json") as f:
    data = json.load(f)
    for server in data:
        fff.parse_info_json(server)"""

with open(r"实用程序\获取服务器信息\2.1\info.ico", "rb") as f:
    with open(r"实用程序\获取服务器信息\2.1\data.py", "a") as f2:
        f2.write('"')
        f2.write(b64encode(f.read()).decode("utf-8"))
        f2.write('"')
