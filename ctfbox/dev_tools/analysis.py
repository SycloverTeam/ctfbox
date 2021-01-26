"""
analysis files in directory and export All global uppercase variables, class name, function name to __init__.py and update __all__
"""

from os import path as _path, listdir as _listdir


def analysis(filepath: str) -> list:
    result = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            if any((not line, line.startswith(" "), line.startswith("from"), line.startswith("import"))):
                continue
            name = ""
            if line.startswith("def") or line.startswith("class"):
                if ("(" in line):
                    endIndex = line.index("(")
                else:
                    endIndex = -2
                name = line[line.index(" ")+1:endIndex]
            if "=" in name:
                name = line[:line.index("=")].strip()
                if not name.isupper():
                    name = ""
            if " " in name or name.startswith("_"):
                name = ""
            if name:
                result.append("'" + name.strip() + "'")
    return result


def write(filepath, result):
    with open(filepath, "r+") as f:
        data = f.readlines()
        for i, line in enumerate(data):
            data[i] = line.strip() + "\n"
            index = line.find("__all__")
            if index != -1:
                data[i] = result + "\n"
                break
        else:
            data.append(result + "\n")
        f.seek(0)
        f.write("".join(data))


def update_export(dirpath: str):
    result = []
    files = [f for f in _listdir(dirpath) if "." in f]
    if "__init__.py" not in files:
        return
    for f in files:
        if f == "__init__.py":
            continue
        result.extend(analysis(_path.join(dirpath, f)))
    result_str = ", ".join(set(result)).strip()
    result_str = "__all__ = [" + result_str + "]"
    write(_path.join(dirpath, "__init__.py"), result_str)


if __name__ == "__main__":
    current_dir = _path.split(_path.realpath(__file__))[0]
    parent_dir = _path.abspath(_path.dirname(current_dir))
    update_export(_path.join(parent_dir, "utils"))
    update_export(_path.join(parent_dir, "web"))
    update_export(_path.join(parent_dir, "reverse"))
    update_export(_path.join(parent_dir, "crypto"))
    update_export(_path.join(parent_dir, "misc"))
