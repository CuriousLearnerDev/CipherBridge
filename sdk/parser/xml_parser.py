"""XML解析器 — 基本XML/HTML解析."""

try:
    import xml.etree.ElementTree as ET
except ImportError:
    ET = None


def parse(data: str) -> dict:
    """尝试将XML字符串解析为嵌套dict."""
    if ET is None:
        return {"_raw": data}
    try:
        root = ET.fromstring(data)
        return _element_to_dict(root)
    except ET.ParseError:
        return {"_raw": data}


def write(obj: dict) -> str:
    if "_raw" in obj and len(obj) == 1:
        return obj["_raw"]
    return ET.tostring(_dict_to_element(obj), encoding="unicode")


def _element_to_dict(elem):
    result = {}
    for child in elem:
        child_dict = _element_to_dict(child)
        tag = child.tag
        if tag in result:
            if not isinstance(result[tag], list):
                result[tag] = [result[tag]]
            result[tag].append(child_dict)
        else:
            result[tag] = child_dict
    if elem.text and elem.text.strip():
        result["#text"] = elem.text.strip()
    result.update({f"@{k}": v for k, v in elem.attrib.items()})
    return result


def _dict_to_element(d):
    tag = d.get("_tag", "root")
    elem = ET.Element(tag)
    for k, v in d.items():
        if k.startswith("@"):
            elem.set(k[1:], str(v))
        elif k in ("_tag", "#text"):
            pass
        elif k == "#text":
            elem.text = str(v)
        elif isinstance(v, list):
            for item in v:
                elem.append(_dict_to_element(item))
        elif isinstance(v, dict):
            child = _dict_to_element(v)
            child.tag = k
            elem.append(child)
        else:
            child = ET.SubElement(elem, k)
            child.text = str(v)
    return elem
