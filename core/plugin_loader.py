"""插件加载器 — 根据Profile匹配规则加载对应的plugin.py."""

import fnmatch
import os
import sys
import yaml
import logging
import importlib.util

from core.match_rules import matches_request
from core.paths import get_app_root

logger = logging.getLogger(__name__)

PROFILES_DIR = os.path.join(get_app_root(), "profiles")
PLUGINS_DIR = os.path.join(get_app_root(), "plugins")


class PluginLoader:
    def __init__(self):
        self._plugins = {}       # plugin_name -> module
        self._profiles = {}      # profile_name -> config dict

    def load_all_profiles(self) -> list:
        """加载 profiles/ 下所有配置文件，返回列表."""
        self._profiles.clear()
        if not os.path.isdir(PROFILES_DIR):
            return []
        profiles = []
        for f in sorted(os.listdir(PROFILES_DIR)):
            if f.endswith(".yaml") and not f.startswith("_"):
                name = f.replace(".yaml", "")
                path = os.path.join(PROFILES_DIR, f)
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        cfg = yaml.safe_load(fh)
                    self._profiles[name] = cfg
                    profiles.append((name, cfg))
                except Exception as e:
                    logger.error("加载配置失败 %s: %s", f, e)
        return profiles

    def load_plugin(self, profile_name: str):
        """加载指定profile对应的插件模块."""
        cfg = self._profiles.get(profile_name, {})
        plugin_dir = cfg.get("plugin", profile_name)
        plugin_path = os.path.join(PLUGINS_DIR, plugin_dir, "plugin.py")

        if not os.path.exists(plugin_path):
            logger.warning("插件文件不存在: %s", plugin_path)
            return None

        mtime = os.path.getmtime(plugin_path)
        cached = self._plugins.get(profile_name)
        if cached and getattr(cached, "__cryptoproxy_mtime__", None) == mtime:
            return cached

        try:
            spec = importlib.util.spec_from_file_location(
                f"plugin_{profile_name}", plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.__cryptoproxy_mtime__ = mtime
            self._plugins[profile_name] = module
            logger.info("已加载插件: %s → %s", profile_name, plugin_path)
            return module
        except Exception as e:
            logger.error("加载插件失败 %s: %s", plugin_path, e)
            return None

    def profile_matches(self, profile_name: str, flow) -> bool:
        """单个 profile 是否命中当前请求."""
        cfg = self._profiles.get(profile_name, {})
        match = cfg.get("match", {})
        return matches_request(
            match,
            host=flow.request.host,
            path=flow.request.path,
            method=flow.request.method,
            content_type=flow.request.headers.get("Content-Type", ""),
            body_text=flow.request.text or "",
        )

    def match_profile(self, flow) -> str:
        """根据请求匹配 Profile，优先命中更具体的 host/path 规则."""
        host = flow.request.host
        path = flow.request.path
        method = flow.request.method

        logger.info("收到请求: %s %s (host=%s)", method, path, host)

        best_name = ""
        best_score = -1

        for name, cfg in self._profiles.items():
            match = cfg.get("match", {})
            if not matches_request(
                match,
                host=host,
                path=path,
                method=method,
                content_type=flow.request.headers.get("Content-Type", ""),
                body_text=flow.request.text or "",
            ):
                continue

            score = 0
            for h in match.get("host", []):
                if h == host:
                    score += 200
                elif h == "*":
                    score += 1
                elif "*" in h:
                    score += 20
            for p in match.get("path", []):
                if fnmatch.fnmatch(path, p):
                    score += len(p.replace("*", ""))
            if match.get("require_fields"):
                score += 10
            score += 5

            if score > best_score:
                best_score = score
                best_name = name

        if best_name:
            logger.info("  ✓ 命中: %s (score=%s)", best_name, best_score)
            return best_name
        logger.info("  ✗ 未匹配任何Profile")
        return ""

    def get_profile_config(self, name: str) -> dict:
        return self._profiles.get(name, {})
