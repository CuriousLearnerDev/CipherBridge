/**
 * Web 反调试绕过（可按站点勾选模块）
 * 启动前由 Playwright 注入 window.__cbInjectOpts，再执行本脚本。
 *
 * 选项见 __cbInjectOpts：
 *   functionHook, evalHook, timerHook, timerNuke,
 *   consoleClear, sizeSpoof
 * 另：浏览器侧还可开启「响应改写」（Playwright route），把源码里的
 * debugger 改成 return，专治字面量 + 递归无限 debugger。
 */
(function () {
    "use strict";
    if (window.__cbAntiDebug) return;
    window.__cbAntiDebug = true;

    var opts = window.__cbInjectOpts || {};
    function on(key, defVal) {
        return opts[key] === undefined ? defVal : !!opts[key];
    }

    function stripDebugger(src) {
        if (typeof src !== "string") return src;
        // 改成 return：打断 sojson「debugger 后递归」一类控制流
        return src
            .replace(/\bdebugger\b/gi, "return")
            .replace(/while\s*\(\s*(?:!!\s*\[\s*\]|!0|true)\s*\)\s*\{\s*\}/gi, "");
    }

    // —— Function / constructor("debugger").call/apply ——
    if (on("functionHook", true)) {
        try {
            var NativeFunction = window.Function;
            function WrappedFunction() {
                var args = Array.prototype.slice.call(arguments);
                if (args.length) {
                    args[args.length - 1] = stripDebugger(args[args.length - 1]);
                }
                return NativeFunction.apply(this, args);
            }
            WrappedFunction.prototype = NativeFunction.prototype;
            try {
                Object.defineProperty(WrappedFunction, "name", { value: "Function" });
                Object.defineProperty(WrappedFunction, "length", {
                    value: NativeFunction.length,
                });
            } catch (e) {}
            window.Function = WrappedFunction;
            try {
                Function.prototype.constructor = WrappedFunction;
            } catch (e) {}
            // 部分混淆：obj.constructor("debugger").call("action")
            try {
                var desc = Object.getOwnPropertyDescriptor(Function.prototype, "constructor");
                if (!desc || desc.configurable) {
                    Object.defineProperty(Function.prototype, "constructor", {
                        configurable: true,
                        enumerable: false,
                        get: function () {
                            return WrappedFunction;
                        },
                        set: function () {},
                    });
                }
            } catch (e) {}
        } catch (e) {}
    }

    // —— eval("debugger") ——
    if (on("evalHook", true)) {
        try {
            var nativeEval = window.eval;
            window.eval = function (code) {
                return nativeEval(stripDebugger(code));
            };
        } catch (e) {}
    }

    // —— setInterval / setTimeout ——
    if (on("timerNuke", false)) {
        // 激进：整段定时器置空（文中「定时器置空」；可能影响正常业务定时器）
        try {
            window.setInterval = function () {
                return 0;
            };
            window.setTimeout = function (handler, timeout) {
                if (typeof handler === "function") {
                    try {
                        var src = Function.prototype.toString.call(handler);
                        if (/\bdebugger\b/i.test(src)) return 0;
                    } catch (e) {}
                }
                if (typeof handler === "string" && /\bdebugger\b/i.test(handler)) {
                    return 0;
                }
                return window.__cbNativeSetTimeout
                    ? window.__cbNativeSetTimeout(handler, timeout)
                    : 0;
            };
        } catch (e) {}
    } else if (on("timerHook", true)) {
        try {
            window.__cbNativeSetTimeout = window.setTimeout.bind(window);
            window.__cbNativeSetInterval = window.setInterval.bind(window);
            function wrapTimer(nativeFn) {
                return function (handler) {
                    var args = Array.prototype.slice.call(arguments);
                    if (typeof handler === "string") {
                        args[0] = stripDebugger(handler);
                    } else if (typeof handler === "function") {
                        try {
                            var src = Function.prototype.toString.call(handler);
                            if (/\bdebugger\b/i.test(src)) {
                                args[0] = function () {};
                            }
                        } catch (e) {}
                    }
                    return nativeFn.apply(this, args);
                };
            }
            window.setInterval = wrapTimer(window.__cbNativeSetInterval);
            window.setTimeout = wrapTimer(window.__cbNativeSetTimeout);
        } catch (e) {}
    }

    if (on("consoleClear", true)) {
        try {
            if (window.console) console.clear = function () {};
        } catch (e) {}
    }

    if (on("sizeSpoof", true)) {
        try {
            var define = Object.defineProperty;
            function spoof(obj, prop, getter) {
                try {
                    define.call(Object, obj, prop, {
                        configurable: true,
                        get: getter,
                    });
                } catch (e) {}
            }
            spoof(window, "outerWidth", function () {
                return window.innerWidth;
            });
            spoof(window, "outerHeight", function () {
                return window.innerHeight;
            });
        } catch (e) {}
    }

    try {
        var enabled = [];
        if (on("functionHook", true)) enabled.push("Function");
        if (on("evalHook", true)) enabled.push("eval");
        if (on("timerNuke", false)) enabled.push("timerNuke");
        else if (on("timerHook", true)) enabled.push("timer");
        if (on("consoleClear", true)) enabled.push("console");
        if (on("sizeSpoof", true)) enabled.push("size");
        console.log("[密桥] 反调试已注入: " + enabled.join(","));
    } catch (e) {}
})();
