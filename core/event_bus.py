"""事件总线 — 插件可以在request/response前后注册钩子."""


class EventBus:
    _handlers = {}

    @classmethod
    def on(cls, event: str, handler):
        """注册事件处理器.

        event: "before_request", "after_request", "before_response", "after_response", "error"
        """
        if event not in cls._handlers:
            cls._handlers[event] = []
        cls._handlers[event].append(handler)

    @classmethod
    def emit(cls, event: str, *args, **kwargs):
        """触发事件."""
        for handler in cls._handlers.get(event, []):
            try:
                handler(*args, **kwargs)
            except Exception as e:
                import logging
                logging.getLogger(__name__).error("事件处理异常 %s: %s", event, e)
