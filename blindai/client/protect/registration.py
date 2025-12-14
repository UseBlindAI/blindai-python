"""Tool registration functionality."""

import inspect
import logging
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class RegistrationMixin:
    """Mixin providing tool registration."""

    def _register_tool_async(self, func: Callable, agent_id: Optional[str] = None) -> None:
        """Register a tool with the API (non-blocking).
        
        Extracts function metadata and sends to /v1/tools/user/register.
        This is called automatically by @protect decorator.
        """
        func_name = func.__name__
        
        # Check if already registered
        with self._registration_lock:
            if func_name in self._registered_tools:
                return
            self._registered_tools.add(func_name)
        
        try:
            sig = inspect.signature(func)
            parameters = {}
            for param_name, param in sig.parameters.items():
                if param.annotation != inspect.Parameter.empty:
                    param_type = param.annotation
                    if hasattr(param_type, "__name__"):
                        parameters[param_name] = param_type.__name__
                    else:
                        parameters[param_name] = str(param_type)
                else:
                    parameters[param_name] = "any"
            
            return_type = None
            if sig.return_annotation != inspect.Signature.empty:
                if hasattr(sig.return_annotation, "__name__"):
                    return_type = sig.return_annotation.__name__
                else:
                    return_type = str(sig.return_annotation)
            
            description = func.__doc__.split("\n")[0] if func.__doc__ else None
            
            def do_register():
                try:
                    headers = {"Content-Type": "application/json"}
                    if self.config.api_key:
                        headers["X-API-Key"] = self.config.api_key
                    
                    self.client.post(
                        "/v1/tools/user/register",
                        json={
                            "name": func_name,
                            "description": description,
                            "parameters": parameters,
                            "return_type": return_type,
                            "agent_id": agent_id,
                        },
                        headers=headers,
                    )
                    logger.debug(f"Registered tool: {func_name}")
                except Exception as e:
                    logger.debug(f"Failed to register tool {func_name}: {e}")
            
            thread = threading.Thread(target=do_register, daemon=True)
            thread.start()
            
        except Exception as e:
            logger.debug(f"Failed to extract tool metadata for {func_name}: {e}")
