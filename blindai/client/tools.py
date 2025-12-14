"""Tool registry methods for ToolGuard."""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ToolsMixin:
    """Mixin providing tool registry methods for ToolGuard."""

    def register_tool(
        self,
        name: str,
        trust_level: str,
        tool_type: str,
        description: str = "",
        allowed_domains: Optional[list[str]] = None,
        allowed_roles: Optional[list[str]] = None,
        rate_limit_per_minute: Optional[int] = None,
        require_approval: bool = False,
        metadata: Optional[dict] = None,
    ) -> dict:
        """Register a tool with security metadata.

        This enables tool-aware policy rules and authorization checks.

        Args:
            name: Unique tool identifier
            trust_level: Trust level (HIGH, MEDIUM, or LOW)
            tool_type: Tool type (DATABASE, API, EMAIL, COMMUNICATION, FILE, COMMAND, etc.)
            description: Human-readable description
            allowed_domains: List of allowed domains for external calls
            allowed_roles: List of roles permitted to use this tool
            rate_limit_per_minute: Maximum calls per minute
            require_approval: Whether calls require human approval
            metadata: Additional custom metadata

        Returns:
            Registered tool metadata

        Raises:
            APIError: If registration fails
            ConfigurationError: If parameters are invalid

        Example:
            ```python
            guard.register_tool(
                name="send_email",
                trust_level="LOW",
                tool_type="EMAIL",
                description="Send email to external recipients",
                allowed_domains=["company.com", "partner.com"],
                allowed_roles=["user", "admin"],
                rate_limit_per_minute=100
            )
            ```
        """
        payload = {
            "name": name,
            "trust_level": trust_level.upper(),
            "tool_type": tool_type.upper(),
            "description": description,
            "allowed_domains": allowed_domains or [],
            "allowed_roles": allowed_roles or [],
            "rate_limit_per_minute": rate_limit_per_minute,
            "require_approval": require_approval,
            "metadata": metadata or {},
        }

        try:
            response = self._request_with_retry(
                "POST", "/v1/tools/register", json=payload
            )
            return response
        except Exception as e:
            if self.config.fail_open:
                # Log error but don't raise
                print(f"Warning: Tool registration failed: {e}")
                return {"name": name, "status": "failed"}
            raise

    def get_tool(self, tool_name: str) -> Optional[dict]:
        """Get tool metadata by name.

        Args:
            tool_name: Tool identifier

        Returns:
            Tool metadata if found, None otherwise

        Raises:
            APIError: If request fails

        Example:
            ```python
            tool = guard.get_tool("send_email")
            if tool and tool["trust_level"] == "LOW":
                print("Low trust tool - extra validation required")
            ```
        """
        from ..exceptions import APIError
        
        try:
            response = self._request_with_retry("GET", f"/v1/tools/{tool_name}")
            return response
        except APIError as e:
            if "404" in str(e):
                return None
            raise

    def list_tools(self) -> list[dict]:
        """List all registered tools.

        Returns:
            List of tool metadata

        Raises:
            APIError: If request fails

        Example:
            ```python
            tools = guard.list_tools()
            for tool in tools:
                print(f"{tool['name']}: {tool['trust_level']}")
            ```
        """
        response = self._request_with_retry("GET", "/v1/tools")
        return response.get("tools", [])

    def list_tools_by_trust_level(self, trust_level: str) -> list[dict]:
        """List tools by trust level.

        Args:
            trust_level: Trust level filter (HIGH, MEDIUM, or LOW)

        Returns:
            List of matching tools

        Raises:
            APIError: If request fails

        Example:
            ```python
            low_trust_tools = guard.list_tools_by_trust_level("LOW")
            for tool in low_trust_tools:
                print(f"Low trust: {tool['name']}")
            ```
        """
        response = self._request_with_retry(
            "GET", f"/v1/tools/by-trust-level/{trust_level.upper()}"
        )
        return response.get("tools", [])

    def list_tools_by_type(self, tool_type: str) -> list[dict]:
        """List tools by type.

        Args:
            tool_type: Tool type filter (DATABASE, API, EMAIL, etc.)

        Returns:
            List of matching tools

        Raises:
            APIError: If request fails

        Example:
            ```python
            db_tools = guard.list_tools_by_type("DATABASE")
            for tool in db_tools:
                print(f"Database tool: {tool['name']}")
            ```
        """
        response = self._request_with_retry(
            "GET", f"/v1/tools/by-type/{tool_type.upper()}"
        )
        return response.get("tools", [])

    def delete_tool(self, tool_name: str) -> bool:
        """Delete a tool from the registry.

        Args:
            tool_name: Tool identifier

        Returns:
            True if deleted, False if not found

        Raises:
            APIError: If request fails

        Example:
            ```python
            deleted = guard.delete_tool("deprecated_tool")
            if deleted:
                print("Tool removed from registry")
            ```
        """
        from ..exceptions import APIError
        
        try:
            self._request_with_retry("DELETE", f"/v1/tools/{tool_name}")
            return True
        except APIError as e:
            if "404" in str(e):
                return False
            raise
