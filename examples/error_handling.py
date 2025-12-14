"""BlindAI SDK Error Handling Example.

This example demonstrates proper error handling patterns.

Run with: python examples/error_handling.py
"""

import os
from blindai import BlindAI
from blindai.exceptions import (
    BlindAIError,
    ThreatBlockedError,
    APIError,
    ConfigurationError,
    TimeoutError,
    RetryExhaustedError,
)

os.environ.setdefault("BLINDAI_API_KEY", "your-api-key")


def main():
    print("=" * 50)
    print("BlindAI Error Handling")
    print("=" * 50)
    
    # Example 1: Handle specific exceptions
    print("\n1. Specific Exception Handling")
    print("-" * 30)
    
    blind = BlindAI()
    
    try:
        result = blind.check("Test input")
        print(f"Result: {result.is_threat}")
    except ThreatBlockedError as e:
        # Content was blocked due to detected threat
        print(f"Threat blocked: {e.threat_level}")
        print(f"Details: {e.details}")
    except APIError as e:
        # API returned an error (4xx, 5xx)
        print(f"API error: {e}")
    except TimeoutError:
        # Request timed out
        print("Request timed out - try again later")
    except RetryExhaustedError:
        # All retries failed
        print("All retries exhausted")
    except BlindAIError as e:
        # Catch-all for any BlindAI error
        print(f"BlindAI error: {e}")
    
    # Example 2: Graceful degradation with fail_open
    print("\n2. Fail-Open Mode")
    print("-" * 30)
    
    # In fail_open mode, requests continue even on API errors
    blind_failopen = BlindAI(fail_open=True)
    
    try:
        result = blind_failopen.check("Test input")
        if result.is_threat:
            print("Threat detected")
        else:
            print("Safe (or API unavailable in fail_open mode)")
    except ThreatBlockedError:
        # Still blocks on actual threats
        print("Threat blocked even in fail_open mode")
    
    # Example 3: Context manager for automatic cleanup
    print("\n3. Context Manager")
    print("-" * 30)
    
    try:
        with BlindAI() as blind:
            result = blind.check("Safe input")
            print(f"Check completed: {not result.is_threat}")
        # Resources automatically cleaned up
        print("Resources cleaned up automatically")
    except BlindAIError as e:
        print(f"Error: {e}")
    
    # Clean up
    blind.close()
    blind_failopen.close()
    print("\n✅ Done!")


if __name__ == "__main__":
    main()
