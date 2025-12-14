"""BlindAI SDK Decorator Options Example.

This example shows all the options available with the @protect decorator.

Run with: python examples/decorator_options.py
"""

import os
from blindai import BlindAI
from blindai.exceptions import ThreatBlockedError

os.environ.setdefault("BLINDAI_API_KEY", "your-api-key")


def main():
    blind = BlindAI()
    
    print("=" * 50)
    print("BlindAI Decorator Options")
    print("=" * 50)
    
    # Option 1: Basic protection (all policies, block on threat)
    @blind.protect
    def basic_protection(text: str) -> str:
        return f"Processed: {text}"
    
    # Option 2: Specific policies only
    @blind.protect(policies=["pii", "prompt_injection"])
    def pii_and_injection_only(text: str) -> str:
        return f"Checked for PII and injection: {text}"
    
    # Option 3: Fast mode (skip ML, 10x faster)
    @blind.protect(mode="fast")
    def fast_check(text: str) -> str:
        return f"Fast checked: {text}"
    
    # Option 4: Warn instead of block
    @blind.protect(on_violation="warn")
    def warn_only(text: str) -> str:
        return f"Warning mode: {text}"
    
    # Option 5: Log silently (for monitoring)
    @blind.protect(on_violation="log")
    def silent_logging(text: str) -> str:
        return f"Logged: {text}"
    
    # Option 6: Combined options
    @blind.protect(
        policies=["prompt_injection"],
        on_violation="block",
        mode="fast",
    )
    def production_ready(text: str) -> str:
        return f"Production: {text}"
    
    # Test each
    test_input = "Hello world"
    
    print("\nTesting with safe input:")
    print(f"  basic_protection: {basic_protection(test_input)}")
    print(f"  pii_and_injection_only: {pii_and_injection_only(test_input)}")
    print(f"  fast_check: {fast_check(test_input)}")
    print(f"  warn_only: {warn_only(test_input)}")
    print(f"  silent_logging: {silent_logging(test_input)}")
    print(f"  production_ready: {production_ready(test_input)}")
    
    blind.close()
    print("\n✅ Done!")


if __name__ == "__main__":
    main()
