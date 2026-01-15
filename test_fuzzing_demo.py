#!/usr/bin/env python3
"""
Simple demo to test the fuzzing engine
"""

def vulnerable_function(user_input):
    """A function with potential vulnerabilities"""
    if user_input == "crash":
        raise ValueError("Intentional crash for testing")

    if len(user_input) > 10000:
        # Simulate buffer overflow detection
        raise BufferError("Input too large")

    return f"Processed: {user_input}"


def safe_function(value):
    """A safe function that shouldn't crash"""
    if isinstance(value, str):
        return len(value)
    return 0


if __name__ == "__main__":
    print("Test functions defined:")
    print("- vulnerable_function(user_input)")
    print("- safe_function(value)")
