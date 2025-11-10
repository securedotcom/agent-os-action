"""
SageMaker-based Foundation-Sec-8B Provider
Uses AWS SageMaker endpoint for fast, scalable inference
"""

import json
import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)


class SageMakerFoundationSecProvider:
    """Foundation-Sec-8B via AWS SageMaker endpoint"""

    def __init__(
        self,
        endpoint_name: Optional[str] = None,
        region_name: str = "us-east-1",
        max_new_tokens: int = 512,
        temperature: float = 0.3,
    ):
        """
        Initialize SageMaker provider

        Args:
            endpoint_name: SageMaker endpoint (or set SAGEMAKER_ENDPOINT env var)
            region_name: AWS region (or set AWS_REGION env var)
            max_new_tokens: Max tokens to generate
            temperature: Sampling temperature (0.0 = deterministic)
        """
        self.endpoint_name = endpoint_name or os.getenv("SAGEMAKER_ENDPOINT")
        self.region_name = region_name or os.getenv("AWS_REGION", "us-east-1")
        self.max_new_tokens = max_new_tokens
        self.temperature = temperature
        self.client = None

        if not self.endpoint_name:
            raise ValueError("SageMaker endpoint required. Set SAGEMAKER_ENDPOINT env var or pass endpoint_name")

        self._init_client()

    def _init_client(self):
        """Initialize boto3 SageMaker runtime client"""
        try:
            import boto3

            # Use IAM role or environment variables for credentials
            # NEVER hardcode credentials
            self.client = boto3.client(
                "sagemaker-runtime",
                region_name=self.region_name,
                # Credentials come from:
                # 1. AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars
                # 2. ~/.aws/credentials file
                # 3. IAM role (if running on EC2/Lambda/etc)
            )

            logger.info(f"✅ SageMaker client initialized (endpoint: {self.endpoint_name})")

        except ImportError:
            raise ImportError("boto3 required for SageMaker. Install: pip install boto3")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize SageMaker client: {e}")

    def generate(
        self,
        prompt: str,
        max_new_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> str:
        """
        Generate completion using SageMaker endpoint

        Args:
            prompt: Input prompt
            max_new_tokens: Override default max tokens
            temperature: Override default temperature

        Returns:
            Generated text
        """
        if not self.client:
            raise RuntimeError("SageMaker client not initialized")

        max_tokens = max_new_tokens or self.max_new_tokens
        temp = temperature or self.temperature

        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": max_tokens,
                "temperature": temp,
                "do_sample": temp > 0,
                "top_p": 0.9,
                "return_full_text": False,
            },
        }

        try:
            logger.debug(f"📤 Invoking SageMaker endpoint: {self.endpoint_name}")

            response = self.client.invoke_endpoint(
                EndpointName=self.endpoint_name, ContentType="application/json", Body=json.dumps(payload)
            )

            result = json.loads(response["Body"].read())

            # Handle TGI response format
            if isinstance(result, list) and len(result) > 0:
                generated_text = result[0].get("generated_text", "")
            elif isinstance(result, dict):
                generated_text = result.get("generated_text", "")
            else:
                generated_text = str(result)

            logger.debug(f"✅ Generated {len(generated_text)} characters")
            return generated_text

        except Exception as e:
            logger.error(f"❌ SageMaker inference failed: {e}")
            raise RuntimeError(f"SageMaker inference error: {e}")

    def analyze_code(self, code: str, context: str = "", focus: str = "security_analysis") -> str:
        """
        Analyze code for security issues using Foundation-Sec

        Args:
            code: Code snippet to analyze
            context: Additional context or prompt
            focus: Analysis focus (security_analysis, false_positive_analysis, etc.)

        Returns:
            AI analysis response
        """
        # Build prompt based on focus
        if (
            focus == "false_positive_analysis"
            or focus == "correlation_analysis"
            or focus == "exploitability_assessment"
            or focus == "secret_detection"
        ):
            prompt = context  # Context already contains the full prompt
        else:
            # Default security analysis
            prompt = f"""Analyze this code for security vulnerabilities:

{context}

Code:
```
{code}
```

Provide a detailed security analysis including:
1. Vulnerabilities found
2. Severity assessment
3. Exploitability
4. Recommendations
"""

        return self.generate(prompt, max_new_tokens=512)

    def test_connection(self) -> dict[str, Any]:
        """Test SageMaker endpoint connectivity"""
        try:
            test_prompt = "Security vulnerability: SQL injection in login form."
            response = self.generate(test_prompt, max_new_tokens=50)

            return {
                "status": "success",
                "endpoint": self.endpoint_name,
                "region": self.region_name,
                "response_length": len(response),
                "message": "SageMaker endpoint is healthy",
            }
        except Exception as e:
            return {
                "status": "error",
                "endpoint": self.endpoint_name,
                "region": self.region_name,
                "error": str(e),
                "message": "SageMaker endpoint test failed",
            }


if __name__ == "__main__":
    # Test script
    import sys

    print("🧪 Testing SageMaker Foundation-Sec Provider")
    print("=" * 60)

    # Check environment
    endpoint = os.getenv("SAGEMAKER_ENDPOINT")
    if not endpoint:
        print("❌ SAGEMAKER_ENDPOINT not set")
        print("\nUsage:")
        print("  export SAGEMAKER_ENDPOINT='your-endpoint-name'")
        print("  export AWS_ACCESS_KEY_ID='your-key'")
        print("  export AWS_SECRET_ACCESS_KEY='your-secret'")
        print("  export AWS_REGION='us-east-1'")
        print("  python scripts/providers/sagemaker_foundation_sec.py")
        sys.exit(1)

    try:
        # Initialize provider
        provider = SageMakerFoundationSecProvider()

        # Test connection
        print("\n🔍 Testing endpoint connectivity...")
        result = provider.test_connection()

        if result["status"] == "success":
            print(f"✅ {result['message']}")
            print(f"   Endpoint: {result['endpoint']}")
            print(f"   Region: {result['region']}")
            print(f"   Response length: {result['response_length']} chars")

            # Test security analysis
            print("\n🔍 Testing security analysis...")
            prompt = """Analyze this vulnerability:

Finding: SQL Injection in user login endpoint
Code: cursor.execute("SELECT * FROM users WHERE username='" + user_input + "'")
Impact: Unauthenticated attackers can bypass authentication

Provide JSON with: cwe_id, exploitability, severity, recommendation"""

            response = provider.generate(prompt, max_new_tokens=256)
            print(f"\n📊 AI Response ({len(response)} chars):")
            print("─" * 60)
            print(response[:500])
            if len(response) > 500:
                print(f"... (truncated, {len(response) - 500} more chars)")

        else:
            print(f"❌ {result['message']}")
            print(f"   Error: {result.get('error')}")
            sys.exit(1)

    except Exception as e:
        print(f"❌ Test failed: {e}")
        sys.exit(1)

    print("\n✅ All tests passed!")
