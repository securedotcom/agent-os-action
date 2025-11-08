#!/usr/bin/env python3
"""
Threat Model Generator for Agent OS
Automatically analyzes repositories and generates security-focused threat models
"""

import os
import sys
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import glob as glob_module

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class ThreatModelGenerator:
    """Generate threat models for repositories using Claude API"""

    def __init__(self, api_key: str):
        """Initialize the threat model generator

        Args:
            api_key: Anthropic API key for Claude
        """
        try:
            from anthropic import Anthropic

            self.client = Anthropic(api_key=api_key)
            logger.info("Initialized Anthropic client for threat modeling")
        except ImportError:
            logger.error("anthropic package not installed. Run: pip install anthropic")
            raise

    def analyze_repository(self, repo_path: str) -> Dict[str, Any]:
        """Scan repository structure and identify key files

        Args:
            repo_path: Path to the repository

        Returns:
            Dictionary with repository context
        """
        logger.info(f"Analyzing repository: {repo_path}")
        repo_path = Path(repo_path).resolve()

        context = {
            "path": str(repo_path),
            "name": repo_path.name,
            "languages": set(),
            "frameworks": set(),
            "key_files": [],
            "file_tree": [],
            "technologies": set(),
            "package_files": [],
        }

        # Language extensions
        lang_map = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".jsx": "React",
            ".tsx": "React/TypeScript",
            ".java": "Java",
            ".go": "Go",
            ".rs": "Rust",
            ".rb": "Ruby",
            ".php": "PHP",
            ".cs": "C#",
            ".swift": "Swift",
            ".kt": "Kotlin",
            ".scala": "Scala",
        }

        # Key files to analyze
        key_file_patterns = [
            "README.md",
            "README.rst",
            "README.txt",
            "package.json",
            "package-lock.json",
            "requirements.txt",
            "Pipfile",
            "pyproject.toml",
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "go.mod",
            "go.sum",
            "Cargo.toml",
            "Cargo.lock",
            "Gemfile",
            "Gemfile.lock",
            "composer.json",
            "composer.lock",
            "docker-compose.yml",
            "docker-compose.yaml",
            "Dockerfile",
            ".env.example",
            "config.yml",
            "config.yaml",
            "tsconfig.json",
            ".eslintrc",
            ".prettierrc",
        ]

        # Scan repository
        for root, dirs, files in os.walk(repo_path):
            # Skip common directories
            dirs[:] = [
                d
                for d in dirs
                if d
                not in {
                    ".git",
                    "node_modules",
                    "venv",
                    "__pycache__",
                    "dist",
                    "build",
                    ".next",
                    "target",
                    "vendor",
                    ".gradle",
                    ".idea",
                    ".vscode",
                }
            ]

            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(repo_path)

                # Track file tree (limit depth)
                if len(rel_path.parts) <= 3:
                    context["file_tree"].append(str(rel_path))

                # Detect languages
                ext = file_path.suffix
                if ext in lang_map:
                    context["languages"].add(lang_map[ext])

                # Find key files
                if file in key_file_patterns or file.lower() in [p.lower() for p in key_file_patterns]:
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read(10000)  # Read first 10KB
                            context["key_files"].append({"path": str(rel_path), "name": file, "content": content})

                            # Track package files for dependency analysis
                            if file in ["package.json", "requirements.txt", "go.mod", "Cargo.toml", "pom.xml"]:
                                context["package_files"].append({"path": str(rel_path), "content": content})
                    except Exception as e:
                        logger.warning(f"Could not read {file_path}: {e}")

        # Detect frameworks from files
        self._detect_frameworks(context)

        # Convert sets to lists for JSON serialization
        context["languages"] = sorted(list(context["languages"]))
        context["frameworks"] = sorted(list(context["frameworks"]))
        context["technologies"] = sorted(list(context["technologies"]))

        logger.info(f"Found {len(context['languages'])} languages, {len(context['frameworks'])} frameworks")
        logger.info(f"Analyzed {len(context['key_files'])} key files")

        return context

    def _detect_frameworks(self, context: Dict[str, Any]) -> None:
        """Detect frameworks and technologies from context

        Args:
            context: Repository context dictionary (modified in-place)
        """
        for key_file in context["key_files"]:
            content = key_file["content"].lower()
            name = key_file["name"].lower()

            # JavaScript/TypeScript frameworks
            if "package.json" in name:
                if "react" in content:
                    context["frameworks"].add("React")
                if "next" in content:
                    context["frameworks"].add("Next.js")
                if "vue" in content:
                    context["frameworks"].add("Vue")
                if "angular" in content:
                    context["frameworks"].add("Angular")
                if "express" in content:
                    context["frameworks"].add("Express")
                if "nestjs" in content or "@nestjs" in content:
                    context["frameworks"].add("NestJS")
                if "fastify" in content:
                    context["frameworks"].add("Fastify")

            # Python frameworks
            if "requirements.txt" in name or "pyproject.toml" in name:
                if "django" in content:
                    context["frameworks"].add("Django")
                if "flask" in content:
                    context["frameworks"].add("Flask")
                if "fastapi" in content:
                    context["frameworks"].add("FastAPI")
                if "pytest" in content:
                    context["technologies"].add("pytest")

            # Java frameworks
            if "pom.xml" in name or "build.gradle" in name:
                if "spring" in content:
                    context["frameworks"].add("Spring Boot")
                if "quarkus" in content:
                    context["frameworks"].add("Quarkus")

            # Go frameworks
            if "go.mod" in name:
                if "gin" in content:
                    context["frameworks"].add("Gin")
                if "echo" in content:
                    context["frameworks"].add("Echo")

            # Rust frameworks
            if "cargo.toml" in name:
                if "actix" in content:
                    context["frameworks"].add("Actix")
                if "rocket" in content:
                    context["frameworks"].add("Rocket")

            # Databases and storage
            if "postgres" in content or "postgresql" in content:
                context["technologies"].add("PostgreSQL")
            if "mysql" in content:
                context["technologies"].add("MySQL")
            if "mongodb" in content or "mongo" in content:
                context["technologies"].add("MongoDB")
            if "redis" in content:
                context["technologies"].add("Redis")

            # Authentication
            if "jwt" in content or "jsonwebtoken" in content:
                context["technologies"].add("JWT")
            if "oauth" in content:
                context["technologies"].add("OAuth")
            if "passport" in content:
                context["technologies"].add("Passport")

            # Containerization
            if "dockerfile" in name or "docker-compose" in name:
                context["technologies"].add("Docker")
            if "kubernetes" in content or "k8s" in content:
                context["technologies"].add("Kubernetes")

    def generate_threat_model(self, repo_context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate threat model using Claude API

        Args:
            repo_context: Repository context from analyze_repository

        Returns:
            Threat model dictionary
        """
        logger.info("Generating threat model with Claude API...")

        # Build prompt
        prompt = self._build_threat_model_prompt(repo_context)

        try:
            # Call Claude API
            message = self.client.messages.create(
                model="claude-sonnet-4-5-20250929", max_tokens=8000, messages=[{"role": "user", "content": prompt}]
            )

            response_text = message.content[0].text
            logger.info(
                f"Received threat model (tokens: {message.usage.input_tokens} in, {message.usage.output_tokens} out)"
            )

            # Extract JSON from response (handle markdown code blocks)
            json_text = response_text.strip()
            if json_text.startswith("```"):
                # Remove markdown code fence
                lines = json_text.split("\n")
                json_text = "\n".join(lines[1:-1])  # Remove first and last lines
                json_text = json_text.strip()

            # Parse JSON response
            threat_model = json.loads(json_text)

            # Add metadata
            threat_model["version"] = "1.0"
            threat_model["generated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            threat_model["repository"] = repo_context["name"]

            return threat_model

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse threat model JSON: {e}")
            # Return a basic threat model structure
            return self._create_fallback_threat_model(repo_context)
        except Exception as e:
            logger.error(f"Failed to generate threat model: {e}")
            raise

    def _build_threat_model_prompt(self, repo_context: Dict[str, Any]) -> str:
        """Build prompt for threat model generation

        Args:
            repo_context: Repository context

        Returns:
            Formatted prompt string
        """
        # Format key files
        key_files_text = "\n\n".join(
            [
                f"File: {kf['path']}\n```\n{kf['content'][:2000]}\n```"
                for kf in repo_context["key_files"][:5]  # Limit to 5 files
            ]
        )

        prompt = f"""You are a security architect performing threat modeling for a software repository.

# Repository Information
- **Name**: {repo_context['name']}
- **Languages**: {', '.join(repo_context['languages'])}
- **Frameworks**: {', '.join(repo_context['frameworks'])}
- **Technologies**: {', '.join(repo_context['technologies'])}

# Key Files
{key_files_text}

# File Structure (sample)
{chr(10).join(repo_context['file_tree'][:30])}

# Your Task
Generate a comprehensive threat model in JSON format with the following structure:

{{
  "attack_surface": {{
    "entry_points": ["List of entry points like API endpoints, file uploads, user inputs"],
    "external_dependencies": ["npm packages", "APIs", "third-party services"],
    "authentication_methods": ["JWT", "OAuth", "Session cookies"],
    "data_stores": ["PostgreSQL", "Redis", "File system"]
  }},
  "trust_boundaries": [
    {{"name": "Public API", "trust_level": "untrusted", "description": "External user access"}},
    {{"name": "Admin API", "trust_level": "authenticated", "description": "Admin-only access"}}
  ],
  "assets": [
    {{"name": "User PII", "sensitivity": "high", "description": "Personal information"}},
    {{"name": "Session tokens", "sensitivity": "critical", "description": "Authentication tokens"}}
  ],
  "threats": [
    {{
      "id": "THREAT-001",
      "name": "SQL Injection",
      "category": "injection",
      "likelihood": "high",
      "impact": "critical",
      "affected_components": ["user search", "admin queries"],
      "description": "Detailed threat description",
      "mitigation": "Use parameterized queries"
    }}
  ],
  "security_objectives": [
    "Protect user PII",
    "Prevent unauthorized access",
    "Maintain data integrity"
  ]
}}

IMPORTANT: Return ONLY valid JSON. No markdown, no explanations, just the JSON object.
"""
        return prompt

    def _create_fallback_threat_model(self, repo_context: Dict[str, Any]) -> Dict[str, Any]:
        """Create a basic fallback threat model when API fails

        Args:
            repo_context: Repository context

        Returns:
            Basic threat model dictionary
        """
        return {
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "repository": repo_context["name"],
            "attack_surface": {
                "entry_points": ["API endpoints", "User input"],
                "external_dependencies": repo_context.get("technologies", []),
                "authentication_methods": ["To be determined"],
                "data_stores": [],
            },
            "trust_boundaries": [{"name": "Public API", "trust_level": "untrusted", "description": "External access"}],
            "assets": [{"name": "User data", "sensitivity": "high", "description": "User information"}],
            "threats": [
                {
                    "id": "THREAT-001",
                    "name": "Generic threat",
                    "category": "security",
                    "likelihood": "medium",
                    "impact": "medium",
                    "affected_components": ["application"],
                    "description": "Manual threat modeling required",
                    "mitigation": "Conduct security review",
                }
            ],
            "security_objectives": ["Protect user data", "Prevent unauthorized access"],
        }

    def save_threat_model(self, threat_model: Dict[str, Any], output_path: str) -> None:
        """Save threat model to JSON file

        Args:
            threat_model: Threat model dictionary
            output_path: Path to output file
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(threat_model, f, indent=2)

        logger.info(f"Threat model saved to: {output_path}")

    def load_existing_threat_model(self, path: str) -> Optional[Dict[str, Any]]:
        """Load existing threat model if it exists

        Args:
            path: Path to threat model file

        Returns:
            Threat model dictionary or None if not found
        """
        path = Path(path)
        if not path.exists():
            logger.info(f"No existing threat model found at {path}")
            return None

        try:
            with open(path, "r", encoding="utf-8") as f:
                threat_model = json.load(f)
            logger.info(f"Loaded existing threat model from {path}")
            return threat_model
        except Exception as e:
            logger.error(f"Failed to load threat model: {e}")
            return None

    def update_threat_model(self, existing: Dict[str, Any], new_context: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing threat model with new context

        Args:
            existing: Existing threat model
            new_context: New repository context

        Returns:
            Updated threat model
        """
        logger.info("Updating existing threat model...")

        # For now, regenerate the threat model
        # In future, this could do incremental updates
        return self.generate_threat_model(new_context)


def main():
    """Main entry point for CLI usage"""
    import argparse

    parser = argparse.ArgumentParser(description="Generate threat model for a repository")
    parser.add_argument("repo_path", nargs="?", default=".", help="Path to repository (default: current directory)")
    parser.add_argument(
        "--output",
        "-o",
        default=".agent-os/threat-model.json",
        help="Output path for threat model (default: .agent-os/threat-model.json)",
    )
    parser.add_argument("--api-key", help="Anthropic API key (or set ANTHROPIC_API_KEY env var)")
    parser.add_argument("--force", action="store_true", help="Force regeneration even if threat model exists")

    args = parser.parse_args()

    # Get API key
    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not set")
        print("Set via environment or --api-key flag")
        sys.exit(1)

    try:
        # Initialize generator
        generator = ThreatModelGenerator(api_key)

        # Check for existing threat model
        output_path = Path(args.repo_path) / args.output
        existing = generator.load_existing_threat_model(output_path)

        if existing and not args.force:
            print(f"Threat model already exists at {output_path}")
            print("Use --force to regenerate")
            sys.exit(0)

        # Analyze repository
        repo_context = generator.analyze_repository(args.repo_path)

        # Generate or update threat model
        if existing and not args.force:
            threat_model = generator.update_threat_model(existing, repo_context)
        else:
            threat_model = generator.generate_threat_model(repo_context)

        # Save threat model
        generator.save_threat_model(threat_model, output_path)

        print(f"\nThreat model generated successfully!")
        print(f"Output: {output_path}")
        print(f"\nSummary:")
        print(f"  Entry points: {len(threat_model.get('attack_surface', {}).get('entry_points', []))}")
        print(f"  Trust boundaries: {len(threat_model.get('trust_boundaries', []))}")
        print(f"  Assets: {len(threat_model.get('assets', []))}")
        print(f"  Threats: {len(threat_model.get('threats', []))}")

    except Exception as e:
        logger.error(f"Failed to generate threat model: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
