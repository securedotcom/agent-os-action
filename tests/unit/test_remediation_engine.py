#!/usr/bin/env python3
"""
Unit tests for Remediation Engine

Tests cover:
- RemediationSuggestion dataclass
- Template-based fix generation
- AI-powered fix generation (mocked)
- Batch processing
- Export formats (markdown, JSON)
- Language detection
- CWE reference mapping
- Error handling
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import sys

# Add scripts to path
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from remediation_engine import RemediationEngine, RemediationSuggestion


class TestRemediationSuggestion(unittest.TestCase):
    """Test RemediationSuggestion dataclass"""

    def test_create_suggestion(self):
        """Test creating a remediation suggestion"""
        suggestion = RemediationSuggestion(
            finding_id="test-001",
            vulnerability_type="sql_injection",
            file_path="app/db.py",
            line_number=45,
            original_code="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
            fixed_code='cursor.execute("SELECT * FROM users WHERE id=?", (uid,))',
            diff="--- before\n+++ after",
            explanation="Use parameterized queries",
            testing_recommendations=["Test with SQL injection"],
            confidence="high",
            cwe_references=["CWE-89"],
        )

        self.assertEqual(suggestion.finding_id, "test-001")
        self.assertEqual(suggestion.vulnerability_type, "sql_injection")
        self.assertEqual(suggestion.confidence, "high")
        self.assertIn("CWE-89", suggestion.cwe_references)

    def test_to_dict(self):
        """Test converting suggestion to dictionary"""
        suggestion = RemediationSuggestion(
            finding_id="test-001",
            vulnerability_type="xss",
            file_path="app.js",
            line_number=10,
            original_code="innerHTML = input",
            fixed_code="textContent = input",
            diff="diff",
            explanation="Escape output",
            testing_recommendations=["Test XSS"],
            confidence="medium",
            cwe_references=["CWE-79"],
        )

        data = suggestion.to_dict()
        self.assertIsInstance(data, dict)
        self.assertEqual(data["finding_id"], "test-001")
        self.assertEqual(data["vulnerability_type"], "xss")

    def test_from_dict(self):
        """Test creating suggestion from dictionary"""
        data = {
            "finding_id": "test-001",
            "vulnerability_type": "sql_injection",
            "file_path": "db.py",
            "line_number": 45,
            "original_code": "code",
            "fixed_code": "fixed",
            "diff": "diff",
            "explanation": "explanation",
            "testing_recommendations": ["test"],
            "confidence": "high",
            "cwe_references": ["CWE-89"],
            "metadata": None,
        }

        suggestion = RemediationSuggestion.from_dict(data)
        self.assertEqual(suggestion.finding_id, "test-001")
        self.assertEqual(suggestion.vulnerability_type, "sql_injection")


class TestRemediationEngine(unittest.TestCase):
    """Test RemediationEngine class"""

    def setUp(self):
        """Set up test fixtures"""
        # Create engine without LLM (template-only mode)
        self.engine = RemediationEngine(llm_manager=None)

    def test_detect_language_python(self):
        """Test language detection for Python files"""
        lang = self.engine._detect_language("app/database.py")
        self.assertEqual(lang, "python")

    def test_detect_language_javascript(self):
        """Test language detection for JavaScript files"""
        lang = self.engine._detect_language("app/main.js")
        self.assertEqual(lang, "javascript")

    def test_detect_language_typescript(self):
        """Test language detection for TypeScript files"""
        lang = self.engine._detect_language("app/component.tsx")
        self.assertEqual(lang, "typescript")

    def test_detect_language_go(self):
        """Test language detection for Go files"""
        lang = self.engine._detect_language("main.go")
        self.assertEqual(lang, "go")

    def test_detect_language_unknown(self):
        """Test language detection for unknown extensions"""
        lang = self.engine._detect_language("file.xyz")
        self.assertEqual(lang, "text")

    def test_get_cwe_references_sql_injection(self):
        """Test CWE reference mapping for SQL injection"""
        cwe = self.engine._get_cwe_references("sql_injection")
        self.assertIn("CWE-89", cwe)

    def test_get_cwe_references_xss(self):
        """Test CWE reference mapping for XSS"""
        cwe = self.engine._get_cwe_references("xss")
        self.assertIn("CWE-79", cwe)

    def test_get_cwe_references_command_injection(self):
        """Test CWE reference mapping for command injection"""
        cwe = self.engine._get_cwe_references("command_injection")
        self.assertIn("CWE-78", cwe)

    def test_get_cwe_references_unknown(self):
        """Test CWE reference for unknown vulnerability"""
        cwe = self.engine._get_cwe_references("unknown_vuln")
        self.assertIn("CWE-Unknown", cwe)

    def test_template_generate_fix_sql_injection(self):
        """Test template-based fix for SQL injection"""
        finding = {
            "id": "sql-001",
            "type": "sql_injection",
            "path": "app/db.py",
            "line": 45,
            "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
        }

        suggestion = self.engine._template_generate_fix(finding)

        self.assertEqual(suggestion.vulnerability_type, "sql_injection")
        self.assertEqual(suggestion.file_path, "app/db.py")
        self.assertEqual(suggestion.confidence, "medium")
        self.assertIn("CWE-89", suggestion.cwe_references)
        self.assertIn("parameterized", suggestion.explanation.lower())

    def test_template_generate_fix_xss(self):
        """Test template-based fix for XSS"""
        finding = {
            "id": "xss-001",
            "type": "xss",
            "path": "app/view.js",
            "line": 78,
            "code_snippet": "element.innerHTML = userInput;",
        }

        suggestion = self.engine._template_generate_fix(finding)

        self.assertEqual(suggestion.vulnerability_type, "xss")
        self.assertIn("CWE-79", suggestion.cwe_references)
        self.assertIn("escape", suggestion.explanation.lower())

    def test_template_generate_fix_command_injection(self):
        """Test template-based fix for command injection"""
        finding = {
            "id": "cmd-001",
            "type": "command_injection",
            "path": "utils/system.py",
            "line": 23,
            "code_snippet": "subprocess.run(f'ls {path}', shell=True)",
        }

        suggestion = self.engine._template_generate_fix(finding)

        self.assertEqual(suggestion.vulnerability_type, "command_injection")
        self.assertIn("CWE-78", suggestion.cwe_references)
        self.assertIn("shell", suggestion.explanation.lower())

    def test_template_generate_fix_path_traversal(self):
        """Test template-based fix for path traversal"""
        finding = {
            "id": "path-001",
            "type": "path_traversal",
            "path": "handlers/file.py",
            "line": 56,
            "code_snippet": "open(base + '/' + filename)",
        }

        suggestion = self.engine._template_generate_fix(finding)

        self.assertEqual(suggestion.vulnerability_type, "path_traversal")
        self.assertIn("CWE-22", suggestion.cwe_references)

    def test_template_generate_fix_hard_coded_secrets(self):
        """Test template-based fix for hard-coded secrets"""
        finding = {
            "id": "secret-001",
            "type": "hard_coded_secrets",
            "path": "config/settings.py",
            "line": 12,
            "code_snippet": 'API_KEY = "sk_live_secret123"',
        }

        suggestion = self.engine._template_generate_fix(finding)

        self.assertEqual(suggestion.vulnerability_type, "hard_coded_secrets")
        self.assertIn("CWE-798", suggestion.cwe_references)
        self.assertIn("environment", suggestion.explanation.lower())

    def test_template_generate_fix_unknown_type(self):
        """Test template fallback for unknown vulnerability type"""
        finding = {
            "id": "unknown-001",
            "type": "unknown_vulnerability",
            "path": "app.py",
            "line": 10,
            "code_snippet": "some code",
        }

        suggestion = self.engine._template_generate_fix(finding)

        self.assertEqual(suggestion.vulnerability_type, "unknown_vulnerability")
        self.assertEqual(suggestion.confidence, "low")
        self.assertIn("TODO", suggestion.fixed_code)

    def test_suggest_fix_uses_template(self):
        """Test suggest_fix uses template when no LLM"""
        finding = {
            "id": "test-001",
            "type": "sql_injection",
            "path": "db.py",
            "line": 10,
            "code_snippet": "code",
        }

        suggestion = self.engine.suggest_fix(finding)

        self.assertIsInstance(suggestion, RemediationSuggestion)
        self.assertEqual(suggestion.vulnerability_type, "sql_injection")

    def test_generate_batch_fixes(self):
        """Test batch processing of multiple findings"""
        findings = [
            {
                "id": "sql-001",
                "type": "sql_injection",
                "path": "db.py",
                "line": 10,
                "code_snippet": "code1",
            },
            {
                "id": "xss-001",
                "type": "xss",
                "path": "view.js",
                "line": 20,
                "code_snippet": "code2",
            },
            {
                "id": "cmd-001",
                "type": "command_injection",
                "path": "sys.py",
                "line": 30,
                "code_snippet": "code3",
            },
        ]

        suggestions = self.engine.generate_batch_fixes(findings)

        self.assertEqual(len(suggestions), 3)
        self.assertIsInstance(suggestions[0], RemediationSuggestion)
        self.assertIsInstance(suggestions[1], RemediationSuggestion)
        self.assertIsInstance(suggestions[2], RemediationSuggestion)

    def test_generate_batch_fixes_with_limit(self):
        """Test batch processing with max_findings limit"""
        findings = [{"id": f"test-{i}", "type": "xss", "path": "a.py", "line": i, "code_snippet": "code"} for i in range(10)]

        suggestions = self.engine.generate_batch_fixes(findings, max_findings=5)

        self.assertEqual(len(suggestions), 5)

    def test_export_as_markdown(self):
        """Test exporting suggestions as markdown"""
        suggestions = [
            RemediationSuggestion(
                finding_id="test-001",
                vulnerability_type="sql_injection",
                file_path="db.py",
                line_number=45,
                original_code="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
                fixed_code='cursor.execute("SELECT * FROM users WHERE id=?", (uid,))',
                diff="--- a/db.py\n+++ b/db.py\n@@ -1 +1 @@\n-old\n+new",
                explanation="Use parameterized queries",
                testing_recommendations=["Test with SQL injection"],
                confidence="high",
                cwe_references=["CWE-89"],
            )
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            output_file = f.name

        try:
            self.engine.export_as_markdown(suggestions, output_file)

            # Verify file was created and contains expected content
            with open(output_file) as f:
                content = f.read()

            self.assertIn("Security Remediation Recommendations", content)
            self.assertIn("sql_injection", content)
            self.assertIn("CWE-89", content)
            self.assertIn("Use parameterized queries", content)
            self.assertIn("```diff", content)
        finally:
            Path(output_file).unlink(missing_ok=True)

    def test_export_as_json(self):
        """Test exporting suggestions as JSON"""
        suggestions = [
            RemediationSuggestion(
                finding_id="test-001",
                vulnerability_type="xss",
                file_path="view.js",
                line_number=78,
                original_code="innerHTML = input",
                fixed_code="textContent = input",
                diff="diff",
                explanation="Escape output",
                testing_recommendations=["Test XSS"],
                confidence="medium",
                cwe_references=["CWE-79"],
            )
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = f.name

        try:
            self.engine.export_as_json(suggestions, output_file)

            # Verify file was created and contains valid JSON
            with open(output_file) as f:
                data = json.load(f)

            self.assertIn("generated_at", data)
            self.assertEqual(data["total_suggestions"], 1)
            self.assertEqual(len(data["suggestions"]), 1)
            self.assertEqual(data["suggestions"][0]["finding_id"], "test-001")
            self.assertEqual(data["suggestions"][0]["vulnerability_type"], "xss")
        finally:
            Path(output_file).unlink(missing_ok=True)

    def test_unified_diff_generation(self):
        """Test that unified diffs are properly generated"""
        finding = {
            "id": "test-001",
            "type": "sql_injection",
            "path": "db.py",
            "line": 10,
            "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
        }

        suggestion = self.engine.suggest_fix(finding)

        # Check diff format
        self.assertIn("---", suggestion.diff)
        self.assertIn("+++", suggestion.diff)
        self.assertIn("-", suggestion.diff)
        self.assertIn("+", suggestion.diff)

    def test_finding_with_evidence_dict(self):
        """Test handling finding with evidence dict instead of code_snippet"""
        finding = {
            "id": "test-001",
            "type": "xss",
            "path": "view.js",
            "line": 10,
            "evidence": {"snippet": "element.innerHTML = input;"},
        }

        suggestion = self.engine.suggest_fix(finding)

        self.assertEqual(suggestion.original_code, "element.innerHTML = input;")

    def test_finding_with_rule_id(self):
        """Test handling finding with rule_id instead of type"""
        finding = {
            "id": "test-001",
            "rule_id": "sql_injection",
            "path": "db.py",
            "line": 10,
            "code_snippet": "code",
        }

        suggestion = self.engine.suggest_fix(finding)

        self.assertEqual(suggestion.vulnerability_type, "sql_injection")

    def test_ai_generate_fix_with_mock_llm(self):
        """Test AI-powered fix generation with mocked LLM"""
        # Create mock LLM
        mock_llm = MagicMock()
        mock_llm.provider = "anthropic"
        mock_llm.model = "claude-sonnet-4-5"
        mock_llm.call_llm_api.return_value = (
            json.dumps(
                {
                    "fixed_code": 'cursor.execute("SELECT * FROM users WHERE id=?", (uid,))',
                    "explanation": "Use parameterized queries to prevent SQL injection",
                    "testing_recommendations": ["Test with malicious SQL", "Test with normal input"],
                    "confidence": "high",
                }
            ),
            100,
            50,
        )

        # Create engine with mocked LLM
        engine = RemediationEngine(llm_manager=mock_llm)

        finding = {
            "id": "test-001",
            "type": "sql_injection",
            "path": "db.py",
            "line": 10,
            "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
        }

        suggestion = engine._ai_generate_fix(finding)

        # Verify AI was called
        mock_llm.call_llm_api.assert_called_once()

        # Verify suggestion
        self.assertEqual(suggestion.confidence, "high")
        self.assertIn("parameterized", suggestion.explanation.lower())
        self.assertEqual(suggestion.metadata["generator"], "ai")
        self.assertEqual(suggestion.metadata["model"], "claude-sonnet-4-5")

    def test_ai_fallback_to_template(self):
        """Test fallback to template when AI fails"""
        # Create mock LLM that raises exception
        mock_llm = MagicMock()
        mock_llm.call_llm_api.side_effect = Exception("API error")

        # Create engine with mocked LLM
        engine = RemediationEngine(llm_manager=mock_llm)

        finding = {
            "id": "test-001",
            "type": "sql_injection",
            "path": "db.py",
            "line": 10,
            "code_snippet": "code",
        }

        # Should fall back to template
        suggestion = engine.suggest_fix(finding)

        self.assertIsInstance(suggestion, RemediationSuggestion)
        self.assertEqual(suggestion.metadata["generator"], "template")


class TestTemplateContent(unittest.TestCase):
    """Test template content quality"""

    def setUp(self):
        """Set up test fixtures"""
        self.engine = RemediationEngine(llm_manager=None)

    def test_all_templates_have_required_fields(self):
        """Test that all templates have required fields"""
        required_fields = ["pattern", "template", "example", "testing"]

        for vuln_type, template in self.engine.FIX_TEMPLATES.items():
            with self.subTest(vuln_type=vuln_type):
                for field in required_fields:
                    self.assertIn(field, template, f"{vuln_type} missing {field}")

    def test_all_templates_have_examples(self):
        """Test that all templates have code examples"""
        for vuln_type, template in self.engine.FIX_TEMPLATES.items():
            with self.subTest(vuln_type=vuln_type):
                self.assertIsInstance(template["example"], dict)
                self.assertGreater(len(template["example"]), 0, f"{vuln_type} has no examples")

                # Check each example has before/after
                for lang, example in template["example"].items():
                    self.assertIn("before", example, f"{vuln_type}/{lang} missing 'before'")
                    self.assertIn("after", example, f"{vuln_type}/{lang} missing 'after'")

    def test_all_templates_have_testing_recommendations(self):
        """Test that all templates have testing recommendations"""
        for vuln_type, template in self.engine.FIX_TEMPLATES.items():
            with self.subTest(vuln_type=vuln_type):
                testing = template["testing"]
                self.assertIsInstance(testing, list)
                self.assertGreater(len(testing), 0, f"{vuln_type} has no testing recommendations")

    def test_cwe_mapping_covers_all_templates(self):
        """Test that CWE mapping exists for all template types"""
        for vuln_type in self.engine.FIX_TEMPLATES.keys():
            with self.subTest(vuln_type=vuln_type):
                cwe = self.engine._get_cwe_references(vuln_type)
                self.assertIsInstance(cwe, list)
                self.assertGreater(len(cwe), 0, f"{vuln_type} has no CWE references")
                self.assertNotIn("CWE-Unknown", cwe, f"{vuln_type} has unknown CWE")


if __name__ == "__main__":
    unittest.main()
