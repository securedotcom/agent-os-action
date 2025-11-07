# Documentation Style Guide

This guide defines the writing style and conventions for all generated documentation.

## Writing Principles

### 1. Clarity First
- Use simple, direct language
- Avoid jargon unless necessary
- Define technical terms on first use
- Write for future readers who may be unfamiliar with the system

### 2. Be Concise
- Get to the point quickly
- Remove unnecessary words
- Use bullet points for lists
- Break long paragraphs into shorter ones

### 3. Be Specific
- Use concrete examples
- Include actual values, not placeholders
- Reference specific files and line numbers
- Provide copy-paste commands

### 4. Be Honest
- Acknowledge limitations
- Mark uncertainty clearly
- Don't hide problems
- Use TODO for missing information

## Voice and Tone

### Active Voice
✅ **Good**: "The service processes requests"
❌ **Bad**: "Requests are processed by the service"

### Present Tense
✅ **Good**: "The API returns a JSON response"
❌ **Bad**: "The API will return a JSON response"

### Second Person
✅ **Good**: "You can deploy using this command"
❌ **Bad**: "One can deploy using this command"

## Structure

### Page Structure
1. **Title** (H1) - One per page
2. **Overview** - Brief introduction
3. **Sections** (H2) - Main content
4. **Subsections** (H3) - Details
5. **Related Links** - At the end

### Section Order
1. What (description)
2. Why (purpose/context)
3. How (implementation/usage)
4. Examples
5. Troubleshooting (if applicable)

## Headings

### Heading Hierarchy
- Use only one H1 per page (the title)
- Don't skip levels (H2 → H4)
- Keep headings short and descriptive
- Use sentence case, not title case

✅ **Good**:
```markdown
# Component Documentation
## Overview
### Key features
```

❌ **Bad**:
```markdown
# Component Documentation
### Key Features  (skipped H2)
```

### Heading Style
- Sentence case: "How to deploy"
- Not title case: "How To Deploy"
- Descriptive: "Deployment procedure"
- Not vague: "Procedure"

## Lists

### Bulleted Lists
Use for unordered items:
```markdown
- Item one
- Item two
- Item three
```

### Numbered Lists
Use for sequential steps:
```markdown
1. First step
2. Second step
3. Third step
```

### Nested Lists
Indent with 2 spaces:
```markdown
- Parent item
  - Child item
  - Another child
- Another parent
```

## Code

### Inline Code
Use backticks for:
- Variable names: `user_id`
- Function names: `getUserById()`
- File names: `config.yml`
- Commands: `npm install`
- Values: `true`, `null`

### Code Blocks
Always specify language:
````markdown
```typescript
function example() {
  return true;
}
```
````

### Command Examples
Show command and expected output:
````markdown
```bash
# Check service status
kubectl get pods

# Expected output
NAME                     READY   STATUS    RESTARTS   AGE
api-service-abc123-xyz   1/1     Running   0          5m
```
````

### Multi-line Commands
Use backslash for continuation:
```bash
docker run \
  -e DB_HOST=localhost \
  -e DB_PORT=5432 \
  myapp
```

## Links

### Internal Links
Use relative paths:
```markdown
[Architecture Docs](../architecture/overview.md)
[API Service](./api-service.md)
```

### External Links
Include full URL:
```markdown
[Docusaurus](https://docusaurus.io/)
```

### Link Text
Use descriptive text:
✅ **Good**: `[deployment guide](../playbooks/deployment.md)`
❌ **Bad**: `[click here](../playbooks/deployment.md)`

## Tables

### Format
Use pipes and hyphens:
```markdown
| Column 1 | Column 2 | Column 3 |
|----------|----------|----------|
| Value 1  | Value 2  | Value 3  |
| Value 4  | Value 5  | Value 6  |
```

### Alignment
- Left align text columns
- Right align number columns
- Center align status/icons

```markdown
| Name     | Count | Status |
|----------|------:|:------:|
| Item 1   |   100 |   ✅   |
| Item 2   |    50 |   ❌   |
```

## Admonitions

### Types
Use for important information:

```markdown
> ⚠️ **Warning**
> This operation cannot be undone.

> ℹ️ **Note**
> This feature requires Node.js 18+.

> ✅ **Tip**
> Use the --dry-run flag to test first.
```

## Examples

### Include Examples
Every concept should have an example:
- Code examples
- Command examples
- Configuration examples
- Use case examples

### Example Format
```markdown
## Configuration

The service uses environment variables for configuration.

**Example**:
```bash
DB_HOST=localhost
DB_PORT=5432
DB_NAME=myapp
```
```

## Formatting

### Emphasis
- **Bold** for important terms
- *Italic* for emphasis (use sparingly)
- `Code` for technical terms

### Line Length
- Aim for 80-100 characters per line
- Break long lines at natural points
- Use line breaks in markdown (they don't affect rendering)

### Spacing
- One blank line between sections
- No blank line between heading and content
- One blank line before and after code blocks
- One blank line before and after lists

## Special Elements

### TODO Markers
Mark incomplete sections:
```markdown
## Performance Metrics

**TODO**: Add actual performance metrics after load testing.
```

### Placeholders
Use clear placeholders:
```markdown
Replace `YOUR_API_KEY` with your actual API key.
```

### Dates
Use ISO format: `2024-11-07`

### Versions
Use semantic versioning: `v1.2.3`

## Accessibility

### Alt Text
Always provide alt text for images:
```markdown
![System architecture diagram showing three services](./architecture-diagram.png)
```

### Link Text
Make links self-descriptive:
✅ **Good**: "See the [deployment guide](link)"
❌ **Bad**: "Click [here](link)"

### Heading Structure
Maintain proper heading hierarchy for screen readers

## AI-Generated Content

### Disclaimer
Always include at the top:
```markdown
> ⚠️ **AI-Generated Documentation**
> This page was generated or updated by an AI agent.
> Please review and approve before treating it as canonical documentation.
```

### Uncertainty
Mark uncertain information:
```markdown
The service **appears to use** PostgreSQL based on the presence of `pg` library.

**TODO**: Verify database choice and reasoning.
```

### Evidence
Link to evidence:
```markdown
Based on the configuration in `config/database.yml` (lines 10-15), the service connects to PostgreSQL.
```

## Common Mistakes to Avoid

❌ **Don't**:
- Use "we" or "I" (use "you" or passive voice)
- Write long paragraphs (break into smaller chunks)
- Use vague language ("some", "various", "etc.")
- Skip code block language specifications
- Use relative dates ("yesterday", "last week")
- Expose secrets or credentials
- Make assumptions without evidence

✅ **Do**:
- Write clear, actionable content
- Include specific examples
- Link to related documentation
- Mark AI-generated content
- Acknowledge limitations
- Use consistent terminology

## Review Checklist

Before finalizing documentation:
- [ ] One H1 heading per page
- [ ] All code blocks have language specified
- [ ] All links work
- [ ] All images have alt text
- [ ] No secrets exposed
- [ ] AI disclaimer present (if AI-generated)
- [ ] Examples are specific and accurate
- [ ] Spelling and grammar checked
- [ ] Consistent terminology used

