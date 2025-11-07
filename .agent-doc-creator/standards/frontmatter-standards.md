# Frontmatter Standards

Standard frontmatter conventions for all documentation.

## Purpose

Frontmatter provides:
1. Document metadata
2. Docusaurus configuration
3. Search optimization
4. Categorization and tagging
5. Version tracking

## Basic Format

```yaml
---
title: Document Title
sidebar_position: 1
---
```

## Required Fields

### title
Document title displayed in browser and sidebar

```yaml
title: Architecture Overview
```

**Rules**:
- Required for all documents
- Use sentence case
- Be descriptive and specific
- Keep under 60 characters

## Common Optional Fields

### sidebar_position
Order in sidebar (lower numbers first)

```yaml
sidebar_position: 1
```

**Rules**:
- Use integers
- Start from 1
- Leave gaps for future insertions (1, 5, 10, 15)

### sidebar_label
Custom label in sidebar (if different from title)

```yaml
sidebar_label: Overview
```

**Use when**:
- Title is too long for sidebar
- Want shorter label
- Need different wording

### tags
Array of tags for categorization

```yaml
tags: [architecture, backend, api]
```

**Guidelines**:
- Use lowercase
- Use hyphens for multi-word tags
- Be consistent across docs
- Limit to 3-5 tags per document

### description
Meta description for SEO

```yaml
description: Comprehensive architecture documentation for the API service
```

**Rules**:
- Keep under 160 characters
- Summarize content
- Include key terms

### keywords
Array of keywords for search

```yaml
keywords: [api, rest, nodejs, express, architecture]
```

## AI-Generated Content Fields

### ai_generated
Flag indicating AI-generated content

```yaml
ai_generated: true
```

**Required when**: Content is AI-generated

### last_updated
Last update timestamp

```yaml
last_updated: 2024-11-07
```

**Format**: YYYY-MM-DD

### human_reviewed
Flag indicating human review completed

```yaml
human_reviewed: true
```

**Set when**: Human has reviewed and approved

### last_human_review
Date of last human review

```yaml
last_human_review: 2024-11-07
reviewer: john.doe@example.com
```

## Document-Type Specific Fields

### Architecture Docs

```yaml
---
title: API Service Architecture
sidebar_position: 2
ai_generated: true
component_type: backend-service
tags: [architecture, api, backend]
last_updated: 2024-11-07
---
```

**Additional fields**:
- `component_type`: backend-service | frontend-app | library | infrastructure
- `service_name`: Name of service
- `language`: Primary language

### ADRs

```yaml
---
title: ADR-0001: Use PostgreSQL as Primary Database
sidebar_position: 1
ai_generated: true
status: Accepted
date: 2024-11-07
decision_makers: [backend-team]
tags: [adr, database, postgresql]
---
```

**Additional fields**:
- `status`: Draft | Accepted | Deprecated | Superseded
- `date`: Decision date
- `decision_makers`: Array of people/teams
- `supersedes`: Link to superseded ADR
- `superseded_by`: Link to superseding ADR

### RFCs

```yaml
---
title: RFC-0001: Migrate to Kubernetes
sidebar_position: 1
ai_generated: true
status: Draft
date: 2024-11-07
authors: [ai-agent]
reviewers: []
priority: high
tags: [rfc, infrastructure, kubernetes]
---
```

**Additional fields**:
- `status`: Draft | Under Review | Accepted | Rejected | Implemented
- `authors`: Array of authors
- `reviewers`: Array of reviewers
- `priority`: critical | high | medium | low
- `target_version`: Target release version

### Runbooks

```yaml
---
title: API Service Runbook
sidebar_position: 1
ai_generated: true
service: api-service
on_call_priority: high
tags: [runbook, operations, api-service]
---
```

**Additional fields**:
- `service`: Service name
- `on_call_priority`: high | medium | low
- `last_tested`: Date procedures were last tested

### ML Documentation

```yaml
---
title: Recommendation Model Card
sidebar_position: 1
ai_generated: true
model_version: v1.2.3
model_type: classification
framework: pytorch
tags: [ml, model-card, recommendation]
---
```

**Additional fields**:
- `model_version`: Model version
- `model_type`: classification | regression | clustering | generation
- `framework`: pytorch | tensorflow | sklearn
- `last_trained`: Date model was last trained

## Advanced Fields

### Custom Sidebar

```yaml
sidebar_custom_props:
  icon: 🏗️
  badge: New
```

### Hide from Sidebar

```yaml
sidebar_class_name: hidden
```

Or:

```yaml
displayed_sidebar: none
```

### Custom Edit URL

```yaml
custom_edit_url: https://github.com/org/repo/edit/main/docs/file.md
```

### Disable Edit Button

```yaml
custom_edit_url: null
```

## Full Example

### Architecture Document

```yaml
---
title: API Service Architecture
sidebar_position: 2
sidebar_label: API Service
description: Architecture documentation for the API service including components, dependencies, and deployment
keywords: [api, rest, nodejs, express, architecture, microservices]
tags: [architecture, backend, api]
ai_generated: true
human_reviewed: false
last_updated: 2024-11-07
component_type: backend-service
service_name: api-service
language: typescript
---
```

### ADR

```yaml
---
title: ADR-0001: Use PostgreSQL as Primary Database
sidebar_position: 1
description: Decision to use PostgreSQL as the primary database for the application
tags: [adr, database, postgresql]
ai_generated: true
status: Accepted
date: 2024-11-07
decision_makers: [backend-team, architecture-team]
---
```

### RFC

```yaml
---
title: RFC-0001: Migrate to Kubernetes
sidebar_position: 1
description: Proposal to migrate from ECS to Kubernetes for container orchestration
tags: [rfc, infrastructure, kubernetes]
ai_generated: true
status: Draft
date: 2024-11-07
authors: [ai-agent]
reviewers: []
priority: high
target_version: v2.0.0
---
```

## Validation Rules

### Required Checks
- [ ] `title` is present
- [ ] `title` is a string
- [ ] `sidebar_position` is a number (if present)
- [ ] `tags` is an array (if present)
- [ ] `ai_generated` is boolean (if present)
- [ ] `status` is valid value (if present)
- [ ] `date` is valid YYYY-MM-DD (if present)

### Best Practices
- [ ] Title is descriptive
- [ ] Tags are lowercase
- [ ] Description under 160 chars
- [ ] Keywords are relevant
- [ ] AI fields present if AI-generated
- [ ] Status matches content

## Common Mistakes

### ❌ Don't

```yaml
---
Title: My Document  # Wrong case
sidebar_position: "1"  # Should be number
tags: Architecture, Backend  # Should be array
ai_generated: yes  # Should be boolean
date: 11/07/2024  # Wrong format
---
```

### ✅ Do

```yaml
---
title: My Document
sidebar_position: 1
tags: [architecture, backend]
ai_generated: true
date: 2024-11-07
---
```

## YAML Syntax

### Strings

```yaml
title: Simple Title
title: "Title with: colon"
title: 'Title with "quotes"'
```

### Numbers

```yaml
sidebar_position: 1
version: 2.0
```

### Booleans

```yaml
ai_generated: true
human_reviewed: false
```

### Arrays

```yaml
tags: [tag1, tag2, tag3]
# Or
tags:
  - tag1
  - tag2
  - tag3
```

### Objects

```yaml
sidebar_custom_props:
  icon: 🏗️
  badge: New
```

### Null

```yaml
custom_edit_url: null
```

### Multi-line Strings

```yaml
description: >
  This is a long description
  that spans multiple lines
  and will be joined into one.
```

## Troubleshooting

### Frontmatter Not Parsing
- Check YAML syntax
- Ensure three dashes before and after
- No spaces before opening `---`
- Valid YAML format

### Sidebar Not Updating
- Check `sidebar_position` is a number
- Verify file is in correct directory
- Rebuild Docusaurus

### Tags Not Working
- Ensure tags is an array
- Use lowercase
- Check for typos

## Related Standards

- [Documentation Style Guide](./doc-style.md)
- [AI Disclaimer](./ai-disclaimer.md)
- [ADR Format](./adr-format.md)
- [RFC Format](./rfc-format.md)

