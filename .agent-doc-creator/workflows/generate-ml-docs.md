# Generate ML Documentation Workflow

This workflow creates ML/AI model documentation including model cards and datasets.

## Prerequisites

- Repository scan completed with ML components detected
- Write permissions to `docs/ml/` directory

## Conditional Execution

**Only run if**: `ml_components.present: true` in scan results

## Workflow Steps

### 1. Verify ML Components

Check scan results for:
- ML framework imports
- Model files
- Training scripts
- Jupyter notebooks
- MLOps tools

**If no ML detected**: Skip this workflow

### 2. Identify Models

Find model files:
- `*.h5`, `*.pt`, `*.pkl`, `*.onnx`, `*.pb`
- Model directories
- Model registry references

Extract model metadata:
- Model name
- Framework (PyTorch, TensorFlow, etc.)
- Model type (classification, regression, etc.)
- Version

### 3. Analyze Training Code

Find and analyze:
- Training scripts
- Training configuration
- Hyperparameters
- Training data references

### 4. Identify Datasets

Look for:
- Dataset files
- Data loading code
- Dataset documentation
- Data preprocessing scripts

### 5. Generate ML Overview

Create `docs/ml/overview.md`:
- Purpose of ML in project
- ML components list
- ML stack (frameworks, tools)
- ML pipeline diagram
- Models in production
- Links to detailed docs

### 6. Generate Model Cards

For each model, create `docs/ml/models/{model-name}.md`:
- Model details (name, version, type, architecture)
- Training data description
- Training procedure
- Evaluation metrics
- Deployment info
- Monitoring setup
- Ethical considerations
- Limitations
- Maintenance schedule
- Changelog

### 7. Generate Dataset Documentation

Create `docs/ml/datasets.md`:
- Dataset overview
- For each dataset:
  - Purpose
  - Source
  - Format and location
  - Schema
  - Statistics
  - Data quality
  - Access instructions
  - Privacy/compliance info

### 8. Generate Evaluation Documentation

Create `docs/ml/evaluation.md`:
- Evaluation procedures
- Metrics used
- Benchmark results
- Evaluation datasets
- Continuous evaluation setup

### 9. Document ML Pipeline

If MLOps tools detected:
- Experiment tracking setup
- Model registry usage
- Deployment process
- Monitoring and retraining

### 10. Update Sidebars

Add ML docs to `sidebars.js`:
```javascript
{
  type: 'category',
  label: 'ML & Models',
  items: [
    'ml/overview',
    {
      type: 'category',
      label: 'Models',
      items: [
        'ml/models/recommendation-model',
        'ml/models/classification-model',
      ],
    },
    'ml/datasets',
    'ml/evaluation',
  ],
}
```

### 11. Validate ML Docs

- Check for hallucinated metrics
- Verify model file references
- Ensure dataset paths are correct
- Validate technical details

## Output Files

- `docs/ml/overview.md` - ML system overview
- `docs/ml/models/{model}.md` - Model cards
- `docs/ml/datasets.md` - Dataset documentation
- `docs/ml/evaluation.md` - Evaluation procedures
- Updated `sidebars.js`

## Quality Guidelines

- **Be accurate**: Only document what's verifiable
- **Be specific**: Include actual metrics, not placeholders
- **Be complete**: Follow model card format
- **Be honest**: Document limitations and biases

## Avoiding Hallucination

- Only document models with file evidence
- Don't invent metrics - mark as TODO
- Don't guess architectures - describe what's in code
- Link to actual training scripts
- Flag uncertainty clearly

## Error Handling

- **Model files not found**: Create placeholder with TODO
- **Training code missing**: Document what's available
- **Metrics unknown**: Mark for human input

## Next Steps

After successful generation:
1. Review with ML team
2. Validate metrics and performance claims
3. Proceed to generate reference docs

