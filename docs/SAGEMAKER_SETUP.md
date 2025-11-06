# 🚀 SageMaker Foundation-Sec Setup Guide

This guide shows how to deploy Foundation-Sec-8B on AWS SageMaker for fast, scalable AI enrichment.

---

## 📋 Prerequisites

- AWS Account with SageMaker access
- AWS CLI configured
- Python 3.9+
- boto3 installed (`pip install boto3`)

---

## 🎯 Option 1: Use Existing Endpoint (Recommended)

If you already have a Foundation-Sec-8B endpoint running:

```bash
# Set environment variables
export SAGEMAKER_ENDPOINT='your-endpoint-name'
export AWS_ACCESS_KEY_ID='your-access-key'
export AWS_SECRET_ACCESS_KEY='your-secret-key'
export AWS_REGION='us-east-1'

# Run hybrid analyzer
python scripts/hybrid_analyzer.py . \
  --enable-semgrep \
  --enable-trivy \
  --enable-foundation-sec \
  --severity-filter critical,high,medium
```

---

## 🛠️ Option 2: Deploy New Endpoint

### Step 1: Deploy Foundation-Sec-8B to SageMaker

```bash
# Using HuggingFace Inference Container
aws sagemaker create-model \
  --model-name foundation-sec-8b \
  --primary-container Image=763104351884.dkr.ecr.us-east-1.amazonaws.com/huggingface-pytorch-tgi-inference:2.0.1-tgi1.1.0-gpu-py39-cu118-ubuntu20.04,\
ModelDataUrl=s3://your-bucket/foundation-sec-8b/,\
Environment='{"HF_MODEL_ID":"fdtn-ai/Foundation-Sec-8B"}' \
  --execution-role-arn arn:aws:iam::YOUR_ACCOUNT:role/SageMakerRole

# Create endpoint configuration
aws sagemaker create-endpoint-config \
  --endpoint-config-name foundation-sec-8b-config \
  --production-variants VariantName=AllTraffic,ModelName=foundation-sec-8b,\
InstanceType=ml.g5.xlarge,InitialInstanceCount=1

# Deploy endpoint
aws sagemaker create-endpoint \
  --endpoint-name foundation-sec-8b-endpoint \
  --endpoint-config-name foundation-sec-8b-config
```

### Step 2: Wait for Deployment (~10 minutes)

```bash
aws sagemaker describe-endpoint \
  --endpoint-name foundation-sec-8b-endpoint \
  --query 'EndpointStatus'
```

### Step 3: Test Endpoint

```python
import boto3
import json

runtime = boto3.client('sagemaker-runtime', region_name='us-east-1')

payload = {
    "inputs": "Analyze this vulnerability: SQL injection in login form",
    "parameters": {"max_new_tokens": 200, "temperature": 0.3}
}

response = runtime.invoke_endpoint(
    EndpointName='foundation-sec-8b-endpoint',
    ContentType='application/json',
    Body=json.dumps(payload)
)

result = json.loads(response['Body'].read())
print(result)
```

---

## 💰 Cost Optimization

| Instance Type | vCPU | Memory | GPU | Cost/Hour | Use Case |
|---------------|------|--------|-----|-----------|----------|
| ml.g5.xlarge | 4 | 16GB | 1x A10G | ~$1.41 | Development |
| ml.g5.2xlarge | 8 | 32GB | 1x A10G | ~$2.03 | Production |
| ml.inf2.xlarge | 4 | 16GB | Inferentia2 | ~$0.76 | Cost-optimized |

**Tips:**
- Use **Inference2** instances for lowest cost ($0.76/hour)
- Enable **auto-scaling** based on traffic
- Use **provisioned concurrency** for consistent performance
- Delete endpoint when not in use (save ~$1,000/month)

---

## 🔒 Security Best Practices

### 1. IAM Role Setup

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sagemaker:InvokeEndpoint"
      ],
      "Resource": "arn:aws:sagemaker:*:*:endpoint/foundation-sec-8b-*"
    }
  ]
}
```

### 2. VPC Configuration

Deploy SageMaker endpoint in private VPC:

```bash
aws sagemaker create-endpoint-config \
  --endpoint-config-name foundation-sec-8b-vpc \
  --production-variants ... \
  --vpc-config SecurityGroupIds=sg-xxx,Subnets=subnet-xxx
```

### 3. Encryption at Rest

```bash
aws sagemaker create-endpoint-config \
  --kms-key-id arn:aws:kms:region:account:key/key-id \
  ...
```

### 4. Access Logging

Enable CloudWatch logging:

```bash
aws sagemaker update-endpoint \
  --endpoint-name foundation-sec-8b-endpoint \
  --retain-all-variant-properties \
  --data-capture-config \
    EnableCapture=true,\
    DestinationS3Uri=s3://your-bucket/logs/
```

---

## 📊 Monitoring

### CloudWatch Metrics

Monitor these key metrics:
- `ModelLatency` - Time to generate response
- `Invocations` - Total requests
- `InvocationErrors` - Failed requests
- `ModelSetupTime` - Cold start time

### Create Alarms

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name foundation-sec-high-latency \
  --metric-name ModelLatency \
  --namespace AWS/SageMaker \
  --statistic Average \
  --period 300 \
  --threshold 5000 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2
```

---

## 🧪 Testing the Integration

```bash
# Test endpoint connectivity
python scripts/providers/sagemaker_foundation_sec.py

# Run sample scan
python scripts/hybrid_analyzer.py /path/to/repo \
  --enable-foundation-sec \
  --severity-filter critical,high
```

---

## 🐛 Troubleshooting

### Error: "Could not connect to endpoint"

**Solution:**
```bash
# Verify endpoint is InService
aws sagemaker describe-endpoint --endpoint-name foundation-sec-8b-endpoint

# Check IAM permissions
aws sts get-caller-identity
```

### Error: "Model inference timeout"

**Solution:**
- Increase `max_new_tokens` timeout in provider
- Scale up to larger instance type
- Enable auto-scaling

### Error: "Access denied"

**Solution:**
```bash
# Attach InvokeEndpoint policy to IAM user/role
aws iam attach-user-policy \
  --user-name your-user \
  --policy-arn arn:aws:iam::aws:policy/AmazonSageMakerFullAccess
```

---

## 📚 Additional Resources

- [AWS SageMaker Pricing](https://aws.amazon.com/sagemaker/pricing/)
- [HuggingFace on SageMaker](https://huggingface.co/docs/sagemaker/index)
- [Foundation-Sec Model Card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B)
- [SageMaker Best Practices](https://docs.aws.amazon.com/sagemaker/latest/dg/best-practices.html)

---

## 💡 Pro Tips

1. **Use Spot Instances** for 70% cost savings (non-critical workloads)
2. **Batch Requests** to reduce latency overhead
3. **Cache Results** to avoid duplicate AI calls
4. **Monitor Costs** with AWS Cost Explorer and set budgets

---

**Questions?** Open an issue in the Agent OS repository!


