# Infrastructure Performance Checklist

## Resource Optimization
- [ ] **Right-Sizing**: Appropriate instance sizes
- [ ] **Auto-Scaling**: Scaling policies configured
- [ ] **Load Balancing**: Traffic distributed efficiently
- [ ] **Resource Limits**: CPU/memory limits set
- [ ] **Cost Optimization**: Reserved instances for steady workloads

## Network Performance
- [ ] **CDN**: Static content cached at edge
- [ ] **DNS**: Low TTL for critical records
- [ ] **Connection Pooling**: Database connections pooled
- [ ] **Keep-Alive**: HTTP keep-alive enabled
- [ ] **Compression**: gzip/brotli enabled

## Storage Performance
- [ ] **IOPS Provisioning**: Appropriate IOPS for workload
- [ ] **Caching**: Redis/Memcached for hot data
- [ ] **Data Partitioning**: Large datasets partitioned
- [ ] **Backup Strategy**: Efficient backup/restore
- [ ] **Archive Policy**: Old data archived

## Monitoring & Alerts
- [ ] **Performance Metrics**: Key metrics monitored
- [ ] **Resource Utilization**: CPU/mem/disk tracked
- [ ] **Alert Thresholds**: Appropriate alerts set
- [ ] **Log Aggregation**: Centralized logging
- [ ] **Distributed Tracing**: Request tracing enabled

## Merge Blockers
- **[BLOCKER]** No resource limits on containers
- **[BLOCKER]** Missing auto-scaling configuration
- **[BLOCKER]** No monitoring/alerting setup
- **[BLOCKER]** Over-provisioned resources (>50% waste)

