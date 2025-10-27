# Data Pipeline Performance Checklist

## Data Processing
- [ ] **Batch Processing**: Large datasets processed in batches
- [ ] **Parallel Processing**: Multi-threading/multiprocessing used
- [ ] **Streaming**: Real-time data streamed efficiently
- [ ] **Memory Management**: Large datasets processed incrementally
- [ ] **Data Partitioning**: Data partitioned for parallel processing

## Database & Storage
- [ ] **Bulk Operations**: Batch inserts/updates used
- [ ] **Indexing**: Appropriate indexes on query fields
- [ ] **Connection Pooling**: Database connections pooled
- [ ] **Compression**: Data compressed for storage/transfer
- [ ] **Caching**: Frequently accessed data cached

## Error Handling & Resilience
- [ ] **Retry Logic**: Exponential backoff for failures
- [ ] **Dead Letter Queue**: Failed records queued
- [ ] **Circuit Breaker**: External service failures handled
- [ ] **Timeout Configuration**: Appropriate timeouts set
- [ ] **Idempotency**: Operations safe to retry

## Merge Blockers
- **[BLOCKER]** Full dataset loaded into memory
- **[BLOCKER]** No batch processing for large datasets
- **[BLOCKER]** Missing retry logic for critical operations
- **[BLOCKER]** No timeout on external calls

