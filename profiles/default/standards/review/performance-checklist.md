# Performance Review Checklist

## Database Performance

### [BLOCKER] Query Optimization
- [ ] No N+1 query patterns detected
- [ ] Database indexes created for frequently queried columns
- [ ] Query execution plans analyzed
- [ ] No SELECT * queries on large tables

### [BLOCKER] Connection Management
- [ ] Database connection pooling implemented
- [ ] Connections properly closed after use
- [ ] Connection timeout configured
- [ ] No connection leaks detected

### [SUGGESTION] Advanced Database Optimization
- [ ] Query caching implemented
- [ ] Database query optimization
- [ ] Read replicas used for read-heavy operations
- [ ] Database partitioning for large tables

## Memory Management

### [BLOCKER] Memory Leak Prevention
- [ ] No unbounded collections or arrays
- [ ] Resources properly disposed (connections, files, streams)
- [ ] Memory usage monitored
- [ ] No memory leaks in long-running processes

### [BLOCKER] Large Object Handling
- [ ] Large files processed with streaming
- [ ] Large datasets processed in chunks
- [ ] Memory usage optimized for large operations
- [ ] No large objects kept in memory unnecessarily

### [SUGGESTION] Advanced Memory Management
- [ ] Memory profiling implemented
- [ ] Garbage collection optimization
- [ ] Memory usage monitoring and alerting
- [ ] Memory-efficient data structures used

## Algorithm Efficiency

### [BLOCKER] Time Complexity
- [ ] No O(n²) algorithms in critical paths
- [ ] Efficient sorting and searching algorithms
- [ ] No redundant calculations
- [ ] Algorithm complexity analyzed

### [SUGGESTION] Advanced Algorithm Optimization
- [ ] Caching implemented for expensive operations
- [ ] Lazy loading for large datasets
- [ ] Parallel processing where appropriate
- [ ] Algorithm optimization for hot paths

## I/O Performance

### [BLOCKER] File Operations
- [ ] Large files processed with streaming
- [ ] File operations optimized
- [ ] No synchronous I/O in critical paths
- [ ] Proper file handling and cleanup

### [BLOCKER] Network Operations
- [ ] Network timeouts configured
- [ ] Connection pooling for external services
- [ ] Retry logic with exponential backoff
- [ ] No blocking network calls in main thread

### [SUGGESTION] Advanced I/O Optimization
- [ ] Asynchronous I/O operations
- [ ] Batch processing for network operations
- [ ] CDN usage for static assets
- [ ] Compression for network requests

## Resource Management

### [BLOCKER] Resource Cleanup
- [ ] All resources properly closed
- [ ] Try-finally blocks for resource cleanup
- [ ] Using statements for automatic cleanup
- [ ] No resource leaks detected

### [BLOCKER] Connection Management
- [ ] HTTP connection pooling
- [ ] Database connection pooling
- [ ] Redis connection pooling
- [ ] Proper connection lifecycle management

### [SUGGESTION] Advanced Resource Management
- [ ] Resource monitoring and alerting
- [ ] Automatic resource scaling
- [ ] Resource usage optimization
- [ ] Resource allocation strategies

## Caching Strategy

### [SUGGESTION] Application Caching
- [ ] In-memory caching implemented
- [ ] Cache invalidation strategy
- [ ] Cache hit ratio monitoring
- [ ] Distributed caching for scalability

### [SUGGESTION] Database Caching
- [ ] Query result caching
- [ ] Database connection caching
- [ ] Cache warming strategies
- [ ] Cache consistency management

### [SUGGESTION] CDN and Static Asset Caching
- [ ] CDN implementation for static assets
- [ ] Cache headers properly configured
- [ ] Asset versioning for cache busting
- [ ] Image optimization and compression

## Concurrency and Parallelism

### [SUGGESTION] Concurrent Processing
- [ ] Async/await patterns used appropriately
- [ ] Parallel processing where beneficial
- [ ] Thread safety considerations
- [ ] Concurrent access patterns handled

### [SUGGESTION] Background Processing
- [ ] Background jobs for heavy operations
- [ ] Queue systems for task processing
- [ ] Worker processes for CPU-intensive tasks
- [ ] Job scheduling and management

## Performance Monitoring

### [SUGGESTION] Performance Metrics
- [ ] Response time monitoring
- [ ] Throughput monitoring
- [ ] Resource usage monitoring
- [ ] Performance regression detection

### [SUGGESTION] Performance Testing
- [ ] Load testing implemented
- [ ] Stress testing performed
- [ ] Performance benchmarks established
- [ ] Performance regression testing

## Scalability Considerations

### [SUGGESTION] Horizontal Scaling
- [ ] Stateless application design
- [ ] Database scaling strategies
- [ ] Load balancing implementation
- [ ] Microservices architecture considerations

### [SUGGESTION] Vertical Scaling
- [ ] Resource usage optimization
- [ ] Memory usage optimization
- [ ] CPU usage optimization
- [ ] I/O optimization

## Performance Anti-Patterns

### [BLOCKER] Performance Anti-Patterns to Avoid
- [ ] No N+1 query patterns
- [ ] No unbounded loops
- [ ] No synchronous operations in async contexts
- [ ] No blocking operations in main thread

### [BLOCKER] Resource Anti-Patterns to Avoid
- [ ] No resource leaks
- [ ] No connection leaks
- [ ] No memory leaks
- [ ] No file handle leaks

## Performance Optimization Techniques

### [SUGGESTION] Code Optimization
- [ ] Algorithm optimization
- [ ] Data structure optimization
- [ ] Loop optimization
- [ ] Function optimization

### [SUGGESTION] System Optimization
- [ ] Database optimization
- [ ] Network optimization
- [ ] Storage optimization
- [ ] CPU optimization

## Performance Standards

### [BLOCKER] Performance Requirements
- [ ] Response time under 200ms for API calls
- [ ] Database queries under 100ms
- [ ] Memory usage within limits
- [ ] CPU usage within limits

### [SUGGESTION] Performance Goals
- [ ] 99.9% uptime target
- [ ] Sub-second response times
- [ ] Efficient resource utilization
- [ ] Scalable architecture design
