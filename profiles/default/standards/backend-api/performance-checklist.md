# Backend API Performance Checklist

## Overview
Performance standards specific to backend API projects to ensure scalability and efficiency.

---

## Database Performance

### Critical Checks
- [ ] **N+1 Query Prevention** - Eager loading used where appropriate
- [ ] **Proper Indexing** - Database indexes on foreign keys and query fields
- [ ] **Connection Pooling** - Database connection pool configured
- [ ] **Query Optimization** - Complex queries optimized with EXPLAIN
- [ ] **Transaction Boundaries** - Minimal transaction scope

### Merge Blockers
- **[BLOCKER]** N+1 query patterns in loops
- **[BLOCKER]** Full table scans on large tables
- **[BLOCKER]** Missing indexes on frequently queried columns
- **[BLOCKER]** Long-running transactions holding locks

### Suggestions
- **[SUGGESTION]** Implement query result caching
- **[SUGGESTION]** Use read replicas for read-heavy operations
- **[SUGGESTION]** Add database query monitoring

---

## API Response Time

### Performance Targets
- Simple GET requests: < 100ms
- Complex queries: < 500ms
- Data aggregation: < 1000ms
- Batch operations: < 3000ms

### Required Checks
- [ ] **Endpoint Performance** - All endpoints meet targets
- [ ] **Lazy Loading** - Large datasets paginated
- [ ] **Response Compression** - GZIP compression enabled
- [ ] **Async Processing** - Long operations run asynchronously
- [ ] **Timeout Configuration** - Appropriate timeouts set

### Merge Blockers
- **[BLOCKER]** API endpoints taking >5 seconds
- **[BLOCKER]** Synchronous calls to slow external services
- **[BLOCKER]** No pagination on list endpoints

---

## Caching Strategy

### Required Checks
- [ ] **Response Caching** - Frequently accessed data cached
- [ ] **Cache Invalidation** - Proper cache eviction strategy
- [ ] **Cache Key Design** - Appropriate cache key granularity
- [ ] **Cache TTL** - Time-to-live configured correctly
- [ ] **Cache Warming** - Critical data pre-loaded

### Suggestions
- **[SUGGESTION]** Implement Redis/Memcached for distributed caching
- **[SUGGESTION]** Add cache hit/miss monitoring
- **[SUGGESTION]** Use ETags for HTTP caching
- **[SUGGESTION]** Implement query result caching at ORM level

---

## Resource Management

### Required Checks
- [ ] **Connection Pooling** - HTTP clients use connection pooling
- [ ] **Resource Cleanup** - Connections/streams properly closed
- [ ] **Memory Management** - No memory leaks detected
- [ ] **Thread Pool Configuration** - Appropriate thread pool sizes
- [ ] **File Handle Management** - Files closed in finally blocks

### Merge Blockers
- **[BLOCKER]** Resource leaks (connections, file handles)
- **[BLOCKER]** Memory leaks in long-running processes
- **[BLOCKER]** Unbounded thread creation

### Suggestions
- **[SUGGESTION]** Implement circuit breakers for external services
- **[SUGGESTION]** Add resource pool monitoring
- **[SUGGESTION]** Configure garbage collection tuning

---

## API Design Efficiency

### Required Checks
- [ ] **Pagination** - Large result sets paginated
- [ ] **Field Filtering** - Clients can request specific fields
- [ ] **Batch Operations** - Batch endpoints for multiple operations
- [ ] **GraphQL/REST** - Appropriate API paradigm chosen
- [ ] **Compression** - Response compression enabled

### Suggestions
- **[SUGGESTION]** Implement GraphQL for flexible queries
- **[SUGGESTION]** Add API versioning for backward compatibility
- **[SUGGESTION]** Use Protocol Buffers for internal services
- **[SUGGESTION]** Implement streaming for large datasets

---

## Concurrency & Parallelism

### Required Checks
- [ ] **Thread Safety** - Shared resources properly synchronized
- [ ] **Async Operations** - Non-blocking I/O used
- [ ] **Parallel Processing** - CPU-intensive tasks parallelized
- [ ] **Deadlock Prevention** - Lock ordering consistent
- [ ] **CompletableFuture Usage** - Async operations properly chained

### Merge Blockers
- **[BLOCKER]** Race conditions detected
- **[BLOCKER]** Deadlocks in concurrent operations
- **[BLOCKER]** Blocking I/O on request threads

### Suggestions
- **[SUGGESTION]** Use reactive programming (WebFlux)
- **[SUGGESTION]** Implement work queues for background tasks
- **[SUGGESTION]** Add virtual threads (Java 21+)

---

## Serialization & Deserialization

### Required Checks
- [ ] **Jackson Configuration** - Optimized serialization settings
- [ ] **Large Object Handling** - Streaming for large payloads
- [ ] **Date/Time Formatting** - Efficient ISO 8601 formatting
- [ ] **Lazy Initialization** - Avoid serialization of lazy collections
- [ ] **Custom Serializers** - Efficient custom converters

### Suggestions
- **[SUGGESTION]** Use @JsonView for different response formats
- **[SUGGESTION]** Implement custom serializers for complex types
- **[SUGGESTION]** Add response size monitoring

---

## Spring Boot Performance

### Required Checks
- [ ] **Actuator Endpoints** - Performance metrics exposed
- [ ] **Lazy Initialization** - Beans lazy-loaded where appropriate
- [ ] **Component Scanning** - Scan scope limited
- [ ] **Auto-configuration** - Unnecessary auto-configs excluded
- [ ] **Embedded Server Tuning** - Tomcat/Jetty optimized

### Configuration Recommendations
```yaml
server:
  tomcat:
    threads:
      max: 200
      min-spare: 10
    connection-timeout: 20000
    max-connections: 10000
  compression:
    enabled: true
    min-response-size: 1024
```

---

## Database Optimization

### Query Optimization
- [ ] **SELECT Specificity** - Avoid SELECT *
- [ ] **JOIN Optimization** - Minimize number of joins
- [ ] **Subquery Performance** - Replace with JOINs where faster
- [ ] **Index Usage** - EXPLAIN plan shows index usage
- [ ] **Batch Operations** - Batch inserts/updates used

### JPA/Hibernate Tuning
- [ ] **Fetch Strategy** - FetchType.LAZY default
- [ ] **Batch Size** - hibernate.jdbc.batch_size configured
- [ ] **Second Level Cache** - Enabled for read-heavy entities
- [ ] **Query Cache** - Enabled for repeated queries
- [ ] **SQL Logging** - P6Spy for query analysis in dev

### Merge Blockers
- **[BLOCKER]** Cartesian product queries
- **[BLOCKER]** Queries scanning millions of rows
- **[BLOCKER]** No WHERE clause on UPDATE/DELETE

---

## External Service Calls

### Required Checks
- [ ] **Timeout Configuration** - All external calls have timeouts
- [ ] **Retry Logic** - Exponential backoff for retries
- [ ] **Circuit Breaker** - Resilience4j/Hystrix implemented
- [ ] **Async Calls** - Non-critical calls made asynchronously
- [ ] **Bulkhead Pattern** - Resource isolation for services

### Merge Blockers
- **[BLOCKER]** No timeouts on external HTTP calls
- **[BLOCKER]** Synchronous calls in request path
- **[BLOCKER]** No fallback for critical dependencies

### Suggestions
- **[SUGGESTION]** Implement service mesh for microservices
- **[SUGGESTION]** Add distributed tracing (Zipkin/Jaeger)
- **[SUGGESTION]** Cache external API responses

---

## Monitoring & Profiling

### Required Metrics
- [ ] **Response Times** - P50, P95, P99 tracked
- [ ] **Throughput** - Requests per second monitored
- [ ] **Error Rates** - 4xx/5xx rates tracked
- [ ] **Database Metrics** - Query times and connection pool stats
- [ ] **JVM Metrics** - Heap usage, GC pauses monitored

### Tools Integration
- **[SUGGESTION]** Integrate Micrometer for metrics
- **[SUGGESTION]** Add distributed tracing
- **[SUGGESTION]** Implement APM (New Relic, Dynatrace, DataDog)
- **[SUGGESTION]** Add profiling in staging (YourKit, JProfiler)

---

## Load Testing Requirements

### Required Tests
- [ ] **Baseline Performance** - Normal load tested
- [ ] **Peak Load** - 2x expected traffic tested
- [ ] **Stress Testing** - Breaking point identified
- [ ] **Endurance Testing** - 24-hour test for memory leaks
- [ ] **Spike Testing** - Sudden traffic spikes tested

### Performance Benchmarks
```
Normal Load: 1000 req/s, P95 < 200ms
Peak Load: 2000 req/s, P95 < 500ms
Stress Test: Graceful degradation at 5000 req/s
```

---

## Code-Level Optimizations

### Common Issues
- [ ] **String Concatenation** - StringBuilder in loops
- [ ] **Stream Operations** - Efficient terminal operations
- [ ] **Exception Handling** - Exceptions not used for control flow
- [ ] **Regex Compilation** - Patterns compiled and cached
- [ ] **Reflection Usage** - Minimized or cached

### Merge Blockers
- **[BLOCKER]** O(n²) or worse algorithms on large datasets
- **[BLOCKER]** Infinite loops or unbounded recursion
- **[BLOCKER]** String concatenation in loops

---

## Review Checklist

### Before Merge
- [ ] Load testing completed for new endpoints
- [ ] Database queries analyzed with EXPLAIN
- [ ] No performance regressions detected
- [ ] Response times within SLA
- [ ] Resource cleanup verified
- [ ] Caching strategy reviewed
- [ ] All blockers resolved

### Performance SLA
- 95% of requests complete in < 500ms
- 99% of requests complete in < 1000ms
- Zero timeout errors under normal load
- No memory leaks in 24-hour test

