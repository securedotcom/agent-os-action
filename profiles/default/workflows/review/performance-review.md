# Performance Review Workflow

## Step 1: Database Query Analysis

### N+1 Query Detection
```bash
# Look for loops with database queries
grep -r "for.*in\|forEach\|map\|filter" --include="*.js" --include="*.py" --include="*.rb" . | grep -i "query\|find\|select\|get"

# Check for database queries in loops
grep -r "\.find\|\.select\|\.get\|\.query" --include="*.js" --include="*.py" --include="*.rb" . | grep -A5 -B5 "for\|while\|each"
```

### Query Efficiency Analysis
```bash
# Look for inefficient query patterns
grep -r "SELECT \*\|\.all\|\.find_all" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"

# Check for missing indexes
grep -r "WHERE\|ORDER BY\|GROUP BY" --include="*.sql" --include="*.js" --include="*.py" . | grep -v "test\|spec"
```

**Check for:**
- N+1 query patterns in loops
- Missing database indexes
- Inefficient SELECT statements
- Unnecessary data fetching
- Query optimization opportunities

## Step 2: Memory Usage Review

### Memory Leak Detection
```bash
# Look for unbounded collections
grep -r "push\|append\|add\|insert" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec" | grep -v "test\|spec"

# Check for resource disposal
grep -r "close\|dispose\|destroy\|cleanup" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"
```

### Large Object Handling
```bash
# Look for large data processing
grep -r "readFile\|load\|parse\|JSON" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"
```

**Check for:**
- Unbounded arrays or collections
- Memory leaks in resource management
- Large file processing without streaming
- Proper resource cleanup
- Garbage collection optimization

## Step 3: Algorithm Efficiency Check

### Time Complexity Analysis
```bash
# Look for nested loops
grep -r "for.*for\|while.*while\|forEach.*forEach" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"

# Check for inefficient algorithms
grep -r "sort\|search\|find" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"
```

**Check for:**
- Nested loops and O(n²) algorithms
- Inefficient search and sort operations
- Redundant calculations
- Missing caching opportunities
- Algorithm optimization potential

## Step 4: I/O Performance Validation

### File Operations
```bash
# Look for file I/O operations
grep -r "readFile\|writeFile\|fs\." --include="*.js" . | grep -v "test\|spec"
grep -r "open\|read\|write" --include="*.py" . | grep -v "test\|spec"
```

### Network Operations
```bash
# Look for network calls
grep -r "fetch\|request\|http\|axios" --include="*.js" . | grep -v "test\|spec"
grep -r "requests\|urllib\|httplib" --include="*.py" . | grep -v "test\|spec"
```

**Check for:**
- Large file operations without streaming
- Synchronous I/O operations
- Missing timeout configurations
- Inefficient network calls
- Batch processing opportunities

## Step 5: Resource Management Review

### Connection Management
```bash
# Look for database connections
grep -r "connect\|connection\|pool" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"
```

### Caching Implementation
```bash
# Look for caching patterns
grep -r "cache\|redis\|memcache" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"
```

**Check for:**
- Database connection pooling
- Proper resource cleanup
- Caching strategy implementation
- Rate limiting and throttling
- Background job optimization

## Step 6: Scalability Assessment

### Concurrent Access Patterns
```bash
# Look for concurrency patterns
grep -r "async\|await\|Promise\|thread\|concurrent" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"
```

### Load Handling
```bash
# Look for load-related code
grep -r "queue\|worker\|job\|batch" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"
```

**Check for:**
- Concurrent access handling
- Queue and worker implementation
- Batch processing capabilities
- Load balancing considerations
- Horizontal scaling readiness

## Performance Review Output

Generate performance findings with severity classification:

### [BLOCKER] Critical Performance Issues
- N+1 query patterns detected
- Unbounded loops or collections
- Memory leaks in resource management
- Missing timeouts on network calls
- Large I/O operations not streamed

### [SUGGESTION] Performance Improvements
- Query optimization opportunities
- Caching implementation suggestions
- Algorithm optimization recommendations
- Resource pooling improvements
- I/O optimization opportunities

### [NIT] Performance Nits
- Minor micro-optimizations
- Style improvements in performance code
- Documentation for performance functions
- Non-critical performance suggestions
