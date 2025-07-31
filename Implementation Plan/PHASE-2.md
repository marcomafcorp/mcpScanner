# Phase 2: Scanner Engine & API

## Objectives
- Develop the core scanner engine for vulnerability detection
- Implement passive and active scanning modules
- Create API endpoints for scan management
- Set up asynchronous task processing
- Build WebSocket implementation for real-time scan status

## Todo List

### 1. Database Schema Implementation
- [ ] Define and create tables for:
  - `scans` (id, target_url, timestamp, status, depth, active_tests, user_id)
  - `findings` (id, scan_id, category, severity, evidence, description, timestamp)
  - `targets` (id, url, ip, hostname, ports, services)
  - `vulnerabilities` (id, finding_id, cve_id, cvss_score, remediation)
- [ ] Create SQLAlchemy models for each table
- [ ] Define relationships between models
- [ ] Implement Pydantic schemas for request/response validation
- [ ] Create Alembic migrations for the schema

### 2. Scanner Core Components
- [ ] Implement base scanner interface/abstract class
- [ ] Create scanner registry for plug-and-play scanner modules
- [ ] Develop scanner result processing pipeline
- [ ] Implement CVSS scoring module
- [ ] Create remediation recommendation engine
- [ ] Set up logger and error handling for scanner processes

### 3. Passive Scanning Modules
- [ ] Implement dependency scanner (using OWASP Dependency-Check)
  - Package vulnerability detection
  - Version analysis
  - Known CVE matching
- [ ] Create configuration analysis module
  - Insecure defaults detection
  - Hardcoded credentials scanner
  - Permissive access controls identification
- [ ] Develop code security analyzer using bandit
  - SQL injection vulnerability detection
  - XSS vulnerability detection
  - Command injection vulnerability detection

### 4. Active Scanning Modules
- [ ] Implement port scanner using python-nmap
  - Open port detection
  - Service version identification
  - Vulnerability correlation
- [ ] Create HTTP/API scanner
  - OWASP Top-10 style tests
  - API endpoint enumeration
  - Authentication bypass attempts
  - Injection testing
- [ ] Implement network analyzer using scapy
  - Protocol analysis
  - Traffic pattern recognition
  - Network configuration issues detection

### 5. API Endpoints Development
- [ ] Create `/scan` endpoint
  - Implement payload validation (target_url, auth?, depth, active_tests)
  - Set up request throttling/rate limiting
  - Implement scan queuing mechanism
- [ ] Develop scan management endpoints
  - GET `/scans` - List all scans with pagination and filtering
  - GET `/scans/{id}` - Get detailed scan information
  - DELETE `/scans/{id}` - Cancel and delete a scan
  - PUT `/scans/{id}/pause` - Pause a running scan
  - PUT `/scans/{id}/resume` - Resume a paused scan
- [ ] Implement findings endpoints
  - GET `/scans/{id}/findings` - Get all findings for a scan
  - GET `/findings/{id}` - Get detailed finding information
  - POST `/findings/{id}/dismiss` - Dismiss a finding
  - POST `/findings/{id}/confirm` - Confirm a finding
- [ ] Create OpenAPI documentation and schemas

### 6. Async Task Processing
- [ ] Set up Celery with Redis as broker
- [ ] Configure Celery task queues and priorities
- [ ] Implement scan task with progress tracking
- [ ] Create task result handling and storage
- [ ] Set up task retry mechanism for failed scans
- [ ] Implement task cancellation functionality

### 7. WebSocket Implementation
- [ ] Create WebSocket endpoint `/ws/scan/{id}`
- [ ] Implement real-time scan status updates
- [ ] Develop progress reporting mechanism
- [ ] Set up finding notification system
- [ ] Create connection management and authentication

## Tests to Validate Phase 2

### Scanner Core Tests
1. **Scanner Registry Test**
   - Test scanner module registration
   - Verify scanner discovery and loading
   - Test scanner execution pipeline

2. **CVSS Scoring Test**
   - Verify correct scoring calculation
   - Test different vulnerability types scoring
   - Verify score normalization and categorization

3. **Remediation Engine Test**
   - Test recommendation generation
   - Verify mapping of vulnerabilities to remediation steps
   - Test prioritization of remediation advice

### Passive Scanning Tests
1. **Dependency Scanner Test**
   - Test detection of vulnerable dependencies
   - Verify version analysis accuracy
   - Test CVE matching functionality

2. **Configuration Analyzer Test**
   - Test detection of insecure defaults
   - Verify credential scanning capabilities
   - Test access control validation

### Active Scanning Tests
1. **Port Scanner Test**
   - Test port discovery functionality
   - Verify service identification accuracy
   - Test handling of firewalled and filtered ports

2. **HTTP/API Scanner Test**
   - Test detection of common web vulnerabilities
   - Verify handling of authentication mechanisms
   - Test injection detection capabilities

3. **Network Analyzer Test**
   - Test protocol analysis capabilities
   - Verify detection of network misconfigurations
   - Test traffic pattern analysis

### API Endpoint Tests
1. **Scan Endpoint Test**
   - Test scan creation with various parameters
   - Verify validation of input parameters
   - Test rate limiting functionality

2. **Scan Management Test**
   - Test listing scans with filters
   - Verify scan details retrieval
   - Test scan cancellation functionality

3. **Findings Endpoint Test**
   - Test retrieval of findings for a scan
   - Verify detailed finding information
   - Test finding status management

### Async Processing Tests
1. **Celery Task Test**
   - Test task creation and execution
   - Verify progress tracking
   - Test task cancellation and retry mechanisms

2. **WebSocket Test**
   - Test connection establishment
   - Verify real-time updates
   - Test multiple client connections

## Definition of Done
- All scanner modules implemented and tested
- API endpoints functional and documented
- Async processing setup working properly
- WebSocket implementation providing real-time updates
- All tests pass with minimum 90% coverage
