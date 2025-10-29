# Taiga WebSocket JWT Expiration Bypass Vulnerability

## Overview

This repository contains proof-of-concept scripts demonstrating an authentication bypass vulnerability in Taiga's WebSocket service (taiga-events repository). The vulnerability allows expired JWT tokens to authenticate and access real-time project data.

## Vulnerability Details

**CVE:** CVE-2025-63290  
**Component:** taiga-events WebSocket service  
**Affected Versions:** Taiga v6.8.1 and earlier  

## Root Cause

The vulnerability exists in `taiga-events/src/crypto/index.js` where JWT verification is configured with `ignoreExpiration: 'true'`, allowing expired tokens to authenticate to the WebSocket service.

```javascript
const options = {
  algorithm: process.env.ALGORITHM || 'HS256',
  audience: process.env.AUDIENCE || '',
  issuer: process.env.ISSUER || '',
  ignoreExpiration: 'true' // HERE
};
```

## Impact

- Real-time surveillance of project activities with expired tokens
- Persistent access after user logout or token expiration
- Business intelligence extraction, including project structure and user activity patterns

## Proof of Concept

### Prerequisites

- Node.js installed
- Taiga application running on localhost:9000 (or modify the script to your host)
  - Two users: `admin:admin` and `testuser:password123` (or modify according to your users)
- A Valid **expired** JWT token

### Scripts

1. **sniff.js** - Main demonstration script
   - Validates token expiration
   - Tests API vs WebSocket authentication
   - Performs real-time surveillance with an expired token

2. **gen.sh** - Event generator script
   - Creates project activities
   - Generates events for surveillance demonstration

### Usage

```bash
# Start surveillance with expired token
node sniff.js

# Generate test events (in another terminal)
./gen.sh
```

### Expected Results

The script will demonstrate:
- Expired token **rejected** by main API (correct behavior)
- Same expired token **accepted** by the WebSocket service
- Real-time interception of project activities
- Intelligence gathering capabilities

### Video Reference
[![YouTube](https://img.youtube.com/vi/fC74ZM7V64w/maxresdefault.jpg)](https://www.youtube.com/watch?v=fC74ZM7V64w)

## References

- [Taiga Events Repository](https://github.com/taigaio/taiga-events)
- [Vulnerable Code](https://github.com/taigaio/taiga-events/blob/main/src/crypto/index.js)
- [WebSocket Client](https://github.com/taigaio/taiga-events/blob/main/src/ws/client.js)
