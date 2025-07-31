# HTTPS Configuration Guide

This guide explains how to configure HTTPS for the MCP Security Scanner in production environments.

## Overview

HTTPS is essential for production deployments to ensure:
- Encrypted communication between clients and server
- Protection against man-in-the-middle attacks
- Browser security features (secure cookies, HSTS)
- Compliance with security standards

## Configuration Options

### 1. Using a Reverse Proxy (Recommended)

The recommended approach is to use a reverse proxy like Nginx or Caddy to handle SSL/TLS termination.

#### Nginx Configuration

```nginx
server {
    listen 80;
    server_name scanner.example.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name scanner.example.com;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/scanner.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/scanner.example.com/privkey.pem;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Proxy to FastAPI
    location / {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # WebSocket support
    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Caddy Configuration

```caddyfile
scanner.example.com {
    # Automatic HTTPS with Let's Encrypt
    tls {
        protocols tls1.2 tls1.3
    }
    
    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }
    
    # Reverse proxy
    reverse_proxy localhost:8000 {
        header_up Host {host}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

### 2. Using Uvicorn with SSL

For development or simple deployments, you can configure Uvicorn to handle SSL directly:

```bash
# Generate self-signed certificate (development only)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Run with SSL
uvicorn app.main:app --host 0.0.0.0 --port 443 --ssl-keyfile=./key.pem --ssl-certfile=./cert.pem
```

### 3. Using Docker with SSL

#### Docker Compose with Nginx

```yaml
version: '3.8'

services:
  app:
    build: .
    expose:
      - "8000"
    environment:
      - ENVIRONMENT=production
  
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
      - ./certbot/www:/var/www/certbot:ro
      - ./certbot/conf:/etc/letsencrypt:ro
    depends_on:
      - app
  
  certbot:
    image: certbot/certbot
    volumes:
      - ./certbot/www:/var/www/certbot:rw
      - ./certbot/conf:/etc/letsencrypt:rw
    entrypoint: "/bin/sh -c 'trap exit TERM; while :; do certbot renew; sleep 12h & wait $${!}; done;'"
```

## SSL Certificate Options

### 1. Let's Encrypt (Free)

```bash
# Install certbot
sudo apt-get update
sudo apt-get install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d scanner.example.com

# Auto-renewal
sudo systemctl enable certbot.timer
```

### 2. Commercial SSL Certificates

1. Purchase certificate from CA (DigiCert, Comodo, etc.)
2. Install certificate files:
   - Certificate file (`.crt`)
   - Private key (`.key`)
   - Intermediate certificates (if any)

### 3. Self-Signed Certificates (Development Only)

```bash
# Generate private key
openssl genrsa -out server.key 4096

# Generate certificate signing request
openssl req -new -key server.key -out server.csr

# Generate self-signed certificate
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
```

## Application Configuration

### Environment Variables

```bash
# .env file
ENVIRONMENT=production
SECRET_KEY=your-secret-key-here
REFRESH_SECRET_KEY=your-refresh-secret-key-here

# Force HTTPS redirects
FORCE_HTTPS=true

# Secure cookies
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=strict
```

### FastAPI Settings

```python
# app/core/config.py
class Settings(BaseSettings):
    # HTTPS settings
    FORCE_HTTPS: bool = Field(default=True)
    SECURE_COOKIES: bool = Field(default=True)
    HSTS_ENABLED: bool = Field(default=True)
    HSTS_MAX_AGE: int = Field(default=31536000)  # 1 year
```

## Security Best Practices

### 1. TLS Configuration
- Use TLS 1.2 or higher
- Disable weak ciphers
- Enable Perfect Forward Secrecy (PFS)
- Use strong key exchange (ECDHE)

### 2. HTTP Headers
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy

### 3. Certificate Management
- Monitor certificate expiration
- Automate renewal process
- Use strong private keys (≥2048 bits RSA or ≥256 bits ECC)
- Protect private keys (chmod 600)

### 4. Monitoring
- Monitor SSL/TLS configuration
- Check for certificate expiration
- Monitor for security vulnerabilities
- Regular security audits

## Testing HTTPS Configuration

### 1. SSL Labs Test
```
https://www.ssllabs.com/ssltest/analyze.html?d=scanner.example.com
```

### 2. OpenSSL Test
```bash
# Test connection
openssl s_client -connect scanner.example.com:443

# Check certificate
openssl x509 -in cert.pem -text -noout

# Test TLS versions
openssl s_client -connect scanner.example.com:443 -tls1_2
openssl s_client -connect scanner.example.com:443 -tls1_3
```

### 3. Curl Test
```bash
# Test HTTPS endpoint
curl -v https://scanner.example.com/api/v1/health

# Test certificate validation
curl --cacert /path/to/ca.crt https://scanner.example.com
```

## Troubleshooting

### Common Issues

1. **Certificate Verification Failed**
   - Check certificate chain is complete
   - Verify domain name matches certificate
   - Check certificate validity dates

2. **Mixed Content Warnings**
   - Ensure all resources use HTTPS
   - Update API endpoints to use HTTPS
   - Check WebSocket connections

3. **HSTS Issues**
   - Clear browser HSTS cache if needed
   - Start with shorter max-age for testing
   - Use includeSubDomains carefully

4. **Performance Issues**
   - Enable HTTP/2
   - Use session resumption
   - Configure OCSP stapling
   - Enable keepalive connections

## Production Checklist

- [ ] Valid SSL certificate installed
- [ ] HTTP redirects to HTTPS
- [ ] Strong TLS configuration
- [ ] Security headers configured
- [ ] HSTS enabled with appropriate max-age
- [ ] Certificate auto-renewal configured
- [ ] Monitoring and alerts set up
- [ ] SSL/TLS testing completed
- [ ] Documentation updated
- [ ] Team trained on certificate management