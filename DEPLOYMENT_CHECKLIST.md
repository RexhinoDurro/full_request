# VPS Deployment Checklist - Two Domain Setup

## Pre-deployment
- [ ] Client domain (client-formsite.com) purchased and DNS configured
- [ ] Admin domain (admin-formsite.com) purchased and DNS configured
- [ ] VPS server provisioned (minimum 2GB RAM recommended)
- [ ] SSH access to VPS server configured
- [ ] SSL certificate email ready

## Environment Configuration
- [ ] Copy `.env.template` to `.env.production` in server directory
- [ ] Fill in all environment variables in `.env.production`
- [ ] Generate secure SECRET_KEY (min 50 characters)
- [ ] Generate secure CRYPTOGRAPHY_KEY
- [ ] Set strong ADMIN_PASSWORD
- [ ] Configure ALLOWED_HOSTS with both domains
- [ ] Configure CORS_ALLOWED_ORIGINS with both domains

## Client Configuration
- [ ] Copy `client/.env.template` to `client/.env.production`
- [ ] Verify VITE_API_URL points to admin domain

## Admin Configuration
- [ ] Copy `admin/.env.template` to `admin/.env.production`
- [ ] Verify VITE_API_URL points to admin domain

## Security
- [ ] Change all default passwords
- [ ] Configure firewall (UFW)
- [ ] Setup fail2ban
- [ ] Configure SSL/TLS for both domains
- [ ] Test security headers on both domains
- [ ] Enable automatic security updates

## Testing
- [ ] Test form submission on client domain
- [ ] Test admin login on admin domain
- [ ] Test API endpoints on admin domain
- [ ] Test SSL certificates for both domains
- [ ] Test rate limiting
- [ ] Verify security headers
- [ ] Test cross-domain communication

## Monitoring
- [ ] Setup backup system
- [ ] Configure log rotation
- [ ] Setup monitoring alerts
- [ ] Test disaster recovery

## Two-Domain Architecture
- [ ] Client domain serves only the public form
- [ ] Admin domain serves admin panel and API
- [ ] Form submissions go from client to admin domain API
- [ ] Admin operations are isolated on admin domain
