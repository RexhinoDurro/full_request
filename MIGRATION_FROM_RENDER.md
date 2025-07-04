# Migration from Render to VPS

## What was removed:
- `server/build.sh` - Render-specific build script
- `server/runtime.txt` - Render Python version specification
- `client/.env.production` - Render-specific client environment
- `admin/.env.production` - Render-specific admin environment

## What was changed:
- Django settings updated for VPS deployment
- Environment configuration templates created
- CORS and CSRF settings updated for custom domain
- Security settings optimized for VPS hosting

## What you need to do:
1. Review the new settings in `server/formsite_project/settings.py`
2. Configure environment variables using the templates
3. Run the VPS deployment script
4. Update your domain DNS to point to the VPS
5. Test all functionality

## Backup locations:
- Original Django settings: `server/formsite_project/settings.py.render-backup`
- Original settings file: `server/formsite_project/settings.py.original`
