# OAuth Setup Instructions

## Overview
This application supports OAuth authentication via Yandex ID and GitHub. You need to create OAuth applications on each platform and configure the credentials.

## Yandex ID Setup

### Step 1: Create OAuth Application
1. Go to [Yandex OAuth](https://oauth.yandex.ru/)
2. Click "Register new application"
3. Fill in the form:
   - **Application name**: Your app name (e.g., "Survey App")
   - **Platform**: Web service
   - **Redirect URI**: `http://localhost/api/auth/oauth/callback` (for development)
     - For production: `https://yourdomain.com/api/auth/oauth/callback`
   - **Access rights**: 
     - ✅ Access to email address
     - ✅ Access to username, first name and surname, profile picture

### Step 2: Get Credentials
After registration, you'll receive:
- **Client ID** (Application ID)
- **Client Secret** (Password)

### Step 3: Configure Environment Variables
Add to `docker-compose.yml` in the `auth_module` service:
```yaml
environment:
  YANDEX_CLIENT_ID: "your_yandex_client_id"
  YANDEX_CLIENT_SECRET: "your_yandex_client_secret"
  OAUTH_REDIRECT_URL: "http://localhost/api/auth/oauth/callback"
```

## GitHub Setup

### Step 1: Create OAuth App
1. Go to GitHub Settings → Developer settings → OAuth Apps
   - Direct link: https://github.com/settings/developers
2. Click "New OAuth App"
3. Fill in the form:
   - **Application name**: Your app name (e.g., "Survey App")
   - **Homepage URL**: `http://localhost` (for development)
   - **Authorization callback URL**: `http://localhost/api/auth/oauth/callback`
     - For production: `https://yourdomain.com/api/auth/oauth/callback`

### Step 2: Get Credentials
After creation, you'll see:
- **Client ID**
- **Client Secret** (click "Generate a new client secret" if needed)

### Step 3: Configure Environment Variables
Add to `docker-compose.yml` in the `auth_module` service:
```yaml
environment:
  GITHUB_CLIENT_ID: "your_github_client_id"
  GITHUB_CLIENT_SECRET: "your_github_client_secret"
  OAUTH_REDIRECT_URL: "http://localhost/api/auth/oauth/callback"
```

## Complete docker-compose.yml Configuration

Add these environment variables to the `auth_module` service:

```yaml
auth_module:
  # ... existing config ...
  environment:
    # ... existing env vars ...
    # OAuth Configuration
    YANDEX_CLIENT_ID: "your_yandex_client_id_here"
    YANDEX_CLIENT_SECRET: "your_yandex_client_secret_here"
    GITHUB_CLIENT_ID: "your_github_client_id_here"
    GITHUB_CLIENT_SECRET: "your_github_client_secret_here"
    OAUTH_REDIRECT_URL: "http://localhost/api/auth/oauth/callback"
```

## Production Setup

For production, update:
1. **Redirect URLs** in OAuth apps to your production domain
2. **OAUTH_REDIRECT_URL** environment variable to `https://yourdomain.com/api/auth/oauth/callback`
3. Ensure your domain is accessible and HTTPS is enabled

## Testing

1. Restart Docker containers:
   ```bash
   docker-compose down
   docker-compose up -d
   ```

2. Open the application and try OAuth login
3. Check logs if there are issues:
   ```bash
   docker-compose logs auth_module
   ```

## Troubleshooting

- **"OAuth not configured"**: Check that environment variables are set correctly
- **"Invalid redirect URI"**: Ensure redirect URI in OAuth app matches `OAUTH_REDIRECT_URL`
- **"Access denied"**: Check that required scopes/permissions are granted in OAuth app settings
- **CORS errors**: Ensure nginx is properly configured to proxy OAuth callbacks

## Security Notes

- Never commit OAuth secrets to version control
- Use environment variables or secrets management
- For production, use HTTPS only
- Regularly rotate OAuth client secrets
