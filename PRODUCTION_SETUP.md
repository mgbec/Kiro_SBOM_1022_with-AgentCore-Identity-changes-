# Production Setup Guide - SBOM Security Agent

## 🚨 Important Changes for Production Deployment

When deploying to **AgentCore Runtime** (production), the OAuth2 flow requires additional components compared to local development with the starter toolkit.

### **Local Development vs Production**

| Aspect | Local Development | Production AgentCore Runtime |
|--------|------------------|------------------------------|
| OAuth Callback | Handled by starter toolkit | **Your web app must handle** |
| Callback URL | Automatic | **Must register with workload identity** |
| Token Exchange | Automatic | **Must call CompleteResourceTokenAuth API** |
| Session Management | Not required | **Must verify user sessions** |

## 🏗️ **Required Components for Production**

### 1. **Web Application with OAuth Callback Handler**
Your web application must host a publicly accessible HTTPS endpoint to handle OAuth callbacks.

### 2. **Workload Identity Configuration**
Register your callback URL with the agent's workload identity using `UpdateWorkloadIdentity` API.

### 3. **Session Verification**
Verify user sessions before completing token authentication to prevent CSRF attacks.

### 4. **CompleteResourceTokenAuth API Call**
Your callback handler must call this API to exchange the authorization code for access tokens.

## 📋 **Step-by-Step Production Setup**

### **Step 1: Environment Variables**

Create a `.env.production` file:

```bash
# GitHub OAuth (same as development)
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Production-specific variables
OAUTH_CALLBACK_URL=https://your-domain.com/oauth/callback
AGENTCORE_AGENT_ID=your-agent-id-from-deployment
COGNITO_DISCOVERY_URL=https://cognito-idp.region.amazonaws.com/pool-id/.well-known/openid_configuration
COGNITO_CLIENT_ID=your-cognito-client-id

# AWS Configuration
AWS_REGION=us-east-1
```

### **Step 2: Deploy the Agent**

```bash
# Set environment variables
export $(cat .env.production | xargs)

# Run production deployment
python production_deployment.py
```

This will:
- Create production OAuth2 provider
- Deploy agent to AgentCore Runtime
- Configure workload identity with callback URL
- Return the agent ID for your web application

### **Step 3: Deploy Your Web Application**

The web application must be deployed separately and be publicly accessible via HTTPS.

#### **Option A: Use the Example Web App**

```bash
# Install additional dependencies
pip install fastapi uvicorn jinja2 python-multipart

# Run the example web application
python web_app_example.py
```

#### **Option B: Integrate with Existing Web App**

Add the OAuth callback handler to your existing application:

```python
from src.sbom_agent.oauth_callback import callback_app

# Mount the callback handler
your_app.mount("/oauth", callback_app)
```

### **Step 4: Configure GitHub OAuth Application**

Update your GitHub OAuth application settings:

1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Edit your OAuth application
3. Update the **Authorization callback URL** to: `https://your-domain.com/oauth/callback`
4. Save changes

### **Step 5: Test the Production Flow**

1. **Access your web application**: `https://your-domain.com`
2. **Try to analyze a repository** - this should trigger OAuth flow
3. **Verify OAuth redirect** - should go to your callback URL
4. **Check authentication completion** - should return to your app with success

## 🔧 **Code Changes Required**

### **1. Update Main Agent File** (`sbom_agent.py`)

Replace the development authentication with production authentication:

```python
# Add at the top
import os
from src.sbom_agent.production_auth import create_production_auth_manager

# Replace the existing auth_manager initialization
if os.getenv("DEPLOYMENT_ENV") == "production":
    # Use production authentication
    auth_manager = await create_production_auth_manager()
else:
    # Use development authentication (existing code)
    from src.sbom_agent.auth import auth_manager
```

### **2. Update Tool Functions** (`src/sbom_agent/tools.py`)

Modify tools to handle production OAuth responses:

```python
@tool
def analyze_repository(repository_url: str, branch: str = "main") -> str:
    # ... existing validation code ...
    
    # Check authentication
    if not auth_manager.is_authenticated():
        if os.getenv("DEPLOYMENT_ENV") == "production":
            # Return OAuth initiation for production
            return json.dumps({
                "auth_required": True,
                "message": "GitHub authentication required",
                "next_step": "initiate_oauth",
                "repository_url": normalized_url,
                "branch": branch
            })
        else:
            # Existing development flow
            return json.dumps({
                "auth_required": True,
                "message": "GitHub authentication is required...",
                # ... existing code
            })
```

### **3. Add Production Dependencies**

Update `requirements.txt`:

```txt
# Existing dependencies...

# Production-specific dependencies
fastapi>=0.104.0
uvicorn>=0.24.0
jinja2>=3.1.0
python-multipart>=0.0.6
```

## 🔒 **Security Considerations**

### **1. HTTPS Required**
- All callback URLs must use HTTPS in production
- Use valid SSL certificates (not self-signed)

### **2. Session Security**
- Implement secure session management
- Use CSRF protection
- Validate session ownership before token exchange

### **3. Token Storage**
- Store access tokens securely (encrypted)
- Implement token rotation
- Use secure storage (Redis, DynamoDB, not in-memory)

### **4. Network Security**
- Restrict callback endpoint access
- Implement rate limiting
- Use Web Application Firewall (WAF)

## 🚨 **Common Issues and Solutions**

### **Issue: "Callback URL not registered"**
**Solution**: Ensure you've called `UpdateWorkloadIdentity` with your callback URL after agent deployment.

### **Issue: "Session verification failed"**
**Solution**: Check that your session management correctly associates OAuth sessions with authenticated users.

### **Issue: "CompleteResourceTokenAuth failed"**
**Solution**: Verify the authorization code is passed correctly from the OAuth callback to the API call.

### **Issue: "HTTPS required"**
**Solution**: Ensure your callback URL uses HTTPS. HTTP is not allowed in production.

## 📊 **Monitoring and Logging**

### **Key Metrics to Monitor**
- OAuth flow completion rate
- Token refresh success rate
- Callback endpoint response times
- Authentication error rates

### **Important Logs**
- OAuth initiation events
- Callback processing results
- Token exchange outcomes
- Session verification results

## 🔄 **Migration from Development**

If you have an existing development deployment:

1. **Keep development environment** for testing
2. **Deploy production version** with new agent name
3. **Test production OAuth flow** thoroughly
4. **Update DNS/routing** to point to production
5. **Monitor both environments** during transition

## 📞 **Support and Troubleshooting**

### **Debug Mode**
Set `LOG_LEVEL=DEBUG` to get detailed OAuth flow logging.

### **Test OAuth Flow**
Use the provided test endpoints to verify OAuth integration:
- `GET /oauth/test` - Test OAuth initiation
- `GET /health` - Verify callback handler is running

### **AWS Support**
For AgentCore-specific issues, contact AWS support with:
- Agent ID
- Error messages from CloudWatch logs
- OAuth flow trace information

---

**⚠️ Important**: Always test the complete OAuth flow in a staging environment before deploying to production!