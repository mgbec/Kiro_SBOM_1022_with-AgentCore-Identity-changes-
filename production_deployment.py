"""
Production deployment configuration for SBOM Security Agent.

This script handles the additional configuration required for production
AgentCore Runtime deployment, including OAuth callback handling.
"""

import os
import asyncio
from typing import Dict, Any

import boto3
from bedrock_agentcore_starter_toolkit import Runtime
from boto3.session import Session

# Production configuration
AGENT_NAME = "sbom-security-agent-prod"
ENTRYPOINT = "sbom_agent.py"
REQUIREMENTS_FILE = "requirements.txt"


async def setup_production_oauth_provider(callback_url: str) -> bool:
    """Set up GitHub OAuth2 credential provider for production."""
    print("Setting up GitHub OAuth2 credential provider for production...")
    
    github_client_id = os.getenv("GITHUB_CLIENT_ID")
    github_client_secret = os.getenv("GITHUB_CLIENT_SECRET")
    
    if not github_client_id or not github_client_secret:
        print("❌ GitHub OAuth credentials not found in environment variables.")
        return False
    
    try:
        boto_session = Session()
        region = boto_session.region_name
        agentcore_client = boto3.client('bedrock-agentcore-control', region_name=region)
        
        # Create OAuth2 provider with production callback URL
        response = agentcore_client.create_oauth2_credential_provider(
            name='github-provider-prod',
            credentialProviderVendor='GithubOauth2',
            oauth2ProviderConfigInput={
                'githubOauth2ProviderConfig': {
                    'clientId': github_client_id,
                    'clientSecret': github_client_secret,
                    'callbackUrl': callback_url  # Production callback URL
                }
            }
        )
        
        print(f"✅ Production GitHub OAuth2 provider created: {response['credentialProviderArn']}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to create production GitHub OAuth2 provider: {str(e)}")
        return False


async def configure_production_runtime() -> Runtime:
    """Configure AgentCore Runtime for production deployment."""
    print("Configuring AgentCore Runtime for production...")
    
    try:
        boto_session = Session()
        region = boto_session.region_name
        
        if not region:
            raise ValueError("AWS region not configured")
        
        print(f"Using AWS region: {region}")
        
        # Initialize AgentCore Runtime
        agentcore_runtime = Runtime()
        
        # Production configuration
        response = agentcore_runtime.configure(
            entrypoint=ENTRYPOINT,
            auto_create_execution_role=True,
            auto_create_ecr=True,
            requirements_file=REQUIREMENTS_FILE,
            region=region,
            agent_name=AGENT_NAME,
            # Production-specific environment variables
            environment_variables={
                "DEPLOYMENT_ENV": "production",
                "OAUTH_CALLBACK_URL": os.getenv("OAUTH_CALLBACK_URL"),
                "AGENTCORE_AGENT_ID": "${AGENT_ID}",  # Will be populated by AgentCore
                "LOG_LEVEL": "INFO"
            },
            # Enhanced resource allocation for production
            memory_size=2048,  # 2GB RAM
            timeout=900,       # 15 minutes
            # Production authorizer configuration
            authorizer_configuration={
                "customJWTAuthorizer": {
                    "discoveryUrl": os.getenv("COGNITO_DISCOVERY_URL"),
                    "allowedClients": [os.getenv("COGNITO_CLIENT_ID")]
                }
            }
        )
        
        print("✅ Production AgentCore Runtime configured successfully")
        return agentcore_runtime
        
    except Exception as e:
        print(f"❌ Failed to configure production runtime: {str(e)}")
        raise


async def deploy_production_agent(agentcore_runtime: Runtime) -> Dict[str, Any]:
    """Deploy the agent to production AgentCore Runtime."""
    print("Deploying SBOM Security Agent to production AgentCore Runtime...")
    
    try:
        # Launch the agent
        launch_result = agentcore_runtime.launch()
        
        # Extract agent ID from launch result
        agent_id = launch_result.get("agentId")
        if not agent_id:
            raise ValueError("Agent ID not found in launch result")
        
        print(f"✅ Agent deployed successfully with ID: {agent_id}")
        
        return {
            "agent_id": agent_id,
            "launch_result": launch_result
        }
        
    except Exception as e:
        print(f"❌ Failed to deploy production agent: {str(e)}")
        raise


async def configure_workload_identity(agent_id: str, callback_url: str) -> bool:
    """Configure workload identity with OAuth callback URL."""
    print(f"Configuring workload identity for agent {agent_id}...")
    
    try:
        boto_session = Session()
        region = boto_session.region_name
        agentcore_client = boto3.client('bedrock-agentcore-control', region_name=region)
        
        # Update workload identity with allowed OAuth return URLs
        response = agentcore_client.update_workload_identity(
            agentId=agent_id,
            allowedResourceOAuth2ReturnUrls=[callback_url]
        )
        
        print(f"✅ Workload identity configured with callback URL: {callback_url}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to configure workload identity: {str(e)}")
        return False


async def validate_production_setup() -> bool:
    """Validate that all required environment variables are set."""
    print("Validating production setup...")
    
    required_vars = [
        "GITHUB_CLIENT_ID",
        "GITHUB_CLIENT_SECRET", 
        "OAUTH_CALLBACK_URL",
        "COGNITO_DISCOVERY_URL",
        "COGNITO_CLIENT_ID"
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
        print("\nRequired environment variables for production:")
        print("- GITHUB_CLIENT_ID: GitHub OAuth application client ID")
        print("- GITHUB_CLIENT_SECRET: GitHub OAuth application client secret")
        print("- OAUTH_CALLBACK_URL: Your web application's HTTPS callback URL")
        print("- COGNITO_DISCOVERY_URL: Cognito User Pool discovery URL")
        print("- COGNITO_CLIENT_ID: Cognito User Pool client ID")
        return False
    
    # Validate callback URL is HTTPS
    callback_url = os.getenv("OAUTH_CALLBACK_URL")
    if not callback_url.startswith("https://"):
        print("❌ OAUTH_CALLBACK_URL must be HTTPS for production")
        return False
    
    print("✅ Production setup validation passed")
    return True


async def main():
    """Main production deployment function."""
    print("🚀 Starting SBOM Security Agent PRODUCTION deployment...")
    print("="*70)
    
    # Step 1: Validate setup
    if not await validate_production_setup():
        print("❌ Production setup validation failed. Deployment cannot continue.")
        return False
    
    callback_url = os.getenv("OAUTH_CALLBACK_URL")
    
    # Step 2: Set up OAuth provider
    if not await setup_production_oauth_provider(callback_url):
        print("❌ OAuth provider setup failed. Deployment cannot continue.")
        return False
    
    print()
    
    # Step 3: Configure runtime
    try:
        agentcore_runtime = await configure_production_runtime()
    except Exception as e:
        print(f"❌ Runtime configuration failed: {str(e)}")
        return False
    
    print()
    
    # Step 4: Deploy agent
    try:
        deployment_result = await deploy_production_agent(agentcore_runtime)
        agent_id = deployment_result["agent_id"]
    except Exception as e:
        print(f"❌ Agent deployment failed: {str(e)}")
        return False
    
    print()
    
    # Step 5: Configure workload identity
    if not await configure_workload_identity(agent_id, callback_url):
        print("⚠️ Workload identity configuration failed. OAuth may not work properly.")
    
    print()
    print("="*70)
    print("🎉 SBOM Security Agent PRODUCTION deployment completed!")
    print()
    print("IMPORTANT NEXT STEPS:")
    print("1. Deploy your web application with the OAuth callback handler")
    print("2. Ensure your callback URL is publicly accessible via HTTPS")
    print("3. Test the OAuth flow end-to-end")
    print("4. Set up monitoring and alerting")
    print("5. Configure backup and disaster recovery")
    print()
    print(f"Agent ID: {agent_id}")
    print(f"Callback URL: {callback_url}")
    print(f"Region: {os.getenv('AWS_REGION', 'us-east-1')}")
    
    return True


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)