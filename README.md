# SBOM Security Agent

A comprehensive security analysis agent that generates Software Bill of Materials (SBOM) reports and performs vulnerability scanning for GitHub repositories.

## Features

- **GitHub Integration**: Secure OAuth2 authentication to access public and private repositories
- **Multi-Language Support**: Analyzes dependencies across multiple package managers (npm, pip, Maven, Gradle, Cargo, Go, Composer, NuGet)
- **SBOM Generation**: Creates industry-standard SBOM reports in SPDX and CycloneDX formats
- **Vulnerability Scanning**: Identifies security vulnerabilities using multiple databases (OSV, GitHub Security Advisories, NVD)
- **Comprehensive Reporting**: Generates executive summaries and detailed security reports
- **AgentCore Integration**: Built on Amazon Bedrock AgentCore with Strands agents and Claude models

## Architecture

The agent is built using the AgentCore framework and follows established patterns for:
- Authentication via AgentCore Identity
- Runtime management via AgentCore Runtime
- Streaming responses for real-time progress updates
- Tool-based architecture for modular functionality

## Prerequisites

- Python 3.10+
- AWS credentials configured
- Amazon Bedrock AgentCore SDK
- Docker (for deployment)
- GitHub OAuth application (for repository access)

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

1. Set up GitHub OAuth2 application
2. Configure environment variables:
   ```bash
   export GITHUB_CLIENT_ID="your-client-id"
   export GITHUB_CLIENT_SECRET="your-client-secret"
   export NVD_API_KEY="your-nvd-api-key"  # Optional
   ```

## Usage

The agent provides conversational interface for:
- Repository analysis requests
- SBOM report generation
- Security vulnerability scanning
- Compliance reporting

## Supported Package Managers

- **npm** (Node.js): package.json, package-lock.json, yarn.lock
- **pip** (Python): requirements.txt, Pipfile, pyproject.toml
- **Maven** (Java): pom.xml
- **Gradle** (Java/Kotlin): build.gradle, build.gradle.kts
- **Cargo** (Rust): Cargo.toml, Cargo.lock
- **Go Modules**: go.mod, go.sum
- **Composer** (PHP): composer.json, composer.lock
- **NuGet** (.NET): *.csproj, packages.config

## SBOM Formats

- **SPDX 2.3**: Industry standard format for software bill of materials
- **CycloneDX 1.4**: Modern format optimized for security use cases

## Security Features

- Vulnerability detection from multiple sources
- Severity assessment and risk scoring
- Remediation recommendations
- Compliance mapping for security standards
- Executive reporting for risk management

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Code formatting
black src/
isort src/

# Type checking
mypy src/

##Notes on AgentCore Identity changes
🔄 Summary of Required Changes for Production
Based on the AWS documentation you referenced, here are the key changes needed to deploy the SBOM Security Agent to production AgentCore Runtime:

🚨 Critical Changes Required:
1. OAuth Callback Handler (NEW)
Created: src/sbom_agent/oauth_callback.py
Purpose: Handles OAuth callbacks that the starter toolkit handled automatically in development
Key Functions:
Receives authorization codes from GitHub
Verifies user sessions to prevent CSRF
Calls CompleteResourceTokenAuth API
2. Production Authentication Manager (NEW)
Created: src/sbom_agent/production_auth.py
Purpose: Manages the more complex OAuth flow required in production
Key Functions:
Initiates OAuth flows with session management
Handles token caching and expiration
Integrates with workload identity configuration
3. Web Application Integration (NEW)
Created: web_app_example.py
Purpose: Example web application that hosts the callback endpoint
Requirements:
Must be publicly accessible via HTTPS
Must handle user session verification
Must integrate with your existing authentication system
4. Production Deployment Script (MODIFIED)
Created: production_deployment.py
Purpose: Handles the additional configuration steps for production
Key Functions:
Registers callback URL with workload identity using UpdateWorkloadIdentity
Configures production-specific environment variables
Sets up enhanced security and monitoring
🔧 Environment Variables to Add:
# Production-specific (in addition to existing ones)
OAUTH_CALLBACK_URL=https://your-domain.com/oauth/callback
AGENTCORE_AGENT_ID=your-agent-id-from-deployment
COGNITO_DISCOVERY_URL=https://cognito-idp.region.amazonaws.com/pool-id/.well-known/openid_configuration
COGNITO_CLIENT_ID=your-cognito-client-id
DEPLOYMENT_ENV=production
📋 Deployment Process Changes:
Development (Current)
python deployment_config.py  # Uses starter toolkit automatic callback handling
Production (New)
python production_deployment.py  # Handles workload identity configuration
# PLUS deploy your web application separately
🏗️ Architecture Changes:
Development Flow:
User → Agent → AgentCore Starter Toolkit (handles OAuth) → GitHub
Production Flow:
User → Your Web App → OAuth Callback Handler → CompleteResourceTokenAuth API → Agent → GitHub
🔒 Security Enhancements:
Session Verification: Prevents CSRF attacks by verifying user sessions
HTTPS Enforcement: All callback URLs must use HTTPS
Workload Identity: Callback URLs must be registered with the agent's workload identity
Token Security: Enhanced token storage and management
⚡ Quick Migration Steps:
Set production environment variables
Run python production_deployment.py (gets agent ID)
Deploy your web application with the callback handler
Update GitHub OAuth app with your production callback URL
Test the complete OAuth flow
The core SBOM analysis functionality remains the same - these changes only affect the authentication flow to meet production security requirements. The agent will work identically once authentication is complete.
```
https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/oauth2-authorization-url-session-binding.html 

When you are using the Amazon Bedrock AgentCore Starter Toolkit in a local environment, the toolkit hosts the callback endpoint and calls the CompleteResourceTokenAuth API on your behalf to verify the user session to get OAuth2.0 access tokens. This is to simplify your local development and testing.

However, when deploying your agent code to AgentCore Runtime, your web application that connects to the agent runtime must host a publicly accessible HTTPS callback endpoint itself, the callback endpoint must be registered against the workload identity as an AllowedResourceOAuth2ReturnUrl by calling UpdateWorkloadIdentity using the agent ID provided by AgentCore Runtime, and then call the CompleteResourceTokenAuth API after verifying the current user's browser session in order to secure your Oauth2.0 authorization flows.

## License


MIT License - see LICENSE file for details.
