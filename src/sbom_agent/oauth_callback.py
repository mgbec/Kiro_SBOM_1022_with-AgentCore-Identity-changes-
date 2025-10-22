"""
OAuth2 callback handler for production AgentCore Runtime deployment.

This module handles the OAuth2 callback flow required when deploying to 
AgentCore Runtime, as opposed to local development where the starter toolkit
handles callbacks automatically.
"""

import asyncio
import json
import logging
from typing import Dict, Any, Optional
from urllib.parse import parse_qs, urlparse

import boto3
import httpx
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import HTMLResponse

from .config import Config
from .exceptions import AuthenticationError

logger = logging.getLogger(__name__)


class OAuth2CallbackHandler:
    """Handles OAuth2 callbacks for production AgentCore Runtime deployment."""
    
    def __init__(self, agent_id: str, region: str = "us-east-1"):
        self.agent_id = agent_id
        self.region = region
        self.agentcore_client = boto3.client('bedrock-agentcore-control', region_name=region)
        self.session_store = {}  # In production, use Redis or DynamoDB
        
    async def register_callback_url(self, callback_url: str) -> bool:
        """
        Register the callback URL with the workload identity.
        
        Args:
            callback_url: The HTTPS callback URL for your web application
            
        Returns:
            bool: True if registration successful
        """
        try:
            response = self.agentcore_client.update_workload_identity(
                agentId=self.agent_id,
                allowedResourceOAuth2ReturnUrls=[callback_url]
            )
            
            logger.info(f"Callback URL registered successfully: {callback_url}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register callback URL: {str(e)}")
            return False
    
    def generate_auth_session(self, user_id: str, provider_name: str) -> str:
        """
        Generate a secure session identifier for OAuth flow.
        
        Args:
            user_id: Unique identifier for the user
            provider_name: OAuth provider name (e.g., "github-provider")
            
        Returns:
            str: Session identifier
        """
        import uuid
        import time
        
        session_id = str(uuid.uuid4())
        
        # Store session data (in production, use persistent storage)
        self.session_store[session_id] = {
            "user_id": user_id,
            "provider_name": provider_name,
            "created_at": time.time(),
            "status": "pending"
        }
        
        return session_id
    
    def verify_session(self, session_id: str, user_id: str) -> bool:
        """
        Verify that the session belongs to the authenticated user.
        
        Args:
            session_id: Session identifier from OAuth callback
            user_id: Current authenticated user ID
            
        Returns:
            bool: True if session is valid and belongs to user
        """
        session_data = self.session_store.get(session_id)
        
        if not session_data:
            logger.warning(f"Session not found: {session_id}")
            return False
        
        if session_data["user_id"] != user_id:
            logger.warning(f"Session user mismatch: {session_id}")
            return False
        
        if session_data["status"] != "pending":
            logger.warning(f"Session already used: {session_id}")
            return False
        
        # Check session expiration (30 minutes)
        import time
        if time.time() - session_data["created_at"] > 1800:
            logger.warning(f"Session expired: {session_id}")
            return False
        
        return True
    
    async def complete_token_auth(
        self, 
        session_id: str, 
        authorization_code: str, 
        provider_name: str
    ) -> Dict[str, Any]:
        """
        Complete the OAuth2 token authentication flow.
        
        Args:
            session_id: Session identifier
            authorization_code: OAuth authorization code from callback
            provider_name: OAuth provider name
            
        Returns:
            Dict[str, Any]: Token response from AgentCore
        """
        try:
            response = self.agentcore_client.complete_resource_token_auth(
                agentId=self.agent_id,
                providerName=provider_name,
                authorizationCode=authorization_code,
                sessionId=session_id
            )
            
            # Mark session as completed
            if session_id in self.session_store:
                self.session_store[session_id]["status"] = "completed"
            
            logger.info(f"Token authentication completed for session: {session_id}")
            return response
            
        except Exception as e:
            logger.error(f"Failed to complete token auth: {str(e)}")
            raise AuthenticationError(f"Token authentication failed: {str(e)}")


# FastAPI app for handling OAuth callbacks
callback_app = FastAPI(title="SBOM Agent OAuth Callback Handler")
oauth_handler = None  # Will be initialized with agent_id


@callback_app.on_event("startup")
async def startup_event():
    """Initialize OAuth handler on startup."""
    global oauth_handler
    
    # Get agent ID from environment or configuration
    agent_id = os.getenv("AGENTCORE_AGENT_ID")
    if not agent_id:
        logger.error("AGENTCORE_AGENT_ID environment variable not set")
        raise ValueError("Agent ID required for OAuth callback handler")
    
    oauth_handler = OAuth2CallbackHandler(agent_id)
    
    # Register callback URL
    callback_url = os.getenv("OAUTH_CALLBACK_URL", "https://your-domain.com/oauth/callback")
    await oauth_handler.register_callback_url(callback_url)


@callback_app.get("/oauth/callback")
async def oauth_callback(request: Request):
    """
    Handle OAuth2 callback from GitHub.
    
    This endpoint receives the authorization code and completes the token exchange.
    """
    try:
        # Extract parameters from callback
        query_params = dict(request.query_params)
        
        authorization_code = query_params.get("code")
        state = query_params.get("state")  # Contains session_id
        error = query_params.get("error")
        
        if error:
            logger.error(f"OAuth error: {error}")
            return HTMLResponse(
                content=f"""
                <html>
                    <body>
                        <h1>Authentication Error</h1>
                        <p>OAuth authentication failed: {error}</p>
                        <p>Please close this window and try again.</p>
                    </body>
                </html>
                """,
                status_code=400
            )
        
        if not authorization_code or not state:
            raise HTTPException(status_code=400, detail="Missing authorization code or state")
        
        # Extract session ID from state parameter
        session_id = state
        
        # Get current user ID (implement based on your authentication system)
        user_id = await get_current_user_id(request)
        
        # Verify session
        if not oauth_handler.verify_session(session_id, user_id):
            raise HTTPException(status_code=403, detail="Invalid session")
        
        # Complete token authentication
        token_response = await oauth_handler.complete_token_auth(
            session_id=session_id,
            authorization_code=authorization_code,
            provider_name="github-provider"
        )
        
        # Return success page
        return HTMLResponse(
            content="""
            <html>
                <body>
                    <h1>Authentication Successful</h1>
                    <p>GitHub authentication completed successfully!</p>
                    <p>You can now close this window and return to the SBOM Security Agent.</p>
                    <script>
                        // Notify parent window if opened in popup
                        if (window.opener) {
                            window.opener.postMessage({type: 'oauth_success'}, '*');
                            window.close();
                        }
                    </script>
                </body>
            </html>
            """
        )
        
    except Exception as e:
        logger.error(f"OAuth callback error: {str(e)}")
        return HTMLResponse(
            content=f"""
            <html>
                <body>
                    <h1>Authentication Error</h1>
                    <p>An error occurred during authentication: {str(e)}</p>
                    <p>Please close this window and try again.</p>
                </body>
            </html>
            """,
            status_code=500
        )


async def get_current_user_id(request: Request) -> str:
    """
    Get the current authenticated user ID from the request.
    
    This should be implemented based on your web application's
    authentication system (JWT, session cookies, etc.).
    
    Args:
        request: FastAPI request object
        
    Returns:
        str: User identifier
    """
    # Example implementation - replace with your authentication logic
    
    # Option 1: JWT token in Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
        # Decode JWT and extract user ID
        # user_id = decode_jwt_token(token)
        # return user_id
    
    # Option 2: Session cookie
    session_id = request.cookies.get("session_id")
    if session_id:
        # Look up user ID from session store
        # user_id = get_user_from_session(session_id)
        # return user_id
    
    # Option 3: Custom header
    user_id = request.headers.get("X-User-ID")
    if user_id:
        return user_id
    
    # Fallback - in production, this should raise an authentication error
    return "anonymous_user"


@callback_app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "oauth_callback_handler"}


# Export for use in main application
__all__ = ["OAuth2CallbackHandler", "callback_app"]