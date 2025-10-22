"""
Production authentication handler for AgentCore Runtime deployment.

This module provides the production-ready authentication flow that integrates
with the OAuth callback handler for secure token management.
"""

import asyncio
import json
import logging
from typing import Optional, Dict, Any

import boto3

from .config import Config
from .exceptions import AuthenticationError
from .oauth_callback import OAuth2CallbackHandler

logger = logging.getLogger(__name__)


class ProductionAuthManager:
    """Manages authentication in production AgentCore Runtime environment."""
    
    def __init__(self, agent_id: str, region: str = "us-east-1"):
        self.agent_id = agent_id
        self.region = region
        self.oauth_handler = OAuth2CallbackHandler(agent_id, region)
        self.agentcore_client = boto3.client('bedrock-agentcore-control', region_name=region)
        self._access_tokens = {}  # In production, use secure storage
    
    async def initiate_oauth_flow(self, user_id: str, provider_name: str = "github-provider") -> Dict[str, str]:
        """
        Initiate OAuth2 flow for production environment.
        
        Args:
            user_id: Unique identifier for the user
            provider_name: OAuth provider name
            
        Returns:
            Dict[str, str]: Contains authorization_url and session_id
        """
        try:
            # Generate session for this OAuth flow
            session_id = self.oauth_handler.generate_auth_session(user_id, provider_name)
            
            # Get OAuth2 authorization URL from AgentCore
            response = self.agentcore_client.get_resource_oauth2_authorization_url(
                agentId=self.agent_id,
                providerName=provider_name,
                scopes=Config.GITHUB_SCOPES,
                state=session_id  # Include session ID in state parameter
            )
            
            authorization_url = response.get("authorizationUrl")
            
            if not authorization_url:
                raise AuthenticationError("Failed to get authorization URL from AgentCore")
            
            logger.info(f"OAuth flow initiated for user {user_id}, session {session_id}")
            
            return {
                "authorization_url": authorization_url,
                "session_id": session_id,
                "provider_name": provider_name
            }
            
        except Exception as e:
            logger.error(f"Failed to initiate OAuth flow: {str(e)}")
            raise AuthenticationError(f"OAuth initiation failed: {str(e)}")
    
    async def get_access_token(self, user_id: str, provider_name: str = "github-provider") -> Optional[str]:
        """
        Get existing access token for user and provider.
        
        Args:
            user_id: User identifier
            provider_name: OAuth provider name
            
        Returns:
            Optional[str]: Access token if available and valid
        """
        try:
            # Check local cache first
            cache_key = f"{user_id}:{provider_name}"
            if cache_key in self._access_tokens:
                token_data = self._access_tokens[cache_key]
                
                # Check if token is still valid (basic expiration check)
                import time
                if time.time() < token_data.get("expires_at", 0):
                    return token_data["access_token"]
                else:
                    # Token expired, remove from cache
                    del self._access_tokens[cache_key]
            
            # Try to get token from AgentCore
            response = self.agentcore_client.get_resource_oauth2_token(
                agentId=self.agent_id,
                providerName=provider_name,
                userId=user_id
            )
            
            access_token = response.get("accessToken")
            expires_in = response.get("expiresIn", 3600)  # Default 1 hour
            
            if access_token:
                # Cache the token
                import time
                self._access_tokens[cache_key] = {
                    "access_token": access_token,
                    "expires_at": time.time() + expires_in - 300  # 5 min buffer
                }
                
                return access_token
            
            return None
            
        except Exception as e:
            logger.warning(f"Failed to get access token: {str(e)}")
            return None
    
    async def handle_token_completion(self, session_id: str, user_id: str) -> bool:
        """
        Handle completion of OAuth token flow.
        
        This is called after the OAuth callback has been processed
        to verify the token was obtained successfully.
        
        Args:
            session_id: OAuth session identifier
            user_id: User identifier
            
        Returns:
            bool: True if token was successfully obtained
        """
        try:
            # Verify session was completed
            session_data = self.oauth_handler.session_store.get(session_id)
            
            if not session_data or session_data["status"] != "completed":
                return False
            
            # Try to get the new access token
            provider_name = session_data["provider_name"]
            access_token = await self.get_access_token(user_id, provider_name)
            
            if access_token:
                logger.info(f"Token completion successful for user {user_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Token completion handling failed: {str(e)}")
            return False
    
    def clear_user_tokens(self, user_id: str) -> None:
        """
        Clear all cached tokens for a user.
        
        Args:
            user_id: User identifier
        """
        keys_to_remove = [key for key in self._access_tokens.keys() if key.startswith(f"{user_id}:")]
        for key in keys_to_remove:
            del self._access_tokens[key]
        
        logger.info(f"Cleared tokens for user {user_id}")


class ProductionAuthDecorator:
    """
    Production replacement for @requires_access_token decorator.
    
    This handles the more complex OAuth flow required in production
    AgentCore Runtime deployment.
    """
    
    def __init__(self, auth_manager: ProductionAuthManager):
        self.auth_manager = auth_manager
    
    def requires_access_token(
        self,
        provider_name: str = "github-provider",
        scopes: list = None,
        auth_flow: str = "USER_FEDERATION",
        force_authentication: bool = False
    ):
        """
        Decorator for functions that require OAuth2 access tokens in production.
        
        Args:
            provider_name: OAuth provider name
            scopes: Required OAuth scopes
            auth_flow: Authentication flow type
            force_authentication: Force re-authentication
        """
        def decorator(func):
            async def wrapper(*args, user_id: str, **kwargs):
                # Check if we have a valid token
                access_token = None
                
                if not force_authentication:
                    access_token = await self.auth_manager.get_access_token(user_id, provider_name)
                
                if not access_token:
                    # Need to initiate OAuth flow
                    oauth_data = await self.auth_manager.initiate_oauth_flow(user_id, provider_name)
                    
                    # Return OAuth initiation response
                    return {
                        "auth_required": True,
                        "authorization_url": oauth_data["authorization_url"],
                        "session_id": oauth_data["session_id"],
                        "message": f"Please visit the authorization URL to authenticate with {provider_name}"
                    }
                
                # Call the original function with the access token
                return await func(*args, access_token=access_token, **kwargs)
            
            return wrapper
        return decorator


# Example usage in production environment
async def create_production_auth_manager() -> ProductionAuthManager:
    """
    Create and configure production authentication manager.
    
    Returns:
        ProductionAuthManager: Configured auth manager
    """
    import os
    
    agent_id = os.getenv("AGENTCORE_AGENT_ID")
    if not agent_id:
        raise ValueError("AGENTCORE_AGENT_ID environment variable required")
    
    region = os.getenv("AWS_REGION", "us-east-1")
    
    auth_manager = ProductionAuthManager(agent_id, region)
    
    # Register callback URL
    callback_url = os.getenv("OAUTH_CALLBACK_URL")
    if callback_url:
        await auth_manager.oauth_handler.register_callback_url(callback_url)
    
    return auth_manager