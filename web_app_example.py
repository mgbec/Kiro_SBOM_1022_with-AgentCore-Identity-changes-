"""
Example web application that integrates with the SBOM Security Agent
and handles OAuth callbacks for production deployment.

This demonstrates how to build a web application that:
1. Hosts the OAuth callback endpoint
2. Manages user sessions
3. Integrates with the SBOM Security Agent
"""

import os
import asyncio
import json
from typing import Dict, Any, Optional

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import httpx
import uvicorn

from src.sbom_agent.oauth_callback import callback_app
from src.sbom_agent.production_auth import ProductionAuthManager

# Initialize FastAPI app
app = FastAPI(title="SBOM Security Agent Web Interface")

# Mount the OAuth callback handler
app.mount("/oauth", callback_app)

# Static files and templates (create these directories)
# app.mount("/static", StaticFiles(directory="static"), name="static")
# templates = Jinja2Templates(directory="templates")

# Global auth manager (initialize on startup)
auth_manager: Optional[ProductionAuthManager] = None
agent_endpoint = os.getenv("AGENTCORE_AGENT_ENDPOINT", "https://your-agent-endpoint.amazonaws.com")


@app.on_event("startup")
async def startup_event():
    """Initialize the application on startup."""
    global auth_manager
    
    agent_id = os.getenv("AGENTCORE_AGENT_ID")
    if not agent_id:
        raise ValueError("AGENTCORE_AGENT_ID environment variable required")
    
    auth_manager = ProductionAuthManager(agent_id)
    print(f"Web application started with agent ID: {agent_id}")


async def get_current_user(request: Request) -> str:
    """
    Extract current user ID from request.
    
    In a real application, this would validate JWT tokens,
    session cookies, or other authentication mechanisms.
    """
    # Example: Extract from JWT token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        # In production, decode and validate JWT
        # For demo, extract user ID from token
        token = auth_header[7:]
        # user_id = decode_jwt_token(token)["user_id"]
        # return user_id
    
    # Example: Extract from session cookie
    session_id = request.cookies.get("session_id")
    if session_id:
        # In production, look up user from session store
        # user_id = get_user_from_session(session_id)
        # return user_id
    
    # For demo purposes, use a header or default
    return request.headers.get("X-User-ID", "demo_user")


@app.get("/", response_class=HTMLResponse)
async def home():
    """Home page with SBOM Security Agent interface."""
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SBOM Security Agent</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .container { background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }
            button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
            button:hover { background: #0056b3; }
            .result { background: white; padding: 15px; border-radius: 4px; margin: 10px 0; white-space: pre-wrap; }
            .error { background: #f8d7da; color: #721c24; }
            .success { background: #d4edda; color: #155724; }
        </style>
    </head>
    <body>
        <h1>🔍 SBOM Security Agent</h1>
        
        <div class="container">
            <h2>Analyze Repository</h2>
            <p>Enter a GitHub repository URL to perform security analysis:</p>
            <input type="text" id="repoUrl" placeholder="https://github.com/owner/repo" style="width: 400px; padding: 8px;">
            <button onclick="analyzeRepository()">Analyze Repository</button>
        </div>
        
        <div class="container">
            <h2>Generate SBOM</h2>
            <p>Generate Software Bill of Materials:</p>
            <input type="text" id="sbomRepoUrl" placeholder="https://github.com/owner/repo" style="width: 300px; padding: 8px;">
            <select id="sbomFormat" style="padding: 8px;">
                <option value="both">Both Formats</option>
                <option value="spdx">SPDX Only</option>
                <option value="cyclonedx">CycloneDX Only</option>
            </select>
            <button onclick="generateSBOM()">Generate SBOM</button>
        </div>
        
        <div id="results"></div>
        
        <script>
            async function analyzeRepository() {
                const repoUrl = document.getElementById('repoUrl').value;
                if (!repoUrl) {
                    alert('Please enter a repository URL');
                    return;
                }
                
                showResult('Starting repository analysis...', 'info');
                
                try {
                    const response = await fetch('/api/analyze', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-User-ID': 'demo_user'
                        },
                        body: JSON.stringify({
                            repository_url: repoUrl,
                            analysis_type: 'comprehensive'
                        })
                    });
                    
                    const result = await response.json();
                    
                    if (result.auth_required) {
                        handleAuthRequired(result);
                    } else {
                        showResult(JSON.stringify(result, null, 2), 'success');
                    }
                } catch (error) {
                    showResult('Error: ' + error.message, 'error');
                }
            }
            
            async function generateSBOM() {
                const repoUrl = document.getElementById('sbomRepoUrl').value;
                const format = document.getElementById('sbomFormat').value;
                
                if (!repoUrl) {
                    alert('Please enter a repository URL');
                    return;
                }
                
                showResult('Generating SBOM...', 'info');
                
                try {
                    const response = await fetch('/api/sbom', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-User-ID': 'demo_user'
                        },
                        body: JSON.stringify({
                            repository_url: repoUrl,
                            format: format
                        })
                    });
                    
                    const result = await response.json();
                    
                    if (result.auth_required) {
                        handleAuthRequired(result);
                    } else {
                        showResult(JSON.stringify(result, null, 2), 'success');
                    }
                } catch (error) {
                    showResult('Error: ' + error.message, 'error');
                }
            }
            
            function handleAuthRequired(result) {
                showResult('Authentication required. Opening GitHub authorization...', 'info');
                
                // Open OAuth URL in popup
                const popup = window.open(
                    result.authorization_url,
                    'oauth',
                    'width=600,height=700,scrollbars=yes,resizable=yes'
                );
                
                // Listen for OAuth completion
                window.addEventListener('message', function(event) {
                    if (event.data.type === 'oauth_success') {
                        popup.close();
                        showResult('Authentication successful! You can now retry your request.', 'success');
                    }
                });
            }
            
            function showResult(message, type) {
                const resultsDiv = document.getElementById('results');
                const resultDiv = document.createElement('div');
                resultDiv.className = 'result ' + type;
                resultDiv.textContent = message;
                resultsDiv.appendChild(resultDiv);
                resultsDiv.scrollTop = resultsDiv.scrollHeight;
            }
        </script>
    </body>
    </html>
    """)


@app.post("/api/analyze")
async def analyze_repository(request: Request):
    """API endpoint to analyze a repository."""
    try:
        data = await request.json()
        user_id = await get_current_user(request)
        
        repository_url = data.get("repository_url")
        if not repository_url:
            raise HTTPException(status_code=400, detail="Repository URL required")
        
        # Check if user has valid GitHub token
        access_token = await auth_manager.get_access_token(user_id, "github-provider")
        
        if not access_token:
            # Initiate OAuth flow
            oauth_data = await auth_manager.initiate_oauth_flow(user_id, "github-provider")
            return JSONResponse(content={
                "auth_required": True,
                "authorization_url": oauth_data["authorization_url"],
                "session_id": oauth_data["session_id"],
                "message": "Please authenticate with GitHub to analyze repositories"
            })
        
        # Call the SBOM Security Agent
        agent_response = await call_agent({
            "prompt": f"Analyze the repository {repository_url} for security vulnerabilities and generate a comprehensive report"
        }, user_id)
        
        return JSONResponse(content=agent_response)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/sbom")
async def generate_sbom(request: Request):
    """API endpoint to generate SBOM."""
    try:
        data = await request.json()
        user_id = await get_current_user(request)
        
        repository_url = data.get("repository_url")
        format_type = data.get("format", "both")
        
        if not repository_url:
            raise HTTPException(status_code=400, detail="Repository URL required")
        
        # Check authentication
        access_token = await auth_manager.get_access_token(user_id, "github-provider")
        
        if not access_token:
            oauth_data = await auth_manager.initiate_oauth_flow(user_id, "github-provider")
            return JSONResponse(content={
                "auth_required": True,
                "authorization_url": oauth_data["authorization_url"],
                "session_id": oauth_data["session_id"],
                "message": "Please authenticate with GitHub to generate SBOM"
            })
        
        # Call the SBOM Security Agent
        agent_response = await call_agent({
            "prompt": f"Generate {format_type} SBOM for repository {repository_url}"
        }, user_id)
        
        return JSONResponse(content=agent_response)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def call_agent(payload: Dict[str, Any], user_id: str) -> Dict[str, Any]:
    """
    Call the SBOM Security Agent with the given payload.
    
    Args:
        payload: Request payload for the agent
        user_id: Current user identifier
        
    Returns:
        Dict[str, Any]: Agent response
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{agent_endpoint}/invocations",
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "X-User-ID": user_id,
                    # Add authentication headers as needed
                },
                timeout=300  # 5 minutes
            )
            
            response.raise_for_status()
            return response.json()
            
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"Agent communication error: {str(e)}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"Agent error: {e.response.text}")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "sbom_web_app"}


if __name__ == "__main__":
    # For development only
    uvicorn.run(
        "web_app_example:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )