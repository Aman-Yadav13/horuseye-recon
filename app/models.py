from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any

class ToolParameter(BaseModel):
    flag: str
    description: Optional[str] = None
    value: Optional[str] = None
    requiresValue: Optional[bool] = False

class ToolExecutionRequest(BaseModel):
    name: str = Field(..., description="The name of the tool to execute (e.g., 'nmap')")
    parameters: List[ToolParameter] = Field(default_factory=list)

class ScanRequest(BaseModel):
    target: str = Field(..., description="The target IP address or hostname")
    tools: List[ToolExecutionRequest] = Field(..., description="List of tools and their parameters to run")
    scan_id: str = Field(..., description="A unique identifier for this scan from the API Gateway")

    @validator('target')
    def target_must_be_valid(cls, v):
        if not v or not v.strip():
            raise ValueError('Target cannot be empty')
        return v.strip()

class ToolOutput(BaseModel):
    tool_name: str
    command: List[str]
    return_code: int
    stdout: str
    stderr: str
    output_file_paths: List[str] = Field(default_factory=list)
    success: bool

class ScanResponse(BaseModel):
    scan_id: str
    target: str
    target_domain: Optional[str] = None
    results: List[ToolOutput]
    message: str
    status: str