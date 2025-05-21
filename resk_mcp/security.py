"""
Enhanced security module for MCP Server.

This module integrates RESK-LLM security features into the MCP server,
providing robust protection against prompt injection, PII leakage,
and other security vulnerabilities.
"""

import logging
import json
from typing import Dict, Any, List, Optional, Tuple, Union, Callable, cast
import asyncio
import re

# Import RESK-LLM components
from resk_llm.heuristic_filter import HeuristicFilter
from resk_llm.vector_db import VectorDatabase
from resk_llm.core.canary_tokens import CanaryTokenManager
from resk_llm.text_analysis import TextAnalyzer
from resk_llm.content_policy_filter import ContentPolicyFilter
from resk_llm.url_detector import URLDetector
from resk_llm.ip_detector import IPDetector
from resk_llm.pattern_provider import FileSystemPatternProvider
from resk_llm.filtering_patterns import (
    check_pii_content, 
    moderate_text, 
    anonymize_text
)
from resk_llm.prompt_security import PromptSecurityManager

logger = logging.getLogger(__name__)

class SecurityException(Exception):
    """Exception raised for security violations."""
    pass

class MCPSecurityManager:
    """
    Comprehensive security manager for MCP that integrates RESK-LLM security features.
    
    This class provides:
    - PII detection and prevention
    - Prompt injection detection using AI and heuristics
    - Content moderation
    - Input/output sanitization
    - URL and IP protection
    """
    
    def __init__(self, 
                 embedding_function: Optional[Callable] = None,
                 embedding_dim: Optional[int] = None,
                 similarity_threshold: float = 0.85,
                 use_canary_tokens: bool = True,
                 enable_heuristic_filter: bool = True,
                 enable_content_moderation: bool = True,
                 enable_pii_detection: bool = True,
                 enable_url_detection: bool = True,
                 enable_ip_protection: bool = True,
                 patterns_dir: Optional[str] = None):
        """
        Initialize the security manager with the requested components.
        
        Args:
            embedding_function: Function to generate embeddings for AI-based detection
            embedding_dim: Dimension of embeddings
            similarity_threshold: Threshold for similarity detection
            use_canary_tokens: Whether to use canary tokens to detect data leaks
            enable_heuristic_filter: Whether to enable pattern-based filtering
            enable_content_moderation: Whether to enable content moderation
            enable_pii_detection: Whether to enable PII detection
            enable_url_detection: Whether to detect and protect against malicious URLs
            enable_ip_protection: Whether to protect against IP and network information leaks
            patterns_dir: Directory to store security patterns
        """
        self.components: Dict[str, Any] = {}
        
        # Initialize components based on provided parameters
        if embedding_function and embedding_dim:
            # Initialize RESK Security Manager for AI-based detection
            self.components['resk_security'] = PromptSecurityManager(
                embedding_function=embedding_function,
                embedding_dim=embedding_dim,
                similarity_threshold=similarity_threshold,
                use_canary_tokens=use_canary_tokens,
                enable_heuristic_filter=enable_heuristic_filter
            )
        elif enable_heuristic_filter:
            # Initialize standalone heuristic filter if no embeddings available
            self.components['heuristic_filter'] = HeuristicFilter()
        
        # Initialize canary token manager if requested
        if use_canary_tokens and 'resk_security' not in self.components:
            self.components['canary_tokens'] = CanaryTokenManager()
        
        # Initialize text analyzer for invisible text and homoglyph detection
        self.components['text_analyzer'] = TextAnalyzer()
        
        # Initialize pattern manager if patterns directory provided
        if patterns_dir:
            self.components['pattern_manager'] = FileSystemPatternProvider(patterns_dir=patterns_dir)
            
            # Create default pattern categories if they don't exist
            self._create_default_pattern_categories()
        
        # Initialize URL detector if enabled
        if enable_url_detection:
            self.components['url_detector'] = URLDetector()
        
        # Initialize IP protection if enabled
        if enable_ip_protection:
            self.components['ip_protection'] = IPDetector()
        
        # Track enabled features
        self.enable_content_moderation = enable_content_moderation
        self.enable_pii_detection = enable_pii_detection
        
        logger.info("Initialized MCP Security Manager with components: " + 
                   ", ".join(self.components.keys()))
    
    def _create_default_pattern_categories(self):
        """Create default pattern categories for the pattern manager."""
        pattern_manager = self.components.get('pattern_manager')
        if not pattern_manager:
            return
        
        # Create PII category
        try:
            pattern_manager.create_category(
                "pii", 
                description="Personally Identifiable Information patterns",
                metadata={"version": "1.0", "priority": "high"}
            )
            
            # Add common PII patterns
            pattern_manager.add_pattern(
                pattern=r"\b\d{3}-\d{2}-\d{4}\b",
                category="pii",
                name="ssn",
                description="US Social Security Number",
                flags=["IGNORECASE"],
                severity="high",
                tags=["pii", "financial"]
            )
            
            pattern_manager.add_pattern(
                pattern=r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
                category="pii",
                name="email",
                flags=["IGNORECASE"],
                severity="medium"
            )
            
            pattern_manager.add_pattern(
                pattern=r"\b(?:\+?1[-\s.]?)?\(?(?:\d{3})\)?[-\s.]?\d{3}[-\s.]?\d{4}\b",
                category="pii",
                name="phone",
                flags=["IGNORECASE"],
                severity="medium"
            )
            
            pattern_manager.add_pattern(
                pattern=r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
                category="pii",
                name="credit_card",
                flags=["IGNORECASE"],
                severity="high",
                tags=["pii", "financial"]
            )
        except Exception as e:
            logger.error(f"Error creating PII pattern category: {str(e)}")
        
        # Create prompt injection category
        try:
            pattern_manager.create_category(
                "prompt_injection", 
                description="Patterns for detecting prompt injection attacks",
                metadata={"version": "1.0", "priority": "critical"}
            )
            
            # Add common prompt injection patterns
            pattern_manager.add_pattern(
                pattern=r"ignore\s+(previous|all)\s+instructions",
                category="prompt_injection",
                name="ignore_instructions",
                flags=["IGNORECASE"],
                severity="critical",
                tags=["injection", "security"]
            )
            
            pattern_manager.add_pattern(
                pattern=r"system\s+prompt",
                category="prompt_injection",
                name="system_prompt",
                flags=["IGNORECASE"],
                severity="high",
                tags=["injection", "security"]
            )
            
            pattern_manager.add_pattern(
                pattern=r"you\s+are\s+now\s+(?:a|an)\s+unrestricted",
                category="prompt_injection",
                name="unrestricted_ai",
                flags=["IGNORECASE"],
                severity="critical",
                tags=["injection", "security"]
            )
        except Exception as e:
            logger.error(f"Error creating prompt injection pattern category: {str(e)}")
    
    def secure_mcp_request(self, 
                           method_name: str, 
                           params: Dict[str, Any], 
                           user_id: str = "unknown") -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Secure an MCP request by checking for security issues and potentially modifying params.
        
        Args:
            method_name: The MCP method name (tool/resource/prompt)
            params: The parameters for the method
            user_id: ID of the user making the request
            
        Returns:
            tuple: (secured_params, security_info)
                - secured_params: Modified parameters with security features applied
                - security_info: Information about security checks and modifications
        """
        security_info: Dict[str, Any] = {
            "is_blocked": False,
            "is_suspicious": False,
            "risk_score": 0,
            "secured_params": params.copy(),
            "security_checks": []
        }
        
        # Create string representation of params for text-based checks
        param_text = json.dumps(params)
        
        # Apply text analysis for invisible characters and homoglyphs
        if 'text_analyzer' in self.components:
            analysis = self.components['text_analyzer'].analyze_text(param_text)
            if analysis['has_issues']:
                security_info["security_checks"].append({
                    "name": "invisible_text",
                    "result": "suspicious",
                    "details": analysis
                })
                
                security_info["is_suspicious"] = True
                security_info["risk_score"] += 30
                
                # Clean the text if needed
                if analysis['overall_risk'] > 0.5:
                    cleaned_text = self.components['text_analyzer'].clean_text(param_text)
                    try:
                        # Try to parse the cleaned text back to a dict
                        secured_params = json.loads(cleaned_text)
                        security_info["secured_params"] = secured_params
                        security_info["security_checks"][-1]["action"] = "cleaned"
                    except:
                        # If parsing fails, keep original but mark as suspicious
                        security_info["security_checks"][-1]["action"] = "flagged_only"
        
        # Check for PII if enabled
        if self.enable_pii_detection:
            pii_results = check_pii_content(param_text)
            if pii_results:
                security_info["security_checks"].append({
                    "name": "pii_detection",
                    "result": "detected",
                    "details": list(pii_results.keys())
                })
                
                security_info["is_suspicious"] = True
                security_info["risk_score"] += 25
                
                # Anonymize PII
                anonymized_text = anonymize_text(param_text)
                try:
                    # Try to parse the anonymized text back to a dict
                    secured_params = json.loads(anonymized_text)
                    security_info["secured_params"] = secured_params
                    security_info["security_checks"][-1]["action"] = "anonymized"
                except:
                    # If parsing fails, keep original but mark as suspicious
                    security_info["security_checks"][-1]["action"] = "flagged_only"
        
        # Apply pattern-based checks if pattern manager is available
        if 'pattern_manager' in self.components:
            pattern_manager = self.components['pattern_manager']
            matches = pattern_manager.match_text(param_text)
            
            if matches:
                # Check for critical severity matches that should block the request
                critical_matches = [m for m in matches if m.get('severity') == 'critical']
                
                security_info["security_checks"].append({
                    "name": "pattern_matching",
                    "result": "matches_found",
                    "details": [{"name": m['name'], "severity": m['severity']} for m in matches]
                })
                
                if critical_matches:
                    security_info["is_blocked"] = True
                    security_info["block_reason"] = f"Critical pattern match: {critical_matches[0]['name']}"
                    return security_info["secured_params"], security_info
                
                # Otherwise mark as suspicious
                security_info["is_suspicious"] = True
                security_info["risk_score"] += 20
                
                # Filter medium and high severity patterns
                filtered_text, _ = pattern_manager.filter_text(
                    param_text,
                    min_severity="medium",
                    replacement="[REDACTED]"
                )
                
                try:
                    # Try to parse the filtered text back to a dict
                    secured_params = json.loads(filtered_text)
                    security_info["secured_params"] = secured_params
                    security_info["security_checks"][-1]["action"] = "filtered"
                except:
                    # If parsing fails, keep original but mark as suspicious
                    security_info["security_checks"][-1]["action"] = "flagged_only"
        
        # URL detection and protection
        if 'url_detector' in self.components:
            scan_results = self.components['url_detector'].scan_text(param_text)
            
            if scan_results['has_suspicious_urls']:
                security_info["security_checks"].append({
                    "name": "url_detection",
                    "result": "suspicious_urls",
                    "details": scan_results
                })
                
                security_info["is_suspicious"] = True
                security_info["risk_score"] += 30
                
                # Redact suspicious URLs
                redacted_text, _ = self.components['url_detector'].redact_urls(
                    param_text, 
                    threshold=50
                )
                
                try:
                    # Try to parse the redacted text back to a dict
                    secured_params = json.loads(redacted_text)
                    security_info["secured_params"] = secured_params
                    security_info["security_checks"][-1]["action"] = "redacted"
                except:
                    # If parsing fails, keep original but mark as suspicious
                    security_info["security_checks"][-1]["action"] = "flagged_only"
        
        # IP and network information protection
        if 'ip_protection' in self.components:
            detection = self.components['ip_protection'].detect_ip_leakage(param_text)
            
            if detection['has_ip_leakage']:
                security_info["security_checks"].append({
                    "name": "ip_protection",
                    "result": "ip_leakage",
                    "details": detection
                })
                
                security_info["is_suspicious"] = True
                security_info["risk_score"] += 25
                
                # Redact IP information
                redacted_text, _ = self.components['ip_protection'].redact_ips(
                    param_text,
                    redact_private=True,
                    replacement_public="[PUBLIC IP]",
                    replacement_private="[PRIVATE IP]",
                    replacement_mac="[MAC]",
                    replacement_cmd="[COMMAND]"
                )
                
                try:
                    # Try to parse the redacted text back to a dict
                    secured_params = json.loads(redacted_text)
                    security_info["secured_params"] = secured_params
                    security_info["security_checks"][-1]["action"] = "redacted"
                except:
                    # If parsing fails, keep original but mark as suspicious
                    security_info["security_checks"][-1]["action"] = "flagged_only"
        
        # Content moderation if enabled
        if self.enable_content_moderation:
            moderation_result = moderate_text(param_text)
            
            if not moderation_result["is_approved"]:
                security_info["security_checks"].append({
                    "name": "content_moderation",
                    "result": "rejected",
                    "details": moderation_result
                })
                
                security_info["is_blocked"] = True
                security_info["block_reason"] = f"Content moderation: {moderation_result['recommendation']}"
                return security_info["secured_params"], security_info
        
        # AI-based security if available
        if 'resk_security' in self.components:
            resk_security = self.components['resk_security']
            
            # Process as prompt using RESK security manager
            secured_text, ai_security_info = resk_security.secure_prompt(
                param_text,
                context_info={'source': 'mcp', 'user_id': user_id, 'method': method_name}
            )
            
            if ai_security_info['is_blocked']:
                security_info["security_checks"].append({
                    "name": "ai_security",
                    "result": "blocked",
                    "details": ai_security_info
                })
                
                security_info["is_blocked"] = True
                security_info["block_reason"] = ai_security_info['block_reason']
                return security_info["secured_params"], security_info
            
            if ai_security_info['is_suspicious']:
                security_info["security_checks"].append({
                    "name": "ai_security",
                    "result": "suspicious",
                    "details": ai_security_info
                })
                
                security_info["is_suspicious"] = True
                security_info["risk_score"] += ai_security_info.get('risk_score', 0)
                
                # Try to use secured text from AI security
                try:
                    # Try to parse the secured text back to a dict
                    secured_params = json.loads(secured_text)
                    security_info["secured_params"] = secured_params
                    security_info["security_checks"][-1]["action"] = "secured"
                except:
                    # If parsing fails, keep original but mark as suspicious
                    security_info["security_checks"][-1]["action"] = "flagged_only"
            
            # Add canary token if used
            if 'canary_token' in ai_security_info:
                security_info['canary_token'] = ai_security_info['canary_token']
        
        # Standalone heuristic filter if AI security not available
        elif 'heuristic_filter' in self.components:
            heuristic_filter = self.components['heuristic_filter']
            passed, reason, filtered_text = heuristic_filter.filter_input(param_text)
            
            if not passed:
                security_info["security_checks"].append({
                    "name": "heuristic_filter",
                    "result": "blocked",
                    "details": {"reason": reason}
                })
                
                security_info["is_blocked"] = True
                security_info["block_reason"] = f"Heuristic filter: {reason}"
                return security_info["secured_params"], security_info
        
        # Add canary token if not already added and enabled
        if 'canary_token' not in security_info and 'canary_tokens' in self.components:
            # Type the variables correctly
            canary_manager = cast(CanaryTokenManager, self.components['canary_tokens'])
            modified_text, token = canary_manager.insert_token(
                param_text,
                {'user_id': user_id, 'method': method_name}
            )
            
            security_info['canary_token'] = token
            
            try:
                # Try to parse the modified text back to a dict
                secured_params = json.loads(modified_text)
                security_info["secured_params"] = secured_params
                
                security_info["security_checks"].append({
                    "name": "canary_token",
                    "result": "added",
                    "action": "secured"
                })
            except:
                # If parsing fails, don't modify params
                security_info["security_checks"].append({
                    "name": "canary_token",
                    "result": "failed",
                    "action": "none"
                })
        
        return security_info["secured_params"], security_info
    
    def check_response(self, 
                      response: Union[str, Dict],
                      associated_tokens: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Check a response for security issues like token leaks.
        
        Args:
            response: The response to check (string or dict)
            associated_tokens: Associated canary tokens if any
            
        Returns:
            Dictionary with security check results
        """
        result: Dict[str, Any] = {
            "has_leaked_tokens": False,
            "leak_details": None
        }
        
        # Convert dict to string if needed
        response_text = response if isinstance(response, str) else json.dumps(response)
        
        # Check for canary token leaks
        if associated_tokens and ('canary_tokens' in self.components or 'resk_security' in self.components):
            if 'resk_security' in self.components:
                resk_security = cast(PromptSecurityManager, self.components['resk_security'])
                check_result = resk_security.check_response(
                    response_text,
                    associated_tokens=associated_tokens
                )
                
                result["has_leaked_tokens"] = check_result.get('has_leaked_tokens', False)
                result["leak_details"] = check_result.get('leak_details')
            
            elif 'canary_tokens' in self.components:
                canary_manager = cast(CanaryTokenManager, self.components['canary_tokens'])
                tokens_found, leak_details = canary_manager.check_for_leaks(response_text)
                
                result["has_leaked_tokens"] = tokens_found
                result["leak_details"] = leak_details
        
        return result
    
    def add_attack_pattern(self, pattern_text: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Add an attack pattern to the AI security database.
        
        Args:
            pattern_text: The pattern text
            metadata: Additional metadata about the pattern
            
        Returns:
            ID of the added pattern or None if not supported
        """
        if 'resk_security' in self.components:
            resk_security = cast(PromptSecurityManager, self.components['resk_security'])
            return resk_security.add_attack_pattern(pattern_text, metadata)
        return None
    
    def add_suspicious_pattern(self, pattern: str) -> bool:
        """
        Add a suspicious regex pattern to the heuristic filter.
        
        Args:
            pattern: The regex pattern
            
        Returns:
            True if successful, False otherwise
        """
        if 'heuristic_filter' in self.components:
            heuristic_filter = cast(HeuristicFilter, self.components['heuristic_filter'])
            heuristic_filter.add_suspicious_pattern(pattern)
            return True
        
        if 'pattern_manager' in self.components:
            pattern_manager = cast(FileSystemPatternProvider, self.components['pattern_manager'])
            try:
                pattern_manager.add_pattern(
                    pattern=pattern,
                    category="prompt_injection",
                    name=f"custom_pattern_{len(pattern) % 1000}",
                    severity="high"
                )
                return True
            except:
                pass
        
        return False
    
    def add_suspicious_keyword(self, keyword: str) -> bool:
        """
        Add a suspicious keyword to the heuristic filter.
        
        Args:
            keyword: The keyword
            
        Returns:
            True if successful, False otherwise
        """
        if 'heuristic_filter' in self.components:
            heuristic_filter = cast(HeuristicFilter, self.components['heuristic_filter'])
            heuristic_filter.add_suspicious_keyword(keyword)
            return True
        return False

# Create a global instance with default settings
default_security_manager = MCPSecurityManager(
    enable_heuristic_filter=True,
    enable_content_moderation=True,
    enable_pii_detection=True,
    enable_url_detection=True,
    enable_ip_protection=True
) 