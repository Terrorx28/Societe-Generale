"""
LLM-powered investigation summary generator.
Supports Hugging Face API (recommended) and OpenAI as fallback.
"""

import os
import json
from dotenv import load_dotenv
import requests

from destination import resolve_destination
from history import resolve_first_time

load_dotenv()

HF_API_KEY = os.getenv('HF_API_KEY', '')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')

def _call_huggingface_api(prompt: str) -> str:
    """
    Call Hugging Face Inference API for text generation.
    Uses Llama-2-7b-chat model - free tier supported.
    """
    if not HF_API_KEY:
        return None
    
    try:
        response = requests.post(
            'https://api-inference.huggingface.co/models/meta-llama/Llama-2-7b-chat-hf',
            headers={'Authorization': f'Bearer {HF_API_KEY}'},
            json={'inputs': prompt},
            timeout=15
        )
        if response.status_code == 200:
            result = response.json()
            if isinstance(result, list) and len(result) > 0:
                generated = result[0].get('generated_text', '').strip()
                # Extract just the summary part (after the prompt)
                if prompt in generated:
                    generated = generated.split(prompt)[-1].strip()
                return generated if generated else None
    except Exception as e:
        print(f"Hugging Face API error: {e}")
    
    return None

def _call_openai_api(prompt: str) -> str:
    """
    Call OpenAI API as fallback if Hugging Face not available.
    """
    if not OPENAI_API_KEY:
        return None
    
    try:
        response = requests.post(
            'https://api.openai.com/v1/chat/completions',
            headers={'Authorization': f'Bearer {OPENAI_API_KEY}'},
            json={
                'model': 'gpt-3.5-turbo',
                'messages': [{'role': 'user', 'content': prompt}],
                'temperature': 0.7,
                'max_tokens': 150,
            },
            timeout=10
        )
        if response.status_code == 200:
            return response.json()['choices'][0]['message']['content'].strip()
    except Exception as e:
        print(f"OpenAI API error: {e}")
    
    return None

def investigate_access(access_data: dict) -> str:
    """
    Generate LLM-powered investigation summary for an access event.
    Tries Hugging Face first (recommended), then OpenAI, then falls back to rules.
    
    Args:
        access_data: dict with keys:
            - username, user_id, department, job_title, privilege_level
            - resource, resource_sensitivity, action
            - timestamp, time_classification, rowcount, deviation_from_user_avg
            - ml_anomaly_score, rules_triggered, severity
    
    Returns:
        Human-readable investigation summary string
    """
    
    destination_type, destination_score = resolve_destination(access_data)
    is_first_time, _ = resolve_first_time(access_data)

    prompt = f"""Analyze this data access event and provide a concise, professional risk assessment:

User: {access_data.get('username', 'Unknown')} ({access_data.get('job_title', 'N/A')})
Department: {access_data.get('department', 'Unknown')}
Privilege: {access_data.get('privilege_level', 'user')}

Action: {access_data.get('action', 'unknown').replace('_', ' ')}
Resource: {access_data.get('resource', 'Unknown')} (Sensitivity: {access_data.get('resource_sensitivity', 'unknown').upper()})
First-Time Resource Access: {'YES — user has never accessed this resource before' if is_first_time else 'No — user has accessed this resource before'}
Destination: {destination_type.replace('_', ' ')} (destination risk contribution: {destination_score})
Time: {access_data.get('timestamp', 'Unknown')} ({access_data.get('time_classification', 'unknown').replace('_', ' ')})
Data Volume: {access_data.get('rowcount', 0)} rows (user avg: {access_data.get('user_avg_rowcount', 0)}, deviation: {access_data.get('deviation_from_user_avg_rowcount', 0)})
ML Anomaly Score: {access_data.get('ml_anomaly_score', 0):.1f}/100
Risk Level: {access_data.get('severity', 'MEDIUM')}
Triggered Rules: {', '.join(access_data.get('rules_triggered', []))}

Provide a 2-3 sentence risk summary explaining:
1. What makes this access unusual or risky
2. Why it matters in context of this user's role
3. Recommended action (investigate, monitor, block, or approve)

Format as: "[RISK_LEVEL] - [Summary]. [Action]"
"""
    
    # Try Hugging Face first (recommended - free tier friendly)
    if HF_API_KEY:
        result = _call_huggingface_api(prompt)
        if result:
            return result
    
    # Fallback to OpenAI
    if OPENAI_API_KEY:
        result = _call_openai_api(prompt)
        if result:
            return result
    
    # Final fallback: rule-based investigation
    return _fallback_investigation(access_data)

def _fallback_investigation(data: dict) -> str:
    """Fallback rule-based investigation when LLM is unavailable."""
    
    risk_level = data.get('severity', 'MEDIUM')
    username = data.get('username', 'Unknown')
    action = data.get('action', 'access').replace('_', ' ')
    resource = data.get('resource', 'resource')
    sensitivity = data.get('resource_sensitivity', 'unknown').upper()
    time_class = data.get('time_classification', 'unknown').replace('_', ' ')
    rowcount = data.get('rowcount', 0)
    deviation = data.get('deviation_from_user_avg_rowcount', 0)
    anomaly_score = data.get('ml_anomaly_score', 0)
    destination_type, destination_score = resolve_destination(data)
    is_first_time, _ = resolve_first_time(data)
    
    # Build summary
    factors = []
    
    # First-time access to a resource is a strong behavioral signal.
    if is_first_time:
        factors.append(f"first-time access to {resource} (no prior history for this user)")
    
    if sensitivity == 'HIGH':
        factors.append(f"accessed high-sensitivity {resource}")
    
    if time_class != 'business_hours':
        factors.append(f"{action} during {time_class}")
    
    if abs(deviation) > 100:
        factors.append(f"data volume {rowcount} rows (typically {data.get('user_avg_rowcount', 0):.0f})")
    
    if anomaly_score > 60:
        factors.append("unusual access pattern detected by ML model")
    
    # High-risk exfiltration destinations are a strong signal on their own.
    if destination_score >= 15:
        factors.append(f"data routed to {destination_type.replace('_', ' ').lower()} (destination risk +{destination_score})")
    
    factor_str = "; ".join(factors) if factors else "routine access"
    
    # Determine action
    if risk_level == 'CRITICAL':
        action_rec = "IMMEDIATE investigation required. Consider temporary access suspension."
    elif risk_level == 'HIGH':
        action_rec = "Schedule investigation within 24 hours. Monitor for related activity."
    else:
        action_rec = "Monitor for context. Escalate if repeated."
    
    return f"[{risk_level}] - {username} {action} with {factor_str}. {action_rec}"

def batch_investigate(events: list) -> dict:
    """Generate investigations for multiple events."""
    return {
        event.get('id', idx): investigate_access(event)
        for idx, event in enumerate(events)
    }
