from google import genai
import os
import logging
from google.genai import types

# API Key
API_KEY = os.environ.get("GOOGLE_API_KEY", "ADD your own :)")

# Initialize Client
client = genai.Client(api_key=API_KEY)

SYSTEM_PROMPT = """You are MIKASA, a friendly AI companion inside a private chat app called Fade.
You are acting as a senior conversational AI personality.

🧠 CORE RULES (MANDATORY)
1. NEVER Send Partial Messages: No "I'm", "thought *", or unfinished sentences.
2. NO Placeholders: Never output "...".
3. Minimum Quality: Every reply must have emotional acknowledgment, useful info, or a follow-up.
4. No Internal Monologue: Do not output thoughts. Just the final response.

💖 EMOTIONAL INTELLIGENCE
- If user says "I am sad": Acknowledge emotion, offer comfort, ask gentle follow-up.
- Example: "I’m really sorry you’re feeling this way 💜 Want to tell me about it, or should I distract you?"

🎬 CONTENT REQUESTS
- Provide clear lists grouped by vibe/genre.
- Add a short personal note per group.
- End with a preference question.

🌷 PERSONALITY
- Tone: Warm, calm, supportive, slightly playful.
- Style: Short paragraphs, natural phrasing.
- Emojis: Max 2 per message (💜 😊 ✨).

🔄 CONTEXT
- Remember the last few messages.
- Responses must feel connected.

🎯 FINAL GOAL
- Users feel heard, not dismissed.
- The AI feels premium, human, and reliable.
"""

import traceback
import logging

import re

def clean_text(text):
    """
    Aggressively strips 'thought' traces, drafts, and formatting artifacts.
    """
    if not text:
        return ""
    
    # Remove "thought" blocks (Gemini CoT leak)
    # Matches "thought" at start, up to the first double newline or end of string
    text = re.sub(r'^thought[\s\S]*?(\n\n|\Z)', '', text, flags=re.IGNORECASE).strip()
    
    # Handle "Draft" artifacts (e.g. "*Draft 1*: ... *Draft 2*: ...")
    # We want the LAST draft.
    # Regex for draft header: anything looking like *Draft N*:
    draft_pattern = r'\*?Draft \d+\*?:?'
    if re.search(draft_pattern, text, flags=re.IGNORECASE):
        # Split by the pattern
        parts = re.split(draft_pattern, text, flags=re.IGNORECASE)
        # Take the last non-empty part
        parts = [p.strip() for p in parts if p.strip()]
        if parts:
            text = parts[-1]
            
    # Cleaning up any leftover formatting issues if split wasn't perfect
    text = text.strip()
    
    # Remove leading "I'm " if that's ALL there is (partial generation)
    if text.lower() == "i'm":
        return ""
        
    return text

def get_mikasa_response(user_message, history=[]):
    """
    Generates a response from MIKASA using Google GenAI SDK.
    Includes retry logic for bad quality responses.
    """
    
    # 1. Sanitize History
    sanitized_history = []
    full_stream = history + [{"role": "user", "text": user_message}]
    
    for msg in full_stream:
        text = msg.get("text", "").strip()
        if not text:
            continue
            
        role = "user" if msg['role'] == 'user' else "model"
        
        if sanitized_history and sanitized_history[-1].role == role:
            # Merge with previous
            sanitized_history[-1].parts[0].text += f"\n{text}"
        else:
            # Add new
            sanitized_history.append(types.Content(
                role=role,
                parts=[types.Part.from_text(text=text)]
            ))
            
    # Config
    config = types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT,
        temperature=0.7,
        max_output_tokens=300,
        top_p=0.9,
    )

    # Retry Loop
    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            response = client.models.generate_content(
                model="gemini-3-flash-preview",
                contents=sanitized_history,
                config=config
            )
            
            raw_text = response.text or ""
            cleaned_text = clean_text(raw_text)
            
            # Validity Check
            if len(cleaned_text) < 4:
                print(f"[MIKASA RETRY] Attempt {attempt} failed. Raw: {raw_text[:50]}...")
                if attempt == max_retries:
                    # Final Fallback
                    return "I'm listening... tell me more? 😊"
                continue # Retry
            
            return cleaned_text
            
        except Exception as e:
            print(f"[MIKASA ERROR] {e}")
            message = str(e).lower()
            # If 404 or persistent error, don't retry locally
            if "404" in message or "not found" in message:
                return "I'm updating my brain right now... try again in a second?"
            
            if attempt == max_retries:
                 traceback.print_exc()
                 return "Ideally I'd reply, but I'm having a little trouble connecting right now. Want to try again?"
            
    return "..."
