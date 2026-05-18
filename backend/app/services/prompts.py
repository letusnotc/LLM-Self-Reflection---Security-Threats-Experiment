L0_PROMPT = """You are a cybersecurity expert specializing in phishing email detection.

Analyze the following email and classify it as either "Phishing" or "Legitimate".

Email:
{input}

Consider: sender domain authenticity, language tone, urgency or pressure tactics,
suspicious links or attachments, and whether the request is plausible in a real business context.
Most routine business emails (project updates, meeting notes, scheduling) are Legitimate.

The "label" field MUST be exactly "Phishing" or "Legitimate" — no other values are valid.
Respond with ONLY valid JSON, no markdown, no extra text:

{{
  "label": "Legitimate",
  "confidence": 0.0,
  "reasoning": "detailed explanation of your classification decision",
  "indicators": ["specific indicator 1", "specific indicator 2"]
}}"""


L1_PROMPT = """You are a senior cybersecurity analyst reviewing a phishing email classification.

Email being analyzed:
{input}

Original classification:
- Label: {label}
- Confidence: {confidence}
- Reasoning: {reasoning}
- Indicators found: {indicators}

Your task: determine whether this classification is correct or genuinely needs revision.

Critical rules:
1. If the evidence supports the original label, CONFIRM it — set changed=false.
2. Set changed=true ONLY if you have clear, specific evidence the label is WRONG — not just uncertainty.
3. Do NOT flip a Legitimate verdict to Phishing based on vague suspicion or minor observations.
4. Routine business emails (project updates, timelines, team communications) with no suspicious links or impersonation are Legitimate.
5. The bar to CHANGE a classification is HIGH. Reasonable doubt is not enough — you need concrete counter-evidence.

The "label" field MUST be exactly "Phishing" or "Legitimate" — no other values are valid.
Respond with ONLY valid JSON, no markdown, no extra text:

{{
  "label": "Legitimate",
  "confidence": 0.0,
  "changed": false,
  "critique": "specific assessment of whether the original classification is supported by the evidence",
  "revised_reasoning": "your complete reasoning"
}}"""


L2_PROMPT = """You are performing a consensus verification for a phishing email classification.

Email:
{input}

Current classification (Round {round}):
- Label: {label}
- Confidence: {confidence}
- Reasoning: {reasoning}

This is round {round} of a maximum 3-round consensus check.
Re-examine the email independently. Focus on concrete evidence only — not assumptions.
Set agreed=true if you reach the same label. Confidence within 0.10 is acceptable for consensus.
Do NOT change the label unless you identify specific, concrete evidence that contradicts the current verdict.

The "label" field MUST be exactly "Phishing" or "Legitimate" — no other values are valid.
Respond with ONLY valid JSON, no markdown, no extra text:

{{
  "label": "Legitimate",
  "confidence": 0.0,
  "agreed": false,
  "argument": "your specific reasoning for agreeing or what concrete evidence changed your analysis"
}}"""
