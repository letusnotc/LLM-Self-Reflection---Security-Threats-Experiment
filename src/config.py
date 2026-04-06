import os
import warnings
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI

warnings.filterwarnings("ignore", message="Convert_system_message_to_human")

load_dotenv()

# --- Model Configuration ---
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
MODEL_NAME = "gemini-2.5-flash-lite"  # Cost-effective, no thinking tokens
TEMPERATURE = 0  # Deterministic output for reproducible experiments

# --- Reflection Configuration ---
MAX_REFLECTION_ROUNDS = 3  # For Level 2 iterative reflection
CONSENSUS_THRESHOLD = 0.7  # Minimum confidence for consensus in Level 2

# --- Experiment Configuration ---
SAMPLES_PER_DOMAIN = 100  # Number of samples to evaluate per threat domain
RANDOM_SEED = 42

# --- Paths ---
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "experiments", "results")


def get_llm(callbacks=None, **kwargs):
    """Create a configured Gemini LLM instance."""
    return ChatGoogleGenerativeAI(
        model=MODEL_NAME,
        google_api_key=GOOGLE_API_KEY,
        temperature=kwargs.get("temperature", TEMPERATURE),
        convert_system_message_to_human=True,
        callbacks=callbacks or [],
    )
