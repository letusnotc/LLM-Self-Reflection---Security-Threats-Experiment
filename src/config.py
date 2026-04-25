import os
import warnings
from dotenv import load_dotenv
from langchain_ollama import ChatOllama

warnings.filterwarnings("ignore")

load_dotenv()

# --- Model Configuration ---
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
MODEL_NAME = os.getenv("OLLAMA_MODEL", "gemma4:e2b")
TEMPERATURE = 0  # Deterministic output for reproducible experiments

# --- Reflection Configuration ---
MAX_REFLECTION_ROUNDS = 3  # For Level 2 iterative reflection
CONSENSUS_THRESHOLD = 0.7  # Minimum confidence for consensus in Level 2

# --- Experiment Configuration ---
SAMPLES_PER_DOMAIN = 20  # Reduced for local inference (override with --samples)
RANDOM_SEED = 42

# --- Paths ---
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "experiments", "results")


def get_llm(callbacks=None, **kwargs):
    """Create a configured Ollama LLM instance (fully local)."""
    return ChatOllama(
        model=MODEL_NAME,
        base_url=OLLAMA_BASE_URL,
        temperature=kwargs.get("temperature", TEMPERATURE),
        callbacks=callbacks or [],
    )
