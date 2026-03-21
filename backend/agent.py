import os
from google import genai
from dotenv import load_dotenv
from backend.vector_store import VectorStore
from backend.pipeline.orchestrator import PipelineOrchestrator

load_dotenv()

class SigmaAgent:
    def __init__(self):
        # Initialize Vector Store (loads existing DB)
        self.vector_store = VectorStore()

        # Initialize Gemini with new SDK
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found")

        self.client = genai.Client(api_key=api_key)
        self.model_name = 'gemini-2.5-flash'

        # Initialize multi-stage pipeline orchestrator
        self.orchestrator = PipelineOrchestrator(
            self.client, self.model_name, self.vector_store
        )

    def analyze_attack(self, attack_description, history=None, media_file=None):
        """
        Main method to process a user's attack description and generate a Sigma rule.
        Uses the multi-stage pipeline (inspired by LLMCloudHunter).

        Returns: {"rule": str, "context": dict, "pipeline_metadata": dict|None}
        """
        print(f"Analyzing: {attack_description}")

        try:
            result = self.orchestrator.run_sync(
                description=attack_description,
                history=history,
                media_file=media_file,
            )
            return result
        except Exception as e:
            print(f"Pipeline error: {e}")
            return {
                "rule": f"Error during analysis: {e}",
                "context": {"sigma": [], "mitre": [], "sysmon": []},
                "pipeline_metadata": None,
            }

    def analyze_attack_stream(self, attack_description, history=None, media_file=None, feedback_data=None):
        """
        Streaming version - yields SSE events for real-time pipeline progress.
        Each event is a dict with 'event' and 'data' keys.

        Args:
            feedback_data: Optional user corrections from the feedback loop.
        """
        print(f"Analyzing (stream): {attack_description}")

        try:
            yield from self.orchestrator.run_stream(
                description=attack_description,
                history=history,
                media_file=media_file,
                feedback_data=feedback_data,
            )
        except Exception as e:
            print(f"Pipeline stream error: {e}")
            yield {
                "event": "result",
                "data": {
                    "rule": f"Error during analysis: {e}",
                    "context": {"sigma": [], "mitre": [], "sysmon": []},
                    "pipeline_metadata": None,
                },
            }


if __name__ == "__main__":
    # Quick Test
    agent = SigmaAgent()
    print(agent.analyze_attack("Attackers are using mimikatz to dump credentials"))
