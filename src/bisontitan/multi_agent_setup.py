"""
BisonTitan Multi-Agent Setup Module
Configures Claude (Anthropic) and Grok (xAI) agents for collaborative security analysis.

Requires:
    - langchain-anthropic: pip install langchain-anthropic
    - xai-sdk: pip install xai-sdk
    - python-dotenv: pip install python-dotenv
"""

import os
import logging
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

logger = logging.getLogger("bisontitan.agents")


class AgentConfigError(Exception):
    """Raised when agent configuration fails."""
    pass


def _validate_api_key(key_name: str) -> str:
    """
    Validate that an API key exists in environment.

    Args:
        key_name: Name of the environment variable

    Returns:
        The API key value

    Raises:
        ValueError: If key is missing or empty
    """
    key = os.getenv(key_name)
    if not key or key.strip() == "":
        raise ValueError(
            f"Missing API key: {key_name}\n"
            f"Please set {key_name} in your .env file.\n"
            f"Expected location: {env_path}"
        )
    return key


def get_claude_llm(
    model: str = "claude-3-5-sonnet-20241022",
    temperature: float = 0.0,
    max_tokens: int = 4096,
) -> Any:
    """
    Initialize Claude LLM via LangChain's Anthropic wrapper.

    Args:
        model: Claude model identifier
        temperature: Sampling temperature (0.0 = deterministic)
        max_tokens: Maximum response tokens

    Returns:
        ChatAnthropic instance

    Raises:
        ValueError: If ANTHROPIC_API_KEY is not set
        ImportError: If langchain-anthropic is not installed
    """
    api_key = _validate_api_key("ANTHROPIC_API_KEY")

    try:
        from langchain_anthropic import ChatAnthropic
    except ImportError:
        raise ImportError(
            "langchain-anthropic not installed.\n"
            "Install with: pip install langchain-anthropic"
        )

    logger.info(f"Initializing Claude LLM: {model}")

    return ChatAnthropic(
        model=model,
        api_key=api_key,
        temperature=temperature,
        max_tokens=max_tokens,
    )


def get_grok_llm(
    model: str = "grok-beta",
    temperature: float = 0.0,
) -> Any:
    """
    Initialize Grok LLM via xAI SDK.

    Args:
        model: Grok model identifier
        temperature: Sampling temperature

    Returns:
        Grok client instance

    Raises:
        ValueError: If XAI_API_KEY is not set
        ImportError: If xai-sdk is not installed
    """
    api_key = _validate_api_key("XAI_API_KEY")

    try:
        from xai_sdk import Client as XAIClient
    except ImportError:
        raise ImportError(
            "xai-sdk not installed.\n"
            "Install with: pip install xai-sdk"
        )

    logger.info(f"Initializing Grok LLM: {model}")

    return XAIClient(
        api_key=api_key,
        model=model,
        temperature=temperature,
    )


class SecurityAnalysisAgent:
    """
    Base class for security analysis agents.
    Provides common functionality for Claude and Grok agents.
    """

    def __init__(self, name: str, llm: Any):
        """
        Initialize agent.

        Args:
            name: Agent identifier
            llm: Language model instance
        """
        self.name = name
        self.llm = llm
        self.context: list[dict] = []

    def analyze(self, prompt: str) -> str:
        """
        Run analysis with the agent's LLM.

        Args:
            prompt: Analysis prompt

        Returns:
            LLM response
        """
        raise NotImplementedError("Subclasses must implement analyze()")

    def add_context(self, role: str, content: str) -> None:
        """Add message to conversation context."""
        self.context.append({"role": role, "content": content})

    def clear_context(self) -> None:
        """Clear conversation context."""
        self.context = []


class ClaudeSecurityAgent(SecurityAnalysisAgent):
    """Claude-based security analysis agent."""

    def __init__(
        self,
        name: str = "Claude-Security",
        model: str = "claude-3-5-sonnet-20241022",
    ):
        """Initialize Claude agent."""
        llm = get_claude_llm(model=model)
        super().__init__(name, llm)

    def analyze(self, prompt: str) -> str:
        """
        Run security analysis with Claude.

        Args:
            prompt: Analysis prompt

        Returns:
            Claude's response
        """
        from langchain_core.messages import HumanMessage, SystemMessage

        messages = [
            SystemMessage(content=(
                "You are a security analysis expert. Analyze the provided data "
                "for potential threats, vulnerabilities, and suspicious patterns. "
                "Be thorough but concise. Flag critical issues prominently."
            )),
            HumanMessage(content=prompt),
        ]

        response = self.llm.invoke(messages)
        return response.content


class GrokSecurityAgent(SecurityAnalysisAgent):
    """Grok-based security analysis agent."""

    def __init__(
        self,
        name: str = "Grok-Security",
        model: str = "grok-beta",
    ):
        """Initialize Grok agent."""
        llm = get_grok_llm(model=model)
        super().__init__(name, llm)

    def analyze(self, prompt: str) -> str:
        """
        Run security analysis with Grok.

        Args:
            prompt: Analysis prompt

        Returns:
            Grok's response
        """
        response = self.llm.chat(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a security analysis expert. Analyze the provided data "
                        "for potential threats, vulnerabilities, and suspicious patterns. "
                        "Be thorough but concise. Flag critical issues prominently."
                    ),
                },
                {"role": "user", "content": prompt},
            ]
        )
        return response.choices[0].message.content


class MultiAgentOrchestrator:
    """
    Orchestrates multiple security agents for comprehensive analysis.
    Combines insights from Claude and Grok for defense-in-depth.
    """

    def __init__(self):
        """Initialize orchestrator with available agents."""
        self.agents: dict[str, SecurityAnalysisAgent] = {}
        self._init_agents()

    def _init_agents(self) -> None:
        """Initialize available agents based on configured API keys."""
        # Try Claude
        try:
            self.agents["claude"] = ClaudeSecurityAgent()
            logger.info("Claude agent initialized")
        except (ValueError, ImportError) as e:
            logger.warning(f"Claude agent not available: {e}")

        # Try Grok
        try:
            self.agents["grok"] = GrokSecurityAgent()
            logger.info("Grok agent initialized")
        except (ValueError, ImportError) as e:
            logger.warning(f"Grok agent not available: {e}")

        if not self.agents:
            raise AgentConfigError(
                "No agents available. Please configure at least one API key:\n"
                "  - ANTHROPIC_API_KEY for Claude\n"
                "  - XAI_API_KEY for Grok"
            )

    def analyze_with_all(self, prompt: str) -> dict[str, str]:
        """
        Run analysis with all available agents.

        Args:
            prompt: Analysis prompt

        Returns:
            Dictionary of agent_name -> response
        """
        results = {}
        for name, agent in self.agents.items():
            try:
                results[name] = agent.analyze(prompt)
            except Exception as e:
                logger.error(f"Agent {name} failed: {e}")
                results[name] = f"Error: {e}"
        return results

    def analyze_with_consensus(self, prompt: str) -> dict:
        """
        Run analysis and attempt to find consensus.

        Args:
            prompt: Analysis prompt

        Returns:
            Dictionary with individual responses and consensus summary
        """
        responses = self.analyze_with_all(prompt)

        # If we have multiple agents, ask one to synthesize
        if len(responses) > 1 and "claude" in self.agents:
            synthesis_prompt = (
                "Synthesize these security analysis results into a consensus view:\n\n"
                + "\n\n".join(
                    f"=== {name.upper()} ===\n{response}"
                    for name, response in responses.items()
                )
            )
            consensus = self.agents["claude"].analyze(synthesis_prompt)
        else:
            consensus = list(responses.values())[0] if responses else "No analysis available"

        return {
            "individual_responses": responses,
            "consensus": consensus,
        }


# Convenience functions for quick agent access
def quick_claude_analysis(prompt: str) -> str:
    """Run quick analysis with Claude."""
    agent = ClaudeSecurityAgent()
    return agent.analyze(prompt)


def quick_grok_analysis(prompt: str) -> str:
    """Run quick analysis with Grok."""
    agent = GrokSecurityAgent()
    return agent.analyze(prompt)


# Module-level check
def check_agent_availability() -> dict[str, bool]:
    """
    Check which agents are available.

    Returns:
        Dictionary of agent_name -> is_available
    """
    availability = {}

    # Check Claude
    try:
        _validate_api_key("ANTHROPIC_API_KEY")
        from langchain_anthropic import ChatAnthropic
        availability["claude"] = True
    except (ValueError, ImportError):
        availability["claude"] = False

    # Check Grok
    try:
        _validate_api_key("XAI_API_KEY")
        from xai_sdk import Client
        availability["grok"] = True
    except (ValueError, ImportError):
        availability["grok"] = False

    return availability


if __name__ == "__main__":
    # Quick test
    print("Checking agent availability...")
    avail = check_agent_availability()
    for agent, available in avail.items():
        status = "Available" if available else "Not configured"
        print(f"  {agent}: {status}")
