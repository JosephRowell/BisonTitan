#!/usr/bin/env python3
"""
BisonTitan Multi-Agent Setup
============================
PM Agent: Grok (xAI) - Planning, architecture, code review
Coder Agent: Claude (Anthropic) - Implementation, bug fixes, testing

Environment variables (in .env file):
    ANTHROPIC_API_KEY=sk-ant-...
    XAI_API_KEY=xai-...

Usage:
    python multi_agent_setup.py
    python multi_agent_setup.py --task "Mobile GUI tweaks"
"""

import os
import sys
from pathlib import Path

# Load .env file manually (no dependency on python-dotenv if missing)
def load_env():
    """Load environment variables from .env file."""
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        print(f"[OK] Loading {env_path}")
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    value = value.strip().strip('"').strip("'")
                    if key.strip() and value:
                        os.environ.setdefault(key.strip(), value)
    else:
        print(f"[WARN] No .env file at {env_path}")

load_env()

# Check API keys before importing heavy libraries
ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY", "")
XAI_KEY = os.getenv("XAI_API_KEY", "")

print("\n[ENV CHECK]")
if ANTHROPIC_KEY:
    print(f"  ANTHROPIC_API_KEY: {ANTHROPIC_KEY[:15]}...{ANTHROPIC_KEY[-4:]}")
else:
    print("  ANTHROPIC_API_KEY: NOT SET")
    print("    Get key at: https://console.anthropic.com/")

if XAI_KEY:
    print(f"  XAI_API_KEY: {XAI_KEY[:10]}...{XAI_KEY[-4:]}")
else:
    print("  XAI_API_KEY: NOT SET")
    print("    Get key at: https://console.x.ai/")

if not ANTHROPIC_KEY or not XAI_KEY:
    print("\n[ERROR] Missing API keys. Add to .env file:")
    print("  ANTHROPIC_API_KEY=sk-ant-api03-...")
    print("  XAI_API_KEY=xai-...")
    sys.exit(1)

# Now import the heavy libraries
try:
    from crewai import Agent, Task, Crew, Process
    print("\n[OK] crewai imported")
except ImportError as e:
    print(f"\n[ERROR] crewai not installed: {e}")
    print("  Install: pip install crewai")
    sys.exit(1)

try:
    from langchain_anthropic import ChatAnthropic
    print("[OK] langchain-anthropic imported")
except ImportError as e:
    print(f"[ERROR] langchain-anthropic not installed: {e}")
    print("  Install: pip install langchain-anthropic")
    sys.exit(1)

try:
    from langchain_xai import ChatXAI
    print("[OK] langchain-xai imported")
except ImportError as e:
    print(f"[ERROR] langchain-xai not installed: {e}")
    print("  Install: pip install langchain-xai")
    sys.exit(1)


def create_agents():
    """Initialize LLMs and agents."""
    print("\n[INIT] Creating agents...")

    # Initialize LLMs with correct model names
    # Claude: claude-sonnet-4-20250514 (latest) or claude-3-5-sonnet-20241022
    # Grok: grok-2-latest or grok-beta
    try:
        claude_llm = ChatAnthropic(
            model="claude-3-5-sonnet-20241022",
            api_key=ANTHROPIC_KEY,
            max_tokens=4096,
        )
        print("  [OK] Claude LLM (Anthropic)")
    except Exception as e:
        print(f"  [ERROR] Claude LLM failed: {e}")
        raise

    try:
        grok_llm = ChatXAI(
            model="grok-2-latest",
            api_key=XAI_KEY,
            max_tokens=4096,
        )
        print("  [OK] Grok LLM (xAI)")
    except Exception as e:
        print(f"  [ERROR] Grok LLM failed: {e}")
        raise

    # PM Agent: Grok - Strategic planning, architecture
    project_manager = Agent(
        role="Project Manager",
        goal="Oversee BisonTitan development: Break down tasks, review code, coordinate with Coder.",
        backstory="""You're a senior dev lead specializing in cybersecurity tools.
Prioritize modularity, error handling, and security best practices.
BisonTitan is a security toolkit with CLI, Streamlit GUI, and Cloudflare Pages deployment.""",
        llm=grok_llm,
        verbose=True,
        allow_delegation=True,
    )
    print("  [OK] PM Agent (Grok)")

    # Coder Agent: Claude - Implementation, coding
    coder = Agent(
        role="Senior Coder",
        goal="Implement secure Python code for BisonTitan. Follow PM's plan, write clean code with tests.",
        backstory="""You're an expert Python developer for cybersecurity tools.
Tech stack: Python 3.12+, Streamlit, Click CLI, Cloudflare Pages (JS functions).
Project structure:
- src/bisontitan/ - Main package
- src/bisontitan/gui/app.py - Streamlit dashboard
- deploy/public/ - Static files
- deploy/functions/ - JS API functions""",
        llm=claude_llm,
        verbose=True,
        allow_delegation=False,
    )
    print("  [OK] Coder Agent (Claude)")

    return project_manager, coder


def run_task(task_description: str):
    """Run a task through the multi-agent crew."""
    print(f"\n{'='*60}")
    print(f"TASK: {task_description}")
    print('='*60)

    pm, coder = create_agents()

    task = Task(
        description=task_description,
        expected_output="Complete implementation with code, explanation, and any risks flagged.",
        agent=pm,
    )

    crew = Crew(
        agents=[pm, coder],
        tasks=[task],
        process=Process.hierarchical,
        manager_agent=pm,
        verbose=True,
    )

    print("\n[RUN] Starting crew...")
    result = crew.kickoff()

    print(f"\n{'='*60}")
    print("RESULT")
    print('='*60)
    print(result)

    return result


def main():
    """Main entry point."""
    # Default task
    default_task = """Plan and implement mobile CSS tweaks for BisonTitan Streamlit GUI:
1. Add responsive breakpoints (768px, 480px)
2. Stack columns vertically on mobile
3. Larger touch targets (44px min)
4. Fix iOS zoom on input fields (16px font)
Output: CSS code to add to src/bisontitan/gui/app.py"""

    if len(sys.argv) > 1:
        if sys.argv[1] == "--task" and len(sys.argv) > 2:
            task = " ".join(sys.argv[2:])
        elif sys.argv[1] in ["--help", "-h"]:
            print("Usage:")
            print("  python multi_agent_setup.py")
            print("  python multi_agent_setup.py --task 'Your task description'")
            print()
            print("Examples:")
            print("  python multi_agent_setup.py --task 'Mobile GUI tweaks'")
            print("  python multi_agent_setup.py --task 'Fix wrangler.toml deploy error'")
            return
        else:
            task = " ".join(sys.argv[1:])
    else:
        task = default_task

    run_task(task)


if __name__ == "__main__":
    main()
