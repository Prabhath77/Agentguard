# =============================================================================
# ecommerce_agent — a LangChain shopping assistant
# =============================================================================
from langchain.agents import initialize_agent, AgentType
from langchain_anthropic import ChatAnthropic
from agent_tools.orders import lookup_order, issue_refund
from agent_tools.accounts import get_user, update_payment_method

llm = ChatAnthropic(model="claude-sonnet-4-20250514")

tools = [lookup_order, issue_refund, get_user, update_payment_method]

agent = initialize_agent(
    tools,
    llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    handle_parsing_errors=True,
)
