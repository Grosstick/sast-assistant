# Development Notes

Personal notes I kept while building this project.

## Week 1 - Research & Setup

Started by researching SAST tools. Found Semgrep mentioned a lot on Reddit and HackerNews.
Watched a few YouTube videos on SQL injection to understand what I'm detecting.

Resources that helped:
- Semgrep docs: https://semgrep.dev/docs/
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- Real Python subprocess tutorial: https://realpython.com/python-subprocess/

Initially tried to parse Semgrep output manually with regex... bad idea. 
Switched to JSON output which is way cleaner.

## Week 2 - Core Pipeline

Got the basic scanner working. Spent way too long debugging why subprocess wasn't 
capturing output - forgot `capture_output=True`

Discovered Pydantic from a Medium article about FastAPI. It's way better than 
manually validating dictionaries everywhere. Wish I knew about this earlier.

The context extraction was tricky - had to handle:
- Files with weird encodings (Latin-1 fallback)
- Line numbers being 1-indexed vs 0-indexed (so confusing)
- Files shorter than the context window I wanted

## Week 3 - AI Integration

Originally wanted to use OpenAI but Gemini has a free tier which is nice for testing.
The API was pretty straightforward once I found the google-genai package.

Biggest challenge: getting the AI to respond in consistent JSON format.
Had to add explicit instructions in the system prompt and handle cases where 
it randomly adds markdown code blocks around the JSON.

Still not 100% reliable but works most of the time.

## Things I Learned

1. Always use `encoding="utf-8"` when reading files
2. Subprocess timeout is important - scans can hang forever otherwise
3. Pydantic > manual dict validation
4. LLMs are inconsistent - need fallback handling
5. Markdown tables are annoying to generate programmatically

## If I Had More Time

Would've added:
- Unit tests (I know, I know...)
- Support for more vulnerability types
- Caching to avoid re-analyzing the same code
- A simple web UI maybe?
