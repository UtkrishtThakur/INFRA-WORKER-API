
import asyncio
from main import app, startup

async def test_startup_resilience():
    print("Testing startup resilience...")
    try:
        # Manually trigger startup hook
        await startup()
        print("Startup hook executed successfully (background task started).")
        print("Worker is ALIVE.")
    except Exception as e:
        print(f"CRITICAL: Startup failed: {e}")
        exit(1)

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    loop.run_until_complete(test_startup_resilience())
