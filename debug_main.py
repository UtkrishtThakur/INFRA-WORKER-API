
import sys
import traceback

with open("debug.log", "w") as f:
    try:
        f.write("Attempting to import main...\n")
        import main
        f.write("Successfully imported main\n")
    except Exception:
        f.write("Failed to import main:\n")
        traceback.print_exc(file=f)
