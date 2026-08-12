"""Allow ``python -m pipelineshield.benchmark`` invocation."""
import sys

from .cli import main

sys.exit(main())
