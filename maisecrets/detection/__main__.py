"""python3 -m maisecrets.detection < request.json: the contract maisecrets.detect/1 (contract.py)."""
import sys

from .contract import main

sys.exit(main())
