import os
import sys

# Add additional module search paths for the python interpreter to look in
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), './test_config')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
