import os
import sys

# Add additional module search paths for the python interpreter to look in
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

import test_config.ef_site_config
import efopen
efopen.ef_site_config = test_config.ef_site_config
