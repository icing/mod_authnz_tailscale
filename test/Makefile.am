# Copyright 2022 Stefan Eissing (<stefan@eissing.org>)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

SERVER_DIR     = @SERVER_DIR@
GEN            = gen


.phony: unit_tests

EXTRA_DIST     = modules pyhttpd unit
 	
test:
	pytest

clean-local:
	rm -rf *.pyc __pycache__
	rm -f data/ssl/valid*
	rm -rf $(SERVER_DIR)
