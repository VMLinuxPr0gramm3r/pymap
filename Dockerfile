from debian

run apt-get update\
    apt-get install git python3
    git clone https://github.com/VMLinuxPr0gramm3r/pymap.git
    
run python3 setup.py\
    python3 src/main.py
