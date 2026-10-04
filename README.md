# CSCE-465-HW2
The setup I did was in Task 0 of the HW where I entered the following commands
cd "$HOME/csce465-agentsec"

(I did not have python venv installed so i had to do)
sudo apt install python3.12-venv

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1

cd "$HOME/csce465-agentsec/hw2"
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem
openssl dhparam -in ffdhe3072.pem -text -noout | head -3

I then took screenshots for the Task 0 requirement of the python and openssl version, and the pip show cryptography pytest

