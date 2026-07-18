import os
import pickle
import subprocess

user_input = "something"

result = eval(user_input)
exec("print('hello')")
os.system("ls -la")
subprocess.Popen("rm -rf /", shell=True)

with open("data.pkl", "rb") as f:
    data = pickle.load(f)