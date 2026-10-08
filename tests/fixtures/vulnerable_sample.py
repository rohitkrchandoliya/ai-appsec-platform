import subprocess

user_value = input()
result = eval(user_value)
subprocess.run(user_value, shell=True)  # noqa: PLW1510
print(result)
