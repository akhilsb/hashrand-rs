import paramiko
import re

# Define the parameters for the devices
ip_prefix = '10.42.0.'
start_num = 232
num_devices = 20
port = 8500
client_port = 7500
syncer_port=9000

# Create a list of devices with IP addresses
devices = [{'ip': f'{ip_prefix}{i}', 'username': f'pi', 'password': f'dcsl_1234', 'working_directory': f'/home/pi/async-cc-hash', 'port':f'()'} for i in range(start_num, start_num + num_devices)]

# Command to run on devices
command_template = 'echo "This is device {ip} with username {username} and password {password}"'

# Loop through the devices and execute the command
for device in devices:
    # Create an SSH client object
    client = paramiko.SSHClient()
    # Automatically add the server key
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Connect to the device
    client.connect(hostname=device['ip'], username=device['username'], password=device['password'])
    # Modify the command string using regex to replace placeholders with device-specific information
    command = re.sub('{ip}', device['ip'], command_template)
    command = re.sub('{username}', device['username'], command)
    command = re.sub('{password}', device['password'], command)
    # Add the working directory to the command string
    command = 'cd ' + device['working_directory'] + ' && ' + command
    # Execute the modified command on the device
    stdin, stdout, stderr = client.exec_command(command)
    # Print the output
    print(stdout.read().decode())
    # Close the SSH connection
    client.close()
