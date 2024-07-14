from web3 import Web3
import json

# Load the contract address and ABI
with open('contract_data.json', 'r') as f:
    contract_data = json.load(f)

contract_address = contract_data['address']
contract_abi = contract_data['abi']

# Connect to Ganache
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))

# Create contract instance
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# Function to read data from the blockchain
def read_data(receiver_address):
    stored_data = contract.functions.getData(receiver_address).call()
    return stored_data

# Example usage
receiver_address = w3.eth.accounts[1]  # Use the second account in Ganache as the receiver

data = read_data(receiver_address)
print(f"Data stored for {receiver_address}: {data}")

# You can also read data for multiple addresses
for i in range(5):  # Read data for the first 5 accounts
    address = w3.eth.accounts[i]
    data = read_data(address)
    print(f"Data stored for account {i} ({address}): {data}")