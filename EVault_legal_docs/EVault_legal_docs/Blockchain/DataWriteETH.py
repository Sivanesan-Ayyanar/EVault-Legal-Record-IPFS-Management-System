from web3 import Web3
import json

# Load the contract address and ABI
with open('contract_data.json', 'r') as f:
    contract_data = json.load(f)

contract_address = contract_data['address']
contract_abi = contract_data['abi']

# Connect to Ganache
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))

# Set up account
sender_address = w3.eth.accounts[0]  # Use the first account in Ganache
private_key = "0x4a274947d9abe1da77c91daaf5d3ea95155b4098609cfcb10795c0880ea44b22"  # Replace with the private key of the first account in Ganache

# Create contract instance
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# Function to write data to the blockchain
def write_data(receiver_address, data):
    # Get the latest gas price
    gas_price = w3.eth.gas_price

    # Build the transaction
    transaction = contract.functions.setData(receiver_address, data).build_transaction({
        "chainId": 1337,  # Ganache chain ID
        "gas": 200000,
        "gasPrice": gas_price,
        "nonce": w3.eth.get_transaction_count(sender_address),
    })

    # Sign the transaction
    signed_txn = w3.eth.account.sign_transaction(transaction, private_key=private_key)

    # Send the transaction
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)

    # Wait for the transaction to be mined
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print(f"Data written to blockchain. Transaction hash: {tx_hash.hex()}")

# Example usage
receiver_address = w3.eth.accounts[1]  # Use the second account in Ganache as the receiver
data_to_write = "HELLO WORLD1"

write_data(receiver_address, data_to_write)

# Verify the data was written
stored_data = contract.functions.getData(receiver_address).call()
print(f"Data stored for {receiver_address}: {stored_data}")