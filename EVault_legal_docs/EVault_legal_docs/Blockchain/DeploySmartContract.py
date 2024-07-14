from solcx import compile_standard, install_solc, get_installed_solc_versions, set_solc_version
import json
from web3 import Web3

def deploy_contract():
    # Specify the Solidity version
    solc_version = "0.8.0"

    # Check if the required version is installed, if not, install it
    print(f"Checking Solidity compiler version {solc_version}...")
    if solc_version not in get_installed_solc_versions():
        print(f"Installing Solidity compiler version {solc_version}...")
        install_solc(solc_version)
    
    # Set the Solidity version to use
    set_solc_version(solc_version)
    print(f"Using Solidity compiler version {solc_version}")

    # Solidity source code
    contract_source_code = '''
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract DataStorage {
        address public sender;
        mapping(address => string[]) private storedData;

        constructor() {
            sender = msg.sender;
        }

        modifier onlySender() {
            require(msg.sender == sender, "Only the sender can write data.");
            _;
        }

        function setData(address receiver, string memory data) public onlySender {
            storedData[receiver].push(data);
        }

        function getData(address receiver) public view returns (string[] memory) {
            return storedData[receiver];
        }

        function getLatestData(address receiver) public view returns (string memory) {
            if (storedData[receiver].length > 0) {
                return storedData[receiver][storedData[receiver].length - 1];
            }
            return "";
        }
    }
    '''

    # Compile the contract
    print("Compiling the contract...")
    compiled_sol = compile_standard({
        "language": "Solidity",
        "sources": {"DataStorage.sol": {"content": contract_source_code}},
        "settings": {
            "outputSelection": {
                "*": {
                    "*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]
                }
            }
        }
    })
    print("Contract compiled successfully.")

    # Extract bytecode and ABI
    bytecode = compiled_sol['contracts']['DataStorage.sol']['DataStorage']['evm']['bytecode']['object']
    abi = json.loads(compiled_sol['contracts']['DataStorage.sol']['DataStorage']['metadata'])['output']['abi']

    # Connect to Ganache
    print("Connecting to Ganache...")
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))
    if not w3.is_connected():
        raise Exception("Failed to connect to Ganache. Make sure it's running.")
    print("Connected to Ganache successfully.")

    # Set pre-funded account as sender
    sender = w3.eth.accounts[0]

    # Create the contract in Python
    DataStorage = w3.eth.contract(abi=abi, bytecode=bytecode)

    # Get the nonce
    nonce = w3.eth.get_transaction_count(sender)

    # Build transaction
    print("Building the transaction...")
    transaction = DataStorage.constructor().build_transaction({
        "chainId": w3.eth.chain_id,
        "gasPrice": w3.eth.gas_price,
        "from": sender,
        "nonce": nonce,
    })

    # Sign the transaction
    print("Signing the transaction...")
    private_key = "0x4a274947d9abe1da77c91daaf5d3ea95155b4098609cfcb10795c0880ea44b22"  # Replace with your actual private key
    signed_txn = w3.eth.account.sign_transaction(transaction, private_key=private_key)

    # Send the transaction
    print("Sending the transaction...")
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)

    # Wait for the transaction to be mined, and get the transaction receipt
    print("Waiting for the transaction to be mined...")
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print(f"Contract deployed at address: {tx_receipt.contractAddress}")

    # Save the contract address and ABI to a file for later use
    with open('contract_data.json', 'w') as f:
        json.dump({
            "address": tx_receipt.contractAddress,
            "abi": abi
        }, f)

    print("Contract address and ABI saved to contract_data.json")

    return tx_receipt.contractAddress, abi

if __name__ == "__main__":
    deploy_contract()