import os
import json
from functools import wraps
import requests
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify,send_file,Response,send_from_directory
from web3 import Web3
import secrets
from dotenv import load_dotenv
from db import mongo
import re
import hashlib
from bson import ObjectId,json_util
import io
import uuid
import json

load_dotenv()
MONGO_URI = os.getenv('MongoURI')
PINATA_API_KEY = os.getenv('PINATA_API_KEY')
PINATA_API_SECRET = os.getenv('PINATA_API_SECRET')
GANACHE_URL = os.getenv('GANACHE_URL', 'http://127.0.0.1:7545')
PRIVATE_KEY = os.getenv('PRIVATE_KEY')

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(16))

app.config['MONGO_URI'] = MONGO_URI
mongo.init_app(app)

w3 = Web3(Web3.HTTPProvider(GANACHE_URL))

with open('contract_data.json', 'r') as f:
    contract_data = json.load(f)
contract_address = contract_data['address']
contract_abi = contract_data['abi']

contract = w3.eth.contract(address=contract_address, abi=contract_abi)

def logged_in_user(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'SessionKey' in session and 'UserName' in session:
            session_key = session['SessionKey']
            user_name = session['UserName']
            user_session = mongo.db.UserSessions.find_one({
                'SessionKey': session_key,
                'UserName': user_name,
                'ExpirationTime': {'$gt': datetime.now(timezone.utc)}
            })
            if user_session:
                return view_func(*args, **kwargs)
        session.clear()
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))
    return decorated_function

def not_logged_in_user(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'SessionKey' in session and 'UserName' in session:
            return redirect(url_for('index'))
        return view_func(*args, **kwargs)
    return decorated_function

def generate_session_key(length=32):
    return secrets.token_hex(length // 2)

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

@app.route('/register', methods=['GET', 'POST'])
@not_logged_in_user
def register():
    if request.method == 'POST':
        user_name = request.form['user_name']
        email = request.form['email']
        password = request.form['password']
    
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$', password):
            flash('Invalid password. It should be at least 8 characters and contain at least one lowercase letter, one uppercase letter, one special character, and one number.', 'error')
            return redirect(url_for('register'))

        if mongo.db.UserDetails.find_one({'Email': email}):
            flash('Email ID already registered. Try logging in.', 'error')
            return redirect(url_for('register'))

        hashed_password = hash_password(password, user_name)

        mongo.db.UserDetails.insert_one({
            'UserName': user_name,
            'Email': email, 
            'Password': hashed_password, 
        })

        return redirect(url_for('login', user_name=user_name))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@not_logged_in_user
def login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']

        if '@' in login:
            user = mongo.db.UserDetails.find_one({'Email': login})
        else:
            user = mongo.db.UserDetails.find_one({'UserName': login})

        if user and hash_password(password, user['UserName']) == user['Password']:
            session_key = generate_session_key()
            session['SessionKey'] = session_key
            session['UserName'] = user['UserName']

            mongo.db.UserSessions.insert_one({
                'SessionKey': session_key,
                'UserName': user['UserName'],
                'ExpirationTime': datetime.now(timezone.utc) + timedelta(hours=1)
            })

            return redirect(url_for('index'))
        else:
            flash('Invalid username/email or password', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/')
@logged_in_user
def index():
    return render_template('index.html', userName=session['UserName'])

@app.route('/upload', methods=['POST'])
@logged_in_user
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    try:
        ipfs_hash = upload_to_ipfs(file)
        tx_hash = write_to_blockchain(ipfs_hash)
        
        current_utc_time = datetime.now(timezone.utc)

        mongo.db.UserFiles.insert_one({
            'filename': file.filename,
            'user': session['UserName'],
            'current_version': 1,
            'versions': [{
                'version': 1,
                'ipfs_hash': ipfs_hash,
                'tx_hash': tx_hash,
                'upload_date': current_utc_time
            }]
        })
        
        return jsonify({
            'success': True, 
            'message': 'File uploaded successfully',
            'ipfs_hash': ipfs_hash,
            'tx_hash': tx_hash,
            'fileAdded': True
        })
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e), 'fileAdded': False}), 500
    
    
@app.route('/file_list')
@logged_in_user
def get_file_list():
    try:
        user_files_list = list(mongo.db.UserFiles.find({'user': session['UserName']}, {'filename': 1, '_id': 0}))
        return jsonify(user_files_list)
    except Exception as e:
        print(f"Error fetching file list: {str(e)}")
        return jsonify({'error': str(e)}), 500    
    
def upload_to_ipfs(file):
    files = {"file": file}
    headers = {
        'pinata_api_key': PINATA_API_KEY,
        'pinata_secret_api_key': PINATA_API_SECRET
    }
    response = requests.post("https://api.pinata.cloud/pinning/pinFileToIPFS", files=files, headers=headers)
    return response.json()["IpfsHash"]

def write_to_blockchain(ipfs_hash):
    sender_address = w3.eth.accounts[0]
    
    transaction = contract.functions.setData(sender_address, ipfs_hash).build_transaction({
        "chainId": 1337,  # Ganache chain ID
        "gas": 200000,
        "gasPrice": w3.eth.gas_price,
        "nonce": w3.eth.get_transaction_count(sender_address),
    })
    
    signed_txn = w3.eth.account.sign_transaction(transaction, private_key=PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if tx_receipt.status == 0:
        raise Exception("Transaction failed")
    
    return tx_hash.hex()

@app.route('/files')
@logged_in_user
def view_files():
    user_files_list = list(mongo.db.UserFiles.find({'user': session['UserName']}).sort('versions.0.upload_date', -1))
    for file in user_files_list:
        file['_id'] = str(file['_id'])
        if 'versions' in file and file['versions']:
            file['latest_version'] = file['versions'][-1]
        else:
            file['latest_version'] = {'upload_date': datetime.now(timezone.utc)}
        file['current_version'] = file.get('current_version', 1)
    return render_template('files.html', files=user_files_list,userName=session['UserName'])


@app.route('/update/<file_id>', methods=['POST'])
@logged_in_user
def update_file(file_id):
    if 'file' not in request.files:
        return jsonify({'error': 'No file part', 'fileUpdated': False}), 400
    file = request.files['file']
    print('File document:', file)
    if file.filename == '':
        return jsonify({'error': 'No selected file', 'fileUpdated': False}), 400
    
    original_file = mongo.db.UserFiles.find_one({'_id': ObjectId(file_id), 'user': session['UserName']})
    if not original_file:
        return jsonify({'error': 'File not found', 'fileUpdated': False}), 404
    
    try:
        ipfs_hash = upload_to_ipfs(file)
        tx_hash = write_to_blockchain(ipfs_hash)
        
        new_version = original_file.get('current_version', 0) + 1
        
        update_result = mongo.db.UserFiles.update_one(
            {'_id': ObjectId(file_id)},
            {
                '$set': {
                    'current_version': new_version,
                },
                '$push': {
                    'versions': {
                        'version': new_version,
                        'ipfs_hash': ipfs_hash,
                        'tx_hash': tx_hash,
                        'upload_date': datetime.now(timezone.utc)
                    }
                }
            }
        )
        
        if update_result.modified_count == 0:
            return jsonify({'error': 'Failed to update file', 'fileUpdated': False}), 500
        
        return jsonify({'success': True, 'message': 'File updated successfully', 'fileUpdated': True})
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e), 'fileUpdated': False}), 500
    
@app.route('/file_details/<file_id>')
@logged_in_user
def get_file_details(file_id):
    try:
        file = mongo.db.UserFiles.find_one({'_id': ObjectId(file_id), 'user': session['UserName']})
        if not file:
            return jsonify({'error': 'File not found'}), 404
        
        return jsonify({
            'filename': file['filename'],
            'current_version': file['current_version'],
            'latest_version': file['versions'][-1]
        })
    except Exception as e:
        print(f"Error fetching file details: {str(e)}")
        return jsonify({'error': str(e)}), 500    
    
@app.route('/file_history/<file_id>')
@logged_in_user
def file_history(file_id):
    file = mongo.db.UserFiles.find_one({'_id': ObjectId(file_id), 'user': session['UserName']})
    if not file:
        return jsonify({"error": "File not found"}), 404
    
    return jsonify({
        "filename": file['filename'],
        "current_version": file['current_version'],
        "versions": file['versions']
    })   




@app.route('/view/<file_id>')
def view_file(file_id):
    try:
        version = request.args.get('version', type=int)
        file = mongo.db.UserFiles.find_one({'_id': ObjectId(file_id)})
        if not file:
            return jsonify({"error": "File not found"}), 404
        
        # Permission check
        if 'UserName' not in session or (file['user'] != session['UserName'] and session['UserName'] not in file.get('shared_with', [])):
            return jsonify({"error": "You don't have permission to view this file"}), 403
        
        # Version selection
        if version is None:
            version_data = file['versions'][-1]
        else:
            version_data = next((v for v in file['versions'] if v['version'] == version), None)
            if not version_data:
                return jsonify({"error": "Version not found"}), 404
        
        ipfs_hash = version_data['ipfs_hash']
        filename = file['filename']
        
        # List of IPFS gateways to try
        ipfs_gateways = [
            f"https://blue-persistent-goose-681.mypinata.cloud/ipfs/{ipfs_hash}",
            f"https://ipfs.io/ipfs/{ipfs_hash}",
            f"https://gateway.pinata.cloud/ipfs/{ipfs_hash}"
        ]
        
        for ipfs_url in ipfs_gateways:
            try:
                response = requests.get(ipfs_url, timeout=10)
                response.raise_for_status()
                
                content_type = response.headers.get('Content-Type', 'application/octet-stream')
                
                if content_type.startswith('image/') or content_type.startswith('text/'):
                    return Response(response.content, content_type=content_type)
                else:
                    return "This file type cannot be viewed directly in the browser. Please download the file to view its contents."
            
            except requests.RequestException as e:
                print(f"Error viewing file from IPFS gateway {ipfs_url}: {str(e)}")
                continue  # Try the next gateway
        
        # If all gateways fail
        return jsonify({"error": "Unable to retrieve file from IPFS. Please try again later or contact support."}), 500

    except Exception as e:
        print(f"Unexpected error in view_file: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500 

@app.route('/download/<file_id>')
@logged_in_user
def download_file(file_id):
    try:
        version = request.args.get('version', type=int)
        file = mongo.db.UserFiles.find_one({'_id': ObjectId(file_id)})
        if not file:
            return jsonify({"error": "File not found"}), 404
        
        if file['user'] != session['UserName'] and session['UserName'] not in file.get('shared_with', []):
            return jsonify({"error": "You don't have permission to download this file"}), 403
        
        if version is None:
            version_data = file['versions'][-1]
        else:
            version_data = next((v for v in file['versions'] if v['version'] == version), None)
            if not version_data:
                return jsonify({"error": "Version not found"}), 404
        
        ipfs_hash = version_data['ipfs_hash']
        filename = file['filename']
        
        ipfs_gateways = [
            f"https://blue-persistent-goose-681.mypinata.cloud/ipfs/{ipfs_hash}",
            f"https://ipfs.io/ipfs/{ipfs_hash}",
            f"https://gateway.pinata.cloud/ipfs/{ipfs_hash}"
        ]
        
        for ipfs_url in ipfs_gateways:
            try:
                response = requests.get(ipfs_url, stream=True, timeout=10)
                response.raise_for_status()
                
                return Response(
                    response.iter_content(chunk_size=8192),
                    content_type=response.headers.get('Content-Type', 'application/octet-stream'),
                    headers={"Content-Disposition": f"attachment; filename={filename}"}
                )
            except requests.RequestException as e:
                print(f"Error downloading file from IPFS gateway {ipfs_url}: {str(e)}")
                continue  # Try the next gateway
        
        # If all gateways fail
        return jsonify({"error": "Unable to download file from IPFS. Please try again later or contact support."}), 500

    except Exception as e:
        print(f"Unexpected error in download_file: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    
    
@app.route('/share_file/<file_id>', methods=['POST'])
@logged_in_user
def share_file(file_id):
    recipient = request.json.get('recipient')
    if not recipient:
        return jsonify({"error": "Recipient not specified"}), 400
    
    file = mongo.db.UserFiles.find_one({'_id': ObjectId(file_id), 'user': session['UserName']})
    if not file:
        return jsonify({"error": "File not found"}), 404
    
    # Check if the recipient exists in the UserDetails collection
    recipient_user = mongo.db.UserDetails.find_one({'UserName': recipient})
    if not recipient_user:
        return jsonify({"error": "Recipient user not found. Please check the username and try again."}), 404
    
    # Add the recipient to the shared_with list
    mongo.db.UserFiles.update_one(
        {'_id': ObjectId(file_id)},
        {'$addToSet': {'shared_with': recipient}}
    )
    
    return jsonify({"message": f"File shared with {recipient}"})

@app.route('/shared_with_me')
@logged_in_user
def shared_with_me():
    shared_files = list(mongo.db.UserFiles.find({'shared_with': session['UserName']}))
    for file in shared_files:
        file['_id'] = str(file['_id'])
    return render_template('shared_with_me.html', files=shared_files,userName=session['UserName'])
        
@app.route('/public_view/<file_id>')
def public_view_file(file_id):
    try:
        public_link = request.args.get('public_link')
        file = mongo.db.UserFiles.find_one({'_id': ObjectId(file_id)})
        
        if not file:
            return jsonify({"error": "File not found"}), 404
        
        # Check if the file has a valid public link
        if not public_link or file.get('public_link') != public_link:
            return jsonify({"error": "Invalid or missing public link"}), 403
        
        version_data = file['versions'][-1]  # Get the latest version
        ipfs_hash = version_data['ipfs_hash']
        filename = file['filename']
        
        # List of IPFS gateways to try
        ipfs_gateways = [
            f"https://blue-persistent-goose-681.mypinata.cloud/ipfs/{ipfs_hash}",
            f"https://ipfs.io/ipfs/{ipfs_hash}",
            f"https://gateway.pinata.cloud/ipfs/{ipfs_hash}"
        ]
        
        for ipfs_url in ipfs_gateways:
            try:
                response = requests.get(ipfs_url, timeout=10)
                response.raise_for_status()
                
                content_type = response.headers.get('Content-Type', 'application/octet-stream')
                
                if content_type.startswith('image/') or content_type.startswith('text/'):
                    return Response(response.content, content_type=content_type)
                else:
                    return "This file type cannot be viewed directly in the browser. Please download the file to view its contents."
            
            except requests.RequestException as e:
                print(f"Error viewing file from IPFS gateway {ipfs_url}: {str(e)}")
                continue  # Try the next gateway
        
        # If all gateways fail
        return jsonify({"error": "Unable to retrieve file from IPFS. Please try again later or contact support."}), 500

    except Exception as e:
        print(f"Unexpected error in public_view_file: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    
    
@app.route('/generate_public_link/<file_id>')
@logged_in_user
def generate_public_link(file_id):
    file = mongo.db.UserFiles.find_one({'_id': ObjectId(file_id), 'user': session['UserName']})
    if not file:
        return jsonify({"error": "File not found"}), 404
    
    public_link = str(uuid.uuid4())
    
    mongo.db.UserFiles.update_one(
        {'_id': ObjectId(file_id)},
        {'$set': {'public_link': public_link}}
    )
    
    return jsonify({"public_link": f"/public_view/{file_id}?public_link={public_link}"})

@app.route('/share_with_user/<file_id>', methods=['POST'])
@logged_in_user
def share_with_user(file_id):
    recipient = request.json.get('recipient')
    if not recipient:
        return jsonify({"error": "Recipient not specified"}), 400
    
    file = mongo.db.UserFiles.find_one({'_id': ObjectId(file_id), 'user': session['UserName']})
    if not file:
        return jsonify({"error": "File not found"}), 404
    
    # Check if the recipient exists in the UserDetails collection
    recipient_user = mongo.db.UserDetails.find_one({'UserName': recipient})
    if not recipient_user:
        return jsonify({"error": "Recipient user not found. Please check the username and try again."}), 404
    
    # Add the recipient to the shared_with list
    mongo.db.UserFiles.update_one(
        {'_id': ObjectId(file_id)},
        {'$addToSet': {'shared_with': recipient}}
    )
    
    return jsonify({"message": f"File shared with {recipient}"})

@app.route('/shared/<public_link>')
def view_shared_file(public_link):
    file = mongo.db.UserFiles.find_one({'public_link': public_link})
    if not file:
        return jsonify({"error": "Shared file not found"}), 404
    
    # Check if the file is shared with the current user
    if 'UserName' in session and session['UserName'] in file.get('shared_with', []):
        return render_template('view_shared_file.html', file=file)
    
    # If it's a public link or shared with the user, allow access
    if file.get('public_link') == public_link:
        return render_template('view_shared_file.html', file=file)
    
    return jsonify({"error": "You don't have permission to view this file"}), 403

@app.route('/user_manual')
def user_manual():
    project_dir = os.path.dirname(os.path.abspath(__file__))
    return send_from_directory(project_dir, 'E-Vault_User_Manual.pdf')

@app.route('/existing_records')
def existing_records():
    try:
        documents = list(mongo.db.legal_documents.find())
        # Convert ObjectId to string for JSON serialization
        documents_json = json.loads(json_util.dumps(documents))
        return render_template('existing_records.html', documents=documents_json)
    except Exception as e:
        # Log the error and return an error page
        app.logger.error(f"An error occurred: {str(e)}")
        return render_template('error.html', error="An error occurred while fetching the records."), 500
    
@app.route('/logout')
@logged_in_user
def Logout():
    session_key = session['SessionKey']
    user_name = session['UserName']
    mongo.db.UserSessions.delete_one({
        'SessionKey': session_key,
        'UserName': user_name
    })
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    # print(app.url_map)
    app.run(debug=True)