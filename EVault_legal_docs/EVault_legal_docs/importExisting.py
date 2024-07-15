import csv
from pymongo import MongoClient

# MongoDB connection
client = MongoClient('')
db = client['evault']
collection = db['legal_documents']

# Read CSV file and insert data into MongoDB
with open('legal_documents.csv', 'r') as file:
    csv_reader = csv.DictReader(file)
    for row in csv_reader:
        collection.insert_one(row)

print("Data imported successfully!")
