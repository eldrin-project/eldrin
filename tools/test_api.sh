#!/bin/bash

BASE_URL="http://localhost:3000/api"

# Get all modules
echo "Listing all modules:"
curl -s $BASE_URL/modules | jq

# Get a specific module
echo -e "\nGetting example_module:"
curl -s $BASE_URL/modules/example_module | jq

# Activate a module
echo -e "\nActivating example_module:"
curl -s -X POST -H "Content-Type: application/json" -d '{"name":"example_module"}' $BASE_URL/modules/activate | jq

# Deactivate a module
echo -e "\nDeactivating example_module:"
curl -s -X POST $BASE_URL/modules/deactivate/example_module | jq

# Try to get a non-existent module
echo -e "\nGetting non-existent module:"
curl -s $BASE_URL/modules/nonexistent_module | jq