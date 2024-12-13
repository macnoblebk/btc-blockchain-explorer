# Bitcoin Blockchain Explorer
A Python-based project to interact with the Bitcoin P2P network, retrieve and manipulate blockchain data, and demonstrate how modifications to a block would be detected and rejected by the network.

## Overview
This project connects to a Bitcoin node, retrieves a specific block based on a user-defined block number, and demonstrates the integrity of blockchain technology by modifying a transaction within the block. It showcases how any changes to the block are identified and rejected by the Bitcoin network.

## Features
- Connect to a peer in the Bitcoin P2P network.
- Retrieve a block by block number.
- Display transactions within the block. 
- Modify a transaction in the block and recalculate the Merkle tree and block hash. 
- Generate a report showing how the modified block is invalid.

## Program Output
![Screenshot 2024-12-12 at 22.01.44.png](Screenshot%202024-12-12%20at%2022.01.44.png)
![Screenshot 2024-12-12 at 22.03.44.png](Screenshot%202024-12-12%20at%2022.03.44.png)
![Screenshot 2024-12-12 at 22.04.38.png](Screenshot%202024-12-12%20at%2022.04.38.png)
![Screenshot 2024-12-12 at 22.04.59.png](Screenshot%202024-12-12%20at%2022.04.59.png)

## Setup
1. To get a list of bitcoin nodes:
   ```bash
   curl https://bitcoin.sipa.be/seeds.txt.gz | gzip -dc > seeds_main.txt
   curl https://bitcoin.sipa.be/asmap-filled.dat > asmap-filled.dat
   python3 makeseeds.py -a asmap-filled.dat -s seeds_main.txt > nodes_main.txt

