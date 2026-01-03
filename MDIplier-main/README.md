# MDIplier

MDIplier is a tool for binary protocol reverse engineering. It takes network traces as input and infer message format by delimiter identifier and hierarchical inference. Please find the details in our paper: [MDIPLIER: Protocol Format Inference via Hierarchical Inference].

## Installation
- Install dependencies (python 3.6 or higher):
```bash
$ pip install -r requirements.txt
```
- Install `netzob`: [https://github.com/netzob/netzob.git](https://github.com/netzob/netzob.git)
- Install `mafft`: [https://mafft.cbrc.jp/alignment/software/](https://mafft.cbrc.jp/alignment/software/)

## Usage

Run MDIplier with the following command:
```bash
$ python main.py -i INPUT_FILE_PATH -o TEMP_OUTPUT_DIR -hr HEADER_RESULTS -br BODY_RESULTS [Other Options]
```
e.g.:
```bash
$ python mdiplier/main.py -i data/modbus_100.pcap -o tmp/modbus -hr header_results/modbus_100.out -br body_results/modbus_100.out 
```
Arguments:
- `-i`, `--input`: the filepath of input trace (required)
- `-hr`, `--header_field_analysis_result`: the filepath of message header field analysis results (required)
- `-br`, `--body_field_analysis_result`: the filepath of message body field analysis results (required)
- `-o`, `--output_dir`: the folder for temp files (default: `tmp/`) (required)
- `-t`, `--type`: the type of the test protocol (for generating the ground truth)  
currently it supports `dhcp`, `dnp3`, `icmp`, `modbus`, `ntp`, `smb`, `smb2`, `tftp`, `zeroaccess`
- `-l`, `--layer`: the layer of the protocol (default: `5`)  
for the network layer protocol (e.g., `icmp`), it should be `3`
- `-m`, `--mafft`: the alignment mode of mafft, including `ginsi`(default), `linsi`, `einsi`  
refer to [mafft](https://mafft.cbrc.jp/alignment/software/algorithms/algorithms.html) for detailed features of each mode
- `-mt`, `--multithread`: using multithreading for alignment (default: `False`)
