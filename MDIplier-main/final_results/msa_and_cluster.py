import sys
import csv


if __name__ == "__main__":

    if len(sys.argv) != 5:
        print(f"python {sys.argv[0]} cluster_file msa_file out_file msg_delimiter")
        exit(0)
    
    csvfile = open(sys.argv[3], "w")
    writer = csv.writer(csvfile)
    writer.writerow(["Hexstream", "Split Indexes", "Splited Hexstream"])

    all_messages = []
    # read cluster_file
    with open(sys.argv[1]) as cluster_file:
        cluster_contents = cluster_file.readlines()
    
    cluster_msg_to_index = {}
    for i, cluster_content in enumerate(cluster_contents):
        if i == 0:
            continue
        cluster_split = cluster_content.split('"', 2)
        msg = "".join(cluster_split[0].split(","))
        index = eval(cluster_split[1])
        cluster_msg_to_index[hash(msg)] = index
    
    # print(f"000100000006ff050000ff00 index is {cluster_msg_to_index[hash('000100000006ff050000ff00')]}")
    print(f"cluster_msg_to_index length is {len(cluster_msg_to_index)}")
    

    # read msa_file
    with open(sys.argv[2]) as msa_file:
        msa_contents = msa_file.readlines()
    
    msa_msg_to_index = {}
    for i, msa_content in enumerate(msa_contents):
        if i == 0:
            continue
        msa_split = msa_content.split('"', 2)
        msg = "".join(msa_split[0].split(","))
        all_messages.append(msg)
        index = eval(msa_split[1])
        msa_msg_to_index[hash(msg)] = index
    
    # print(f"000100000006ff050000ff00 index is {msa_msg_to_index[hash('000100000006ff050000ff00')]}")
    print(f"msa_msg_to_index length is {len(msa_msg_to_index)}")

    # write
    delimiter = int(sys.argv[4]) # header分隔符
    for message in all_messages:
        msa_and_cluster_index = [delimiter]

        # 当下标小于16取msa结果
        msa_index = msa_msg_to_index[hash(message)]
        for msa_delimiter in msa_index:
            if msa_delimiter < delimiter:
                msa_and_cluster_index.append(msa_delimiter)
            else:
                break
        
        # 当下标大于16取cluster结果
        cluster_index = cluster_msg_to_index[hash(message)]
        for cluster_delimiter in cluster_index:
            if cluster_delimiter > delimiter:
                msa_and_cluster_index.append(cluster_delimiter)
            else:
                continue

        msa_and_cluster_index.sort()
        pkt_layer_split = " ".join(
            message[msa_and_cluster_index[i] : msa_and_cluster_index[i + 1]] for i in range(len(msa_and_cluster_index) - 1)
        )
        writer.writerow([message, msa_and_cluster_index, pkt_layer_split])



