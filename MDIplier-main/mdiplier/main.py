import argparse
import sys
import os
import csv
import json
import time
import logging
logging.basicConfig(level=logging.INFO, stream=sys.stdout)
#logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)


from mdiplier import MDIplier
from processing import Processing
from alignment import Alignment
from clustering import Clustering

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input', required=True, dest='filepath_input', help='filepath of input trace')
    parser.add_argument('-t', '--type', dest='protocol_type', help='type of the protocol (for generating the ground truth): \
        # dhcp, dnp3, icmp, modbus, ntp, smb, smb2, tftp, zeroaccess')
    parser.add_argument('-o', '--output_dir', dest='output_dir', default='tmp/', help='temp_output directory')
    parser.add_argument('-l', '--layer', dest='layer', default=5, type=int, help='the layer of the protocol')
    parser.add_argument('-m', '--mafft', dest='mafft_mode', default='ginsi', help='the mode of mafft: [ginsi, linsi, einsi]')
    parser.add_argument('-mt', '--multithread', dest='multithread', default=False, action='store_true', help='run mafft with multi threads')
    parser.add_argument('-hr', '--header_field_analysis_result', dest='header_field_analysis_result',
                        default=None, help='field_analysis_result')
    parser.add_argument('-br', '--body_field_analysis_result', dest='body_field_analysis_result',
                        default=None, help='field_analysis_result')


    args = parser.parse_args()

    start_time = time.time()
    p = Processing(filepath=args.filepath_input, protocol_type=args.protocol_type, layer=args.layer)
    # p.print_dataset_info()
    
    res_dict = {}
    for i,message in enumerate(p.messages):
        res_dict[i] = message.data.hex()
    
    
    with open("mdiplier/delimiter_identifier/100data.json","w") as f:
        json.dump(res_dict,f)
    
    mode = args.mafft_mode
    if args.protocol_type in['dnp3']:
        mode = 'linsi'
    mdiplier = MDIplier(messages=p.messages, direction_list=p.direction_list, output_dir=args.output_dir, mode=mode, multithread=args.multithread)
    fid_inferred = mdiplier.execute()
    
    # Clustering
    messages_aligned = Alignment.get_messages_aligned(mdiplier.messages, os.path.join(mdiplier.output_dir, Alignment.FILENAME_OUTPUT_ONELINE))
    messages_request, messages_response = Processing.divide_msgs_by_directionlist(mdiplier.messages, mdiplier.direction_list)
    messages_request_aligned, messages_response_aligned = Processing.divide_msgs_by_directionlist(messages_aligned, mdiplier.direction_list)

    clustering = Clustering(fields=mdiplier.fields, protocol_type=args.protocol_type)
    # clustering_result_request_true = clustering.cluster_by_kw_true(messages_request)
    # clustering_result_response_true = clustering.cluster_by_kw_true(messages_response)
    clustering_result_request_mdiplier = clustering.cluster_by_kw_inferred(fid_inferred, messages_request_aligned)
    clustering_result_response_mdiplier = clustering.cluster_by_kw_inferred(fid_inferred, messages_response_aligned)
    # clustering.evaluation([clustering_result_request_true, clustering_result_response_true], [clustering_result_request_mdiplier, clustering_result_response_mdiplier])
    
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    csvfile = open(args.header_field_analysis_result, "w")
    msa_writer = csv.writer(csvfile)
    msa_writer.writerow(["Hexstream", "Split Indexes", "Splited Hexstream"])

    msa_folder_name = os.path.join(args.output_dir, Alignment.FILENAME_FIELDS_VISUAL)
    with open(msa_folder_name, "r") as fout:
        lines = fout.readlines()

    for line in lines:
        msa_index = [0]
        msa_cur = 0

        msa_fields = line.split(" ")
        fields = []
        for msa_field in msa_fields:
            f = "".join(msa_field.split("-")).strip().replace("~", "")
            if len(f):
                msa_cur += len(f)
                if len(f) % 2:
                    print(
                        f"Result of {msa_folder_name} containts half-byte field: {msa_field}"
                    )
                msa_index.append(msa_cur)
                fields.append(f)
        pkt = "".join(fields).replace("~", "")
        pkt_split = " ".join(fields)
        msa_writer.writerow([pkt, msa_index, pkt_split])
    
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    
    messages_request_process = []
    messages_response_process = []
    for i, message in enumerate(p.messages):
        if p.direction_list[i] == 0:
            messages_request_process.append(message)
        else:
            messages_response_process.append(message)

    dict_fv_i = dict()
    assert len(clustering_result_request_mdiplier) == len(messages_request_process)  # 这里应该用messages_request_aligned
    for i, fv in enumerate(clustering_result_request_mdiplier):
        if fv not in dict_fv_i:
            dict_fv_i[fv] = list()
        dict_fv_i[fv].append(messages_request_process[i])

    assert len(clustering_result_response_mdiplier) == len(messages_response_process)  # 这里应该用messages_response_aligned
    for i, fv in enumerate(clustering_result_response_mdiplier):
        if fv not in dict_fv_i:
            dict_fv_i[fv] = list()
        dict_fv_i[fv].append(messages_response_process[i])

    for fv in dict_fv_i:
        folder_name = os.path.join(args.output_dir, fv)
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)
        alignment = Alignment(messages=dict_fv_i[fv], output_dir=os.path.join(args.output_dir, fv))
        alignment.execute()

    msa_word = "msa_fields_visual.txt"

    msa_folder = os.path.join(args.output_dir, "new_msa")
    if not os.path.exists(msa_folder):
        os.mkdir(msa_folder)

    with open(os.path.join(msa_folder, msa_word), 'a') as fout:
        for fv in dict_fv_i:
            folder_name = os.path.join(args.output_dir, fv)
            with open(os.path.join(folder_name, msa_word)) as f:
                content = f.read()
                fout.write(content)
    
    end_time = time.time()
    print("{} messages spend {:.2f}s".format(len(p.messages), end_time - start_time))


    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    
    msg_to_index = {}

    csvfile = open(args.body_field_analysis_result, "w")
    cluster_writer = csv.writer(csvfile)
    cluster_writer.writerow(["Hexstream", "Split Indexes", "Splited Hexstream"])

    with open(os.path.join(msa_folder, msa_word), "r") as f:
        lines = f.readlines()

    for line in lines:
        cluster_index = [0]
        cluster_cur = 0

        msa_fields = line.split(" ")
        fields = []
        need_analyze = False
        for msa_field in msa_fields:
            f = "".join(msa_field.split("-")).strip().replace("~", "")
            if len(f):
                cluster_cur += len(f)
                if len(f) % 2:
                    print(
                        f"Result of {os.path.join(msa_folder, msa_word)} containts half-byte field: {msa_field}"
                    )
                cluster_index.append(cluster_cur)
                fields.append(f)
        pkt = "".join(fields).replace("~", "")
        pkt_split = " ".join(fields)
        cluster_writer.writerow([pkt, cluster_index, pkt_split])
    
    print("msg_to_index is done.")