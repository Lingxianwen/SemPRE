import json

with open("./100data.json","r") as f:
    data = json.load(f)

data_nums = len(data.keys())

# get message_min_len
min_len=100000
for idx,item in enumerate(data):
    if min_len>len(data[str(idx)]):
        min_len = len(data[str(idx)])

min_len =int(min_len/2)


diff_list = []
down_up_minus_one_list = []
for sp_idx in range(min_len):
    print("sp_idx:",sp_idx)
    down_up_minus_one_flag = True
    for idx, item in enumerate(data):
        if idx==0:
            continue
        diff = abs(int(data[str(idx)][sp_idx*2:(sp_idx+1)*2],16)-int(data[str((idx-1))][sp_idx*2:(sp_idx+1)*2],16))
        if diff!=1 and diff !=0:
            down_up_minus_one_flag = False
    down_up_minus_one_list.append(down_up_minus_one_flag)

    diff_total = 0
    for idx, item in enumerate(data):
        if idx==0:
            continue
        diff = abs(int(data[str(idx)][sp_idx*2:(sp_idx+1)*2],16)-int(data[str(idx-1)][sp_idx*2:(sp_idx+1)*2],16))
        
        diff_total+=diff
    
    diff_list.append(diff_total)

min_value = min(diff_list)
min_indices = [i for i, value in enumerate(diff_list) if value == min_value]



# logic one
logic1 = True
res1 = 0
if logic1:

    for i in range(1,len(diff_list)):
        zero_flag = True
        if diff_list[len(diff_list)-i]==0 and zero_flag:
            zero_flag=False
            continue
        if diff_list[len(diff_list)-i]!=0:
            print(diff_list[len(diff_list)-i])
            res1=(len(diff_list)-i)
            break
print("logic1:",res1)

# logic two
logic2 = True
res2 = 0
if logic2:
    non_zero_list = [num for num in diff_list if num != 0]
    average = sum(non_zero_list) / len(non_zero_list) if len(non_zero_list) > 0 else 0
    for i in range(1,len(diff_list)):
        zero_flag = True
        if diff_list[len(diff_list)-i]==0 and zero_flag:
            zero_flag=False
            continue
        if average<diff_list[len(diff_list)-i]:
            res2=(len(diff_list)-i)
            break
print("logic2:",res2)

# logic three
logic3 = True
res3 = 0
if logic2:
    idx = 0
    for i in down_up_minus_one_list:
        if i==False:
            break
        else:
            idx+=1
    res3=idx
print("logic3:",res3)

# logic 4
logic4 = True
res4 = []

if logic4:
    non_zero_list = [num for num in diff_list if num != 0]
    average = sum(non_zero_list) / len(diff_list) if len(non_zero_list) > 0 else 0
    one_byte_gain = average
    rebuild_diff_list = []
    
    for idx,item in enumerate(diff_list):
        if idx==0:
            total_gain = 0
        else:
            total_gain = rebuild_diff_list[idx-1]
        if idx==0 or down_up_minus_one_list[idx]:
            total_gain+=one_byte_gain
        else:
            total_gain+=one_byte_gain
            total_gain-=diff_list[idx]
        rebuild_diff_list.append(total_gain)
    max_gain = max(rebuild_diff_list)
    res4 = rebuild_diff_list.index(max_gain)
    print("logic4:",res4)