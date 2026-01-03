import os

from alignment import Alignment

class FieldSplitByMSA:
    
    def __init__(self, messages, output_dir='tmp/', mode='ginsi', multithread=False):
        self.messages = messages
        self.output_dir = output_dir
        self.mode = mode
        self.multithread = multithread
    
    def field_split_by_MSA(self):
        msa = Alignment(messages=self.messages, output_dir=self.output_dir, mode=self.mode, multithread=self.multithread)
        msa.execute()
        
        filepath_fields_info = os.path.join(self.output_dir, Alignment.FILENAME_FIELDS_INFO)
        filepath_fields_visual = os.path.join(self.output_dir, Alignment.FILENAME_FIELDS_VISUAL)
        filepath_fields_describe = os.path.join(self.output_dir, Alignment.FILENAME_FIELDS_DESCRIBE)
        
        result = {}
        field_format_dict = {"D":"D(L = {}, V = [{}])", "S":"S(V = {})", "V":"D(L = ({},{}))"}
        split_fields_rows = []

        with open(filepath_fields_visual) as f01:
            field_value_list = f01.readlines()
            for i in range(len(field_value_list)):
                split_fields_rows.append(field_value_list[i].split())
                for j in range(len(split_fields_rows[i])):
                    if "-" in split_fields_rows[i][j]:
                        new_field_list = split_fields_rows[i][j].split("-")
                        new_field = ''.join(new_field_list)
                        split_fields_rows[i][j] = new_field
                    else:
                        continue
            print(split_fields_rows)

        with open(filepath_fields_info) as f02:
            field_format_list = f02.readlines()
            for i in range(len(field_format_list)):
                typename, typesizemin, typesizemax, fieldtype = field_format_list[i].split()
                if fieldtype == "S":
                    result['f'+ str(i+1)] = field_format_dict[fieldtype].format(split_fields_rows[0][i])
                elif fieldtype == "D":
                    field_set = set()
                    for j in range(len(split_fields_rows)):
                        field_set.add(split_fields_rows[j][i])
                    res = ""
                    for k,s in enumerate(iter(field_set)):
                        if k == len(field_set) - 1:
                            res = res + s
                        else:
                            res = res + s + ","
                    result['f'+ str(i+1)] = field_format_dict[fieldtype].format(eval(typesizemax) // 16, res)
                elif fieldtype == "V":
                    result['f'+ str(i+1)] = field_format_dict[fieldtype].format(eval(typesizemin) // 16, eval(typesizemax) // 16)

        with open(filepath_fields_describe, 'w+') as f03:
            for key, value in result.items():
                f03.write('{}:{}'.format(key, value)+'\n')
        return result