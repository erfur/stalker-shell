import json
import sys
from loguru import logger
import pprint


def read_json_file(fname):
    with open(fname) as f:
        return json.load(f)


def run(args):
    fcn_info = read_json_file(args[0])
    trace = read_json_file(args[1])

    module_name = fcn_info['name']
    function_list = fcn_info['functions']

    logger.info(f'module name: {module_name}')


    for tid in trace:
        current_indent = 0
        output = ''
        
        logger.info(f'tid {tid}')
        for trace_obj in trace[tid]:
            obj_type = trace_obj['type']
            fcn_offset = trace_obj['fcnOffset']
            fcn_name_list = [i['name'] for i in function_list if i['offset'] == int(fcn_offset, 16)]

            if fcn_name_list:
                fcn_name = fcn_name_list[0]
            else:
                fcn_name = ''

            
            if obj_type == 'call':
                ret_offset = trace_obj['retOffset']
                output += f'{current_indent*2*" "} -> {fcn_name} {fcn_offset}, ret {ret_offset}\n'
                current_indent += 1
            else:
                ret_value = trace_obj['retValue']
                current_indent -= 1
                output += f'{current_indent*2*" "} <- {fcn_name} {fcn_offset}, retval {ret_value}\n'

        print(output)


if __name__ == '__main__':
    run(sys.argv[1:])
