# ---------------------------------------------------------------------
# dwarfparse.py
#
# Parse DWARF information and generate C header files using pyelftools
#
# Istvan Telek <moriss@realmoriss.me>
# ---------------------------------------------------------------------

import argparse
import json
import os

from pyelftools.elftools.dwarf.compileunit import CompileUnit
from pyelftools.elftools.dwarf.die import DIE
from pyelftools.elftools.elf.elffile import ELFFile


def build_dict(seq, key):
    return dict((d[key], dict(d, index=index)) for (index, d) in enumerate(seq))


def dict_by_offset(item_list):
    return build_dict(item_list, key='_offset')


def parse_die(die: DIE):
    item = {'_offset': die.offset, '_tag': die.tag}
    if 'DW_AT_name' in die.attributes:
        item['name'] = die.attributes['DW_AT_name'].value.decode('ascii')
    if 'DW_AT_byte_size' in die.attributes:
        item['size'] = die.attributes['DW_AT_byte_size'].value
    if 'DW_AT_encoding' in die.attributes:
        item['encoding'] = die.attributes['DW_AT_encoding'].value
    if 'DW_AT_type' in die.attributes:
        item['type'] = die.attributes['DW_AT_type'].value
    if 'DW_AT_data_member_location' in die.attributes:
        item['offset'] = die.attributes['DW_AT_data_member_location'].value
    if 'DW_AT_upper_bound' in die.attributes:
        item['ub'] = die.attributes['DW_AT_upper_bound'].value
    if 'DW_AT_lower_bound' in die.attributes:
        item['lb'] = die.attributes['DW_AT_lower_bound'].value
    if 'DW_AT_bit_size' in die.attributes:
        item['bitsize'] = die.attributes['DW_AT_bit_size'].value
    children = []
    if (die.has_children and die.tag != 'DW_TAG_compile_unit') \
            or die.tag == 'DW_TAG_structure_type':
        for child in die.iter_children():
            children.append(parse_die(child))
    item['children'] = children
    return item


def parse_die_json(die: DIE):
    children = []
    if die.has_children:
        for child in die.iter_children():
            children.append(child.offset)
    attributes = {}
    for key, attr in die.attributes.items():
        val = attr.value
        rawval = attr.raw_value
        if type(attr.value) is bytes or type(attr.value) is bytearray:
            val = attr.value.decode('ascii')
        if type(attr.raw_value) is bytes or type(attr.raw_value) is bytearray:
            rawval = attr.raw_value.decode('ascii')
        attributes[key] = {'name': attr.name, 'form': attr.form, 'value': val,
                           'raw_value': rawval, 'offset': attr.offset}
    item = {'offset': die.offset, 'tag': die.tag, 'attributes': attributes,
            'has_children': die.has_children, 'size': die.size, 'children': children}
    return item


def parse_cu(cu: CompileUnit):
    items = []
    for die in cu.iter_DIEs():
        items.append(parse_die(die))
    return {'items': dict_by_offset(items), '_items': items}


def parse_item(item, items, indent=0):
    blacklist = ['__va_list', '__gnuc_va_list', 'va_list', 'va_format', 'mutex', 'size_t',
                 'ssize_t', 'int32_t', 'uint32_t', 'bool']

    ret = {'text': '', 'post_text': '', 'deps': set(), 'size': 0}

    if item is None:
        return ret

    item_name = ''
    if item is not None and 'name' in item:
        item_name = item['name']
        if item_name in blacklist:
            item_name = 'blt_{}'.format(item_name)

    if item['_tag'] == 'DW_TAG_base_type':
        if 'name' in item:
            ret['text'] = item['name']
        else:
            ret['text'] = 'void'
        if 'size' in item:
            ret['size'] = item['size']

    elif item['_tag'] == 'DW_TAG_member':
        member_type = {}
        if 'type' in item:
            item_type = items.get(item['type'])
            member_type = parse_item(item_type, items, indent + 1)
            if item_type is not None:
                ret['deps'].add(item_type['_offset'])
                ret['deps'] |= member_type['deps']
            ret['size'] = member_type['size']
        item_name = '{}'.format(item_name)
        if 'bitsize' in item:
            item_name = "{}: {}".format(item_name, item['bitsize'])
        ret['text'] = "{}{} {}{};".format('\t' * indent, member_type['text'], item_name,
                                          member_type['post_text'])

    elif item['_tag'] == 'DW_TAG_array_type':
        member_type = 'void'
        if 'type' in item:
            item_type = items.get(item['type'])
            parsed_item = parse_item(item_type, items, indent + 1)
            member_type = parsed_item['text']
            ret['deps'].add(item_type['_offset'])
            ret['deps'] |= parsed_item['deps']
            ret['size'] = parsed_item['size']
        ret['text'] = member_type
        for child in item['children']:
            parsed_child = parse_item(child, items, indent + 1)
            ret['post_text'] = '{}[{}]'.format(ret['post_text'], parsed_child['text'])
            ret['size'] *= parsed_child['size']

    elif item['_tag'] == 'DW_TAG_pointer_type':
        member_type = 'void'
        if 'size' in item:
            ret['size'] = item['size']
        if 'type' in item:
            item_type = items.get(item['type'])
            if item_type is not None and \
                    item_type['_tag'] == 'DW_TAG_structure_type' and \
                    'children' in item_type:
                dummy_type = items.get(-item_type['_offset'])
                if dummy_type is None:
                    dummy_type = {'_offset': -item_type['_offset'], '_tag': item_type['_tag'],
                                  'name': item_type['name']}
                    items[-item_type['_offset']] = dummy_type
                item_type = dummy_type
                item['type'] = item_type['_offset']
            parsed_item = parse_item(item_type, items, indent + 1)
            member_type = parsed_item['text']
            ret['deps'].add(item_type['_offset'])
            ret['deps'] |= parsed_item['deps']
        ret['text'] = member_type + '*'

    elif item['_tag'] == 'DW_TAG_volatile_type':
        member_type = 'void'
        if 'type' in item:
            item_type = items.get(item['type'])
            parsed_item = parse_item(item_type, items, indent + 1)
            member_type = parsed_item['text']
            ret['deps'].add(item_type['_offset'])
            ret['deps'] |= parsed_item['deps']
            ret['size'] = parsed_item['size']
        ret['text'] = 'volatile ' + member_type

    elif item['_tag'] == 'DW_TAG_const_type':
        member_type = 'void'
        if 'type' in item:
            item_type = items.get(item['type'])
            parsed_item = parse_item(item_type, items, indent + 1)
            member_type = parsed_item['text']
            ret['deps'].add(item_type['_offset'])
            ret['deps'] |= parsed_item['deps']
            ret['size'] = parsed_item['size']
        ret['text'] = member_type + ' const '

    elif item['_tag'] == 'DW_TAG_subroutine_type':
        member_type = 'void'
        if 'type' in item:
            item_type = items.get(item['type'])
            parsed_item = parse_item(item_type, items, indent + 1)
            member_type = parsed_item['text']
            ret['deps'].add(item_type['_offset'])
            ret['deps'] |= parsed_item['deps']
            ret['size'] = parsed_item['size']
        ret['text'] = member_type

    elif item['_tag'] == 'DW_TAG_union_type':
        if 'size' in item:
            ret['size'] = item['size']
        if item_name == '' or indent == 0:
            if item_name != '':
                item_name += ' '
            ret['text'] = 'union {}{{\n'.format(item_name)
            for child in item['children']:
                ret['deps'].add(child['_offset'])
                parsed_item = parse_item(child, items, indent + 1)
                ret['text'] += parsed_item['text'] + '\n'
                ret['deps'] |= parsed_item['deps']
            ret['text'] += '\t' * (indent - 1) + '}'
            if indent == 0:
                ret['text'] += ';'
        else:
            ret['text'] = 'union {}'.format(item_name)

    elif item['_tag'] == 'DW_TAG_enumeration_type':
        if 'size' in item:
            ret['size'] = item['size']
        if item_name == '' or indent == 0:
            if item_name != '':
                item_name += ' '
            ret['text'] = 'enum {}{{\n'.format(item_name)
            for child in item['children']:
                ret['deps'].add(child['_offset'])
                parsed_item = parse_item(child, items, indent + 1)
                ret['text'] += parsed_item['text'] + '\n'
                ret['deps'] |= parsed_item['deps']
            ret['text'] += '\t' * (indent - 1) + '}'
            if indent == 0:
                ret['text'] += ';'
        else:
            ret['text'] = 'enum {}'.format(item_name)

    elif item['_tag'] == 'DW_TAG_structure_type':
        if 'size' in item:
            ret['size'] = item['size']
        if item_name == '' or (indent == 0 and 'children' in item):
            if item_name != '':
                item_name += ' '
            ret['text'] += 'struct {}{{\n'.format(item_name)
            child_offs, child_size, counter = 0, 0, 0
            if 'children' in item:
                for child in item['children']:
                    prev_offs = child_offs
                    if 'offset' in child:
                        child_offs = child['offset']
                        if prev_offs + child_size < child_offs:
                            padding_offs = child_offs - prev_offs - child_size
                            ret['text'] = '{}{}char _{}{}pad[{}];\n'.format(ret['text'],
                                                                            '\t' * (indent + 1),
                                                                            item['_offset'],
                                                                            counter, padding_offs)
                            counter += 1
                    ret['deps'].add(child['_offset'])
                    parsed_item = parse_item(child, items, indent + 1)
                    ret['text'] += parsed_item['text'] + '\n'
                    ret['deps'] |= parsed_item['deps']
                    child_size = parsed_item['size']
            struct_size = child_offs + child_size
            if struct_size < ret['size']:
                ret['text'] = '{}{}char _{}pad[{}];\n'.format(ret['text'], '\t' * (indent + 1),
                                                              item['_offset'],
                                                              item['size'] - struct_size)
            ret['text'] = '{}{}}}'.format(ret['text'], '\t' * (indent - 1))
            if indent == 0:
                ret['text'] += ';'
        else:
            ret['text'] = 'struct {}'.format(item_name)
            if indent == 0:
                ret['text'] += ';'

    elif item['_tag'] == 'DW_TAG_enumerator':
        item_name = 'void'
        if 'name' in item:
            item_name = item['name']
        ret['text'] = '\t' * indent + item_name + ','

    elif item['_tag'] == 'DW_TAG_subrange_type':
        ub = lb = size = 0
        if 'ub' in item:
            ub = item['ub']
        if 'lb' in item:
            lb = item['lb']
        if ub > 0 or lb > 0:
            size = ub - lb + 1
        ret['text'] = str(size)
        ret['size'] = size

    elif item['_tag'] == 'DW_TAG_typedef':
        item_type = {'text': 'void', 'post_text': ''}
        if 'type' in item:
            it = items.get(item['type'])
            if it is not None:
                item_type = parse_item(it, items, indent + 1)
                if it['_tag'] != 'DW_TAG_base_type' and indent == 0:
                    ret['deps'].add(it['_offset'])
                    ret['deps'] |= item_type['deps']
                ret['size'] = item_type['size']
        if indent == 0:
            ret['text'] += 'typedef {} '.format(item_type['text'])
        ret['text'] += item_name
        if indent == 0:
            ret['text'] += item_type['post_text'] + ';'

    return ret


def print_all(dwarfinfo, file=None, gen_headers=True):
    printables = []

    print('Preprocessing items...')
    for item in dwarfinfo['_items']:
        if 'name' in item:
            if item['_tag'] in ['DW_TAG_structure_type', 'DW_TAG_union_type',
                                'DW_TAG_enumeration_type', 'DW_TAG_typedef']:
                parse_item(item, dwarfinfo['items'], 0)

    print('Parsing items...')
    for offset, item in dwarfinfo['items'].items():
        if 'name' in item:
            if item['_tag'] in ['DW_TAG_structure_type', 'DW_TAG_union_type',
                                'DW_TAG_enumeration_type', 'DW_TAG_typedef']:
                parsed_item = parse_item(item, dwarfinfo['items'], 0)
                print_item = {'item': offset, 'deps': parsed_item['deps'],
                              'text': parsed_item['text']}
                printables.append(print_item)

    print('Resolving dependencies...')
    printables = sorted(printables, key=lambda el: len(el['deps']))
    change_num = 0
    changed = True
    while changed:
        changed = False
        for i, item in enumerate(printables):
            for j, dep in enumerate(printables):
                if i > j and item['item'] in dep['deps'] and dep['item'] not in item['deps']:
                    it = printables.pop(i)
                    dep_i = printables.index(dep)
                    printables.insert(dep_i, it)
                    change_num += 1
                    changed = True
                    break
    print('{0} dependencies were resolved.'.format(change_num))

    if gen_headers:
        print('Generating C header...')
        print('/* AUTO GENERATED FILE */', file=file)

        for item in printables:
            if 'text' in item:
                print(item['text'], file=file)


class ValidFile(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if not os.path.isfile(values):
            parser.error('{0} is not a valid file.'.format(values))
        if os.access(values, os.R_OK):
            setattr(namespace, self.dest, values)
        else:
            parser.error('{0} is not accessible.'.format(values))


class ValidDir(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if not os.path.isdir(values):
            parser.error('{0} is not a valid directory.'.format(values))
        if os.access(values, os.W_OK):
            setattr(namespace, self.dest, values)
        else:
            parser.error('{0} is not accessible.'.format(values))


def main():
    parser = argparse.ArgumentParser(
        description='Parse DWARF information and generate C header files')
    parser.add_argument('file', help='path of input ELF binary', action=ValidFile)
    parser.add_argument('-o', '--out', help='output directory for header files (optional)',
                        action=ValidDir)
    parser.add_argument('-s', '--suppress', dest='suppr', action='store_true',
                        help='do not generate output headers')
    args = parser.parse_args()
    with open(args.file, 'rb') as f:
        elffile = ELFFile(f)
        if elffile.has_dwarf_info():
            dwarfinfo = elffile.get_dwarf_info()
            for cu in dwarfinfo.iter_CUs():
                items = {}
                for die in cu.iter_DIEs():
                    die_item = parse_die_json(die)
                    items[die_item['offset']] = die_item
                print('Found compile unit at offset {}'.format(cu.cu_offset))
                print('Reading DWARF information...')
                result = parse_cu(cu)
                print('Found {} nodes in compilation unit.'.format(len(result['items'])))
                if args.out:
                    with open(os.path.join(args.out, 'cu_{}.h'.format(cu.cu_offset)),
                              'w') as output:
                        print_all(result, output, gen_headers=not args.suppr)
                    with open(os.path.join(args.out, 'cu_{}.json'.format(cu.cu_offset)),
                              'w') as output:
                        print(json.dumps(items, indent=2), file=output)
                else:
                    print_all(result, gen_headers=not args.suppr)
            print('Done.')
        else:
            print('The specified file does not contain DWARF information.')


if __name__ == '__main__':
    main()
