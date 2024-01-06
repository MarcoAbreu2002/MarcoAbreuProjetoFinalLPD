def transform_ports(input_filename, output_filename):
    with open(input_filename, 'r') as input_file:
        input_string = input_file.read()

    output_lines = []

    for line in input_string.split('\n'):
        parts = line.split(' : ')
        if '–' in parts[0]:
            start, end = map(int, parts[0].split('–'))
            protocol_info = parts[1]
            # print(protocol_info)
            for port in range(start, end + 1):
                # print(protocol_info)
                # if len(protocol_info) == 2:
                output_lines.append(f"{port} : {protocol_info} ")
                # else:
                #     Handle the case where protocol_info doesn't have the expected number of elements
                #     output_lines.append(f"{port} : Unknown Protocol")
        else:
            output_lines.append(line)

    output_string = '\n'.join(output_lines)

    with open(output_filename, 'w') as output_file:
        output_file.write(output_string)

# Example usage:
transform_ports('output.txt', 'outputTT.txt')
