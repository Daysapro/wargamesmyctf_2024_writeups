values = [25, 10, 0, 3, 17, 19, 23, 27, 4, 13, 20, 8, 24, 21, 31, 15, 7, 29, 6, 1, 9, 30, 22, 5, 28, 18, 26, 11, 2, 14, 16, 12]

with open('challenge.dcm', 'rb') as file:
    file = file.read()

binary_lines = []
for i in range(12, len(file), 12):
    binary_lines.append(file[i:i+12])

flag = ""
for value in values:
    flag += chr(binary_lines[value][-4])

print("WGMY{" + flag + "}")