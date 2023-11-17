import pickle

pickle_file = open("port_description.dat", "wb")  # Open in binary mode for writing
file_name = input("Enter the file name: ")

with open(file_name, "rb") as f:  # Open in binary mode for reading
    dict1 = {}
    for line in f:
        # Ensure the line is decoded to a string before splitting
        line = line.decode("utf-8")
        key, value = line.split(':', 1)
        dict1[int(key.strip())] = value.strip()


print("Dictionary is created")
pickle.dump(dict1, pickle_file)
pickle_file.close()
print("port_description.dat is created")

