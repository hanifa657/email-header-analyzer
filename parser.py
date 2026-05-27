def extract_headers(file_path):

    headers = {}

    with open(file_path, "r") as file:
        lines = file.readlines()

    for line in lines:

        if ":" in line:
            key, value = line.split(":", 1)

            headers[key.strip()] = value.strip()

    return headers