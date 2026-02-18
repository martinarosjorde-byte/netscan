# loadsubnets.py

def load_subnets_from_file(path):
    subnets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                subnets.append(line)
    return subnets