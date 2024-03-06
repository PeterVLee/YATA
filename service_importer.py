import pandas as pd

def import_2fas(input_file):
    names = []
    secrets = []

    with open(input_file, "rb") as f:
        data = f.read().decode()

    data = data.split('"name":"')

    for row in data:
        row = row.split('","')
        # check if row is actual data
        # messy, needs better error handling
        try:
            if row[1][:6] != 'secret':
                continue
        except:
            continue

        names.append(row[0])
        secrets.append(row[1][9:])

    return pd.DataFrame({'name': names, 'secret':secrets})
    #df.to_csv("2fas.csv", index=False)