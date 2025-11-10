import pandas as pd

for i in range(1, 11):
    input_path = f'set{i}_full_min_matched_attacks.csv'

    df = pd.read_csv(input_path)

    # Convert microsecond timestamps based on chosen time unit: 'second', 'minute', 'hour'
    time_unit = 'hour'  # options: 'second', 'minute', 'hour'
    if time_unit == 'second':
        df['timestamp'] = (df['timestamp'] // 1_000_000).astype(int)
    elif time_unit == 'minute':
        df['timestamp'] = (df['timestamp'] // 1_000_000 // 60).astype(int)
    elif time_unit == 'hour':
        df['timestamp'] = (df['timestamp'] // 1_000_000 // 3600).astype(int)
    else:
        raise ValueError("Unsupported time_unit: choose from 'second', 'minute', or 'hour'")

    # collapse duplicates on all columns except 'count', summing 'count'
    before = len(df)
    group_cols = [c for c in df.columns if c != 'count']
    df = df.groupby(group_cols, as_index=False)['count'].sum()
    after = len(df)
    print(f'[{input_path}] Collapsed {before - after} duplicate groups; now {after} rows.')

    # write dataframe to a compressed CSV file
    out_path = input_path.replace('.csv', '_hour_out.csv')
    df.to_csv(out_path, index=False)
    print(f'[{input_path}] Wrote {len(df)} rows to {out_path}')