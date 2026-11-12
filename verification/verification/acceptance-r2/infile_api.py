"""Parameter mapping only; all security behavior is in the frozen product."""
def execute(cursor, sql, streams):
    return cursor.execute(sql, local_infile_streams=streams)
