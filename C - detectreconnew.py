import pandas as pd
import numpy as np

logs = pd.read_csv('http.log', header=None, sep='\t', names=["Time", "RequestID", "SourceIP", "SourcePort", "DestIP", "DestPort", "Unknown1", "RequestType", "RemoteLocation", "Resource", "FullResource", "UserAgent", "Unknown2", "Unknown3", "HTTPStatus", "HTTPStatusMsg", "Unknown4", "Unknown5", "Unknown6", "Unknown7", "Unknown8", "Unknown9", "Unknown10", "ReqID2", "MIME1", "ReqID3", "MIME2"])

# For debuggging purposes
logs = logs.head(10000)

# Easiest - check for IP/UA that made the most request
x=logs[['Time', 'SourceIP', 'DestIP', 'DestPort', 'RequestType', 'UserAgent']].groupby(['SourceIP', 'DestIP', 'DestPort', 'RequestType','UserAgent'])["DestPort"].count().reset_index(name='count').sort_values(['count'], ascending=False)

new = pd.DataFrame(columns=['SourceIP', 'DestIP', 'DestPort', 'RequestType', 'UserAgent','count', 'Duration', 'AverageReqPerSec'])
import time
for idx in x.index:
    
    t = time.time()
    tmp = logs[(logs['SourceIP']==x.iloc[idx]['SourceIP']) & (logs['DestIP']==x.iloc[idx]['DestIP']) & (logs['DestPort']==x.iloc[idx]['DestPort']) & (logs['RequestType']==x.iloc[idx]['RequestType']) & (logs['UserAgent']==x.iloc[idx]['UserAgent'])]
    dur = max(tmp['Time'])-min(tmp['Time'])
    if x.iloc[idx]['count'] == 1:
        new = pd.concat([new,pd.concat([x.iloc[[idx]], pd.DataFrame.from_dict({"Duration": [dur],"AverageReqPerSec":[0] },orient='columns').set_index(x.iloc[[idx]].index)],axis=1, ignore_index=False)])
    else:
        new = pd.concat([new,pd.concat([x.iloc[[idx]], pd.DataFrame.from_dict({"Duration": [dur],"AverageReqPerSec":[x.iloc[idx]['count']/dur] },orient='columns').set_index(x.iloc[[idx]].index)],axis=1, ignore_index=False)])
    print(time.time()-t)


new.to_csv('ReqCount.csv', index=False)