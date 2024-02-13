import pandas as pd
import numpy as np

logs = pd.read_csv('http.log', header=None, sep='\t', names=["Time", "RequestID", "SourceIP", "SourcePort", "DestIP", "DestPort", "Unknown1", "RequestType", "RemoteLocation", "Resource", "FullResource", "UserAgent", "Unknown2", "Unknown3", "HTTPStatus", "HTTPStatusMsg", "Unknown4", "Unknown5", "Unknown6", "Unknown7", "Unknown8", "Unknown9", "Unknown10", "ReqID2", "MIME1", "ReqID3", "MIME2"])

# For debuggging purposes
# logs = logs.head(10000)

def keywordsearch():
    # Easiest - Look for certain keywords indicative of enumeration (Nmap, dirbuster, nikto, nessus) from UA, omitting clear directory enumeration using './' or '../' using UA
    UAcnt=logs[['SourceIP', 'UserAgent']].groupby(['SourceIP', 'UserAgent'])['UserAgent'].count().reset_index(name='count').sort_values(['count'], ascending=False)
    UAcnt['enumsoftware'] = UAcnt['UserAgent'].apply(lambda x: x.lower()).str.contains('|'.join(['nessus', 'dirbuster', 'nikto', 'nmap']))
    return set(UAcnt[UAcnt['enumsoftware']==True]['SourceIP'])

    # Debugging use
    # UAcnt.to_csv('UA.csv', index=False)

def highreqsearch():
    # Easier - check for IP that made the most requests / highest avg requests per second (barring a minimum threshold)
    # The following code is more thorough in that it includes UserAgent and HTTP Request Methods (GET, POST, PUT, HEAD) etc but 3x slower - ~12k rows x 5 columns
    # Assumption is that the duration between requests is similar (of course the best way to analyse is to use moving windows)
    '''
    x=logs[['Time', 'SourceIP', 'DestIP', 'DestPort', 'RequestType', 'UserAgent']].groupby(['SourceIP', 'DestIP', 'DestPort', 'RequestType','UserAgent'])["DestPort"].count().reset_index(name='count').sort_values(['count'], ascending=False)
    new = pd.DataFrame(columns=['SourceIP', 'DestIP', 'DestPort', 'RequestType', 'UserAgent','count', 'Duration', 'AverageReqPerSec'])

    import time
    for idx in x.index:
        row = x.loc[idx]
        rowdf = x.loc[[idx]]
        t = time.time()
        tmp = logs[(logs['SourceIP']==row['SourceIP']) & (logs['DestIP']==row['DestIP']) & (logs['DestPort']==row['DestPort']) & (logs['RequestType']==row['RequestType']) & (logs['UserAgent']==row['UserAgent'])]
        dur = max(tmp['Time'])-min(tmp['Time'])
        if x.loc[idx]['count'] == 1 or dur == 0:
            new = pd.concat([new,pd.concat([rowdf, pd.DataFrame.from_dict({"Duration": [dur],"AverageReqPerSec":[0] },orient='columns').set_index(rowdf.index)],axis=1, ignore_index=False)])
        else:
            new = pd.concat([new,pd.concat([rowdf, pd.DataFrame.from_dict({"Duration": [dur],"AverageReqPerSec":[row['count']/dur] },orient='columns').set_index(rowdf.index)],axis=1, ignore_index=False)])
    '''

    # This stripped down code only focuses on raw number of connections originating from sourceIP address (with respect to destinationIP) - ~700 rows x 3 columns
    reqcnt=logs[['Time', 'SourceIP', 'DestIP']].groupby(['SourceIP', 'DestIP'])['SourceIP'].count().reset_index(name='count').sort_values(['count'], ascending=False)

    new = pd.DataFrame(columns=['SourceIP', 'DestIP', 'count', 'Duration', 'AverageReqPerSec'])
    for idx in reqcnt.index:
        row = reqcnt.loc[idx]
        rowdf = reqcnt.loc[[idx]]
        tmp = logs[(logs['SourceIP']==row['SourceIP']) & (logs['DestIP']==row['DestIP'])]
        dur = max(tmp['Time'])-min(tmp['Time'])
        if row['count'] == 1 or dur == 0:
            new = pd.concat([new,pd.concat([rowdf, pd.DataFrame.from_dict({"Duration": [dur],"AverageReqPerSec":[0] },orient='columns').set_index(rowdf.index)],axis=1, ignore_index=False)])
        else:
            new = pd.concat([new,pd.concat([rowdf, pd.DataFrame.from_dict({"Duration": [dur],"AverageReqPerSec":[row['count']/dur] },orient='columns').set_index(rowdf.index)],axis=1, ignore_index=False)])

    # Get sourceIP for the 10 highest connection sources
    rawreqcntIP = set(new.sort_values(by='count', ascending=False).head(10)['SourceIP'])

    # Get sourceIP for high number of average requests per second (minimum 100 requests have to be made first to have some threshold)
    avgreqcntIP = set(new[(new['count']>=100) & (new["AverageReqPerSec"]>=20)]['SourceIP'])

    # Debugging use
    # new.to_csv('ReqCount.csv', index=False)
    
    return rawreqcntIP | avgreqcntIP

def unknownrequestsearch():

    # Medium - Look for sourceIP where there is non-standard HTTP request methods (Requires awareness of https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods)
    # Could be an indication of attempting to see which web server is running by sending bogus HTTP requests and viewing what is being returned
    unknownhttpreq = logs[['SourceIP', 'RequestType']].groupby(['SourceIP', 'RequestType'])['RequestType'].count().reset_index(name='count').sort_values(['count'], ascending=False)

    # '-' is added to the list of methods to look for as there is not enough info to classify it as a non-standard HTTP request method
    unknownhttpreq['standard'] = unknownhttpreq['RequestType'].apply(lambda x: x.lower()).str.contains('|'.join(['get', 'head', 'post', 'put', 'delete','connect', 'options', 'trace', 'patch', '-']))
    return set(unknownhttpreq[unknownhttpreq['standard']==False]['SourceIP'])

    # Debugging use
    # unknownhttpreq.to_csv('HTTPReq.csv', index=False)

def higherrorsearch():
    # Harder - Check % of 404 errors
    httpstatcnt=logs[['SourceIP', 'DestIP', 'DestPort', 'HTTPStatus']].groupby(['SourceIP', 'DestIP', 'DestPort','HTTPStatus'])['HTTPStatus'].count().reset_index(name='count').sort_values(['count'], ascending=False)

    # This is required as not all rows are stored as int
    httperror=httpstatcnt[(httpstatcnt['HTTPStatus']==404) | (httpstatcnt['HTTPStatus']=='404')][['SourceIP', 'DestIP', 'DestPort']].drop_duplicates()

    # Assumption is that the most of the errors are from a single enumeration program (Note that nikto reports multiple UA) so UA is omitted, and that the number of 404 would be far greater than normal traffic
    errorpct = pd.DataFrame(columns=['SourceIP', 'DestIP', 'DestPort', '404Pct'])
    for idx in httperror.index:
        row = httperror.loc[idx]
        rowdf = httperror.loc[[idx]]
        tmp = httpstatcnt[(httpstatcnt['SourceIP']==row['SourceIP']) & (httpstatcnt['DestIP']==row['DestIP']) & (httpstatcnt['DestPort']==row['DestPort'])]
        errorcnt = sum(tmp[(tmp['HTTPStatus']==404) | (tmp['HTTPStatus']=='404')]['count'])
        totcnt = sum(tmp['count'])
        
        # Only consider after a reasonable number of requests being sent (100)
        if totcnt >= 100:
            errorpct = pd.concat([errorpct,pd.concat([rowdf, pd.DataFrame.from_dict({"404Pct": [errorcnt/totcnt*100] },orient='columns').set_index(rowdf.index)],axis=1, ignore_index=False)])

    # Set a threshold of 80% 404 rate
    errorpct[errorpct['404Pct']>=80]

    return set(errorpct[errorpct['404Pct']>=80]['SourceIP'])


    # Debugging use
    errorpct.to_csv('404Pct.csv', index=False)

def highheadsearch():
    # Easier - Search for high number of HEAD requests - as HEAD contains the information needed to tell if the resource exists without requiring pulling the entire file
    # A large number of HEAD requests can indicate enumeration
    headreq = logs[['SourceIP', 'RequestType']].groupby(['SourceIP', 'RequestType'])['RequestType'].count().reset_index(name='count').sort_values(['count'], ascending=False)
    
    headreq['head'] = headreq['RequestType'].apply(lambda x: x.lower()).str.contains('head')
    return set(headreq[(headreq['head']==True) & (headreq['count']>=1000)]['SourceIP'])

# Union the set of IP addresses together (duplicates will be automatically removed)
UAcntIP = keywordsearch()
reqIP = highreqsearch() 
unknownhttpreqIP = unknownrequestsearch()
errorpctIP = higherrorsearch()
highheadIP = highheadsearch() 

# list of IP addresses with possible recon features
IPset = UAcntIP | reqIP | unknownhttpreqIP | errorpctIP | highheadIP

print(IPset)