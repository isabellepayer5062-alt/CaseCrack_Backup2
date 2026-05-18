import json

gau = json.load(open('CaseCrack/reports/recon-gau.json', encoding='utf-8'))
gf = gau.get('findings', [])
print('GAU findings:', len(gf))
urls_with_params = [f.get('url','') or f.get('title','') for f in gf if '?' in str(f.get('url','') or f.get('title',''))]
print('GAU URLs with params:', len(urls_with_params))
for u in urls_with_params[:10]:
    print(' ', str(u)[:120])

params = json.load(open('CaseCrack/reports/recon-params.json', encoding='utf-8'))
pf = params.get('findings', [])
print('\nParams findings:', len(pf))
for p in pf[:20]:
    ev = str(p.get('evidence',''))
    print(' ', p.get('severity'), '|', p.get('title','')[:60], '|', ev[:60])

pipeline = json.load(open('CaseCrack/reports/recon-pipeline.json', encoding='utf-8'))
pf2 = pipeline.get('findings', [])
print('\nPipeline findings:', len(pf2))
urls2 = [f.get('url','') for f in pf2 if '?' in str(f.get('url',''))]
print('Pipeline URLs with params:', len(urls2))
for u in urls2[:10]:
    print(' ', str(u)[:120])

# Check the dorks for actionable URLs
dorks = json.load(open('CaseCrack/reports/recon-dorks.json', encoding='utf-8'))
df = dorks.get('findings', [])
print('\nDorks findings:', len(df))
shopify_urls = [f for f in df if 'sugarrushed.ca' in str(f.get('title','')) or 'sugarrushed.ca' in str(f.get('url',''))]
print('Dorks sugarrushed.ca URLs:', len(shopify_urls))
print('Sample titles:', [f.get('title','')[:80] for f in shopify_urls[:5]])
