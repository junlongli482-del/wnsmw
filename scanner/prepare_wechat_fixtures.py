"""Prepare camera-frame transport fixtures; no detection or enhancement here."""
from probe_recovered_models import ROOT,load_image
import cv2,numpy as np,json,hashlib

def main():
    folder=ROOT/'.work/wechat-page-fixtures';folder.mkdir(exist_ok=True)
    page=cv2.resize(load_image(ROOT/'scanner/samples/photo-1.jpg'),(300,225));records=[]
    for kind,left in [('stable',90),('shift',165),('blank',None)]:
        image=np.full((360,480,3),70,np.uint8)
        if left is not None:image[65:290,left:left+300]=page
        raw=cv2.cvtColor(image,cv2.COLOR_BGR2RGBA).tobytes();path=folder/f'{kind}.rgba';path.write_bytes(raw)
        records.append({'kind':kind,'width':480,'height':360,'file':path.name,'sha256':hashlib.sha256(raw).hexdigest()})
    (folder/'manifest.json').write_text(json.dumps(records,indent=2),encoding='utf-8')

if __name__=='__main__':main()
