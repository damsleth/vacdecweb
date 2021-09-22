# vacdecweb

A Frontend for [vacdec]((https://github.com/hannob/vacdec)), an EU COVID19 passport QR code decoder written in python by Hanno Böck.  
The webapp itself uses nodejs and express, and allows you to upload a photo of your QR code and get the JSON data contents in return

## Prerequisites

nodejs - testet with v14 but will probably work with v12 as well. `once` will fail on versions < 11  
python >=3.7 with pip

* clone repo
* `pip install -r requirements.txt`
* `npm install`
* `npm index.js`

## License
WTFPL