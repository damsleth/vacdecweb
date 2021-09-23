import express from "express"
import path from "path"
import favicon from "serve-favicon"
import download from "image-downloader"
import multer from "multer"
import once from "once"
const app = express()
const port = process.env.PORT || 3000
app.set('view engine', 'ejs')
app.use(express.static(__dirname + '/public'))
app.use(favicon(path.join(__dirname, 'public', 'img', 'favicon.ico')))

const storage = multer.diskStorage(
  {
    destination: './public/uploads/',
    filename: function (_req, file, cb) { cb(null, file.originalname) }
  }
)
const upload = multer({ storage: storage })

app.get('/', (_req, res) => { res.render("index") })

app.get('/getImage', (req, res) => {
  let imageUrl = req.query.url
  if (!imageUrl) { return }
  let imageFileName = `/memes/${new Date().getTime()}.jpg`
  let opts = {
    url: imageUrl,
    dest: `public/${imageFileName}`
  }
  download.image(opts).then(() => res.json({ path: imageFileName }))
})


// upload file route with handling of non-images
app.post('(/upload)', upload.single("file"), (req, res, next) => {
  if (!req.file.mimetype.startsWith('image/')) {
    return res.status(422).json({ error: 'The uploaded file must be an image' })
  }
  return res.status(200).send(req.file)
})

app.get('/decodeImage', async (req, res) => {
  console.log("decode image hit!")
  let imgUrl = req.query.url
  if (!imgUrl) return
  console.log(`decoding ${imgUrl}`)
  // hack, only support uploading images so they're all in the uploads folder
  let upImgUrl = `./public${imgUrl.substring(imgUrl.indexOf("/uploads"))}`
  let imgData = await getQR(upImgUrl)
  res.status(200)
  res.send(imgData)
  res.end()

  function getQR(url) {
    return new Promise((resolve, reject) => {
      console.log("getQR triggered")
      console.log("decoding" + url)
      let output = ''
      let spawn = require('child_process').spawn
      let py = spawn('pipenv', ['run', './vacdec', `${url}`])
      py.stdin.setEncoding = 'utf-8'
      py.stdout.on('data', (data) => { output += data.toString() })
      py.stderr.on('data', (data) => { console.log('error:' + data) })
      py.stdout.on('end', async function (code) {
        if (!code) {
          console.log("no usable QR data found")
          resolve("ERROR: no usable QR data found - try another image")
        } else {
          console.log("finished")
          resolve(output)
        }
      })
      once(py, 'close')
      return
    })
  }
})

// 404 route, for all routes not hit by any other endpoints
app.get('(/*)?', (_req, res) => res.render("404"))

// Start App
app.listen(port, () => console.log(`Example app listening on port ${port}!`))