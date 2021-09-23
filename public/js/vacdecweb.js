function init() {
  if (localStorage["darkmode"] == "true") {
    document.body.classList.toggle('darkmode')
    document.getElementById("darkmodetoggle").setAttribute("checked", "checked")
  }
}

function imageDropped() {
  document.getElementById("qrdata").value = ""
  document.getElementById("spinner").style.display = "inline"
}

async function decodeQR() {
  let imgUrl = document.getElementById("qrurl")["value"]
  if (!imgUrl && !isLocalImage(imgUrl)) {
    let localImgUrl = await getImageURL(imgUrl)
    if (localImgUrl) imgUrl = localImgUrl
  }
  let QRJSON = await fetch(`/decodeImage?url=${imgUrl}`).then(res => res.text())
  doneDecoding(QRJSON)
}

function doneDecoding(qrjson) {
  document.getElementById("spinner").style.display = ""
  if (!qrjson) {
    document.getElementById("qrdata").value = "Error decoding image - are you sure there's a vaccine passport QR code in this photo?"
  } else {
    document.getElementById("qrdata").value = qrjson
  }
}

function isLocalImage(url) {
  return url.startsWith(document.location.href)
}

async function getImageURL(url) {
  return fetch(`/getImage?url=${url}`).then(res => res.json().then(img => img["path"]))
}

function toggleDarkMode() {
  document.body.classList.toggle('darkmode')
  localStorage["darkmode"] == "true" ? localStorage["darkmode"] = "false" : localStorage["darkmode"] = "true"
};

document.getElementById("dropzone").addEventListener("click",(function(){
  Dropzone.forElement("#dropzone").removeAllFiles(true);
}))

(() => init())()