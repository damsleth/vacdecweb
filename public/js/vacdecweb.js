function init() {
  if (localStorage["darkmode"] == "true") {
    document.body.classList.toggle('darkmode')
    document.getElementById("darkmodetoggle").setAttribute("checked", "checked")
  }
}

function imageDropped() {
  document.getElementById("qrdata").value = ""
  document.getElementById("copydatabtn").value = "Copy JSON"
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
    document.getElementById("copydatabtn").style.display = "inline"
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

function copyQRData() {
  let qrtxt = document.getElementById("qrdata")
  qrtxt.select()
  qrtxt.setSelectionRange(0, 99999) /* For mobile devices */
  navigator.clipboard.writeText(qrtxt.value)
  iosCopyToClipboard(qrtxt)
  document.getElementById("copydatabtn").value = "Copied to clipboard"
  clearSelection()
}


function iosCopyToClipboard(el) {
  var oldContentEditable = el.contentEditable,
    oldReadOnly = el.readOnly,
    range = document.createRange()

  el.contentEditable = true
  el.readOnly = false
  range.selectNodeContents(el)

  var s = window.getSelection()
  s.removeAllRanges()
  s.addRange(range)

  el.setSelectionRange(0, 999999) // A big number, to cover anything that could be inside the element.

  el.contentEditable = oldContentEditable
  el.readOnly = oldReadOnly

  document.execCommand('copy')
}

function clearSelection() {
  if (window.getSelection) { window.getSelection().removeAllRanges() }
  else if (document.selection) { document.selection.empty() }
}

(() => init())()