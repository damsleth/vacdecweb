function init() {
    if (localStorage["darkmode"] == "true") {
        document.body.classList.toggle('darkmode')
        document.getElementById("darkmodetoggle").setAttribute("checked", "checked")
    }
}

async function decodeQR() {
    let imgUrl = document.getElementById("qrurl")["value"];
    if (!imgUrl && !isLocalImage(imgUrl)) {
        let localImgUrl = await getImageURL(imgUrl)
        if (localImgUrl) imgUrl = localImgUrl
    }
    let QRJSON = await fetch(`/decodeImage?url=${imgUrl}`).then(res => res.text())
    document.getElementById("qrdata").value=QRJSON
    document.getElementById("copydatabtn").style.display="inline"
}

function isLocalImage(url) {
    return url.startsWith(document.location.href)
}

async function getImageURL(url) {
    return fetch(`/getImage?url=${url}`).then(res => res.json().then(img => img["path"]))
}

function toggleDarkMode() {
    document.body.classList.toggle('darkmode');
    localStorage["darkmode"] == "true" ? localStorage["darkmode"] = "false" : localStorage["darkmode"] = "true"
};

function copyQRData() {
  let qrtxt = document.getElementById("qrdata");
  qrtxt.select();
  qrtxt.setSelectionRange(0, 99999); /* For mobile devices */
  navigator.clipboard.writeText(qrtxt.value);
  document.getElementById("copydatabtn").value = "Copied to clipboard"
}

(() => init())()