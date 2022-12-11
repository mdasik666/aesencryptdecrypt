function encrypt() {
    var msgencrypt = document.querySelector('#msgencrypt');
    var ekey = document.querySelector('#ekey');
    var encryptmsg = document.querySelector('#encryptmsg');
    var algorithm = document.querySelector("#selectAlgorithm").value;
    if (algorithm == "AES") {
        var encrypted = CryptoJS.AES.encrypt(msgencrypt.value, ekey.value);
        encryptmsg.value = encrypted;
    } else {
        alert(algorithm + " algorithm not implemented");
    }
}

function copyEncryptBtn() {
    var encryptmsg = document.querySelector('#encryptmsg');
    encryptmsg.select();
    navigator.clipboard.writeText(encryptmsg.value);
}

function decrypt() {
    var msgdecrypt = document.querySelector('#msgdecrypt');
    var dkey = document.querySelector('#dkey');
    var decryptmsg = document.querySelector('#decryptmsg');
    var algorithm = document.querySelector("#selectAlgorithm").value;
    if (algorithm == "AES") {
        var decrypted = CryptoJS.AES.decrypt(msgdecrypt.value, dkey.value).toString(CryptoJS.enc.Utf8);
        decryptmsg.value = decrypted;
    } else {
        alert(algorithm + " algorithm not implemented");
    }
}

function copyDecryptBtn() {
    var decryptmsg = document.querySelector('#decryptmsg');
    decryptmsg.select();
    navigator.clipboard.writeText(decryptmsg.value);
}