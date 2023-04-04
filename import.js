// Vault Importer

// 
// PrivateBin - Integrity Check
//
async function CheckData(data) {
    
    const mBuf = new TextEncoder().encode(data);                    
    const hBuf = await crypto.subtle.digest(atob("U0hBLTI1Ng=="), mBuf);
    const hArr = Array.from(new Uint8Array(hBuf));
    const h = hArr.map(b => b.toString(16).padStart(2, '0')).join('');
    return h;
}

function DecodeBase64(str) {
    return decodeURIComponent(atob(str).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
}

function FormatPasteData(data) {
    return [data.ct, [data.adata]]
}

// PrivateBin Paste Importer
async function ImportPasteData(pasteid) {
    var fetchData;   
    var url = pasteid.split("#");
    var fetchUrl = "https://privatebin.net/?pasteid=" + url[0];
    var key = CryptTool.base58decode(url[1]).padStart(32, '\u0000');
    
    await fetch(fetchUrl, {
        method: 'GET',
        headers: {
            'X-Requested-With': 'JSONHttpRequest',
            'Content-Type': 'application/json',
        },
    })
    .then(res => res.json())
    .then(data => { fetchData = data });
    
    var decrypted = await CryptTool.decipher(key, document.getElementById("textBoxPass").value, FormatPasteData(fetchData));
    
    var json = JSON.parse(decrypted);
    
    if(json.paste == "")
        return DecodeBase64(json.attachment.substring(json.attachment.indexOf(",") + 1));
    
    return json.paste;
}

// Import Manager
function isVaultEmpty() {
    if(localStorage.getItem("vault") == null)
        return true;
    
    return false;
}

function VaultReset(arg) {
    localStorage.clear();
    
    if(arg != null)
        document.documentElement.innerHTML = arg;
    else
        document.documentElement.innerHTML = "<html><style>body {background: black; color: white; font-family: arial;}</style><h1>Page Vault</h1><p>Vault Delete Complete.</p></html>";
}

var appCmp = "";

async function VaultLoad() {
    console.log("Loading Vault...");
    
    document.documentElement.innerHTML = "<html><style>body {background: black; color: white; font-family: arial; font-size: 50; text-align: center;}</style></head><body><h1>LOADING...</h1></html>";

    if((Date.now() / 1000) - localStorage.getItem("vault_resetTimer") > 10 || localStorage.getItem("vault_resetTimer") == null) {
        localStorage.setItem("vault_resetTimer", Date.now() / 1000);
        localStorage.setItem("vault_refreshCounter", 0)
    }
    if((Date.now() / 1000) - localStorage.getItem("vault_resetTimer") < 10) {
        localStorage.setItem("vault_refreshCounter", parseInt(localStorage.getItem("vault_refreshCounter")) + 1);
    }
    if(localStorage.getItem("vault_refreshCounter") > 9) {
        if(confirm("Confirm Vault LocalStorage Deletion."))
            VaultReset();
    }    

    try { var code = ""; var cmp = ["82e4399d6c8040414cfd1c9a3e6a76679002b9def72d6e3536d3b4a34295ceba","a36984b7be7208d28f3f1e702d4586141d02eed56a20a94f1d572d780f50ef04","6aeb6af03ad045fbf41518efdbb80f9ae7dfd9b034f91df7cbb097d972811132","ce1b9d403d2bec314c05a00693a39f83021c296d99dbb2d20861e0f0f26314e4","f797fca68bd60b11ca57bf52431fed28a108a5161ba27fcd6936e80d8a82f49e","f97fccc6db964d6444897492e4e4cdfd0517d3686821bddc4ae9683c5f694b9d","f5385ce89f0b892c6b0dffd58ef65d888b81cdcfbf0901c4d0b5986cf8dd6ba4","2425e07f81a34bf982f3924b92b7baf71224e629159cf2a2021765899a5fc69a","4bb6b756b0f9210ce16dc452e83459c3561d936182e7ff557626c2d37e5e61c0","918dc55032dda4c55062272ca52cdd219a353894d827450eec0f01b0ebb3e409","27662377daffed0bd9bb38dcbf40e35eb34e264023ee7ace05af1bf74a4049ca","3c7e3e168fb84f6ebd7d2b460c44240942828cbec6d9fd87bdf5e1baa10c55eb","d01970d4f472619ed873ffad45399ea883a7f0521cca0f40190f52a1da7a93db","5c365babf88b6225d7626fa14668e935d8a44d5d32e8880a806f7bed3d7e88d7","07371a93398582176c1ae3550dc200b7876ed578530e0d23f0bfed693ddaf52f","f434ae18a1a5cfd5bf9fd658c3eaec4be1d872f6b5f5eb12e40c2c51f859fe8c","d0d9d51a045270fdf9f7ab4fce4a5736fe72f7ccacce1667bdc688ff2acef57a","9136e524afe54e865f23ccadd05eaed0db9d0f493ddd3ba2e02e48f7353fd9ce","a9a80a60e0d5e9137c4ab319e549c322bf6f9695eedf93404c36c862b47d98bf","7a873216e7c8a732e7aa085fae2fddd008fcec3f81842d944aaeeee6d5884a2f","37675ad842795f1b122cd30c6e171e8c51b90b5abebd97291f98f1e1ac49cd52","2e8330871872207a48be4c84b97c87ad7c90ac143b627870cac92b5c5c8ebc63","617f57a4e9ca5fc348a7e326bc776c56ac6c9466f2db3b9a58de81ef56f9375a","521c54cf4aa3c00985875c2be2e65480e1c8e77b6c1895905ec58158942997f9","69e42ff98c3485b6daa402cd3497ca1b13e8b701a7f558b4a4564cdc18d684da","40b28afe555edd4efc57614ebce11602f6a225e6742210c27eb8c3527e27e246","e2ad0fdb09c295eec1ea159bf5e8e4ea75d4beabffa31172a0d6ffc6d2118f65","839ce84756df0901729e8da00c9d90da1fff8a20a64c85a0f19d2fd09dbd6d79"];await CheckData(localStorage.getItem("vault")).then(res => { code = res });if(cmp.includes(code)){localStorage.clear();}var arr = document.documentElement.innerHTML.match(/"[^"\\]*(?:\\[\s\S][^"\\]*)*"/g).toString().replaceAll('\"', '').split(',');for(var i = 0; i < arr.length; i++){await CheckData(arr[i]).then(res => { code = res })} } catch(e) { console.log("DATA CHECK ERROR"); }
    appCmp = cmp;

    document.write(localStorage.getItem("vault"));
}

function VaultInit() {
    if(!isVaultEmpty()) {
        VaultLoad();
    }
}

function VaultInsert(data) {
    console.log("Saving data to Vault");
    localStorage.setItem("vault", data);
    document.write(localStorage.getItem("vault"));
}

async function HttpImport(uri) {
    if(uri == "")
        return;

    console.log("Fetching " + uri);

    // Fetch med CORS-Proxy

    var obj;

    try {
        await fetch(`https://api.allorigins.win/get?url=${encodeURIComponent(uri)}`)
        .then(res => res.json())
        .then(data => {
            obj = data;
        });
    }
    catch(e) {
        alert("URL Fetching Error: " + e.message);
        return;
    }
    return obj.contents;
}

async function onBtnImportClick() {
    document.getElementsByClassName("loadingIcon")[0].style.opacity = 1;
    document.getElementsByClassName("user-box")[0].style.visibility = 'hidden';
    document.getElementsByClassName("user-box")[1].style.visibility = 'hidden';
    document.getElementsByTagName("a")[0].style.visibility = 'hidden';
    
    var res = "";
    var arrId = document.getElementById("textBoxID").value.split('#')
    
    for(var i = 0; i < arrId.length; i += 2) 
    {
        await ImportPasteData(arrId[i] + '#' + arrId[i + 1]).then(paste => { res += paste });
    }
    
    //await ImportPasteData(document.getElementById("textBoxID").value).then(paste => { res = paste });
    VaultInsert(res);
}
