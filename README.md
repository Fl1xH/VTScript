# VTScript v0.1

VTScript is a tiny cli-tool to fastly get informations about a file and url using the official Virustotal API.

```

 __     _______ ____            _       _    
 \ \   / /_   _/ ___|  ___ _ __(_)_ __ | |_  
  \ \ / /  | | \___ \ / __| '__| | '_ \| __| 
   \ V /   | |  ___) | (__| |  | | |_) | |_  
    \_/    |_| |____/ \___|_|  |_| .__/ \__|
                                 |_|         
  Made by Fl1x				v0.1

1 -- File scan from hash
2 -- File scan upload
3 -- Url scan
4 -- Exit

Enter your choice: 

```

## Install dependencies

You just need to install the Virustotal API lib for this tool.

```bash
pip3 install vt-py
```

## Getting started

To start using this tool, you need an free API from Virustotal. You just create an account and retrieve the API key from the account profile.

Then you add the key into the `API_client` variable (line 15).

```python3
API_client = vt.Client("YOUR_API_KEY_HERE")
```

And that's it! You can launch the tool simply like that:

```bash
./VTScriptv0.1.py
```

# TODO / TOADD

