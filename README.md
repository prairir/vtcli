# VTCLI
virus total cli tool

## Situation
have you ever been SSHed into a server? poking around? then you find a weird file. Not sure what it is, you want to put it into Virus Total. Unfortunetly theres no GUI or FTP. You're stuck. 


With **VTCLI** you can just install and run.


VTCLI has a bunch of features, uploading an entire folder, uploading URL, uploading files. All work with VTCLI.


## Usage

```
usage: vtcli [-h] [-u] [-d] [-dk] [-k] [-f] [-v] [-r] File

CLI tool for virus scanning with Virus Total

positional arguments:
  File

optional arguments:
  -h, --help            show this help message and exit
  -u, --url             Scan url
  -d, --directory       Scan directory
  -dk, --directoryKeepGoing
                        Scan directory continue on error
  -k, --keepGoing       Continue on error, only useful with -d
  -f, --file            Scan file, same as no flags
  -v, --verbose         More output, better if you want to see specifics
  -r, --raw             Raw output of json
```

### Operating options

`-u` is for scanning a URL

`-d` is for scanning a directory

`-f` is for scanning a file

`-k` is for scanning a directory and keeping going on error

### Printing options

`-r` is for printing the raw json

`-v` is for printing a more detailed response

no flag prints a summary

## Examples

scanning google.com
```
python vtcli.py -u google.com
```

scanning every file in home and printing verbose
```
python vtcli.py -d ~ -v
```

scanning a file
```
python vtcli.py resume.pdf
```

## Install

copy and rename `secrets.example.conf` to `secrets.conf`

put your api key into `secrets.conf`

install dependencies by running 
```
pip install -r requirements.txt
```

thats it, have fun, good luck :)
