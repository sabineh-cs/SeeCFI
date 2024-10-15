# SeeCFI

SeeCFI is a tool to automatically analyze all memory-unsafe binaries in a system image to determine which one of them has been compiled using CFI (control-flow integrity).  

---

## Details  

- Can detect forward- and backward-edge CFI
- Distinguishes between single-module and multi-module (crossDSO) CFI
- Supports Android image formats and Debian and Ubuntu (.iso and .img)

---
## Requirements  

- Update `config.ini` file with own `[database]`, `[username]`, and `[password]`.
- python3.9 or higher
- MariaDB server
- mysql-connector  
  `pip install mysql-connector`
- angr  
  `pip install angr`
- python-magic  
  `pip install python-magic`

---

## Usage


````
./main.py [-h] [--android | --linux] [-i] [-e] [-m] [-s]
               image_path distribution

positional arguments:
  image_path            Path to the image file to analyze
  distribution          The name you want to use in the database, e.g., the
                        distribution "Ubuntu"

optional arguments:
  -h, --help            show this help message and exit
  --android             Analyze an Android based image
  --linux               Analyze an Linux image (only Ubuntu and Debian
                        supported)
  -i, --ignore-unsafe   Re-run the experiments without checking if binary was
                        compiled from unsafe language
  -e, --error-static-exit
                        Re-run analysis of all binaries that could not be
                        analyzed because of static_exit error
  -m, --only-multi-module
                        Only run the multi-module CFI check
  -s, --skip-database-check
                        Always run analysis regardless of existence in
                        database
````

---

## Example

1. Setup MariaDB database:  
    <https://mariadb.com/get-started-with-mariadb/>  
   `CREATE [database]`  
2. Download Android image  
   1. `mkdir example && cd example/`  
   2. `wget https://dl.google.com/dl/android/aosp/cheetah-td1a.220804.009.a2-factory-8e7393e1.zip`
3. Unpack Android image  
   1. `unzip cheetah-td1a.220804.009.a2-factory-8e7393e1.zip`  
   2. `cd cheetah-td1a.220804.009.a2`  
   3. `unzip image-cheetah-td1a.220804.009.a2.zip`
4. Create virtual python environment and install packages in SeeCFI directory  
   1. `python -m venv env_seecfi`  
   2. `. env_seecfi/bin/activate`  
   3. `(env_seecfi) pip install mysql-connector angr python-magic`
5. Run SeeCFI  
   `./main.py --android [path_to]/cheetah-td1a.220804.009.a2/ Android`