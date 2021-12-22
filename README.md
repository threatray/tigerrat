This repository contains scripts and IOCs for the Andariel APT group research published in December 2021 accessible here: https://threatray.com/blog/establishing-the-tigerrat-and-tigerdownloader-malware-families

Please refer to the blog post for further background information.


## Scripts

Two scripts are provided to unpack TigerDownloader and TigerRAT samples, as well as extract their config values.

These scripts require Python 3 and pip and the `pefile` library to be installed. Install `pefile` with:
```
pip3 install pefile
```

The script `unpack_samples.py` unpacks packed TigerDownloader and TigerRAT samples.

```
$ python3 unpack_samples.py -h
usage: unpack_samples.py [-h] [-o [OUTPUT_FOLDER]] samples [samples ...]

Simple script to unpack samples from Andariel's APT group related to its Tiger
tooling (TigerRAT, TigerDownloader)

positional arguments:
  samples              A packed PE file of Tiger tooling, the Downloader or
                       the RAT

optional arguments:
  -h, --help           show this help message and exit
  -o [OUTPUT_FOLDER]  The full path of the folder where the unpacked files
                       are going to be stored

```

Example:

```
$ python3 unpack_samples.py -o tigerout f4765f7b089d99b1cdcebf3ad7ba7e3e23ce411deab29b7afd782b23352e698f
[+] Unpacking /home/tiger/f4765f7b089d99b1cdcebf3ad7ba7e3e23ce411deab29b7afd782b23352e698f
	section(OTT),b'UkneC!11@2DQKxCF',None
	Sample unpacked... tigerout/f4765f7b089d99b1cdcebf3ad7ba7e3e23ce411deab29b7afd782b23352e698f.unpacked

$ sha256sum tigerout/f4765f7b089d99b1cdcebf3ad7ba7e3e23ce411deab29b7afd782b23352e698f.unpacked
5c2f339362d0cd8e5a8e3105c9c56971087bea2701ea3b7324771b0ea2c26c6c  tigerout/f4765f7b089d99b1cdcebf3ad7ba7e3e23ce411deab29b7afd782b23352e698f.unpacked
```

The script `configuration_extractor.py` extracts config values from unpacked TigerDownloader and TigerRAT samples.

```
$ python3 configuration_extractor.py -h
usage: configuration_extractor.py [-h] samples [samples ...]

Simple script to extract configuration from Andariel's APT group samples
related to its Tiger tooling (TigerRAT, TigerDownloader)

positional arguments:
  samples     An unpacked PE file of Tiger tooling, the Downloader or the RAT
              (TigerRAT)

optional arguments:
  -h, --help  show this help message and exit
```

Example:

```
$ python3 configuration_extractor.py tigerout/f4765f7b089d99b1cdcebf3ad7ba7e3e23ce411deab29b7afd782b23352e698f.unpacked
[+] Extracting config for tigerout/f4765f7b089d99b1cdcebf3ad7ba7e3e23ce411deab29b7afd782b23352e698f.unpacked
	CNC: http://mail.sisnet.co.kr/jsp/user/sms/sms_recv.jsp
	CNC: http://mail.neocyon.com/jsp/user/sms/sms_recv.jsp
```

## IOCs

Two CSV files are provided with metadata and config values on the packed ([packer_configs.csv](./iocs/packer_configs.csv)) and unpacked ([payload_configs.csv](./iocs/payload_configs.csv)) TigerDownloader and TigerRAT samples.
