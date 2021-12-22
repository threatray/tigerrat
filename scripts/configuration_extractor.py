import sys
import argparse
from tigerlib import extractor as ext

def main(samples):
    for sample in samples:

        print(f'[+] Extracting config for {sample}')
        extractor = ext.ExtractorFactory().get_extractor(sample)
    
        config = extractor.extract()
        for ip in config.get('ips', []):
            if not ip:
                continue
            print(f'\tIP: {ip}')
            
        for cnc in config.get('cncs', []):
            if not cnc:
                continue
            print(f'\tCNC: {cnc}')
    
        if config.get('des_key', None):
            print(f'\tDES Key: {" ".join([f"{c:02X}" for c in config["des_key"]])}')
    
        if config.get('rc4_key', None):
            print(f'\tRC4 Key: {" ".join([f"{c:02X}" for c in config["rc4_key"]])}')



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple script to extract configuration from Andariel\'s APT group samples related to its Tiger tooling (TigerRAT, TigerDownloader)')
    parser.add_argument('samples', type=str, nargs='+', help='An unpacked PE file of Tiger tooling, the Downloader or the RAT (TigerRAT)')
    args = parser.parse_args()
    main(args.samples)

