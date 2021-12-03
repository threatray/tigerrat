import os
import argparse
from tigerlib import unpacker


def main(samples, output_folder):
    for sample in samples:
        print(f'[+] Unpacking {sample}')
        u = unpacker.AndarielAPTUnpacker(sample)
        unpacked_pe = u.unpack()

        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        output_file = os.path.join(output_folder, os.path.basename(sample) + '.unpacked')
        with open(output_file, 'wb') as f:
                f.write(unpacked_pe)
                
        print(f'\t{u.payload_location},{u.xor_key},{u.encoding}')
        print(f'\tSample unpacked... {output_file}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple script to unpack samples from Andariel\'s APT group related to its Tiger tooling (TigerRAT, TigerDownloader)')
    parser.add_argument('samples', type=str, nargs='+', help='A packed PE file of Tiger tooling, the Downloader or the RAT')
    parser.add_argument('--o', type=str, dest='output_folder', nargs='?', default='output', help='The full path of the folder where the unpacked files are going to be stored')
    args = parser.parse_args()
    main(args.samples, args.output_folder)
