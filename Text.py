import argparse

parser = argparse.ArgumentParser(description="Word Checking")
parser.add_argument("-w", "--word", type=str, required=True, help="Word for checking")
args = parser.parse_args()


def wordCheck(w):
    count = 0

    with open('malicious.txt', encoding="utf8", errors='ignore') as f:
        found = False
        for line in f:
            if w in line:  # Key line: check if `w` is in the line.
                print(line)
                print(count)
                count += 1
                found = True
            if not found:
                print('The data cannot be found!')
                found = True
        count = 0


if __name__ == '__main__':
    checker = wordCheck(str(args.__getattribute__("word")).lower())