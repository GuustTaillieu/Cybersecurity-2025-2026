

def main():
    inp = input("Enter a string: ")
    print(f"Encrypted string: {encrypt(inp)}")


def encrypt(input: str):
    char_list = list(input)
    for i in range(len(list)):
        list[i] = chr(ord(list[i]) + 1)
    return "".join(list)

if __name__ == "__main__":
    main()
