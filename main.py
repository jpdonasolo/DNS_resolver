from DNS import resolve, TYPE_A


def main():
    print(resolve("google.com", TYPE_A))

if __name__ == "__main__":
    main()