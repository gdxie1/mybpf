import random
import time


def dummy():
    pass

def multi_next(num: int, res: int) -> int:
    dummy()
    return num * res

def get_value_direct(num: int) -> int:
    fact = {0:0, 1:1, 2:2, 3:6, 4:24, 5:120 }
    dummy()
    return fact.get(num)
def factorial(num: int = 1) -> int:
    if num < 0:
        return -1
    if num == 0:
        return 0
    if num<6:
        return get_value_direct(num)
    res = 1
    while num:
        res = multi_next(num, res)
        num -= 1
    return res


def main():
    while 1:
        try:
            str_num = input("Enter count you want to iterate of factorial: ")
            num = int(str_num)
            if num < 0:
                raise ValueError
            time.sleep(2)
            for i in range(int(str_num)):
                num = random.randint(-3, 10)
                print("the num for factorial is  %d" % num)
                print(factorial(num))
            exit(0)
        except ValueError:
            print('Please enter positive number representing the count of random value for a factorial')
            exit(-1)
        except KeyboardInterrupt:
            exit(1)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
