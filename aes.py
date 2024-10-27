from typing import Self


class GF28:
    base = 2
    degree = 8
    order = 256
    poly = 0b100011011

    def __init__(self, value: int):
        self.value = value % self.order

    def __add__(self, rhs: Self) -> Self:
        return GF28(self.value ^ rhs.value)

    def __sub__(self, rhs: Self) -> Self:
        return self + rhs

    def __mul__(self, rhs: Self) -> Self:
        result = 0
        for i in range(self.degree):
            if rhs.value & 1 << i:
                result ^= self.value << i
        for i in range(self.degree - 1, -1, -1):
            if result & 1 << i + self.degree:
                result ^= self.poly << i
        return GF28(result)

    def __pow__(self, degree: int) -> Self:
        if degree == 0:
            return GF28(1)
        if degree == 1:
            return GF28(self.value)
        half = self ** (degree // 2)
        return half * half * self if degree % 2 else half * half

    def __truediv__(self, rhs: Self) -> Self:
        if rhs.value == 0:
            raise ZeroDivisionError
        return self * rhs ** (self.order - 2)

    def __int__(self) -> int:
        return self.value

    def __str__(self) -> str:
        return str(self.value)
