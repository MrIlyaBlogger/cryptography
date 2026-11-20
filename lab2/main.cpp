#include "number_theory.hpp"

#include <iostream>

int main() {
    using lab2::Integer;
    using lab2::NumberTheory;

    const Integer a = 30;
    const Integer b = 18;
    const auto bezout = NumberTheory::extendedGcd(a, b);
    std::cout << "Euclidean gcd(30, 18) = " << NumberTheory::gcd(a, b) << '\n'
              << "Binary gcd(30, 18) = " << NumberTheory::binaryGcd(a, b) << '\n'
              << "Extended gcd(30, 18) = " << bezout.gcd
              << ", x = " << bezout.x << ", y = " << bezout.y << '\n'
              << "Bezout: 30 * (" << bezout.x << ") + 18 * (" << bezout.y
              << ") = " << a * bezout.x + b * bezout.y << "\n\n"
              << "Legendre (5 / 11) = " << NumberTheory::legendre(5, 11) << '\n'
              << "Legendre (2 / 11) = " << NumberTheory::legendre(2, 11) << '\n'
              << "Legendre (22 / 11) = " << NumberTheory::legendre(22, 11) << '\n'
              << "Jacobi (2 / 15) = " << NumberTheory::jacobi(2, 15) << '\n'
              << "Jacobi (7 / 15) = " << NumberTheory::jacobi(7, 15) << '\n'
              << "Jacobi (6 / 15) = " << NumberTheory::jacobi(6, 15) << '\n'
              << "7^13 mod 19 = " << NumberTheory::modPow(7, 13, 19) << "\n\n";

    for (unsigned n : {1, 8, 36, 45}) {
        std::cout << "n = " << n
                  << ", phi (definition) = " << NumberTheory::phiByDefinition(n)
                  << ", phi (factorization) = " << NumberTheory::phiByFactorization(n)
                  << ", phi (Fourier) = " << NumberTheory::phiByFourier(n)
                  << ", lambda = " << NumberTheory::carmichael(n) << '\n';
    }
}
