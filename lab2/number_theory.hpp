#pragma once

#include <boost/multiprecision/cpp_int.hpp>

namespace lab2 {

using Integer = boost::multiprecision::cpp_int;

struct BezoutResult {
    Integer gcd;
    Integer x;
    Integer y;
};

class NumberTheory {
public:
    static Integer gcd(Integer a, Integer b);
    static BezoutResult extendedGcd(const Integer& a, const Integer& b);
    static Integer binaryGcd(Integer a, Integer b);

    static int legendre(const Integer& a, const Integer& p);
    static int jacobi(Integer a, Integer n);
    static Integer modPow(Integer base, Integer exponent, const Integer& modulus);

    static Integer phiByDefinition(const Integer& n);
    static Integer phiByFactorization(const Integer& n);
    static Integer phiByFourier(const Integer& n);
    static Integer carmichael(const Integer& n);
};

}
