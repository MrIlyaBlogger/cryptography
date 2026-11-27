#include "number_theory.hpp"

#include <boost/multiprecision/cpp_dec_float.hpp>

#include <cstddef>
#include <stdexcept>
#include <utility>
#include <vector>

namespace lab2 {
namespace {

using Real = boost::multiprecision::cpp_dec_float_50;

bool isEven(const Integer& value) {
    return (value & 1) == 0;
}

Integer magnitude(Integer value) {
    if (value < 0) {
        value = -value;
    }
    return value;
}

Integer normalize(Integer value, const Integer& modulus) {
    value %= modulus;
    if (value < 0) {
        value += modulus;
    }
    return value;
}

void requirePositive(const Integer& n) {
    if (n <= 0) {
        throw std::invalid_argument("The argument must be positive");
    }
}

struct PrimePower {
    Integer prime;
    Integer power;
};

std::vector<PrimePower> factorize(Integer n) {
    requirePositive(n);
    std::vector<PrimePower> factors;
    auto takeFactor = [&](const Integer& prime) {
        if (n % prime != 0) {
            return;
        }
        Integer power = 1;
        do {
            n /= prime;
            power *= prime;
        } while (n % prime == 0);
        factors.push_back({prime, std::move(power)});
    };

    takeFactor(2);
    for (Integer divisor = 3; divisor * divisor <= n; divisor += 2) {
        takeFactor(divisor);
    }
    if (n > 1) {
        factors.push_back({n, n});
    }
    return factors;
}

}

Integer NumberTheory::gcd(Integer a, Integer b) {
    a = magnitude(std::move(a));
    b = magnitude(std::move(b));
    while (b != 0) {
        Integer remainder = a % b;
        a = std::move(b);
        b = std::move(remainder);
    }
    return a;
}

BezoutResult NumberTheory::extendedGcd(const Integer& a, const Integer& b) {
    BezoutResult previous{magnitude(a), 1, 0};
    BezoutResult current{magnitude(b), 0, 1};
    while (current.gcd != 0) {
        const Integer quotient = previous.gcd / current.gcd;
        BezoutResult next{
            previous.gcd - quotient * current.gcd,
            previous.x - quotient * current.x,
            previous.y - quotient * current.y
        };
        previous = std::move(current);
        current = std::move(next);
    }
    if (a < 0) {
        previous.x = -previous.x;
    }
    if (b < 0) {
        previous.y = -previous.y;
    }
    return previous;
}

Integer NumberTheory::binaryGcd(Integer a, Integer b) {
    a = magnitude(std::move(a));
    b = magnitude(std::move(b));
    if (a == 0) {
        return b;
    }
    if (b == 0) {
        return a;
    }

    std::size_t commonShifts = 0;
    while (isEven(a) && isEven(b)) {
        a >>= 1;
        b >>= 1;
        ++commonShifts;
    }
    while (isEven(a)) {
        a >>= 1;
    }
    do {
        while (isEven(b)) {
            b >>= 1;
        }
        if (a > b) {
            std::swap(a, b);
        }
        b -= a;
    } while (b != 0);
    return a << commonShifts;
}

Integer NumberTheory::modPow(Integer base, Integer exponent, const Integer& modulus) {
    requirePositive(modulus);
    if (exponent < 0) {
        throw std::invalid_argument("The exponent must be nonnegative");
    }
    base = normalize(std::move(base), modulus);
    Integer result = Integer(1) % modulus;
    while (exponent != 0) {
        if (!isEven(exponent)) {
            result = (result * base) % modulus;
        }
        exponent >>= 1;
        if (exponent != 0) {
            base = (base * base) % modulus;
        }
    }
    return result;
}

int NumberTheory::legendre(const Integer& a, const Integer& p) {
    if (p <= 2 || isEven(p)) {
        throw std::invalid_argument("Legendre symbol requires an odd prime denominator");
    }
    const Integer residue = normalize(a, p);
    if (residue == 0) {
        return 0;
    }
    const Integer criterion = modPow(residue, (p - 1) / 2, p);
    if (criterion == 1) {
        return 1;
    }
    if (criterion == p - 1) {
        return -1;
    }
    throw std::invalid_argument("Legendre symbol requires an odd prime denominator");
}

int NumberTheory::jacobi(Integer a, Integer n) {
    if (n <= 0 || isEven(n)) {
        throw std::invalid_argument("Jacobi symbol requires a positive odd denominator");
    }
    a = normalize(std::move(a), n);
    int sign = 1;
    while (a != 0) {
        while (isEven(a)) {
            a >>= 1;
            const Integer residue = n % 8;
            if (residue == 3 || residue == 5) {
                sign = -sign;
            }
        }
        if (a % 4 == 3 && n % 4 == 3) {
            sign = -sign;
        }
        std::swap(a, n);
        a %= n;
    }
    return n == 1 ? sign : 0;
}

Integer NumberTheory::phiByDefinition(const Integer& n) {
    requirePositive(n);
    Integer count = 0;
    for (Integer k = 1; k <= n; ++k) {
        if (gcd(k, n) == 1) {
            ++count;
        }
    }
    return count;
}

Integer NumberTheory::phiByFactorization(const Integer& n) {
    Integer result = 1;
    for (const PrimePower& factor : factorize(n)) {
        result *= (factor.power / factor.prime) * (factor.prime - 1);
    }
    return result;
}

Integer NumberTheory::phiByFourier(const Integer& n) {
    requirePositive(n);
    const Real realN(n);
    const Real twoPi = 2 * acos(Real(-1));
    Real sum = 0;
    for (Integer k = 1; k <= n; ++k) {
        const Real angle = twoPi * Real(k) / realN;
        sum += Real(gcd(k, n)) * cos(angle);
    }

    const Real rounded = floor(sum + Real("0.5"));
    if (abs(sum - rounded) > Real("1e-10") || rounded < 1 || rounded > realN) {
        throw std::runtime_error("Fourier sum did not converge to an admissible integer");
    }
    return rounded.convert_to<Integer>();
}

Integer NumberTheory::carmichael(const Integer& n) {
    Integer result = 1;
    for (const PrimePower& factor : factorize(n)) {
        Integer term;
        if (factor.prime == 2 && factor.power >= 8) {
            term = factor.power / 4;
        } else {
            term = (factor.power / factor.prime) * (factor.prime - 1);
        }
        result = (result / gcd(result, term)) * term;
    }
    return result;
}

}
