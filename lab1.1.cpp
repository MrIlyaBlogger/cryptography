#include <iostream>
#include <vector>
#include <cstdint>
#include <bitset>

std::uint8_t value = 0b10110010;

std::vector<int> p_block = {2, 0, 7, 4, 6, 1, 5, 3};

void permute_bits (
    std::uint8_t *value,
    const std::vector<int> &p_block,
    bool least_significant_first,
    bool zero_is_first
) {
    std::uint8_t result = 0;

    for (int i = 0; i < p_block.size(); ++i) {
        int source = p_block[i];
        int destination = i;

        if (!zero_is_first) {
            source -= 1;
        }

        if (!least_significant_first) {
            source = 7 - source;
        }

        bool bit = (*value >> source) & 1;

        if (bit) {
            result |= (1 << destination);
        }
    }

    *value = result;
}

int main() {
    permute_bits(&value, p_block, true, true);

    std::cout << std::bitset<8>(value) << '\n';

    return 0;
} //проверка git