#include "bloom.h"

static inline int bloom_calc_partitions(bloom_s *bf, long target_size, long k, primes_s *primes);

static inline long binary_search_nearest(const uint64_t *elem_array, size_t num_elems, uint64_t value);

static inline uint64_t unsigned_abs(uint64_t a, uint64_t b);

static inline int bloom_calc_partitions(bloom_s *bf, long target_size, long k, primes_s *primes) {
    uint64_t avg_part_size = (uint64_t) ceil(target_size / k);
    long avg_index = binary_search_nearest(primes->primes, primes->count, avg_part_size);
    long sum = 0;
    long start_index = avg_index - k + 1 >= 0 ? avg_index - k + 1 : 0;
    for (long i = start_index; i <= avg_index; i++) {
        sum += primes->primes[i];
    }

    long min = labs(sum - target_size);
    long lowest_index = start_index;

    long j = avg_index + 1;
    long delta = 0;
    while (1) {
        sum += primes->primes[j] - primes->primes[lowest_index];
        delta = labs(sum - target_size);
        if (delta >= min) {
            break;
        }
        min = delta;
        j++;
        lowest_index++;
    }

    uint64_t *part_lengths_bytes = malloc(sizeof(uint64_t) * k);
    if (!part_lengths_bytes) {
        return -1;
    }

    for (uint64_t i = 0; i < k; i++) {
        bf->partition_lengths[i] = primes->primes[lowest_index + i];
        part_lengths_bytes[i] = (uint64_t) ceil((double) bf->partition_lengths[i] / 8);
        bf->size += part_lengths_bytes[i];
    }

    bf->total_size = bf->size + bf->prefix_len;
    if (!bf->base_ptr) {
        bf->base_ptr = calloc(1, bf->total_size);
        if (!bf->base_ptr) {
            free(part_lengths_bytes);
            return -1;
        }
        bf->bloom_ptr = bf->base_ptr + bf->prefix_len;
    }

    uint64_t offset_sum = 0;
    bf->partition_ptrs[0] = bf->bloom_ptr;
    for (uint64_t i = 1; i < k; i++) {
        offset_sum += part_lengths_bytes[i - 1];
        bf->partition_ptrs[i] = bf->bloom_ptr + offset_sum;
    }

    free(part_lengths_bytes);
    return 0;
}

static inline uint64_t unsigned_abs(uint64_t a, uint64_t b) {
    uint64_t diff = a - b;
    if (b > a) {
        diff = 1 + ~diff;
    }
    return diff;
}

static inline long binary_search_nearest(const uint64_t *elem_array, size_t num_elems, uint64_t value) {
    if (!elem_array || num_elems <= 0) {
        return -1;
    }
    if (num_elems == 1) {
        return elem_array[0];
    }

    long low = 0;
    long high = num_elems - 1;
    long mid = 0;

    while (low <= high) {
        mid = low + (high - low) / 2;
        if (value < elem_array[mid])
            high = mid - 1;
        else if (value > elem_array[mid])
            low = ++mid;
        else
            break;
    }

    long index;
    if (elem_array[mid] == value) {
        index = mid;
    } else {
        uint64_t diff1 = unsigned_abs(elem_array[mid - 1], value);
        uint64_t diff2 = unsigned_abs(elem_array[mid + 1], value);
        index = diff1 > diff2 ? mid + 1 : mid - 1;
    }

    return index;
}

uint64_t bloom_remaining_capacity(bloom_s *bf) {
    if (!bf) {
        return 0;
    }

    return bf->capacity > bf->num_elems ? bf->capacity - bf->num_elems : 0;
}

int bloom_add_elem(bloom_s *bf, uint8_t *data, uint64_t data_len) {
    if (!bf || !data || !data_len) {
        return -1;
    }

    uint64_t hash = XXH64(data, data_len, 0);
    for (uint64_t i = 0; i < bf->num_partitions; i++) {
        uint64_t partition_bit = hash % bf->partition_lengths[i];
        bf->partition_ptrs[i][partition_bit / 8] |= 1 << (partition_bit % 8);
    }

    bf->num_elems++;
    return 0;
}

int bloom_lookup(bloom_s *bf, uint8_t *data, uint64_t data_len) {
    if (!bf || !data || !data_len) {
        return -1;
    }

    uint64_t hash = XXH64(data, data_len, 0);

    for (uint64_t i = 0; i < bf->num_partitions; i++) {
        uint64_t partition_bit = hash % bf->partition_lengths[i];
        if (!(bf->partition_ptrs[i][partition_bit / 8] & 1 << partition_bit % 8)) {
            return 1;
        }
    }
    return 0;
}

int bloom_lookup_constant_time(bloom_s *bf, uint8_t *data, uint64_t data_len) {
    if (!bf || !data || !data_len) {
        return -1;
    }
    uint64_t hash = XXH64(data, data_len, 0);

    int result = 0;
    for (uint64_t i = 0; i < bf->num_partitions; i++) {
        uint64_t partition_bit = hash % bf->partition_lengths[i];
        if (!(bf->partition_ptrs[i][partition_bit / 8] & 1 << partition_bit % 8)) {
            result = 1;
        }
    }
    return result;
}

bloom_s *bloom_alloc(double p, uint64_t n, uint8_t *bloom_data, uint64_t prefix_len) {
    bloom_s *bf = calloc(1, sizeof *bf);

    if (bloom_init(bf, p, n, bloom_data, prefix_len)) {
        bloom_free(bf);
        bf = NULL;
    }

    return bf;
}

int bloom_init(bloom_s *bf, double p, uint64_t n, uint8_t *bloom_data, uint64_t prefix_len) {
    if (!bf || p <= 0.0 || n <= 0) {
        return -1;
    }

    double target_size = ceil((n * log(p)) / log(1.0 / (pow(2.0, log(2.0)))));
    uint64_t num_partitions = (uint64_t) ceil(log(2.0) * target_size / n);
    bf->partition_ptrs = calloc(num_partitions, sizeof *bf->partition_ptrs);
    bf->partition_lengths = calloc(num_partitions, sizeof(uint64_t));
    if (!bf->partition_ptrs || !bf->partition_lengths) {
        return -1;
    }

    primes_s primes;
    if (generate_primes(&primes, (target_size / num_partitions) + 300)) {
        return -1;
    }

    bf->prefix_len = prefix_len;
    bf->num_partitions = num_partitions;
    bf->false_pos_rate = p;

    bf->capacity = n;
    bf->num_elems = 0;

    if (bloom_data) {
        bf->base_ptr = bloom_data;
        bf->bloom_ptr = bf->base_ptr + bf->prefix_len;
    }

    int res = bloom_calc_partitions(bf, (long) target_size, num_partitions, &primes);
    free(primes.primes);
    return res;
}

void bloom_print(bloom_s *bf) {
    printf("Bloomfilter stats\n--------\n");
    printf("Size: %ld bytes (% ld bits)\n", bf->size, bf->size * 8);
    printf("Capacity: %ld (%ld used)\n", bf->capacity, bf->num_elems);
    printf("Number of partitions: %ld\n", bf->num_partitions);
    printf("Target false positive rate: %.10f\n", bf->false_pos_rate);
    printf("Partition sizes (bits): ");
    for (int i = 0; i < bf->num_partitions - 1; i++) {
        printf("%ld, ", bf->partition_lengths[i]);
    }
    printf("%ld\n", bf->partition_lengths[bf->num_partitions - 1]);
}

void bloom_clear(bloom_s *bf) {
    if (!bf)
        return;

    free(bf->partition_ptrs);
    free(bf->partition_lengths);
    free(bf->base_ptr);

    bf->base_ptr = NULL;
    bf->bloom_ptr = NULL;
    bf->size = 0;
    bf->total_size = 0;
    bf->num_partitions = 0;
    bf->prefix_len = 0;
    bf->false_pos_rate = 0.0;
    bf->partition_ptrs = NULL;
    bf->partition_lengths = NULL;
    bf->capacity = 0;
    bf->num_elems = 0;
}

void bloom_free(bloom_s *bf) {
    bloom_clear(bf);
    free(bf);
}

