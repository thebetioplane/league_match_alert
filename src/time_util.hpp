#pragma once

void sleep_ms(int ms);

// Once a rate limit is exhausted it sleeps for that amount.
class RateCounter
{
public:
    RateCounter(int max_amt_, int sleep_amt_) : max_amt(max_amt_), sleep_amt(sleep_amt_), current_value(max_amt_) {}

    void operator--();

private:
    const int max_amt;
    const int sleep_amt;
    int current_value;
};
