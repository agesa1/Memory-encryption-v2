#include "encryptor.h"
#include <iostream>
#include <vector>
#include <string>
#include <windows.h>

using namespace mem_prot;

struct GameState {
    int player_health;
    int player_ammo;
    float position_x;
    float position_y;
    uint64_t score;
};

ProtectedValue<int>* g_health = nullptr;
ProtectedValue<uint64_t>* g_score = nullptr;
TLSProtector* g_tls = nullptr;

__declspec(noinline) void protected_function() {
    StackGuard guard;

    int local_val = g_health->get();
    local_val += 10;
    g_health->set(local_val);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    guard.verify();
}

__declspec(noinline) int sensitive_calculation(int base) {
    StackGuard guard;

    ProtectedValue<int> temp(base);
    int result = temp.get() * 2;

    SecureXOR xor_engine;
    xor_engine.process_block(&result, sizeof(result));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    xor_engine.process_block(&result, sizeof(result));

    guard.verify();

    return result;
}

void init_protection_layer() {
    g_health = new ProtectedValue<int>(100);
    g_score = new ProtectedValue<uint64_t>(0);
    g_tls = new TLSProtector();

    GameState state = { 100, 50, 123.45f, 678.90f, 0 };
    g_tls->store_encrypted(&state, sizeof(GameState));
}

void gameplay_loop() {
    for (int i = 0; i < 5; ++i) {
        protected_function();

        GameState state;
        if (g_tls->retrieve_decrypted(&state, sizeof(GameState))) {
            state.score += 100;
            state.player_health = g_health->get();
            g_tls->store_encrypted(&state, sizeof(GameState));
        }

        int calc = sensitive_calculation(i * 10);
        uint64_t current_score = g_score->get();
        current_score += calc;
        g_score->set(current_score);

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void display_protected_state() {
    GameState state;
    if (g_tls->retrieve_decrypted(&state, sizeof(GameState))) {
        std::cout << "\nFinal: H=" << g_health->get() << " S=" << g_score->get() << std::endl;
    }
}

DWORD WINAPI monitor_thread(LPVOID param) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        SecureXOR random_xor;
        uint8_t noise[64];
        for (int i = 0; i < 64; ++i) noise[i] = rand() & 0xFF;
        random_xor.process_block(noise, 64);
    }
    return 0;
}

int main() {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    HANDLE h_monitor = CreateThread(nullptr, 0, monitor_thread, nullptr, 0, nullptr);

    init_protection_layer();

    gameplay_loop();

    display_protected_state();

    TerminateThread(h_monitor, 0);
    CloseHandle(h_monitor);

    delete g_health;
    delete g_score;
    delete g_tls;

    return 0;
}
