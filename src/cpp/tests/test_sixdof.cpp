#include "netrecon/sixdof_core.h"
#include <iostream>
#include <cassert>
#include <cmath>
using namespace sixdof;
void testRK4() {
    State s; s.quat = qidentity(); s.omega = {0.1, 0, 0}; s.mass = 1;
    InertiaTensor I = inertiaDiag(1, 2, 3);
    auto fn = [](const State&, double) -> ForcesTorques { return {}; };
    double t = 0;
    for (int i = 0; i < 1000; i++) { s = rk4Step(s, I, 0.01, t, fn); t += 0.01; }
    assert(std::abs(qnorm(s.quat) - 1.0) < 1e-6);
    std::cout << "  6DOF RK4 ✓\n";
}
int main() { std::cout << "=== netrecon 6DOF ===\n"; testRK4();
    std::cout << "All netrecon 6DOF tests passed.\n"; return 0; }
