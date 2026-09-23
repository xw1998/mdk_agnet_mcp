#include "widget.hpp"

namespace demo {

static int scale(int x)
{
    return x * 2;
}

Widget::Widget(int v) : v_(v) {}

int Widget::value() const { return scale(v_); }

int twice(int x)
{
    return scale(x) + scale(x);
}

}  // namespace demo
