#pragma once

namespace demo {

class Widget {
public:
    explicit Widget(int v);
    int value() const;
private:
    int v_;
};

}  // namespace demo
