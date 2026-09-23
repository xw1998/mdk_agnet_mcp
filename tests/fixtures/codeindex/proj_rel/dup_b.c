static int dup_fn(void)
{
    return 2;
}

int use_dup_b(void)
{
    return dup_fn();
}
