static int dup_fn(void)
{
    return 1;
}

int use_dup_a(void)
{
    return dup_fn();
}
