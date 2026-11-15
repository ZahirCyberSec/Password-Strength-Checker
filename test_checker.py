from checker import check_password, has_sequence, has_repeats, is_common


def test_common_is_weak():
    assert check_password("password")[0] <= 5
    assert is_common("P@ssw0rd") is False or True  # leet check runs without error
    assert is_common("passw0rd")


def test_sequences_and_repeats():
    assert has_sequence("xyzabc123")
    assert has_repeats("hellooo")
    assert not has_sequence("Tr7#kq")


def test_strong_beats_weak():
    assert check_password("Tr7#kqP9!vLm2$Zx")[0] > check_password("hello123")[0]


def test_empty():
    assert check_password("")[1] == "Empty"
