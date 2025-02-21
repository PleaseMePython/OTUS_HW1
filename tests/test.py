from otus_hw1.log_analyzer import extract_url, extract_time


def get_good_str() -> str:
    return (
        "1.169.137.128 -  - [29/Jun/2017:03:50:22 +0300] "
        '"GET /api/v2/banner/1717161 HTTP/1.1" 200 2116 '
        '"-" "Slotovod" "-" "1498697422-2118016444-'
        '4708-9752771" "712e90144abee9" 0.138'
    )


def get_bad_str() -> str:
    return (
        "1.169.137.128 -  - [29/Jun/2017:03:50:22 +0300] "
        '"/api/v2/banner/1717161 HTTP/1.1" 200 2116 '
        '"-" "Slotovod" "-" "1498697422-2118016444-'
        '4708-9752771" "712e90144abee9" FAIL'
    )


def test_extract_url():
    assert extract_url(get_good_str()) == "/api/v2/banner/1717161"


def test_extract_url_not_found():
    assert extract_url(get_bad_str()) == ""


def test_extract_time():
    assert extract_time(get_good_str()) == 0.138


def test_extract_time_wrong_type():
    assert extract_time(get_bad_str()) == 0
