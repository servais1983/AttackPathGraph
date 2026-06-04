from tests.test_modules import (
    run_analysis_check,
    run_integration_check,
    run_parsers_check,
    run_reporting_check,
    run_scoring_check,
)


def test_parser_modules():
    assert run_parsers_check()


def test_analysis_modules():
    assert run_analysis_check()


def test_scoring_modules():
    assert run_scoring_check()


def test_reporting_modules():
    assert run_reporting_check()


def test_integration_modules():
    assert run_integration_check()
