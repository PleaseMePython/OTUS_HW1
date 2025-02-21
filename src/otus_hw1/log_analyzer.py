"""Анализатор логов."""

import os
import re
import gzip
import argparse
import configparser
import json
import sys
from pathlib import Path

from collections.abc import Generator
from dataclasses import dataclass, asdict
from datetime import date, MINYEAR
from typing import NamedTuple, Dict, List, Any
from statistics import mean, median
from string import Template


import structlog

# log_format ui_short '$remote_addr  $remote_user '
#                     '$http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" '
#                     '"$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "ERROR_FILE": "./errors.log",
    "REPORT_TEMPLATE": "./report.html",
}


type LogGrouped = Dict[str, List[float]]


class LogInfo(NamedTuple):
    """Обработанный дог."""

    url_count: int = 0
    url_total_time: float = 0
    log_grouped: LogGrouped = {}


class FileInfo(NamedTuple):
    """Сведения о файле лога."""

    name: str = ""
    f_date: date = date(day=1, month=1, year=MINYEAR)
    is_archive: bool = False


class UrlInfo(NamedTuple):
    """Распарсенные данные из файла лога."""

    url: str = ""
    requestTime: float = 0


@dataclass
class UrlStats:
    """Статистика из файла лога."""

    url: str = ""
    # сколько раз встречается URL, абсолютное значение
    count: int = 0
    # сколько раз встречается URL, в процентах
    count_perc: float = 0
    # суммарное время для данного URL, абсолютное значение
    time_sum: float = 0
    # суммарное время для данного URL, в процентах
    time_perc: float = 0
    # среднее время для данного URL
    time_avg: float = 0
    # максимальное время для данного URL
    time_max: float = 0
    # медианное время для данного URL
    time_med: float = 0


# Таблица статистики
type UrlStatsTab = List[UrlStats]


def get_project_root() -> Path:
    """Получение пути к проекту.

    :return: Путь к проекту
    """
    return Path(__file__).parent.parent.parent.resolve()


def get_log_file_name(path: Path) -> FileInfo:
    """Получение имени файла лога.

    :arg path - путь к каталогу с логами
    :return: Кортеж имени файла, даты и признака архива
    """
    # nginx-access-ui.log-YYYYMMDD с необязательным расширением gz
    pattern = re.compile(
        r"^nginx-access-ui\.log-"
        + r"2\d\d\d"  # Год
        + r"((0[1-9])|(1[0-2]))"  # Месяц
        + r"(([0-2]\d)|(3[0-1]))"  # День
        + r"(\.gz){0,1}$"
    )  # Расширение
    # Список файлов (исключая папки) по заданной маске
    file_list = [
        s
        for s in os.listdir(path=path)
        if pattern.match(s) and os.path.isfile(os.path.join(path, s))
    ]
    # Минимальная дата для сравнения
    result = FileInfo()

    for file_name in file_list:
        # Парсим дату из имени файла. Отсутствие ошибок конверсии гарантировано
        # проверкой по маске
        file_date = date(
            year=int(file_name[20:24]),
            month=int(file_name[24:26]),
            day=int(file_name[26:28]),
        )
        # Сохраняем имя файла, если дата в имени больше сохраненной
        if file_date > result.f_date:
            result = FileInfo(
                name=os.path.join(path, file_name),
                f_date=file_date,
                is_archive=file_name[-2:].lower() == "gz",
            )
    return result


def get_config(default_config: Dict) -> Dict:
    """Получение конфигурации.

    :arg default_config - конфигурация из глобальной переменной
    :return: Конфигурация из файла
    """
    parser = argparse.ArgumentParser(description="Анализатор логов")
    parser.add_argument(
        "--config",
        type=str,
        default="./config.cnf",
        help="Путь к конфигурационному файлу",
    )
    arg_val = parser.parse_args()
    cnf_file_name = arg_val.config
    cnf_parser = configparser.ConfigParser()
    cnf_parser["DEFAULT"] = default_config
    cnf_file_path = get_project_root().joinpath(cnf_file_name)
    cnf_parser.read(cnf_file_path, encoding="utf-8")
    cnf_dict = dict(cnf_parser["DEFAULT"])
    return cnf_dict


def extract_url(log_line: str) -> str:
    """Извлечение url из лога.

    :arg log_line - строка
    :return: url
    """
    err_logger = structlog.stdlib.get_logger()
    # URL начинается через пробел от команды GET/POST
    url_off_start = log_line.find("GET", 0)
    url_start_shift = 4  # GET + пробел
    if url_off_start == -1:
        url_off_start = log_line.find("POST", 0)
        url_start_shift = 5  # POST + пробел
    # Ищем следующий за URL пробел
    # Недействительный начальный адрес -1+4=3
    url_off_end = (
        log_line.find(" ", url_off_start + url_start_shift)
        if url_off_start != -1
        else -1
    )
    if url_off_start != -1 and url_off_end != -1:
        return log_line[url_off_start + url_start_shift : url_off_end]
    else:
        err_logger.error("URL value not found")
        return ""


def extract_time(log_line: str) -> float:
    """Извлечение времени из лога.

    :arg log_line - строка
    :return: время
    """
    # Последний пробел с конца без учета концевого
    time_off_start = log_line.rstrip().rfind(" ") + 1

    err_logger = structlog.stdlib.get_logger()

    if time_off_start != 0:
        try:
            return float(log_line[time_off_start:])
        except ValueError:
            err_logger.error("Time value is not float")
            return 0
        except OverflowError:
            err_logger.error("Time value overflow")
            return 0
    else:
        err_logger.error("Time value not found")
        return 0


def parse_log_file(file_info: FileInfo) -> Generator[UrlInfo, None, None]:
    """Парсинг файла лога.

    :arg file_info - кортеж с именем и датой файла
    :return: Путь к папке
    """
    err_logger = structlog.stdlib.get_logger()
    if not os.access(file_info.name, mode=os.R_OK):
        err_logger.error("Access to log file denied", path=file_info.name)
        return

    with (
        open(file_info.name, "r", encoding="utf-8")
        if not file_info.is_archive
        else gzip.open(file_info.name, "rt", encoding="utf-8") as file
    ):
        for logLine in file:
            yield UrlInfo(url=extract_url(logLine), requestTime=extract_time(logLine))


def process_log(file_attr: FileInfo) -> LogInfo:
    """Обработка файла лога.

    :arg file_attr - кортеж с именем и датой файла
    :return: Сгруппированные URL
    """
    log_grouped: LogGrouped = {}
    url_count = 0
    url_total_time = float(0)
    for url_info in parse_log_file(file_attr):
        # Счетчик обращений к серверу
        url_count += 1
        # Общее время обращения к серверу
        url_total_time += url_info.requestTime
        # Группируем запросы по URL
        log_grouped.setdefault(url_info.url, []).append(url_info.requestTime)

    return LogInfo(
        url_count=url_count, url_total_time=url_total_time, log_grouped=log_grouped
    )


def gather_stats(log_info: LogInfo, report_size: int) -> UrlStatsTab:
    """Сбор статистики лога.

    :arg log_info - Сгруппированные URL
    :arg report_size - Количество URL в отчете
    :return: Статистика по логу
    """
    err_logger = structlog.stdlib.get_logger()
    url_stats: UrlStatsTab = []
    for grp_key in log_info.log_grouped:
        grp_array = log_info.log_grouped[grp_key]
        grp_len = len(grp_array)
        grp_total = sum(grp_array)
        try:
            url_stats.append(
                UrlStats(
                    url=grp_key,
                    count=grp_len,
                    count_perc=grp_len / log_info.url_count * 100,
                    time_sum=grp_total,
                    time_perc=grp_total / log_info.url_total_time * 100,
                    time_avg=mean(grp_array),
                    time_max=max(grp_array),
                    time_med=median(grp_array),
                )
            )
        except ZeroDivisionError:
            err_logger.error("Division by zero")
    url_stats.sort(key=lambda x: x.time_sum, reverse=True)
    return url_stats[:report_size]


def round_floats(src):
    """Округление float при преобразовании в JSON.

    :arg src - исходные данные
    :return: округленные данные
    """
    if isinstance(src, float):
        return round(src, 3)
    if isinstance(src, dict):
        return {k: round_floats(v) for k, v in src.items()}
    if isinstance(src, (list, tuple)):
        return [round_floats(x) for x in src]
    return src


def get_report_file_name(report_dir: Path, file_date: date) -> Path:
    """Запись отчета в HTML-файл.

    :arg report_dir - каталог для отчета
    :arg file_date - дата отчета
    :return: имя файла
    """
    rep_file_name = "report-" + file_date.strftime("%Y.%m.%d") + ".html"
    return report_dir.joinpath(rep_file_name)


def write_report(
    url_stats: UrlStatsTab, template_file_name: Path, report_file_name: Path
) -> None:
    """Запись отчета в HTML-файл.

    :arg url_stats - статистика URL
    :arg template_file_name - имя файла шаблона
    :arg report_file_name - имя файла отчета
    """
    err_logger = structlog.stdlib.get_logger()

    src_for_json = []
    for url_line in url_stats:
        src_for_json.append(asdict(url_line))
    # json.encoder.FLOAT_REPR = lambda o: format(o, '.3f')
    tab_json = json.dumps(round_floats(src_for_json), default=str)

    try:
        with open(report_file_name, mode="wt", encoding="utf-8") as rep_file:
            with open(template_file_name, mode="rt", encoding="utf-8") as rep_tmpl:
                file_template = Template(rep_tmpl.read())
                file_content = file_template.safe_substitute(table_json=tab_json)
                rep_file.write(file_content)
    except FileNotFoundError:
        err_logger.error("Template file not found", path=template_file_name)
        return
    except PermissionError as pe:
        err_logger.error("No permission on file", path=pe.filename)
        return

    err_logger.info("Report ready", path=report_file_name)


def analyse_logs(actual_config: Dict) -> None:
    """Основной алгоритм.

    :arg actual_config - конфигурация по-умолчанию
    """
    err_logger = structlog.stdlib.get_logger()
    project_root = get_project_root()
    # Имя последнего лога
    file_attr = get_log_file_name(project_root.joinpath(actual_config["log_dir"]))
    report_file_name = get_report_file_name(
        project_root.joinpath(actual_config["report_dir"]), file_attr.f_date
    )
    if file_attr.name == "":
        # Ничего не нашли
        err_logger.error("Log file fot found")
    elif os.path.exists(report_file_name) and os.path.getsize(report_file_name) > 0:
        err_logger.info("Report already prepared")
    else:
        err_logger.info("Log file analysis start", path=file_attr.name)

        try:
            log_grouped = process_log(file_attr)
        except PermissionError:
            err_logger.error("Access to log file denied", path=file_attr.name)
            return

        url_stats = gather_stats(log_grouped, int(actual_config["report_size"]))
        write_report(
            url_stats,
            project_root.joinpath(actual_config["report_template"]),
            report_file_name,
        )


def setup_err_log(actual_config: Dict) -> Any:
    """Основной алгоритм.

    :arg actual_config - конфигурация по-умолчанию
    :return: логгер
    """
    project_root = get_project_root()
    try:
        error_path = project_root.joinpath(actual_config["error_file"])
    except KeyError:
        error_path = project_root

    # Путь указан неверно
    wrong_path = (
        error_path != project_root and error_path.exists() and not error_path.is_file()
    )

    # Путь не указан в конфиге или указан неверно
    if error_path == project_root or wrong_path:
        # Выводим в stdout
        structlog.configure(
            processors=[
                structlog.processors.add_log_level,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.dev.ConsoleRenderer(),
            ],
            logger_factory=structlog.PrintLoggerFactory(),
        )
    else:
        # Выводим в файл
        structlog.configure(
            processors=[
                structlog.processors.add_log_level,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.dict_tracebacks,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.KeyValueRenderer(
                    key_order=["event"], repr_native_str=False
                ),
                structlog.processors.JSONRenderer(),
            ],
            logger_factory=structlog.WriteLoggerFactory(
                file=Path(error_path).open("wt", encoding="utf-8")
            ),
        )
    logger = structlog.stdlib.get_logger()
    if wrong_path:
        logger.error("Invalid error file path", path=error_path)
    return logger


def main(default_config: Dict) -> None:
    """Основной алгоритм.

    :arg default_config - конфигурация по-умолчанию
    """
    # Путь к папке с логами
    actual_config = get_config(default_config)
    # Конфигурация сообщений об ошибках
    err_log = setup_err_log(actual_config)
    try:
        # Анализ логов
        analyse_logs(actual_config)
    except BaseException as be:
        err_log.exception(be)
        sys.exit(1)


if __name__ == "__main__":
    main(config)
