# !/usr/bin/env python3
# -*- coding=utf-8 -*-
#
# @File:        parse.py
# @Time:        5/7/22 9:41 AM
# @Author:      Wang Bohan <wbhan_cn@qq.com>
# @Description: Convert and modify your yara rule between text and object

# MIT License
#
# Copyright (c) 2022 b1tkeeper
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import re
from typing import Dict, List


def split_rules(yara_text: str) -> List[str]:
    """
    Split all yara rules into a list from yara file.
    :param yara_text: text in yara rules.
    :return: list of yara rules(text).
    """
    # return re.findall(r"rule\s+.*?}", yara_text, flags=re.S)
    return re.findall(r"rule\s*.*?condition:.*?}", yara_text, flags=re.S)


def parse_meta(meta_text) -> Dict[str, str]:
    meta = dict()
    for line in meta_text.splitlines():
        # Exclude blank line.
        if len(line.strip()) == 0:
            continue
        idx = line.find("=")
        k, v = line[:idx].strip(), line[idx + 1:].strip()
        meta[k] = v
    return meta


def parse_strings(strings_text) -> Dict[str, str]:
    strings = dict()
    for line in strings_text.splitlines():
        # Exclude blank line.
        if len(line.strip()) == 0:
            continue
        idx = line.find("=")
        k, v = line[:idx].strip(), line[idx + 1:].strip()
        strings[k] = v
    return strings


class RuleInfo:

    def __init__(self, identifier: str, meta: Dict[str, str], strings: Dict[str, str], condition: str):
        self.identifier, self.meta, self.strings, self.condition = identifier, meta, strings, condition

    @staticmethod
    def load(yara_text: str) -> 'RuleInfo':
        """
        Load RuleInfo from a yara rule.
        :param yara_text: a single yara rule, It will throw exception when multiple.
        :return: a RuleInfo object
        """
        if len(split_rules(yara_text)) > 1:
            raise ValueError('RuleInfo.load can only receive a single yara rule.')
        # parse identifier info
        matched_i = re.search(r"rule\s+(.*?)$", yara_text, re.M)
        try:
            identifier = matched_i.group(1)
        except AttributeError:
            raise SyntaxError(f"Can't detect identifier from this yara rule\n{yara_text}")

        # parse meta info
        matched_m = re.search(r"meta:(.*?)strings:", yara_text, re.S)
        try:
            meta_string = matched_m.group(1).strip()
        except AttributeError:
            raise SyntaxError(f"Can't detect meta info from this yara rule\n{yara_text}")
        meta = parse_meta(meta_string)

        # parse strings info
        matched_s = re.search(r"strings:(.*?)condition:", yara_text, re.S)
        try:
            strings_string = matched_s.group(1).strip()
        except AttributeError:
            raise SyntaxError(f"Can't detect strings info from this yara rule\n{yara_text}")
        strings = parse_strings(strings_string)

        # parse condition info
        matched_c = re.search(r"condition:(.*?)}", yara_text, re.S)
        try:
            condition = matched_c.group(1).strip()
        except AttributeError:
            raise SyntaxError(f"Can't detect condition info from this yara rule\n{yara_text}")

        return RuleInfo(identifier, meta, strings, condition)

    @staticmethod
    def load_multiple(yara_text: str) -> List['RuleInfo']:
        """
        Load multiple rules from yara text.
        :param yara_text: yara text, include multiple yara rules.
        :return: List of `RuleInfo`
        """
        rules = split_rules(yara_text)
        return [RuleInfo.load(r) for r in rules]

    def dump(self) -> str:
        tab = " " * 4

        # generate meta
        meta_expr = [
            f'''{tab * 2}{k} = {v}'''
            for k, v in self.meta.items()
        ]
        meta_expr = "\n".join(meta_expr)

        # generate strings
        strings_expr = [
            f'''{tab * 2}{k} = {v}'''
            for k, v in self.strings.items()
        ]
        strings_expr = "\n".join(strings_expr)
        return """rule {identifier}
{{
    meta:
{meta_expr}
    strings:
{strings_expr}
    condition:
{condition_expr}
}}""".format(identifier=self.identifier, meta_expr=meta_expr, strings_expr=strings_expr,
             condition_expr=tab * 2 + self.condition)

    @staticmethod
    def dump_multiple(rules: List['RuleInfo']) -> str:
        return "\n".join([r.dump() for r in rules])
