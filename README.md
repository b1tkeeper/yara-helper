# yara-helper

A tool to parse Yara rules and help you edit Yara rules in your program

## Demo

### Load and dump single rule

```shell
>>> rule_text = """rule person
... {
...     meta:
...         name = "James"
...         age = 18
...         is_male = true
...     strings:
...         say1 = "Hi"
...         say2 = "Nice"
...     condition:
...         all of them
... }"""
>>> info = RuleInfo.load(rule_text)
>>> info.meta['name']
'"James"'
>>> info.strings['say1']
'"Hi"'
>>> info.meta['age'] = 22
>>> info.dump()
'rule person\n{\n    meta:\n        name = "James"\n        age = 22\n        is_male = true\n    strings:\n        say1 = "Hi"\n        say2 = "Nice"\n    condition:\n        all of them\n}'
```

### Load and dump multiple rules

```shell
>>> RuleInfo.load_multiple(yara_text) # return List[RuleInfo]
>>> RuleInfo.dump_multiple(list_of_ruleinfo) # return List[str]
```