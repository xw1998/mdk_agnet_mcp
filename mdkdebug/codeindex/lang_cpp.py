# -*- coding: utf-8 -*-
"""C++ 的 tree-sitter 查询定义（捕获协议见 lang_c.py）。

**覆盖范围如实说明（不假装完整）**：函数/方法、类/结构体/联合/枚举、typedef、
命名空间、include、调用（含 `obj.method()` 与限定名 `A::b()`）、类型使用。
**不覆盖**：模板实例化、重载消歧、运算符重载、继承链、宏展开——这些在批69 会落进盲区。
"""
LANG = "cpp"
GRAMMAR = "tree_sitter_cpp"
EXTENSIONS = (".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h++")

QUERIES = (
    # ---- 函数与方法
    ("function.def", """
      (function_definition
        declarator: (function_declarator declarator: (identifier) @name)) @node
    """),
    ("function.def", """
      (function_definition
        declarator: (function_declarator declarator: (field_identifier) @name)) @node
    """),
    ("function.def", """
      (function_definition
        declarator: (pointer_declarator
          declarator: (function_declarator declarator: (identifier) @name))) @node
    """),
    ("function.decl", """
      (declaration
        declarator: (function_declarator declarator: (identifier) @name)) @node
    """),
    ("function.decl", """
      (declaration
        declarator: (function_declarator declarator: (field_identifier) @name)) @node
    """),
    # ---- 宏
    ("macro.def", """(preproc_def name: (identifier) @name) @node"""),
    ("macro.fn", """(preproc_function_def name: (identifier) @name) @node"""),
    # ---- 类型
    ("class.def", """(class_specifier name: (type_identifier) @name) @node"""),
    ("struct.def", """(struct_specifier name: (type_identifier) @name) @node"""),
    ("union.def", """(union_specifier name: (type_identifier) @name) @node"""),
    ("enum.def", """(enum_specifier name: (type_identifier) @name) @node"""),
    ("enum.member", """(enumerator (identifier) @name) @node"""),
    ("typedef.def", """(type_definition declarator: (_) @name) @node"""),
    ("namespace.def", """
      (namespace_definition name: (namespace_identifier) @name) @node
    """),
    # ---- 成员
    ("field.def", """(field_declaration (field_identifier) @name) @node"""),
    ("field.def", """(field_declaration
        (pointer_declarator declarator: (field_identifier) @name)) @node"""),
    # ---- 文件作用域变量（函数体内的局部变量由 parser 过滤掉）
    ("variable.def", """(declaration
        declarator: (init_declarator declarator: (identifier) @name)) @node"""),
    ("variable.def", """(declaration declarator: (identifier) @name) @node"""),
    ("fptr.def", """
      (declaration
        declarator: (function_declarator
          declarator: (parenthesized_declarator
            (pointer_declarator declarator: (identifier) @name)))) @node
    """),
    # ---- 依赖
    ("include", """(preproc_include path: (_) @target) @node"""),
    # ---- 调用
    ("call", """(call_expression function: (identifier) @callee) @node"""),
    ("call", """(call_expression function: (qualified_identifier) @callee) @node"""),
    ("call", """(call_expression
        function: (field_expression field: (field_identifier) @callee)) @node"""),
    ("call.ptr", """(call_expression function: (parenthesized_expression) @callee) @node"""),
    # ---- 引用
    ("type.use", """(type_identifier) @name"""),
    ("macro.use", """(preproc_if condition: (identifier) @name)"""),
    ("macro.use", """(preproc_if condition: (binary_expression (identifier) @name))"""),
    ("macro.use", """(preproc_ifdef name: (identifier) @name)"""),
)
