# -*- coding: utf-8 -*-
"""C 语言的 tree-sitter 查询定义。

**捕获协议**（parser.py 依赖这套约定，加语言照抄即可）：
- `@node`   —— 这个概念的主节点（决定行号范围）
- `@name`   —— 名字节点
- `@target` —— 被包含的头文件名（include）
- `@callee` —— 被调用的名字（call / call.ptr）

一律**不**在查询里用 `body:` 之类的字段捕获：不同语法版本的字段名会变，查询会直接编译失败。
体范围、作用域、storage 这类信息由 parser 从主节点的子节点推。
"""
LANG = "c"
GRAMMAR = "tree_sitter_c"
EXTENSIONS = (".c", ".h", ".inc")

# (概念, 查询)。同一概念可以有多条查询，解析结果按顺序追加。
QUERIES = (
    # ---- 函数
    ("function.def", """
      (function_definition
        declarator: (function_declarator declarator: (identifier) @name)) @node
    """),
    ("function.decl", """
      (declaration
        declarator: (function_declarator declarator: (identifier) @name)) @node
    """),
    # ---- 宏
    ("macro.def", """(preproc_def name: (identifier) @name) @node"""),
    ("macro.fn", """(preproc_function_def name: (identifier) @name) @node"""),
    # ---- 类型
    ("struct.def", """(struct_specifier name: (type_identifier) @name) @node"""),
    ("union.def", """(union_specifier name: (type_identifier) @name) @node"""),
    ("enum.def", """(enum_specifier name: (type_identifier) @name) @node"""),
    ("enum.member", """(enumerator (identifier) @name) @node"""),
    ("typedef.def", """(type_definition declarator: (_) @name) @node"""),
    # ---- 结构体字段
    ("field.def", """(field_declaration (field_identifier) @name) @node"""),
    ("field.def", """(field_declaration
        (pointer_declarator declarator: (field_identifier) @name)) @node"""),
    # ---- 文件作用域变量（函数体内的局部变量由 parser 过滤掉）
    ("variable.def", """(declaration
        declarator: (init_declarator declarator: (identifier) @name)) @node"""),
    ("variable.def", """(declaration declarator: (identifier) @name) @node"""),
    # ---- 函数指针声明（盲区证据：这名字可能被间接调用）
    ("fptr.def", """
      (declaration
        declarator: (function_declarator
          declarator: (parenthesized_declarator
            (pointer_declarator declarator: (identifier) @name)))) @node
    """),
    # ---- 依赖
    ("include", """(preproc_include path: (_) @target) @node"""),
    # ---- 调用（调用点是事实；解析到哪个定义是批69 的推断）
    ("call", """(call_expression function: (identifier) @callee) @node"""),
    ("call", """(call_expression
        function: (field_expression field: (field_identifier) @callee)) @node"""),
    ("call.ptr", """(call_expression function: (parenthesized_expression) @callee) @node"""),
    # ---- 引用（只收可证的两类：类型使用、条件编译里的宏名）
    ("type.use", """(type_identifier) @name"""),
    ("macro.use", """(preproc_if condition: (identifier) @name)"""),
    ("macro.use", """(preproc_if condition: (binary_expression (identifier) @name))"""),
    ("macro.use", """(preproc_ifdef name: (identifier) @name)"""),
)
