# Markdown 语法常用技巧

## 提示块

提示块遵循简单的语法：块以 `!!!` 开头，后跟用作类型限定符的单个关键字。块的内容在下一行，缩进四个空格：

??? note "查看例子"

    - `!!! note "Note"` 会呈现为不可折叠块
    - `??? note "Note"` 会呈现为可折叠块
    - `???+ note "Note"` 会呈现为展开状态的可折叠块





``` markdown title="Admonition, collapsible and initially expanded"
???+ note "Note"

    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla et euismod
    nulla. Curabitur feugiat, tortor non consequat finibus, justo purus auctor
    massa, nec semper lorem quam in massa.
```

<div class="result" markdown>

???+ note "Note"

    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla et euismod
    nulla. Curabitur feugiat, tortor non consequat finibus, justo purus auctor
    massa, nec semper lorem quam in massa.

</div>