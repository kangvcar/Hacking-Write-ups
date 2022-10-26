# Markdown 语法常用技巧

这里只列出特色的语法，更多语法请参考

- [mkdocs-material/reference](https://squidfunk.github.io/mkdocs-material/reference/)
- [Markdown 语法说明 (简体中文版)](https://markdown.com.cn/basic-syntax/)。

## 代码块

```` markdown title="1. 包含标题的代码块"
```python
``` py title="bubble_sort.py"
def bubble_sort(items):
    for i in range(len(items)):
        for j in range(len(items) - 1 - i):
            if items[j] > items[j + 1]:
                items[j], items[j + 1] = items[j + 1], items[j]
```
````

<div class="result" markdown>

``` py title="bubble_sort.py"
def bubble_sort(items):
    for i in range(len(items)):
        for j in range(len(items) - 1 - i):
            if items[j] > items[j + 1]:
                items[j], items[j + 1] = items[j + 1], items[j]
```

</div>


```` markdown title="2. 包含注释的代码块"
``` yaml
theme:
  features:
    - content.code.annotate # (1)
```

1.  :man_raising_hand: I'm a code annotation! I can contain `code`, __formatted
    text__, images, ... basically anything that can be written in Markdown.
````

<div class="result" markdown>

``` yaml
theme:
  features:
    - content.code.annotate # (1)
```

1.  :man_raising_hand: I'm a code annotation! I can contain `code`, __formatted
    text__, images, ... basically anything that can be written in Markdown.

</div>

```` markdown title="3. 包含行号的代码块"
``` yaml linenums="1"
``` py linenums="1"
def bubble_sort(items):
    for i in range(len(items)):
        for j in range(len(items) - 1 - i):
            if items[j] > items[j + 1]:
                items[j], items[j + 1] = items[j + 1], items[j]
```
````

<div class="result" markdown>

``` py linenums="1"
def bubble_sort(items):
    for i in range(len(items)):
        for j in range(len(items) - 1 - i):
            if items[j] > items[j + 1]:
                items[j], items[j + 1] = items[j + 1], items[j]
```

</div>

```` markdown title="4. 指定高亮行的代码块"
``` py hl_lines="2 3"
def bubble_sort(items):
    for i in range(len(items)):
        for j in range(len(items) - 1 - i):
            if items[j] > items[j + 1]:
                items[j], items[j + 1] = items[j + 1], items[j]
```
````

<div class="result" markdown>

``` py linenums="1" hl_lines="2 3"
def bubble_sort(items):
    for i in range(len(items)):
        for j in range(len(items) - 1 - i):
            if items[j] > items[j + 1]:
                items[j], items[j + 1] = items[j + 1], items[j]
```

</div>

## 图片

??? tip "支持的控制设置"

    - `{ width="300" }`: 图片宽度
    - `{ width=50% }`: 图片缩放比例
    - `{ align="left" }`: 图片对齐方式
    - `{ loading=lazy }`: 懒惰模式加载图片

``` markdown title="图片，缩放比例"
![Image title](https://dummyimage.com/600x400/){ width=50% }
```

<div class="result" markdown>
  <img src="https://dummyimage.com/600x400/f5f5f5/aaaaaa&text=–%20Image%20–" width=50% />
</div>

## 提示块

提示块遵循简单的语法：块以 `!!!` 开头，后跟用作类型限定符的单个关键字。块的内容在下一行，缩进四个空格：

??? note "查看例子"

    - `!!! note "Note"` 会呈现为不可折叠块
    - `??? note "Note"` 会呈现为可折叠块
    - `???+ note "Note"` 会呈现为展开状态的可折叠块
    - `???+ tip "Note"` 会呈现为折叠状态的可折叠块，且带有一个小图标

??? tip "支持的类型"

    - `note`
    - `abstract`
    - `info`
    - `tip`
    - `success`
    - `question`
    - `warning`
    - `failure`
    - `danger`
    - `bug`
    - `example`
    - `quote`



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


## 按钮

为了将链接呈现为按钮，请使用{ .md-button }作为后缀。例子如下：

``` markdown title="Button"
[Subscribe to our newsletter](https://wp.hvvyxs.com/){ .md-button }
```

<div class="result" markdown>

[Subscribe to our newsletter](https://wp.hvvyxs.com/){ .md-button }

</div>

``` markdown title="Button, primary"
[Subscribe to our newsletter](https://wp.hvvyxs.com/){ .md-button .md-button--primary }
```

<div class="result" markdown>

[Subscribe to our newsletter](https://wp.hvvyxs.com/){ .md-button .md-button--primary }

</div>


``` markdown title="Button with icon"
[Send :fontawesome-solid-paper-plane:](https://wp.hvvyxs.com/){ .md-button }
```

<div class="result" markdown>

[Send :fontawesome-solid-paper-plane:](https://wp.hvvyxs.com/){ .md-button }

</div>

## 表格

``` markdown title="Data table"
| Method      | Description                          |
| ----------- | ------------------------------------ |
| `GET`       | :material-check:     Fetch resource  |
| `PUT`       | :material-check-all: Update resource |
| `DELETE`    | :material-close:     Delete resource |
```

<div class="result" markdown>

| Method      | Description                          |
| ----------- | ------------------------------------ |
| `GET`       | :material-check:     Fetch resource  |
| `PUT`       | :material-check-all: Update resource |
| `DELETE`    | :material-close:     Delete resource |

</div>

## 脚注

``` title="带有脚注引用的文本"
Lorem ipsum[^1] dolor sit amet, consectetur adipiscing elit.[^2]

[^1]: Lorem ipsum dolor sit amet, consectetur adipiscing elit.

```

<div class="result" markdown>

Lorem ipsum[^1] dolor sit amet, consectetur adipiscing elit.

[^1]: Lorem ipsum dolor sit amet, consectetur adipiscing elit.

</div>

