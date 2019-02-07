> 学习地址：
>
> - https://hexo.io/docs/index.html

# 1. Overview

install hexo:

```bash
$ npm install -g hexo-cli
```

# 2.Setup

Once Hexo is installed, run the following commands to initialise Hexo in the target `<folder>`.

```bash
$ hexo init <folder>

$ cd <folder>

$ npm install
```

在这个文件夹中可以看到一下的文件结构：

## `_config.yml`

Site [configuration](https://hexo.io/docs/configuration) file. You can configure most settings here.

## `package.json`

Application data. The [EJS](http://embeddedjs.com/), [Stylus](http://learnboost.github.io/stylus/) and [Markdown](http://daringfireball.net/projects/markdown/) renderers are installed by default. If you want, you can uninstall them later.

```json
package.json
{
  "name": "hexo-site",
  "version": "0.0.0",
  "private": true,
  "hexo": {
    "version": ""
  },
  "dependencies": {
    "hexo": "^3.0.0",
    "hexo-generator-archive": "^0.1.0",
    "hexo-generator-category": "^0.1.0",
    "hexo-generator-index": "^0.1.0",
    "hexo-generator-tag": "^0.1.0",
    "hexo-renderer-ejs": "^0.1.0",
    "hexo-renderer-stylus": "^0.2.0",
    "hexo-renderer-marked": "^0.2.4",
    "hexo-server": "^0.1.2"
  }
}
```

## `scaffolds`

[Scaffold](https://hexo.io/docs/writing#Scaffolds) folder. When you create a new post, Hexo bases the new file on the scaffold.

## `source`

Source folder. This is where you put your site’s content. Hexo ignores hidden files and files or folders whose names are prefixed with `_` (underscore) - except the `_posts` folder. Renderable files (e.g. Markdown, HTML) will be processed and put into the `public` folder, while other files will simply be copied.

## `themes`

[Theme](https://hexo.io/docs/themes) folder. Hexo generates a static website by combining the site contents with the theme.

# 3. Configuration

You can modify site settings in `_config.yml` or in an [alternate config file](https://hexo.io/docs/configuration#Using-an-Alternate-Config).

## `site`

| Setting       | Description                                                  |
| ------------- | ------------------------------------------------------------ |
| `title`       | The title of your website                                    |
| `subtitle`    | The subtitle of your website                                 |
| `description` | The description of your website                              |
| `author`      | Your name                                                    |
| `language`    | The language of your website. Use a [2-lettter ISO-639-1 code](https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes). Default is `en`. |
| `timezone`    | The timezone of your website. Hexo uses the setting on your computer by default. You can find the list of available timezones [here](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones). Some examples are `America/New_York`, `Japan`, and `UTC`. |

