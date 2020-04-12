# LastPass Rust Client

[![Continuous integration](https://github.com/Michael-F-Bryan/lastpass/workflows/Continuous%20integration/badge.svg?branch=master)](https://github.com/Michael-F-Bryan/lastpass/actions)

([API Docs])

An unofficial interface to the LastPass API based on the
[lastpass/lastpass-cli][upstream] project..

## License

This project is considered a derived work of [lastpass-cli][upstream], and is
therefore also licensed under GPLv2.

> Copyright (C) 2020  Michael-F-Bryan <michaelfbryan@gmail.com>
>
> This program is free software: you can redistribute it and/or modify
> it under the terms of the GNU General Public License as published by
> the Free Software Foundation, either version 3 of the License, or
> (at your option) any later version.
>
> This program is distributed in the hope that it will be useful,
> but WITHOUT ANY WARRANTY; without even the implied warranty of
> MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
> GNU General Public License for more details.
>
> You should have received a copy of the GNU General Public License
> along with this program.  If not, see <https://www.gnu.org/licenses/>.

### Contribution

It is recommended to always use [cargo-crev][crev] to verify the
trustworthiness of each of your dependencies, including this one.

The intent of this crate is to be free of soundness bugs. The developers will
do their best to avoid them, and welcome help in analysing and fixing them.

[API Docs]: https://michael-f-bryan.github.io/lastpass
[crev]: https://github.com/crev-dev/cargo-crev
[upstream]: https://github.com/lastpass/lastpass-cli
