![TRAP logo](https://mauricelambert.github.io/info/perl/code/TRAP_small.png "TRAP logo")

# TRAP

## Name

TRAP - Tool for Regex Analysis with Perl

## Version

Version 0.0.1

## Description

A forensic tool to extract some informations from files.

I created this tool following an investigation of an infected backup file. This file was only part of a backup and it was necessary to identify the server to which this piece of backup corresponded. I finally found the server by analyzing the file, strings after strings. Some strings allowed the absolute identification of the server. I chose to create this tool in order to avoid long search to other people in a similar case.

It was also important to find out why the file was detected as infected. This tool will allow you to identify certain payloads or abnormal elements on a server.

I make this tool in perl because it is pre-integrated on all Linux systems and it is particularly optimized for regular expression.

## Requirements

 - Perl (v5.26)
 - Perl Standard Library
     - strict
     - JSON::PP
     - Text::CSV
     - Pod::Usage
     - Time::Piece
     - Getopt::Long
     - File::Basename
     - Term::ANSIColor
     - File::Map

## Installation

```bash
git clone https://github.com/MauriceLambert/TRAP.git
```

## Usages

### Perl

```perl
use TRAP;
open my $report, ">>", "report.json";
my $csv = Text::CSV->new ( { binary => 1, sep_char => "," } );
my %files = (CSV => $csv, report => $report);
analysis "myfile.bak", \%files;
```

### Command line

```bash
perl TRAP.pm -h
perl TRAP.pm --help
perl TRAP.pm -t
./TRAP.pm --test --debug --no-color
perl TRAP.pm -c -d -f *.txt,*.bak,*.bin
./TRAP.pm --files *.txt,*.bak,*.bin
```

## Screens

![TRAP screen](https://mauricelambert.github.io/info/perl/code/TRAP_demo.PNG "TRAP screen")

## Logo

![TRAP Logo](https://mauricelambert.github.io/info/perl/code/TRAP.png "TRAP logo")

## Link

 - [Documentation](https://mauricelambert.github.io/info/perl/code/TRAP.html)
 - [Github](https://github.com/MauriceLambert/TRAP)

## License

Licensed under the [GPL, version 3. (GPL-3.0 License)](https://www.gnu.org/licenses/)